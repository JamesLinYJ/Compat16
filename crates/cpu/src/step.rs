//! Instruction-boundary access planning and architectural state commits.

use guest_core::{
    GuestMemory,
    io::{NoPorts, PortIo},
};

use crate::{
    Cpu, CpuError, IF, RealModeSegments, SegmentResolver, StepOutcome, execute,
    execution_boundary::{ExecutionBoundaryReport, ExecutionProgress},
    interrupt_delivery::{CpuEvent, EventSource, deliver_event_checked, exception_event},
    memory_access::{AccessSite, CpuBus, CpuMemoryAccess, DataBreakpointHits},
    registers::SegmentRegister,
    x86_decode, x87,
};

use x86_decoder::Mnemonic;

const EFLAGS_RF: u32 = 1 << 16;

struct StepBoundary {
    progress: ExecutionProgress,
    outcome: StepOutcome,
    interrupt_source: Option<EventSource>,
    instruction_opcode: u8,
    task_switched: bool,
    data_breakpoint_hits: DataBreakpointHits,
}

impl Cpu {
    /// Execute one instruction against process-owned guest memory.
    pub fn step(&mut self, memory: &mut impl GuestMemory) -> Result<StepOutcome, CpuError> {
        self.step_with_io(memory, &mut NoPorts)
    }

    /// Execute with an explicitly supplied emulated device bus.
    pub fn step_with_io(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
    ) -> Result<StepOutcome, CpuError> {
        self.step_with_context(memory, ports, &RealModeSegments)
    }

    /// Execute one instruction and return a CPU event before its architectural
    /// delivery. The runtime may enter a guest-owned handler, then replay the
    /// opaque event token after that checked continuation returns.
    pub fn step_with_context_observing_events(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
    ) -> Result<crate::CpuObservedStepOutcome, CpuError> {
        self.step_with_context_observing_events_report(memory, ports, segments).outcome
    }

    pub(crate) fn step_with_context_observing_events_report(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
    ) -> ExecutionBoundaryReport<crate::CpuObservedStepOutcome> {
        self.deferred_cpu_event = None;
        self.defer_cpu_events = true;
        let report = self.step_with_context_report(memory, ports, segments);
        self.defer_cpu_events = false;
        let outcome = match (report.outcome, self.deferred_cpu_event.take()) {
            (Ok(_), Some(event)) => Ok(crate::CpuObservedStepOutcome::EventDeferred(event)),
            (Ok(outcome), None) => Ok(crate::CpuObservedStepOutcome::Executed(outcome)),
            (Err(error), None) => Err(error),
            (Err(error), Some(_)) => Err(error),
        };
        ExecutionBoundaryReport { progress: report.progress, outcome }
    }

    /// The machine owner supplies code/stack sizes and checked segment aliases.
    pub fn step_with_context(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
    ) -> Result<StepOutcome, CpuError> {
        self.step_with_context_report(memory, ports, segments).outcome
    }

    pub(crate) fn step_with_context_report(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
    ) -> ExecutionBoundaryReport<StepOutcome> {
        let mut progress = ExecutionProgress::NoInstruction;
        let outcome = self.step_with_context_inner(memory, ports, segments, &mut progress);
        ExecutionBoundaryReport { progress, outcome }
    }

    fn step_with_context_inner(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
        progress: &mut ExecutionProgress,
    ) -> Result<StepOutcome, CpuError> {
        let Some(next_sequence) = self.next_call_boundary_sequence() else {
            self.call_boundary_sequence_exhausted = true;
            self.control_transfer = None;
            self.invalidate_control_transfer_provenance();
            return Err(CpuError::CallBoundarySequenceExhausted);
        };
        self.call_boundary_sequence = next_sequence;
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        self.normalize_model_eflags();
        if let Some(reason) = self.shutdown_reason.as_ref() {
            return Err(reason.clone());
        }
        self.initialize_explicit_real_mode_context(segments);
        if self.system.architectural_context_initialized
            && std::mem::replace(&mut self.pending_task_debug_trap, false)
        {
            self.system.debug.status |= 1 << 15;
            self.debug_exception_shadow = false;
            self.deferred_data_breakpoint_hits = DataBreakpointHits::default();
            self.halted = false;
            let event = CpuEvent {
                vector: 1,
                source: EventSource::Trap,
                saved_eip: self.regs.eip,
                instruction_ip: self.regs.eip,
                instruction_opcode: 0,
                error_code: None,
            };
            if self.defer_step_event(event, None) {
                return Ok(StepOutcome::Continue);
            }
            deliver_event_checked(self, event, None, memory, segments)?;
            return Ok(StepOutcome::Continue);
        }
        if self.can_accept_non_maskable_interrupt() {
            if !self.system.architectural_context_initialized {
                return Err(CpuError::CompatibilityGap {
                    opcode: 0,
                    ip: self.regs.eip,
                    feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
                });
            }
            let event = CpuEvent {
                vector: 2,
                source: EventSource::NonMaskableInterrupt,
                saved_eip: self.regs.eip,
                instruction_ip: self.regs.eip,
                instruction_opcode: 0,
                error_code: None,
            };
            self.pending_non_maskable_interrupt = false;
            self.non_maskable_interrupt_blocked = true;
            // An accepted event ends a stack-switch debug shadow. Any data
            // match waiting for the post-SS instruction is lost on delivery.
            self.debug_exception_shadow = false;
            self.deferred_data_breakpoint_hits = DataBreakpointHits::default();
            self.halted = false;
            if self.defer_step_event(event, None) {
                return Ok(StepOutcome::Continue);
            }
            deliver_event_checked(self, event, None, memory, segments)?;
            return Ok(StepOutcome::Continue);
        }
        if self.halted {
            return Ok(StepOutcome::Halt);
        }
        let flags_before = self.regs.eflags;
        let code_bits = if self.system.architectural_context_initialized {
            self.system.code_bits()
        } else {
            segments.code_bits()
        };
        let legacy_projection = !self.system.architectural_context_initialized
            && self.system.cr0 & crate::system::CR0_PE == 0;
        let protected_eip32 = !legacy_projection
            && self.system.execution_mode(self.regs.eflags)
                == Some(crate::CpuExecutionMode::Protected);
        let virtual_8086 = !legacy_projection
            && self.system.execution_mode(self.regs.eflags)
                == Some(crate::CpuExecutionMode::Virtual8086);
        let instruction_ip = if code_bits == 16 && !protected_eip32 && !virtual_8086 {
            u32::from(self.regs.ip())
        } else {
            self.regs.eip
        };
        // The previous boundary's REP marker remains available to any event
        // delivered between calls. Once execution resumes, the next boundary
        // must establish its own explicit completion state.
        let resumes_repeat_iteration = self.intermediate_rep_boundary;
        self.intermediate_rep_boundary = false;
        let debug_shadow_was_active = self.debug_exception_shadow;
        // Faults may preserve partial REP or task-switch effects. Only a
        // successful executor boundary can promote this to completed progress.
        *progress = ExecutionProgress::InstructionIncomplete;
        match self.step_instruction(memory, ports, segments, resumes_repeat_iteration) {
            Err(CpuError::FloatException)
                if self.system.architectural_context_initialized
                    && self.system.cr0 & crate::system::CR0_NE == 0 =>
            {
                self.pending_x87_irq13 = true;
                Ok(StepOutcome::Continue)
            }
            Err(CpuError::TaskSwitchCommitted { target_ip, fault })
                if self.system.architectural_context_initialized =>
            {
                if let Some(mut event) = exception_event(&fault, target_ip) {
                    self.clear_debug_shadow_after_fault(debug_shadow_was_active);
                    event.saved_eip = target_ip;
                    event.instruction_ip = target_ip;
                    if self.defer_step_event(event, Some((*fault).clone())) {
                        return Ok(StepOutcome::Continue);
                    }
                    deliver_event_checked(self, event, Some(*fault), memory, segments)?;
                    Ok(StepOutcome::Continue)
                } else {
                    Err(*fault)
                }
            }
            Err(error) if self.system.architectural_context_initialized => {
                let event = if matches!(&error, CpuError::FloatException) {
                    Some(CpuEvent {
                        vector: 16,
                        source: EventSource::Fault,
                        saved_eip: instruction_ip,
                        instruction_ip,
                        instruction_opcode: 0,
                        error_code: None,
                    })
                } else {
                    exception_event(&error, instruction_ip)
                };
                if let Some(event) = event {
                    self.clear_debug_shadow_after_fault(debug_shadow_was_active);
                    if self.defer_step_event(event, Some(error.clone())) {
                        return Ok(StepOutcome::Continue);
                    }
                    deliver_event_checked(self, event, Some(error), memory, segments)?;
                    Ok(StepOutcome::Continue)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
            Ok(boundary) => {
                // Preserve body progress even if the following architectural
                // delivery faults, redirects execution, or defers an event.
                *progress = boundary.progress;
                debug_assert_eq!(
                    boundary.progress == ExecutionProgress::RepeatPartial,
                    self.intermediate_rep_boundary,
                );
                if std::mem::replace(&mut self.pending_task_debug_trap, false) {
                    self.system.debug.status |= 1 << 15;
                    let event = CpuEvent {
                        vector: 1,
                        source: EventSource::Trap,
                        saved_eip: self.regs.eip,
                        instruction_ip: self.regs.eip,
                        instruction_opcode: 0,
                        error_code: None,
                    };
                    if self.defer_step_event(event, None) {
                        return Ok(StepOutcome::Continue);
                    }
                    deliver_event_checked(self, event, None, memory, segments)?;
                    if boundary.outcome == StepOutcome::Halt {
                        return Ok(StepOutcome::Continue);
                    }
                }
                let mut software_interrupt_delivered = false;
                if let (Some(source), StepOutcome::Interrupt(vector)) =
                    (boundary.interrupt_source, boundary.outcome)
                {
                    if matches!(
                        self.architectural_execution_mode(),
                        Some(
                            crate::CpuExecutionMode::Protected
                                | crate::CpuExecutionMode::Virtual8086
                        )
                    ) || (self.architectural_execution_mode()
                        == Some(crate::CpuExecutionMode::RealAddress))
                    {
                        let event = CpuEvent {
                            vector,
                            source,
                            saved_eip: self.regs.eip,
                            instruction_ip,
                            instruction_opcode: boundary.instruction_opcode,
                            error_code: None,
                        };
                        if self.defer_step_event(event, None) {
                            return Ok(StepOutcome::Continue);
                        }
                        deliver_event_checked(self, event, None, memory, segments)?;
                        software_interrupt_delivered = true;
                    }
                }
                let single_step = flags_before & crate::TF != 0
                    && !self.debug_exception_shadow
                    && !boundary.task_switched
                    && matches!(boundary.outcome, StepOutcome::Continue | StepOutcome::Halt)
                    && self.system.architectural_context_initialized;
                if boundary.data_breakpoint_hits.enabled != 0 || single_step {
                    self.system.debug.status |=
                        u32::from(boundary.data_breakpoint_hits.matching);
                    if single_step {
                        self.system.debug.status |= 1 << 14;
                    }
                    let event = CpuEvent {
                        vector: 1,
                        source: EventSource::Trap,
                        saved_eip: self.regs.eip,
                        instruction_ip: self.regs.eip,
                        instruction_opcode: 0,
                        error_code: None,
                    };
                    if self.defer_step_event(event, None) {
                        return Ok(StepOutcome::Continue);
                    }
                    deliver_event_checked(self, event, None, memory, segments)?;
                    if boundary.outcome == StepOutcome::Halt || software_interrupt_delivered {
                        return Ok(StepOutcome::Continue);
                    }
                }
                if software_interrupt_delivered {
                    return Ok(StepOutcome::Continue);
                }
                Ok(boundary.outcome)
            }
        }
    }

    fn step_instruction(
        &mut self,
        memory: &mut impl GuestMemory,
        ports: &mut impl PortIo,
        segments: &impl SegmentResolver,
        resumes_repeat_iteration: bool,
    ) -> Result<StepBoundary, CpuError> {
        self.initialize_explicit_real_mode_context(segments);
        // Until the machine imports CPU-owned hidden state or explicitly
        // refreshes real-mode caches, preserve the existing resolver boundary
        // for unknown mode/CPL or checked protected selector projection. Once
        // that boundary is established, CS hidden state owns decode width.
        let legacy_projection = !self.system.architectural_context_initialized
            && self.system.cr0 & crate::system::CR0_PE == 0;
        let code_bits = if legacy_projection {
            segments.code_bits()
        } else {
            self.system.code_bits()
        };
        let protected_eip32 = !legacy_projection
            && self.system.execution_mode(self.regs.eflags)
                == Some(crate::CpuExecutionMode::Protected);
        let virtual_8086 = !legacy_projection
            && self.system.execution_mode(self.regs.eflags)
                == Some(crate::CpuExecutionMode::Virtual8086);
        let start_ip = if code_bits == 16 && !protected_eip32 && !virtual_8086 {
            u32::from(self.regs.ip())
        } else {
            self.regs.eip
        };
        if !resumes_repeat_iteration && self.instruction_breakpoint_matches(start_ip)? {
            return Err(CpuError::InstructionBreakpointFault { ip: start_ip });
        }
        let debug_shadow_was_active = self.debug_exception_shadow;
        let mut bus = CpuMemoryAccess::new(
            memory,
            segments,
            &mut self.system,
            AccessSite {
                opcode: 0,
                ip: start_ip,
                eflags: self.regs.eflags,
            },
        );
        let decoded = x86_decode::decode_cached(
            &mut bus, self.regs.cs, start_ip, &mut self.decode_cache,
        )?;
        bus.set_instruction_opcode(decoded.opcode);
        if !self
            .model
            .supports_instruction_features(decoded.required_cpu_features())
        {
            return Err(CpuError::InvalidOpcode {
                opcode: decoded.opcode,
                ip: decoded.start_ip,
            });
        }
        if matches!(decoded.instruction.mnemonic(), Mnemonic::Iret | Mnemonic::Iretd) {
            // Intel clears NMI blocking when IRET starts, before frame reads;
            // a fault in the return frame does not re-block NMI recognition.
            self.non_maskable_interrupt_blocked = false;
        }
        self.jit.observe(decoded, self.regs.cs, &mut self.decode_cache);
        let transfer_candidate = decoded.control_transfer_candidate(self.regs.cs, self.regs.ss);
        let interrupt_shadow = decoded
            .creates_interrupt_shadow(self.regs.eflags & IF != 0, self.maskable_interrupt_shadow);
        // This path accepts only nontrapping GPR/flag IR after fetch and model
        // validation. It cannot touch the bus or segment/system state, so it
        // needs no speculative full-register clone or unrelated executors.
        // The common retirement and outer event boundary still run below.
        let jit_completed = self.jit.execute(&mut self.regs, decoded);
        if !jit_completed && decoded.is_x87() {
            let unavailable = if decoded.is_wait() {
                bus.system().wait_instruction_unavailable()
            } else {
                bus.system().x87_instruction_unavailable()
            };
            if unavailable {
                return Err(CpuError::DeviceNotAvailableFault { ip: start_ip });
            }
            let mut regs = self.regs.clone();
            let mut state = self.x87.clone();
            let had_pending_exception = state.pending_unmasked_exceptions() != 0;
            let exception_flags_before = state.status_word & crate::x87_state::X87_EXCEPTION_FLAGS;
            let instruction = x86_decode::NormalizedInstruction::new(decoded);
            match x87::execute(&mut regs, &mut bus, &mut state, &instruction, &mut self.jit) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(CpuError::UnsupportedOpcode {
                        opcode: decoded.opcode,
                        ip: start_ip,
                    });
                }
                Err(error @ CpuError::FloatException) => {
                    // The coprocessor's exception status is architectural even
                    // when it suppresses the destination register update.
                    self.x87 = state;
                    if bus.system().architectural_context_initialized && !had_pending_exception {
                        // A new unmasked exception is reported before the next
                        // waiting instruction, so this instruction retires and
                        // the pending status chooses IRQ13 or #MF later.
                        regs.eip = decoded.next_ip;
                        regs.eflags &= !EFLAGS_RF;
                        self.regs = regs;
                        if bus.system().cr0 & crate::system::CR0_NE == 0 {
                            self.pending_x87_irq13 = true;
                        }
                        self.maskable_interrupt_shadow = interrupt_shadow;
                        self.debug_exception_shadow = !debug_shadow_was_active
                            && decoded.creates_debug_exception_shadow();
                        let data_breakpoint_hits = retire_data_breakpoints(
                            &mut self.deferred_data_breakpoint_hits,
                            bus.take_data_breakpoint_hits(),
                            self.debug_exception_shadow,
                        );
                        return Ok(StepBoundary {
                            progress: ExecutionProgress::InstructionBodyCompleted,
                            outcome: StepOutcome::Continue,
                            interrupt_source: None,
                            instruction_opcode: 0,
                            task_switched: false,
                            data_breakpoint_hits,
                        });
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
            regs.eip = decoded.next_ip;
            regs.eflags &= !EFLAGS_RF;
            self.regs = regs;
            self.x87 = state;
            let newly_recorded_unmasked_exception_flags = (self.x87.status_word
                & !exception_flags_before
                & !self.x87.control_word)
                & crate::x87_state::X87_EXCEPTION_FLAGS;
            if bus.system().architectural_context_initialized
                && bus.system().cr0 & crate::system::CR0_NE == 0
                && !had_pending_exception
                && newly_recorded_unmasked_exception_flags != 0
                && !matches!(
                    decoded.instruction.mnemonic(),
                    Mnemonic::Fldenv | Mnemonic::Frstor
                )
            {
                // Only this instruction's newly raised exception can latch
                // IRQ13. Imported status and an older flag exposed by FLDCW
                // remain pending until a waiting instruction observes them.
                self.pending_x87_irq13 = true;
            }
            self.maskable_interrupt_shadow = interrupt_shadow;
            self.debug_exception_shadow = !debug_shadow_was_active
                && decoded.creates_debug_exception_shadow();
            let data_breakpoint_hits = retire_data_breakpoints(
                &mut self.deferred_data_breakpoint_hits,
                bus.take_data_breakpoint_hits(),
                self.debug_exception_shadow,
            );
            return Ok(StepBoundary {
                progress: ExecutionProgress::InstructionBodyCompleted,
                outcome: StepOutcome::Continue,
                interrupt_source: None,
                instruction_opcode: 0,
                task_switched: false,
                data_breakpoint_hits,
            });
        }
        if !jit_completed
            && let Some(instruction) = x86_decode::normalize_system_instruction(decoded)
        {
            let mut regs = self.regs.clone();
            execute::execute_system(&mut regs, &mut bus, &instruction)?;
            regs.eip = decoded.next_ip;
            regs.eflags &= !EFLAGS_RF;
            self.regs = regs;
            self.maskable_interrupt_shadow = interrupt_shadow;
            self.debug_exception_shadow = !debug_shadow_was_active
                && decoded.creates_debug_exception_shadow();
            let data_breakpoint_hits = retire_data_breakpoints(
                &mut self.deferred_data_breakpoint_hits,
                bus.take_data_breakpoint_hits(),
                self.debug_exception_shadow,
            );
            return Ok(StepBoundary {
                progress: ExecutionProgress::InstructionBodyCompleted,
                outcome: StepOutcome::Continue,
                interrupt_source: None,
                instruction_opcode: 0,
                task_switched: false,
                data_breakpoint_hits,
            });
        }
        if !jit_completed
            && let Some((next_ip, unfinished_repeat, data_breakpoint_hits)) =
            execute::execute_io(&mut self.regs, &mut bus, ports, decoded)?
        {
            self.regs.eip = next_ip;
            self.regs.eflags &= !EFLAGS_RF;
            self.intermediate_rep_boundary = unfinished_repeat;
            self.maskable_interrupt_shadow = interrupt_shadow;
            self.debug_exception_shadow = !debug_shadow_was_active
                && decoded.creates_debug_exception_shadow();
            return Ok(StepBoundary {
                progress: ExecutionProgress::after_repeat(unfinished_repeat),
                outcome: StepOutcome::Continue,
                interrupt_source: None,
                instruction_opcode: 0,
                task_switched: false,
                data_breakpoint_hits: retire_data_breakpoints(
                    &mut self.deferred_data_breakpoint_hits,
                    data_breakpoint_hits,
                    self.debug_exception_shadow,
                ),
            });
        }
        let task_before = bus.system().task;
        let (outcome, next_ip, task_debug_trap, data_breakpoint_hits, progress) =
            if jit_completed {
                (
                    StepOutcome::Continue, decoded.next_ip, false,
                    bus.take_data_breakpoint_hits(), ExecutionProgress::InstructionBodyCompleted,
                )
            } else if execute::is_string_instruction(decoded) {
            // REP commits each completed iteration. A later fault must retain
            // that progress alongside its memory/device side effects; replacing
            // the entire register context would undo only half the operation.
            match execute::execute_string_boundary(&mut self.regs, &mut bus, decoded) {
                Ok((next_ip, unfinished_repeat, data_breakpoint_hits)) => {
                    self.intermediate_rep_boundary = unfinished_repeat;
                    (
                        StepOutcome::Continue, next_ip, false, data_breakpoint_hits,
                        ExecutionProgress::after_repeat(unfinished_repeat),
                    )
                }
                Err(error) => {
                    // Intel SDM Vol. 2B, REP: repeated CMPS/SCAS restore the
                    // pre-instruction EFLAGS on a fault. Completed count/index
                    // progress stays live; it is not a whole-context rollback.
                    if decoded.restores_repeat_flags_on_fault() {
                        self.regs.eflags = bus.instruction_site().eflags;
                    }
                    return Err(error);
                }
            }
        } else {
            // Ordinary instructions commit registers/flags after all required
            // accesses succeed. Bus/page state and external storage effects
            // remain live; this is not a memory rollback mechanism.
            let mut regs = self.regs.clone();
            let (outcome, next_ip, task_debug) =
                if execute::execute_jit_memory(&mut self.jit, &mut regs, &mut bus, decoded)? {
                    (StepOutcome::Continue, decoded.next_ip, false)
                } else { match execute::execute(&mut regs, &mut bus, decoded, self.model) {
                    Ok(result) => result,
                    Err(error @ CpuError::TaskSwitchCommitted { target_ip, .. }) => {
                        regs.eip = target_ip;
                        self.regs = regs;
                        self.normalize_model_eflags();
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                } };
            self.regs = regs;
            let data_breakpoint_hits = bus.take_data_breakpoint_hits();
            (
                outcome, next_ip, task_debug, data_breakpoint_hits,
                ExecutionProgress::InstructionBodyCompleted,
            )
        };
        let restores_flags_image = matches!(
            decoded.instruction.mnemonic(),
            Mnemonic::Iret | Mnemonic::Iretd
        );
        let switched_tasks = bus.system().task != task_before;
        self.pending_task_debug_trap |= task_debug_trap;
        self.regs.eip = next_ip;
        self.normalize_model_eflags();
        if !restores_flags_image && !switched_tasks && !matches!(outcome, StepOutcome::Interrupt(_))
        {
            self.regs.eflags &= !EFLAGS_RF;
        }
        self.maskable_interrupt_shadow = interrupt_shadow;
        self.debug_exception_shadow = !switched_tasks
            && !debug_shadow_was_active
            && decoded.creates_debug_exception_shadow();
        self.control_transfer = transfer_candidate;
        self.control_transfer_sequence =
            transfer_candidate.map(|_| self.call_boundary_sequence);
        if outcome == StepOutcome::Halt {
            self.halted = true;
        }
        let interrupt_source = if matches!(outcome, StepOutcome::Interrupt(_)) {
            Some(match decoded.instruction.mnemonic() {
                Mnemonic::Int1 => EventSource::InstructionDebugTrap,
                Mnemonic::Into => EventSource::SoftwareOverflow,
                Mnemonic::Int3 => EventSource::SoftwareBreakpoint,
                _ => EventSource::SoftwareInterrupt,
            })
        } else {
            None
        };
        let data_breakpoint_hits = retire_data_breakpoints(
            &mut self.deferred_data_breakpoint_hits,
            data_breakpoint_hits,
            self.debug_exception_shadow,
        );
        Ok(StepBoundary {
            progress,
            outcome,
            interrupt_source,
            instruction_opcode: decoded.opcode,
            task_switched: switched_tasks,
            data_breakpoint_hits,
        })
    }

    fn initialize_explicit_real_mode_context(&mut self, segments: &impl SegmentResolver) {
        const EFLAGS_VM: u32 = 1 << 17;
        let resolver_owns_real_mode = segments.execution_mode()
            == Some(crate::CpuExecutionMode::RealAddress)
            && segments.current_privilege_level() == Some(0)
            && !segments.protected_mode();
        if !self.system.architectural_context_initialized
            && self.system.cr0 & crate::system::CR0_PE == 0
            && self.regs.eflags & EFLAGS_VM == 0
            && resolver_owns_real_mode
        {
            // A mode hint alone cannot seed hidden state; require the resolver
            // to certify both RealAddress mode and CPL0.
            self.system.initialize_real_mode_segments(&self.regs);
            self.system.architectural_context_initialized = true;
        }
    }

    fn instruction_breakpoint_matches(
        &mut self,
        instruction_ip: u32,
    ) -> Result<bool, CpuError> {
        if !self.system.architectural_context_initialized
            || self.system.execution_mode(self.regs.eflags).is_none()
            || self.regs.eflags & EFLAGS_RF != 0
            || self.debug_exception_shadow
        {
            return Ok(false);
        }
        let linear = self
            .system
            .segment_cache(SegmentRegister::Cs)
            .descriptor
            .base
            .wrapping_add(instruction_ip);
        let control = self.system.debug.control;
        let mut matching = 0_u32;
        let mut enabled_hits = 0_u32;
        for index in 0..4_u32 {
            let enabled = (control >> (index * 2)) & 0b11 != 0;
            let execute = (control >> (16 + index * 4)) & 0b11 == 0;
            if execute && self.system.debug.addresses[index as usize] == linear {
                let length = (control >> (18 + index * 4)) & 0b11;
                if length != 0 {
                    // Intel specifies one-byte instruction breakpoints; the
                    // behavior of an execution match with another LEN is undefined.
                    if enabled {
                        return Err(CpuError::CompatibilityGap {
                            opcode: 0,
                            ip: instruction_ip,
                            feature: crate::CpuCompatibilityGap::DebugExceptionDelivery,
                        });
                    }
                    continue;
                }
                matching |= 1 << index;
                if enabled {
                    enabled_hits |= 1 << index;
                }
            }
        }
        if enabled_hits == 0 {
            return Ok(false);
        }
        // The i486 manual says an enabled match raises #DB and all matching
        // conditions, including disabled ones, are then reflected in DR6.Bn.
        self.system.debug.status |= matching;
        Ok(true)
    }

    fn clear_debug_shadow_after_fault(&mut self, shadow_was_active: bool) {
        if shadow_was_active {
            self.debug_exception_shadow = false;
            self.deferred_data_breakpoint_hits = DataBreakpointHits::default();
        }
    }
}

fn retire_data_breakpoints(
    deferred: &mut DataBreakpointHits,
    current: DataBreakpointHits,
    shadow_after: bool,
) -> DataBreakpointHits {
    let hits = deferred.union(current);
    if shadow_after {
        // Modern SDM §6.8.3 delays a data match from MOV/POP SS until after
        // the next instruction; a faulting next instruction discards it.
        *deferred = hits;
        DataBreakpointHits::default()
    } else {
        *deferred = DataBreakpointHits::default();
        hits
    }
}
