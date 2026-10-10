//! Win16 guest instruction loop and service-gate scheduling.

use guest_core::GuestMemory;
use x86_cpu::{CpuObservedStepOutcome, StepOutcome};

use formats::NeImportTarget;

use super::{ImportBinding, Win16State, dos_interrupts, interrupt_entry};
use crate::machine::Runtime;
use crate::win16_loader::Win16Segments;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16IoEvent,
    Win16ServiceBoundaryStage,
};

#[path = "win16_execute_schedule.rs"]
mod schedule;

#[path = "win16_execute_teardown.rs"]
mod teardown;
#[path = "win16_execute_toolhelp.rs"]
mod toolhelp;

/// A service-gate slot already identifies its NE import binding. Snapshot it
/// only for an enabled trace so dispatch may mutate runtime state without
/// holding metadata borrows across the call.
struct Win16ServiceTraceIdentity {
    module: Vec<u8>,
    name: Option<Vec<u8>>,
    ordinal: Option<u16>,
}

fn service_trace_identity(
    state: &Win16State,
    selector: u16,
    offset: u16,
) -> Option<Win16ServiceTraceIdentity> {
    if !state.is_service_gate(selector) || offset & 1 != 0 {
        return None;
    }
    let binding = state.bindings.get(usize::from(offset) / 2)?;
    Some(match binding {
        ImportBinding::Supported(descriptor) => Win16ServiceTraceIdentity {
            module: descriptor.module().as_bytes().to_vec(),
            name: Some(descriptor.name().as_bytes().to_vec()),
            ordinal: Some(descriptor.ordinal()),
        },
        ImportBinding::Unavailable { module, target } => match target {
            NeImportTarget::Ordinal(ordinal) => Win16ServiceTraceIdentity {
                module: module.clone(),
                name: None,
                ordinal: Some(*ordinal),
            },
            NeImportTarget::Name(name) => Win16ServiceTraceIdentity {
                module: module.clone(),
                name: Some(name.clone()),
                ordinal: None,
            },
        },
    })
}

fn observe_service_boundary(
    host: &mut impl RuntimeHost,
    identity: &Win16ServiceTraceIdentity,
    instruction: u64,
    selector: u16,
    offset: u16,
    stage: Win16ServiceBoundaryStage,
) {
    host.observe_win16_io(&Win16IoEvent::ServiceBoundary {
        module: &identity.module,
        name: identity.name.as_deref(),
        ordinal: identity.ordinal,
        instruction,
        selector,
        offset,
        stage,
    });
}

impl Runtime {
    /// Execute NE code with selector-based address translation. The Win16
    /// service gate is the only path from guest calls to native host APIs.
    pub(crate) fn run_win16(
        &mut self,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
    ) -> Result<u8, RuntimeError> {
        let result = self.run_win16_inner(host, instruction_limit);
        let result = self.finish_win16_teardown(result, host, instruction_limit);
        match self.memory.storage_failure() {
            Some(error) => {
                let storage = crate::runtime_error(error);
                Err(match result {
                    Ok(_) => storage,
                    Err(operation) => operation.with_cleanup(
                        "Win16 execution and guest-memory storage both failed",
                        storage,
                    ),
                })
            }
            None => result,
        }
    }

    fn run_win16_inner(
        &mut self,
        host: &mut impl RuntimeHost,
        instruction_limit: u64,
    ) -> Result<u8, RuntimeError> {
        if let Some(state) = self.win16.as_mut() {
            state.seed_initial_task_directory(host)?;
            if state.vm_start_tick.is_none() {
                state.vm_start_tick = Some(host.win16_get_tick_count()?);
            }
        }
        if self.instructions == 0 {
            if let Some(state) = self.win16.as_ref() {
                let unavailable = state.unavailable_imports();
                if !unavailable.is_empty() {
                    let examples = unavailable
                        .iter()
                        .take(6)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 module imports {} APIs without an ABI bridge; first: {examples}. Execution stops only if one is called", unavailable.len()),
                    ));
                }
            }
        }
        let mut scheduler = schedule::ExecutionSchedule::new(self.instructions);
        loop {
            self.check_memory_storage()?;
            if self.instructions >= instruction_limit {
                return Err(RuntimeError::new(
                    Kind::ExecutionLimit,
                    "Win16 instruction budget exhausted",
                ));
            }
            if let Some(status) = self
                .win16
                .as_mut()
                .ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant, "Win16 execution state is missing")
                })?
                .service_pending_toolhelp_task_exit(
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                    host,
                )?
            {
                return Ok(status);
            }
            let state = self.win16.as_mut().ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "Win16 execution state is missing")
            })?;
            if state.classic_dde_task_exit_needs_pump() {
                let owner = state.tasks.current().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 task-exit DDE pump has no exact task owner",
                ))?;
                state.service_classic_dde_task_exit_safe_point(
                    owner,
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                    host,
                )?;
                continue;
            }
            if self.service_toolhelp_module_entry()? {
                continue;
            }
            // A parked native wait is an API safe point. Drain its owned work
            // before dispatching the unchanged service gate a second time.
            let state = self.win16.as_mut().ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "Win16 execution state is missing")
            })?;
            let guest_dispatch_allowed = !self
                .process_frames
                .last()
                .is_some_and(crate::process::ProcessFrame::is_win16_dos_child)
                && !state.pe32_dispatch.has_active_call();
            if guest_dispatch_allowed
                && state.retry_mci_callback_progress(&mut self.cpu, &mut self.memory, host)?
            {
                continue;
            }
            if guest_dispatch_allowed
                && state.service_pending_window_property_callback(
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                )?
            {
                continue;
            }
            if state.service_pending_window_dde_callback(
                &mut self.cpu,
                &mut self.dos,
                &mut self.memory,
                host,
                guest_dispatch_allowed,
            )? {
                continue;
            }
            if state.service_pending_modal_guest_work(
                &mut self.cpu,
                &mut self.memory,
                &mut self.dos,
                host,
                guest_dispatch_allowed,
            )? {
                continue;
            }
            if state.service_pending_window_guest_work(
                &mut self.cpu,
                &mut self.memory,
                &mut self.dos,
                host,
                guest_dispatch_allowed,
            )? {
                continue;
            }
            if guest_dispatch_allowed
                && state.service_pending_ole1_com_work(
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                    host,
                )?
            {
                continue;
            }
            if self.cpu.take_pending_x87_irq13() {
                self.ports.request_irq(13).map_err(crate::runtime_error)?;
            }
            if self.cpu.has_architectural_context() && self.cpu.can_accept_maskable_interrupt() {
                if let Some(vector) = self.ports.acknowledge_interrupt() {
                    let observe = self.win16.as_ref().is_some_and(|state| {
                        state.can_observe_toolhelp_interrupt(
                            &self.cpu,
                            vector,
                            self.cpu.regs.eip,
                            &self.memory,
                        )
                    });
                    if observe {
                        let event = self.cpu.deferred_external_interrupt(vector);
                        self.win16
                            .as_mut()
                            .ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "Win16 execution state is missing",
                                )
                            })?
                            .begin_toolhelp_cpu_interrupt_callback(
                                event,
                                &mut self.cpu,
                                &mut self.dos,
                                &mut self.memory,
                                host,
                            )?;
                    } else {
                        let context = {
                            let state = self.win16.as_ref().ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "Win16 execution state is missing",
                                )
                            })?;
                            Win16Segments {
                                selectors: &state.selectors,
                                memory_len: self.memory.len(),
                            }
                        };
                        let writer = self.cpu.regs.clone();
                        let mut memory = crate::trace::GuestMemoryWriteObserver::new(
                            self.memory.bus(),
                            self.memory_write_watch.as_mut(),
                            self.instructions,
                            &writer,
                            crate::trace::GuestWriteBoundary::InterruptEntry,
                        );
                        self.cpu
                            .deliver_external_interrupt(vector, &mut memory, &context)
                            .map_err(crate::runtime_error)?;
                    }
                }
            }
            let (callback_gate, native_procedure_gate, service_gate) = {
                let state = self.win16.as_mut().ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant, "Win16 execution state is missing")
                })?;
                if let Some(trace) = self.instruction_trace.as_mut() {
                    trace.record_win16(
                        self.instructions,
                        &self.cpu.regs,
                        &self.memory,
                        &state.selectors,
                    );
                }
                (
                    state.is_callback_gate(self.cpu.regs.cs),
                    state.is_native_procedure_gate(self.cpu.regs.cs),
                    state.is_service_gate(self.cpu.regs.cs),
                )
            };
            crate::machine::check_memory_storage(&self.memory)?;
            let mut returned_from_guest = false;
            if self.cpu.allows_real_mode_service_intercepts() && callback_gate {
                self.win16
                    .as_mut()
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 execution state disappeared",
                        )
                    })?
                    .finish_callback(&mut self.cpu, &mut self.memory, &mut self.dos, host)
                    .map_err(|error| {
                        error.with_context(format!(
                            "Win16 callback at {:04X}:{:04X}",
                            self.cpu.regs.cs,
                            self.cpu.regs.ip(),
                        ))
                    })?;
                self.instructions += 1;
                returned_from_guest = true;
            } else if self.cpu.allows_real_mode_service_intercepts() && native_procedure_gate {
                let exit = self
                    .win16
                    .as_mut()
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 execution state disappeared",
                        )
                    })?
                    .dispatch_native_procedure(&mut self.cpu, &mut self.dos, &mut self.memory, host)
                    .map_err(|error| {
                        error.with_context(format!(
                            "Win16 native procedure at {:04X}:{:04X}",
                            self.cpu.regs.cs,
                            self.cpu.regs.ip(),
                        ))
                    })?;
                self.instructions += 1;
                if let Some(status) = exit {
                    return Ok(status);
                }
            } else if self.cpu.allows_real_mode_service_intercepts() && service_gate {
                let service = self
                    .win16
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 execution state disappeared",
                        )
                    })?
                    .kernel_register_service_at(&self.cpu.regs)?;
                let trace_instruction = self.instructions;
                let trace_selector = self.cpu.regs.cs;
                let trace_offset = self.cpu.regs.ip();
                let trace_identity = if host.win16_service_trace_enabled() {
                    self.win16.as_ref().and_then(|state| {
                        service_trace_identity(state, trace_selector, trace_offset)
                    })
                } else {
                    None
                };
                if let Some(identity) = trace_identity.as_ref() {
                    observe_service_boundary(
                        host,
                        identity,
                        trace_instruction,
                        trace_selector,
                        trace_offset,
                        Win16ServiceBoundaryStage::DispatchEnter,
                    );
                }
                let step_limit =
                    instruction_limit.saturating_sub(self.instructions.saturating_add(1));
                // The service gate below is charged after dispatch. Reserve
                // its one guest boundary in the absolute limit passed to a
                // KERNEL procedure that may run a nested DOS child now.
                let child_instruction_limit =
                    instruction_limit.checked_sub(1).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "Win16 service gate has no budget for its own instruction boundary",
                        )
                    })?;
                let dispatched = match service {
                    Some(service) => super::kernel_register_calls::dispatch(
                        self,
                        service,
                        host,
                        child_instruction_limit,
                    ),
                    None => self
                        .win16
                        .as_mut()
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "Win16 execution state disappeared",
                            )
                        })?
                        .dispatch(
                            &mut self.cpu,
                            &mut self.memory,
                            &mut self.dos,
                            host,
                            step_limit,
                        ),
                };
                // This records only the runtime dispatch Result boundary. A
                // successful dispatch can transfer control to a guest callback
                // while the original Win16 ABI/native continuation is pending.
                if let Some(identity) = trace_identity.as_ref() {
                    observe_service_boundary(
                        host,
                        identity,
                        trace_instruction,
                        trace_selector,
                        trace_offset,
                        if dispatched.is_ok() {
                            Win16ServiceBoundaryStage::DispatchReturn
                        } else {
                            Win16ServiceBoundaryStage::DispatchError
                        },
                    );
                }
                self.instructions = self.instructions.checked_add(1).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 instruction counter overflowed",
                    )
                })?;
                let pe32_steps = self
                    .win16
                    .as_mut()
                    .map(|state| state.pe32_dispatch.take_charged_boundaries())
                    .unwrap_or(0);
                self.instructions = self.instructions.checked_add(pe32_steps).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "PE32 charged-boundary counter overflowed",
                    )
                })?;
                let exit = dispatched.map_err(|error| {
                    error.with_context(format!(
                        "Win16 API at {:04X}:{:04X}",
                        self.cpu.regs.cs,
                        self.cpu.regs.ip(),
                    ))
                })?;
                if let Some(status) = exit {
                    return Ok(status);
                }
            } else {
                let state = self.win16.as_mut().ok_or_else(|| {
                    RuntimeError::new(Kind::InternalInvariant, "Win16 execution state disappeared")
                })?;
                if self.cpu.allows_real_mode_service_intercepts() {
                    if let Some(vector) = dos_interrupts::firmware_service_at(
                        state,
                        self.cpu.regs.cs,
                        self.cpu.regs.ip(),
                        &self.memory,
                    )? {
                        let before = self.cpu.regs.clone();
                        let action = interrupt_entry::call_firmware_service(
                            state,
                            &mut self.dos,
                            vector,
                            &mut self.cpu.regs,
                            &mut self.memory,
                            host,
                        )
                        .map_err(|error| {
                            error.with_context(format!(
                                "Win16 INT {vector:02X}h AX={:04X}",
                                before.ax(),
                            ))
                        })?;
                        if vector == 0x21 {
                            host.observe_dos_service(self.instructions, &before, &self.cpu.regs);
                        }
                        match action {
                            dos_kernel::DosAction::Continue => {
                                if vector == 0x21 {
                                    state.begin_pending_file_cdr_callback(
                                        &mut self.cpu,
                                        &mut self.dos,
                                        &mut self.memory,
                                        host,
                                    )?;
                                }
                            }
                            dos_kernel::DosAction::Exit(status) => {
                                if let Some(exit_status) =
                                    state.finish_task(&mut self.memory, host, u16::from(status))?
                                {
                                    return Ok(exit_status);
                                }
                                if let Some(exit_status) = state
                                    .service_pending_toolhelp_task_exit(
                                        &mut self.cpu,
                                        &mut self.dos,
                                        &mut self.memory,
                                        host,
                                    )?
                                {
                                    return Ok(exit_status);
                                }
                            }
                            _ => {
                                return Err(RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "Win16 firmware bridge returned an unhandled DOS action",
                                ));
                            }
                        }
                        // The next CPU step executes the actual ROM IRET. A
                        // PUSHF/CALL FAR chain and a software INT share this path.
                    }
                }
                let context = Win16Segments {
                    selectors: &state.selectors,
                    memory_len: self.memory.len(),
                };
                let instruction_address = (self.cpu.regs.cs, self.cpu.regs.ip());
                let before_stack = (self.cpu.regs.ss, self.cpu.regs.sp());
                let outcome = crate::cpu_execution::step_observing_events(
                    &mut self.cpu,
                    self.memory.bus(),
                    &mut self.ports,
                    &context,
                    self.memory_write_watch.as_mut(),
                    self.instructions,
                )
                .map_err(|error| {
                    crate::runtime_error(error).with_context(format!(
                        "Win16 instruction at {:04X}:{:04X}",
                        instruction_address.0,
                        instruction_address.1,
                    ))
                })?;
                crate::machine::check_memory_storage(&self.memory)?;
                self.instructions += 1;
                if self.cpu.allows_real_mode_service_intercepts() {
                    state.observe_control_transfer(
                        self.cpu.control_transfer(),
                        before_stack,
                        &self.cpu.regs,
                    )?;
                    returned_from_guest = self
                        .cpu
                        .control_transfer()
                        .is_some_and(x86_cpu::ControlTransfer::is_call_return);
                }
                if state.finish_toolhelp_interrupt_iret(
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                )? {
                    returned_from_guest = true;
                }
                if state.finish_toolhelp_interrupt_architectural_chain(
                    &mut self.cpu,
                    &mut self.dos,
                    &mut self.memory,
                )? {
                    returned_from_guest = true;
                }
                match outcome {
                    CpuObservedStepOutcome::Executed(StepOutcome::Continue) => {}
                    CpuObservedStepOutcome::Executed(StepOutcome::Halt) => {
                        return Err(RuntimeError::new(
                            Kind::GuestFault,
                            "Win16 guest halted without a runnable task",
                        ));
                    }
                    CpuObservedStepOutcome::Executed(StepOutcome::Interrupt(vector)) => {
                        if self.cpu.allows_real_mode_service_intercepts()
                            && state.can_observe_toolhelp_interrupt(
                                &self.cpu,
                                vector,
                                self.cpu.regs.eip,
                                &self.memory,
                            )
                        {
                            state.begin_toolhelp_software_interrupt_callback(
                                vector,
                                &mut self.cpu,
                                &mut self.dos,
                                &mut self.memory,
                                host,
                            )?;
                        } else {
                            state.begin_software_interrupt(
                                vector,
                                &mut self.cpu,
                                &mut self.memory,
                            )?;
                        }
                    }
                    CpuObservedStepOutcome::EventDeferred(event) => {
                        if state.can_observe_toolhelp_deferred_event(
                            &self.cpu,
                            &event,
                            &self.memory,
                        ) {
                            state.begin_toolhelp_cpu_interrupt_callback(
                                event,
                                &mut self.cpu,
                                &mut self.dos,
                                &mut self.memory,
                                host,
                            )?;
                        } else {
                            state.deliver_unobserved_toolhelp_event(
                                event,
                                &mut self.cpu,
                                &mut self.memory,
                                host,
                                "no live registration or supported guest event frame is available",
                            )?;
                        }
                    }
                }
            }
            self.capture_memory_watch_cpu_history();
            crate::machine::check_memory_storage(&self.memory)?;
            let state = self.win16.as_mut().ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "Win16 execution state disappeared")
            })?;
            // A callback acknowledged by this dispatch must restore the
            // complete interrupted CPU state before another scheduler poll
            // can capture or enter guest execution.
            while state.restore_next_dde_context(&mut self.cpu, &mut self.dos, &mut self.memory)? {
                returned_from_guest = true;
            }
            if let Some(status) = state.drain_kernel_diagnostic_effects(&mut self.memory, host)? {
                return Ok(status);
            }
            if let Some(status) = state.service_pending_toolhelp_task_exit(
                &mut self.cpu,
                &mut self.dos,
                &mut self.memory,
                host,
            )? {
                return Ok(status);
            }
            let (turn, guest_dispatch_allowed, callback_dispatch_allowed, source_dispatch_allowed) =
                if scheduler.checkpoint(self.instructions) {
                    let running_dos_child = self.process_frames.last()
                        .is_some_and(crate::process::ProcessFrame::is_win16_dos_child);
                    let guest_dispatch_allowed =
                        !running_dos_child && !state.pe32_dispatch.has_active_call();
                    let callback_dispatch_allowed = guest_dispatch_allowed
                        && self.cpu.allows_real_mode_service_intercepts()
                        && state.callback_kinds.is_empty()
                        && !self.cpu.interrupt_shadow_active()
                        && !state.is_service_gate(self.cpu.regs.cs)
                        && !state.is_native_procedure_gate(self.cpu.regs.cs)
                        && !state.is_callback_gate(self.cpu.regs.cs);
                    let source_dispatch_allowed = callback_dispatch_allowed
                        || toolhelp::protected_toolhelp_dispatch_allowed(
                            state, &self.cpu, guest_dispatch_allowed);
                    let turn = scheduler.turn(self.instructions, host.win16_scheduler_readiness(),
                        || state.has_scheduler_work(), source_dispatch_allowed);
                    (turn, guest_dispatch_allowed, callback_dispatch_allowed, source_dispatch_allowed)
                } else { (schedule::ScheduleTurn::default(), false, false, false) };
            if turn.pump_host {
                host.pump_events()?;
                // Native modal callbacks can consume WM_DROPFILES without
                // reaching the queued-message projection. Poll the separate
                // lease-retirement transport at this guest safe point.
                let _ = state.poll_native_drop_retirement(host)?;
            }
            if turn.poll_sources {
                let mut source_progress = false;
                let callback_was_active = !state.callback_kinds.is_empty();
                let mut classic_dde_owned = false;
                // WAVE completion updates checked guest WAVEHDR state and
                // queues notifications only while the owning Win16 process
                // view is active. DOS children and PE calls keep their own
                // CPU and address-space views until they return.
                if guest_dispatch_allowed {
                    source_progress |= state.poll_wave_events(&mut self.memory, host, true)?;
                    state.poll_sound(&mut self.memory, host)?;
                }
                // A mailbox callback starts only after an instruction and
                // outside any active synchronous call or callback gate.
                if callback_dispatch_allowed {
                    source_progress |= state.poll_network_events(&mut self.memory, host)?;
                    source_progress |= state.dispatch_pending_network_print_notification(host)?;
                    classic_dde_owned = state.service_classic_dde_safe_point(
                        &mut self.cpu,
                        &mut self.dos,
                        &mut self.memory,
                        host,
                    )?;
                    let netbios_dispatch = if classic_dde_owned {
                        super::netbios_async::NetbiosDispatch::Idle
                    } else {
                        state.dispatch_pending_netbios_notification(
                            &mut self.cpu,
                            &mut self.memory,
                            host,
                        )?
                    };
                    source_progress |= !matches!(netbios_dispatch, super::netbios_async::NetbiosDispatch::Idle);
                    let netbios_callback_entered = matches!(
                        netbios_dispatch,
                        super::netbios_async::NetbiosDispatch::CallbackEntered
                    );
                    let wave_callback_entered = if classic_dde_owned || netbios_callback_entered {
                        false
                    } else {
                        state.dispatch_pending_wave_function_callback(
                            &mut self.cpu,
                            &mut self.memory,
                            host,
                        )?
                    };
                    let midi_callback_entered = if classic_dde_owned
                        || netbios_callback_entered
                        || wave_callback_entered
                    {
                        false
                    } else {
                        let midi = state.dispatch_midi_notification_with_progress(
                            &mut self.cpu, &mut self.memory, host,
                        )?;
                        source_progress |= !matches!(midi, super::midi::MidiDispatch::Idle);
                        matches!(midi, super::midi::MidiDispatch::CallbackEntered)
                    };
                    let toolhelp_callback_entered = if classic_dde_owned
                        || netbios_callback_entered
                        || wave_callback_entered
                        || midi_callback_entered
                    {
                        false
                    } else {
                        state.dispatch_pending_toolhelp_notify(
                            &mut self.cpu,
                            &mut self.dos,
                            &mut self.memory,
                        )?
                    };
                    source_progress |= wave_callback_entered || toolhelp_callback_entered;
                    if !classic_dde_owned
                        && !netbios_callback_entered
                        && !wave_callback_entered
                        && !midi_callback_entered
                        && !toolhelp_callback_entered
                    {
                        if let Some(event) = host.win16_take_guest_callback()? {
                            source_progress = true;
                            state.begin_asynchronous_guest_callback(
                                &mut self.cpu,
                                &mut self.memory,
                                event,
                            )?;
                        }
                    }
                    // An unsolicited DDE callback runs only when the ordinary
                    // mailbox callback did not leave a guest call active.
                    // Its full CPU context remains keyed by the native frame
                    // until that exact frame is acknowledged.
                    if !classic_dde_owned && state.callback_kinds.is_empty() {
                        if let Some(step) = host.win16_dde_poll_callback()? {
                            source_progress = true;
                            let frame = step.frame;
                            state.capture_dde_guest_context(
                                &self.cpu,
                                &mut self.dos,
                                &mut self.memory,
                                frame,
                            )?;
                            let origin =
                                super::dde_callback::Win16DdeCallbackOrigin::GuestExecution {
                                    frame,
                                };
                            if let Some((origin, next)) = state.begin_dde_callback(
                                step,
                                origin,
                                &mut self.cpu,
                                &mut self.dos,
                                &mut self.memory,
                                host,
                            )? {
                                state.route_dde_callback_step(
                                    &mut self.cpu,
                                    &mut self.dos,
                                    &mut self.memory,
                                    host,
                                    origin,
                                    next,
                                )?;
                            }
                        }
                    }
                }
                if !classic_dde_owned {
                    toolhelp::dispatch_protected_toolhelp_notifications(
                        state, &mut self.cpu, &mut self.dos, &mut self.memory,
                        guest_dispatch_allowed,
                    )?;
                }
                source_progress |= !callback_was_active && !state.callback_kinds.is_empty();
                scheduler.finish_sources(source_dispatch_allowed
                    && !classic_dde_owned && state.callback_kinds.is_empty(), source_progress);
            }
            crate::machine::check_memory_storage(&self.memory)?;
            // A safe-point callback may have taken the documented empty
            // fallback path and completed synchronously without guest entry.
            while state.restore_next_dde_context(&mut self.cpu, &mut self.dos, &mut self.memory)? {
                returned_from_guest = true;
            }
            if let Some(status) = state.drain_kernel_diagnostic_effects(&mut self.memory, host)? {
                return Ok(status);
            }
            if !self.cpu.interrupt_shadow_active()
                && (returned_from_guest || turn.pump_host || turn.poll_sources)
            {
                state.reap_modules(&mut self.cpu, &mut self.memory, host)?;
            }
        }
    }
}

/// Unforgeable proof that `run_win16_inner` returned and the CPU will not be
/// stepped again. Runtime owners may only discard retained CPU frames after
/// this proof and after their native producers have quiesced.
pub(super) struct Win16TaskExecutionEnded {
    _seal: (),
}

impl Win16TaskExecutionEnded {
    /// Test-only stand-in for a stopped execution loop; never a runtime proof.
    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self { _seal: () }
    }

    fn after_cpu_execution_boundary() -> Self {
        Self { _seal: () }
    }
}
