//! Checked stack-frame preparation and CPU transfer into a ToolHelp observer.

use super::*;
use crate::RuntimeHost;
use x86_cpu::{CpuEventObservation, CpuEventSource};

impl Win16State {
    pub(in crate::win16_runtime) fn begin_toolhelp_cpu_interrupt_callback(
        &mut self,
        event: CpuDeferredEvent,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let observation = event.observation();
        if observation.saved_ip > u32::from(u16::MAX) {
            self.deliver_unobserved_toolhelp_event(
                event,
                cpu,
                memory,
                host,
                "the event return IP does not fit the SDK's WORD field",
            )?;
            return Ok(());
        }
        let origin = cpu.regs.clone();
        let mut resume = Some(Win16ToolhelpInterruptResume::Cpu(event));
        let mut stack = match self.prepare_toolhelp_callback_stack(cpu, &origin, memory, host) {
            Ok(Some(stack)) => stack,
            Ok(None) => {
                let Some(Win16ToolhelpInterruptResume::Cpu(event)) = resume.take() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ToolHelp stack decline lost its deferred CPU event",
                    ));
                };
                self.deliver_unobserved_toolhelp_event(
                    event,
                    cpu,
                    memory,
                    host,
                    "no checked guest stack is available for the callback frame",
                )?;
                return Ok(());
            }
            Err(error) if super::toolhelp_preflight_declines(&error) => {
                let Some(Win16ToolhelpInterruptResume::Cpu(event)) = resume.take() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ToolHelp stack rejection lost its deferred CPU event",
                    ));
                };
                self.deliver_unobserved_toolhelp_event(
                    event,
                    cpu,
                    memory,
                    host,
                    &format!("stack preparation failed: {error}"),
                )?;
                return Ok(());
            }
            Err(error) => {
                let Some(event) = resume.take() else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ToolHelp stack failure lost its deferred CPU event",
                    )
                    .with_cleanup("preserve the original ToolHelp stack failure", error));
                };
                if let Err(retain) = self.retain_stopped_toolhelp_event(origin, event) {
                    return Err(error.with_cleanup(
                        "retain deferred CPU event after ToolHelp stack failure",
                        retain,
                    ));
                }
                return Err(error);
            }
        };
        match self.begin_toolhelp_interrupt_callback(
            observation,
            &mut resume,
            &mut stack,
            cpu,
            dos,
            memory,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                let cleanup =
                    self.release_unentered_toolhelp_callback_stack(&mut stack, cpu, memory);
                if let Err(cleanup_error) = cleanup {
                    if let Some(event) = resume.take() {
                        if let Err(retain) =
                            self.retain_stopped_toolhelp_event(origin.clone(), event)
                        {
                            return Err(error
                                .with_cleanup(
                                    "release unentered ToolHelp stack after callback-entry failure",
                                    cleanup_error,
                                )
                                .with_cleanup(
                                    "retain original ToolHelp event after stack cleanup failure",
                                    retain,
                                ));
                        }
                    }
                    return Err(error.with_cleanup(
                        "release unentered ToolHelp stack after callback-entry failure",
                        cleanup_error,
                    ));
                }
                let cleanup: Result<(), RuntimeError> = Ok(());
                match resume.take() {
                    Some(Win16ToolhelpInterruptResume::Cpu(event))
                        if super::toolhelp_preflight_declines(&error) =>
                    {
                        let delivery = self.deliver_unobserved_toolhelp_event(
                            event,
                            cpu,
                            memory,
                            host,
                            &format!("checked callback entry failed: {error}"),
                        );
                        match (delivery, cleanup) {
                            (Ok(()), Ok(())) => Ok(()),
                            (Err(delivery), Ok(())) => Err(delivery),
                            (Ok(()), Err(cleanup)) => {
                                if let Err(stop) =
                                    self.stop_toolhelp_interrupt_execution(origin.clone(), None)
                                {
                                    return Err(error.with_cleanup(
                                        "release unentered ToolHelp stack after normal event delivery",
                                        cleanup,
                                    ).with_cleanup("record ToolHelp stopped execution", stop));
                                }
                                Err(error.with_cleanup(
                                    "release unentered ToolHelp stack after normal event delivery",
                                    cleanup,
                                ))
                            }
                            (Err(delivery), Err(cleanup)) => Err(delivery.with_cleanup(
                                "release unentered ToolHelp stack after event-delivery failure",
                                cleanup,
                            )),
                        }
                    }
                    Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { .. })
                        if super::toolhelp_preflight_declines(&error) =>
                    {
                        match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(cleanup.with_context(format!(
                                "ToolHelp callback setup was declined and its stack cleanup failed: {error}"
                            ))),
                        }
                    }
                    Some(event) => {
                        if let Err(retain) =
                            self.retain_stopped_toolhelp_event(origin.clone(), event)
                        {
                            return Err(error.with_cleanup(
                                "retain unentered ToolHelp event after callback-entry failure",
                                retain,
                            ));
                        }
                        match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(error.with_cleanup(
                                "release unentered ToolHelp stack after callback-entry failure",
                                cleanup,
                            )),
                        }
                    }
                    None => match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error.with_cleanup(
                            "release unentered ToolHelp stack after callback-entry failure",
                            cleanup,
                        )),
                    },
                }
            }
        }
    }

    pub(in crate::win16_runtime) fn deliver_unobserved_toolhelp_event(
        &mut self,
        event: CpuDeferredEvent,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        let segments = Win16Segments {
            selectors: &self.selectors,
            memory_len: memory.len(),
        };
        let origin = cpu.regs.clone();
        if let Err(failure) = cpu.resume_deferred_event(event, memory, &segments) {
            let (error, deferred) = failure.into_parts();
            let primary = crate::runtime_error(error);
            if let Some(deferred) = deferred {
                if let Err(retain) = self.retain_stopped_toolhelp_event(
                    origin,
                    Win16ToolhelpInterruptResume::Cpu(deferred),
                ) {
                    return Err(primary.with_cleanup(
                        "retain deferred event after checked event-delivery rejection",
                        retain,
                    ));
                }
            }
            return Err(primary);
        }
        host.report_diagnostic(&crate::Diagnostic::warning(
            Kind::CompatibilityGap,
            format!("ToolHelp interrupt observer declined the event; native CPU delivery continued ({reason})"),
        ));
        Ok(())
    }

    pub(in crate::win16_runtime) fn begin_toolhelp_software_interrupt_callback(
        &mut self,
        vector: u8,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let observation = CpuEventObservation {
            vector,
            source: CpuEventSource::SoftwareInterrupt,
            saved_cs: cpu.regs.cs,
            saved_ip: cpu.regs.eip,
            saved_flags: cpu.regs.eflags,
            error_code: None,
        };
        let origin = cpu.regs.clone();
        let mut stack = match self.prepare_toolhelp_callback_stack(cpu, &origin, memory, host) {
            Ok(Some(stack)) => stack,
            Ok(None) => {
                host.report_diagnostic(&crate::Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "ToolHelp software-interrupt observer has no checked callback stack; requesting native delivery",
                ));
                return self
                    .begin_unobserved_toolhelp_software_interrupt(vector, origin, cpu, memory);
            }
            Err(error) if super::toolhelp_preflight_declines(&error) => {
                host.report_diagnostic(&crate::Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!("ToolHelp software-interrupt observer declined the event; requesting native delivery ({error})"),
                ));
                return self
                    .begin_unobserved_toolhelp_software_interrupt(vector, origin, cpu, memory);
            }
            Err(error) => {
                let resume = Win16ToolhelpInterruptResume::SoftwareInterrupt { vector };
                if let Err(retain) = self.retain_stopped_toolhelp_event(origin, resume) {
                    return Err(error.with_cleanup(
                        "retain software interrupt after ToolHelp stack failure",
                        retain,
                    ));
                }
                return Err(error);
            }
        };
        let mut resume = Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { vector });
        match self.begin_toolhelp_interrupt_callback(
            observation,
            &mut resume,
            &mut stack,
            cpu,
            dos,
            memory,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                let cleanup =
                    self.release_unentered_toolhelp_callback_stack(&mut stack, cpu, memory);
                if !super::toolhelp_preflight_declines(&error) {
                    if let Some(event) = resume.take() {
                        if let Err(retain) =
                            self.retain_stopped_toolhelp_event(origin.clone(), event)
                        {
                            return Err(error.with_cleanup(
                                "retain software interrupt after ToolHelp entry failure",
                                retain,
                            ));
                        }
                    }
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error.with_cleanup(
                            "release unentered ToolHelp stack after software observer failure",
                            cleanup,
                        )),
                    };
                }
                let Some(_event) = resume.take() else {
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error.with_cleanup(
                            "release unentered ToolHelp stack after software observer failure",
                            cleanup,
                        )),
                    };
                };
                match self.begin_unobserved_toolhelp_software_interrupt(
                    vector, origin.clone(), cpu, memory,
                ) {
                    Ok(()) => match cleanup {
                        Ok(()) => Ok(()),
                        Err(cleanup) => {
                            let stop = self.stop_toolhelp_interrupt_execution(
                                origin.clone(), None,
                            );
                            match stop {
                                Ok(()) => Err(error.with_cleanup(
                                    "release unentered ToolHelp stack after software interrupt delivery",
                                    cleanup,
                                )),
                                Err(stop) => Err(error.with_cleanup(
                                    "release unentered ToolHelp stack after software interrupt delivery",
                                    cleanup,
                                ).with_cleanup("record ToolHelp stopped execution", stop)),
                            }
                        }
                    },
                    Err(fallback) => match cleanup {
                        Ok(()) => Err(fallback.with_context(format!(
                            "ToolHelp callback entry was declined: {error}"
                        ))),
                        Err(cleanup) => Err(fallback.with_cleanup(
                            "release unentered ToolHelp stack after software interrupt delivery failure",
                            cleanup,
                        ).with_context(format!(
                            "ToolHelp callback entry was declined: {error}"
                        ))),
                    },
                }
            }
        }
    }

    fn begin_unobserved_toolhelp_software_interrupt(
        &mut self,
        vector: u8,
        origin: Registers,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        match self.begin_software_interrupt(vector, cpu, memory) {
            Ok(()) => Ok(()),
            Err(error) => {
                let resume = Win16ToolhelpInterruptResume::SoftwareInterrupt { vector };
                if let Err(stop) = self.retain_stopped_toolhelp_event(origin, resume) {
                    return Err(error.with_cleanup(
                        "retain unhandled software interrupt after native delivery failed",
                        stop,
                    ));
                }
                Err(error)
            }
        }
    }

    fn begin_toolhelp_interrupt_callback(
        &mut self,
        observation: CpuEventObservation,
        resume: &mut Option<Win16ToolhelpInterruptResume>,
        stack: &mut Win16ToolhelpCallbackStack,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if resume.is_none() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp interrupt callback has no deferred event to own",
            ));
        }
        if !toolhelp_vector_supported(observation.vector) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "unsupported vector reached the ToolHelp interrupt callback entry",
            ));
        }
        let task = self.current_task_handle()?;
        let callback = self
            .interrupt_callbacks
            .get(&task)
            .copied()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp interrupt callback entry has no current-task registration",
                )
            })?;
        let registration = self
            .toolhelp_interrupt_handles
            .get(&task)
            .copied()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp interrupt registration lost its guest-side opaque handle",
                )
            })?;
        if self.selectors.reference(callback.selector().raw()).ok()
            != Some(registration.callback_selector)
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt callback selector generation changed while registered",
            ));
        }
        let registration_handle = registration.guest_handle;
        self.selectors
            .translate(callback, Access::Execute, 1, memory)
            .map_err(|error| {
                crate::runtime_error(error).with_context(
                    "validate retained ToolHelp interrupt callback selector generation",
                )
            })?;

        self.toolhelp_interrupt_frames
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain ToolHelp interrupt callback frame",
                    error,
                )
            })?;
        let callback_id = self.reserve_callback_frame_id()?;
        let origin = cpu.regs.clone();
        let callback_code_selector = stack.callback_code_selector;
        let callback_sp = stack.callback_sp;
        let callback_return_sp = stack.callback_return_sp;
        let fault_stack_frame = stack.fault_stack_frame;
        let deferred_event = match resume.as_ref() {
            Some(Win16ToolhelpInterruptResume::Cpu(event)) => Some(event),
            Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { .. }) | None => None,
        };
        let event_vector =
            u16::from(observation.vector) | if fault_stack_frame { 0x8000 } else { 0 };
        let owner_result = match cpu.architectural_execution_mode() {
            Some(CpuExecutionMode::Virtual8086) => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "ToolHelp interrupt observers do not support VM86 delivery frames",
            )),
            Some(CpuExecutionMode::RealAddress | CpuExecutionMode::Protected) => self
                .capture_toolhelp_architectural_owner(cpu, dos, memory, &origin, deferred_event)
                .map(Win16ToolhelpInterruptCallOwner::Architectural),
            None => self
                .capture_legacy_cpu_call_frame(cpu, dos, memory)
                .map(Win16ToolhelpInterruptCallOwner::Legacy),
        };
        let mut owner = match owner_result {
            Ok(owner) => owner,
            Err(primary) => {
                if let Some(allocation) = stack.private.as_mut() {
                    match self.release_toolhelp_private_stack(allocation, cpu, memory) {
                        Ok(()) => stack.private = None,
                        Err(cleanup) => {
                            let allocation =
                                stack.private.take().expect("retained stack was present");
                            self.toolhelp_interrupt_retained_stacks
                                .push(Win16ToolhelpRetainedStack { task, allocation });
                            return Err(primary.with_cleanup(
                                "retain ToolHelp private stack after CPU-owner capture failure",
                                cleanup,
                            ));
                        }
                    }
                }
                return Err(primary);
            }
        };

        let mut callback_binding_pushed = false;
        let mut callback_stack_pointer = None;
        let frame_bytes = if fault_stack_frame {
            usize::from(CALLBACK_FRAME_BYTES + CALLBACK_FAULT_STACK_EXTENSION_BYTES)
        } else {
            usize::from(CALLBACK_FRAME_BYTES)
        };
        let mut previous_callback_frame =
            [0_u8; (CALLBACK_FRAME_BYTES + CALLBACK_FAULT_STACK_EXTENSION_BYTES) as usize];
        let mut callback_frame_written = false;
        let setup: Result<(), RuntimeError> = (|| {
            let callback_stack = self
                .selectors
                .pointer_from_raw(Selector(stack.selector), callback_sp)
                .map_err(crate::runtime_error)?;
            self.selectors
                .translate(callback_stack, Access::Write, frame_bytes, memory)
                .map_err(crate::runtime_error)?;
            self.selectors
                .read(
                    memory,
                    callback_stack,
                    &mut previous_callback_frame[..frame_bytes],
                )
                .map_err(crate::runtime_error)?;
            callback_stack_pointer = Some(callback_stack);

            let mut bytes =
                [0_u8; (CALLBACK_FRAME_BYTES + CALLBACK_FAULT_STACK_EXTENSION_BYTES) as usize];
            let (return_ip, return_cs) = match &owner {
                Win16ToolhelpInterruptCallOwner::Legacy(_) => (0, self.callback_gate_selector.0),
                Win16ToolhelpInterruptCallOwner::Architectural(_) => (origin.ip(), origin.cs),
            };
            write_word(&mut bytes, 0, return_ip);
            write_word(&mut bytes, 2, return_cs);
            write_word(&mut bytes, 4, origin.ax());
            write_word(&mut bytes, 6, event_vector);
            // The SDK exposes no public layout for this private INTERRUPT
            // record. Keep a stable nonzero guest token for this registration;
            // runtime ownership resolves it, never a host pointer.
            write_word(&mut bytes, 8, registration_handle);
            write_word(&mut bytes, 10, observation.saved_ip as u16);
            write_word(&mut bytes, 12, observation.saved_cs);
            write_word(&mut bytes, 14, observation.saved_flags as u16);
            if fault_stack_frame {
                // XP ToolHelp marks a callback using its fault-handler stack
                // and appends the interrupted stack image after the public
                // 16-byte frame; keep that image editable by assembly callers.
                write_word(&mut bytes, 16, origin.sp());
                write_word(&mut bytes, 18, origin.ss);
            }
            self.selectors
                .write(memory, callback_stack, &bytes[..frame_bytes])
                .map_err(crate::runtime_error)?;
            callback_frame_written = true;

            if let Win16ToolhelpInterruptCallOwner::Legacy(id) = &owner {
                let mut callback_registers = origin.clone();
                callback_registers.ss = stack.selector;
                callback_registers.set_sp(callback_sp);
                callback_registers.cs = callback_code_selector;
                callback_registers.set_ip(callback.offset());
                let mut callback_gate = callback_registers.clone();
                callback_gate.cs = self.callback_gate_selector.0;
                callback_gate.set_ip(0);
                callback_gate.set_sp(callback_return_sp);
                self.retain_legacy_cpu_frame_roots(*id, &callback_registers, dos, memory)?;
                self.retain_legacy_cpu_frame_roots(*id, &callback_gate, dos, memory)?;
            }
            if let Win16ToolhelpInterruptCallOwner::Architectural(architectural) = &mut owner {
                let mut callback_registers = origin.clone();
                callback_registers.ss = stack.selector;
                callback_registers.set_sp(callback_sp);
                callback_registers.cs = callback_code_selector;
                callback_registers.set_ip(callback.offset());
                self.retain_legacy_cpu_binding_roots(
                    architectural.selector_roots.as_mut().ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "architectural ToolHelp callback lost selector roots before entry",
                        )
                    })?,
                    &callback_registers,
                    dos,
                    memory,
                )
                .map_err(|error| {
                    super::toolhelp_binding_error(error)
                        .with_context("retain architectural ToolHelp callback selector roots")
                })?;
            }
            self.push_callback_kind(CallbackKind::ToolhelpInterrupt, callback_id)?;
            callback_binding_pushed = true;
            match &owner {
                Win16ToolhelpInterruptCallOwner::Legacy(_) => {
                    cpu.enter_legacy_guest_16bit_callback_on_stack(
                        callback_code_selector,
                        callback.offset(),
                        stack.selector,
                        callback_sp,
                    )
                    .map_err(crate::runtime_error)?;
                }
                Win16ToolhelpInterruptCallOwner::Architectural(_) => {
                    let segments = Win16Segments {
                        selectors: &self.selectors,
                        memory_len: memory.len(),
                    };
                    cpu.enter_guest_16bit_callback_on_stack(
                        callback_code_selector,
                        callback.offset(),
                        stack.selector,
                        callback_sp,
                        CpuGuest16BitReturnFrame {
                            code_segment: return_cs,
                            instruction_pointer: return_ip,
                            flags: observation.saved_flags as u16,
                        },
                        memory,
                        &segments,
                    )
                    .map_err(crate::runtime_error)?;
                }
            }
            Ok(())
        })();

        match setup {
            Ok(()) => {}
            Err(primary) => {
                if callback_binding_pushed {
                    if let Err(cleanup) =
                        self.retire_callback_binding(CallbackKind::ToolhelpInterrupt, callback_id)
                    {
                        self.toolhelp_interrupt_frames
                            .push(Win16ToolhelpInterruptFrame {
                                callback_id,
                                callback,
                                registration_handle,
                                event_vector,
                                origin,
                                callback_stack_selector: stack.selector,
                                callback_stack_pointer: callback_sp,
                                callback_return_sp,
                                fault_stack_frame,
                                private_stack: stack.private.take(),
                                cpu_owner: Some(owner),
                                cpu_restored: false,
                                event_handled: false,
                                resume: resume.take(),
                            });
                        return Err(primary.with_cleanup(
                            "retain the exact ToolHelp observer owner after callback-stack rollback failed",
                            cleanup,
                        ));
                    }
                }
                let frame_cleanup = if callback_frame_written {
                    match callback_stack_pointer {
                        Some(pointer) => self
                            .selectors
                            .write(memory, pointer, &previous_callback_frame[..frame_bytes])
                            .map_err(crate::runtime_error),
                        None => Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "ToolHelp callback frame lost its checked guest pointer",
                        )),
                    }
                } else {
                    Ok(())
                };
                let owner_cleanup = match &mut owner {
                    Win16ToolhelpInterruptCallOwner::Legacy(id) => {
                        let target = LegacyRegisterTransfer {
                            registers: origin,
                            stack_pointer: LegacyStackPointerTarget::RegisterValue,
                        };
                        self.restore_legacy_cpu_call_frame(
                            *id,
                            cpu,
                            memory,
                            CallEffectPolicy::RestoreSavedX87,
                            CallResumeBoundary::NoGuestExecution,
                            target,
                        )
                        .and_then(|()| self.release_legacy_cpu_frame(*id, dos, memory))
                    }
                    Win16ToolhelpInterruptCallOwner::Architectural(architectural) => {
                        match architectural.selector_roots.as_mut() {
                            Some(roots) => {
                                self.release_legacy_cpu_binding_owner(roots, dos, memory)
                            }
                            None => Ok(()),
                        }
                    }
                };
                let mut cleanup = frame_cleanup.and(owner_cleanup);
                if cleanup.is_err() {
                    if let Win16ToolhelpInterruptCallOwner::Architectural(architectural) =
                        &mut owner
                    {
                        if let Some(roots) = architectural.selector_roots.take() {
                            self.toolhelp_interrupt_retained_selector_owners
                                .push(Win16ToolhelpRetainedSelectorOwner { task, owner: roots });
                        }
                    }
                    if let Some(allocation) = stack.private.take() {
                        self.toolhelp_interrupt_retained_stacks
                            .push(Win16ToolhelpRetainedStack { task, allocation });
                    }
                } else if let Some(allocation) = stack.private.as_mut() {
                    cleanup = self.release_toolhelp_private_stack(allocation, cpu, memory);
                    if cleanup.is_err() {
                        let allocation = stack.private.take().expect("retained stack was present");
                        self.toolhelp_interrupt_retained_stacks
                            .push(Win16ToolhelpRetainedStack { task, allocation });
                    }
                }
                return match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(primary.with_cleanup(
                        "rollback ToolHelp interrupt callback entry while retaining its first failure",
                        cleanup,
                    )),
                };
            }
        };

        self.toolhelp_interrupt_frames
            .push(Win16ToolhelpInterruptFrame {
                callback_id,
                callback,
                registration_handle,
                event_vector,
                origin,
                callback_stack_selector: stack.selector,
                callback_stack_pointer: callback_sp,
                callback_return_sp,
                fault_stack_frame,
                private_stack: stack.private.take(),
                cpu_owner: Some(owner),
                cpu_restored: false,
                event_handled: false,
                resume: resume.take(),
            });
        Ok(())
    }

    fn release_unentered_toolhelp_callback_stack(
        &mut self,
        stack: &mut Win16ToolhelpCallbackStack,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let Some(allocation) = stack.private.as_mut() else {
            return Ok(());
        };
        match self.release_toolhelp_private_stack(allocation, cpu, memory) {
            Ok(()) => {
                stack.private = None;
                Ok(())
            }
            Err(error) => {
                let allocation = stack.private.take().expect("retained stack was present");
                let task = self.current_task_handle()?;
                self.toolhelp_interrupt_retained_stacks
                    .push(Win16ToolhelpRetainedStack { task, allocation });
                Err(error)
            }
        }
    }
}
