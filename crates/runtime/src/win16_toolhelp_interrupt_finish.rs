//! Checked completion and teardown for ToolHelp interrupt callback frames.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_toolhelp_interrupt_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.finish_toolhelp_interrupt_chain(cpu, dos, memory, true)
    }

    /// Finish a checked architectural RETF that returned directly to the
    /// interrupted CS:IP. The execute loop calls this before stepping there.
    pub(in crate::win16_runtime) fn finish_toolhelp_interrupt_architectural_chain(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        if self.callback_kinds.last() != Some(&CallbackKind::ToolhelpInterrupt) {
            return Ok(false);
        }
        let Some(frame) = self.toolhelp_interrupt_frames.last() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp interrupt callback stack has no owner frame",
            ));
        };
        if !matches!(
            frame.cpu_owner,
            Some(Win16ToolhelpInterruptCallOwner::Architectural(_))
        ) || cpu.control_transfer() != Some(ControlTransfer::FarReturn)
            || cpu.regs.ss != frame.callback_stack_selector
            || cpu.regs.sp() != frame.callback_return_sp
            || cpu.regs.cs != frame.origin.cs
            || cpu.regs.ip() != frame.origin.ip()
        {
            return Ok(false);
        }
        self.finish_toolhelp_interrupt_chain(cpu, dos, memory, false)?;
        Ok(true)
    }

    fn finish_toolhelp_interrupt_chain(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        through_legacy_gate: bool,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::ToolhelpInterrupt)?;
        let mut frame = self.toolhelp_interrupt_frames.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp interrupt callback lost its exact frame",
            )
        })?;
        let owner_matches = match frame.cpu_owner.as_ref() {
            Some(Win16ToolhelpInterruptCallOwner::Legacy(_)) => through_legacy_gate,
            Some(Win16ToolhelpInterruptCallOwner::Architectural(_)) => !through_legacy_gate,
            None => false,
        };
        let target_matches = if through_legacy_gate {
            self.is_callback_gate(cpu.regs.cs) && cpu.regs.ip() == 0
        } else {
            cpu.regs.cs == frame.origin.cs && cpu.regs.ip() == frame.origin.ip()
        };
        if frame.callback_id != callback_id
            || !owner_matches
            || !target_matches
            || cpu.regs.ss != frame.callback_stack_selector
            || cpu.regs.sp() != frame.callback_return_sp
        {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt handler returned with an invalid RETF chain frame",
            ));
        }
        let Some(ControlTransfer::FarReturn) = cpu.control_transfer() else {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt callback gate has no exact guest RETF transfer",
            ));
        };
        if !preserved_interrupt_registers(&frame.origin, &cpu.regs) {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt assembly handler did not preserve its live registers",
            ));
        }
        let returned = match self.read_toolhelp_interrupt_return_frame(&frame, memory) {
            Ok(returned) => returned,
            Err(error) => {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
        };
        if returned_uses_released_toolhelp_stack(&frame, returned) {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp IRET selected the temporary callback stack that must be released",
            ));
        }
        if returned.event_vector != frame.event_vector
            || returned.registration_handle != frame.registration_handle
        {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt callback corrupted its private registration frame",
            ));
        }
        if !frame.cpu_restored {
            let owner_result = match frame.cpu_owner.as_mut() {
                Some(Win16ToolhelpInterruptCallOwner::Legacy(owner)) => {
                    let target = LegacyRegisterTransfer {
                        registers: frame.origin.clone(),
                        stack_pointer: LegacyStackPointerTarget::RegisterValue,
                    };
                    self.restore_legacy_cpu_call_frame(
                        *owner,
                        cpu,
                        memory,
                        CallEffectPolicy::RestoreSavedX87,
                        CallResumeBoundary::GuestCallReturn {
                            transfer: ControlTransfer::FarReturn,
                        },
                        target,
                    )
                }
                Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) => {
                    let result = match owner.continuation.as_ref() {
                        Some(continuation) => cpu
                            .restore_event_observer_after_guest_retf(continuation)
                            .map_err(toolhelp_cpu_capture_error)
                            .map_err(|error| {
                                error.with_context(
                                    "restore architectural ToolHelp observer after RETF chain",
                                )
                            }),
                        None => Ok(()),
                    };
                    if result.is_ok() {
                        owner.continuation = None;
                    }
                    result
                }
                None => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp interrupt frame lost its captured CPU owner",
                )),
            };
            if let Err(error) = owner_result {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.cpu_restored = true;
        }
        if let Some(Win16ToolhelpInterruptCallOwner::Legacy(owner)) = frame.cpu_owner.as_ref() {
            if let Err(error) = self.release_legacy_cpu_frame(*owner, dos, memory) {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.cpu_owner = None;
        }
        if let Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) =
            frame.cpu_owner.as_mut()
        {
            let Some(roots) = owner.selector_roots.as_mut() else {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp interrupt selector roots were already released",
                ));
            };
            if let Err(error) = self.release_legacy_cpu_binding_owner(roots, dos, memory) {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            owner.selector_roots = None;
            frame.cpu_owner = None;
        }
        if matches!(
            frame.cpu_owner,
            Some(Win16ToolhelpInterruptCallOwner::Legacy(_))
        ) {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "legacy ToolHelp interrupt CPU owner remained after its checked RETF",
            ));
        }
        if let Some(allocation) = frame.private_stack.as_mut() {
            if let Err(error) = self.release_toolhelp_private_stack(allocation, cpu, memory) {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.private_stack = None;
        }
        if let Err(error) =
            self.retire_callback_binding(CallbackKind::ToolhelpInterrupt, callback_id)
        {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(error);
        }
        let mut resume = frame.resume.take();
        if let Err(error) = self.resume_toolhelp_interrupt(&mut resume, returned, cpu, memory) {
            // The callback binding and its CPU/selector owners are already
            // retired. Preserve any still-owned event in the execution-stop
            // slot and block a later guest step; if delivery consumed the
            // event before failing, the slot still records the fatal stop.
            self.toolhelp_interrupt_stopped_event = Some(Win16ToolhelpStoppedEvent {
                task: self.current_task_handle().ok(),
                _origin: frame.origin.clone(),
                _resume: resume.take(),
            });
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_toolhelp_interrupt_iret(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        if self.callback_kinds.last() != Some(&CallbackKind::ToolhelpInterrupt)
            || cpu.control_transfer() != Some(ControlTransfer::InterruptReturn)
        {
            return Ok(false);
        }
        let Some(frame) = self.toolhelp_interrupt_frames.last() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp interrupt callback stack has no owner frame",
            ));
        };
        let Some(iret_stack_end) = frame
            .callback_stack_pointer
            .checked_add(CALLBACK_FRAME_BYTES)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp callback IRET stack end overflowed",
            ));
        };
        if cpu.regs.ss != frame.callback_stack_selector || cpu.regs.sp() != iret_stack_end {
            // A nested interrupt IRET returns to the assembly handler's own
            // stack, not the original event stack, and must leave this frame live.
            return Ok(false);
        }
        if !preserved_interrupt_registers(&frame.origin, &cpu.regs) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt IRET handler did not preserve its live registers",
            ));
        }
        let returned = self.read_toolhelp_interrupt_return_frame(frame, memory)?;
        if returned_uses_released_toolhelp_stack(frame, returned) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp IRET selected the temporary callback stack that must be released",
            ));
        }
        if returned.event_vector != frame.event_vector
            || returned.registration_handle != frame.registration_handle
            || cpu.regs.cs != returned.code_segment
            || cpu.regs.ip() != returned.instruction_pointer
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt IRET changed private state or missed its guest return image",
            ));
        }
        if let Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) =
            frame.cpu_owner.as_ref()
        {
            if let Some(continuation) = owner.continuation.as_ref() {
                cpu.validate_event_observer_guest_iret(continuation)
                    .map_err(toolhelp_cpu_capture_error)
                    .map_err(|error| {
                        error.with_context("validate architectural root after ToolHelp guest IRET")
                    })?;
            }
        }
        let callback_id = frame.callback_id;
        let mut frame = self.toolhelp_interrupt_frames.pop().expect("checked frame");
        if !frame.event_handled {
            match frame.resume.take() {
                Some(Win16ToolhelpInterruptResume::Cpu(event)) => {
                    match cpu.complete_deferred_event_after_guest_iret(event) {
                        Ok(CpuDeferredEventResolution::HandledByGuestIret) => {}
                        Ok(CpuDeferredEventResolution::DeliveredToOriginalHandler) => {
                            self.toolhelp_interrupt_frames.push(frame);
                            return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "ToolHelp guest IRET returned a chain disposition",
                            ));
                        }
                        Err(completion) => {
                            let (error, event) = completion.into_parts();
                            frame.resume = Some(Win16ToolhelpInterruptResume::Cpu(event));
                            self.toolhelp_interrupt_frames.push(frame);
                            return Err(crate::runtime_error(error));
                        }
                    }
                }
                Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { .. }) => {}
                None => {
                    self.toolhelp_interrupt_frames.push(frame);
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ToolHelp IRET frame lost its deferred event before completion",
                    ));
                }
            }
            frame.event_handled = true;
        }
        if !frame.cpu_restored {
            let owner_cleanup = match frame.cpu_owner.as_mut() {
                Some(Win16ToolhelpInterruptCallOwner::Legacy(owner)) => {
                    let (stack_segment, stack_pointer) = returned
                        .faulting_stack
                        .unwrap_or((frame.origin.ss, frame.origin.sp()));
                    cpu.restore_legacy_guest_callback_stack(stack_segment, stack_pointer)
                        .map_err(crate::runtime_error)
                        .map_err(|error| {
                            error.with_context(
                                "restore the guest-edited legacy ToolHelp stack image after IRET",
                            )
                        })
                        .and_then(|()| self.release_legacy_cpu_frame(*owner, dos, memory))
                }
                Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) => {
                    let stack_restore = match owner.continuation.as_ref() {
                        Some(continuation) => cpu
                            .complete_event_observer_guest_iret(
                                continuation,
                                returned.faulting_stack,
                                memory,
                                &Win16Segments {
                                    selectors: &self.selectors,
                                    memory_len: memory.len(),
                                },
                            )
                            .map_err(|error| match error {
                                x86_cpu::CpuEventObserverCompletionError::Continuation(error) => {
                                    toolhelp_cpu_capture_error(error)
                                        .with_context("complete ToolHelp guest IRET continuation")
                                }
                                x86_cpu::CpuEventObserverCompletionError::Stack(error) => {
                                    crate::runtime_error(error).with_context(
                                        "apply guest-edited ToolHelp IRET stack image",
                                    )
                                }
                            }),
                        None => Ok(()),
                    };
                    if stack_restore.is_ok() {
                        owner.continuation = None;
                    }
                    stack_restore.and_then(|()| match owner.selector_roots.as_mut() {
                        Some(roots) => self.release_legacy_cpu_binding_owner(roots, dos, memory),
                        None => Ok(()),
                    })
                }
                None => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp interrupt IRET frame lost its captured CPU owner",
                )),
            };
            if let Err(error) = owner_cleanup {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.cpu_owner = None;
            frame.cpu_restored = true;
        }
        if let Some(allocation) = frame.private_stack.as_mut() {
            if let Err(error) = self.release_toolhelp_private_stack(allocation, cpu, memory) {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.private_stack = None;
        }
        if let Err(error) =
            self.retire_callback_binding(CallbackKind::ToolhelpInterrupt, callback_id)
        {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(error);
        }
        // IRET committed the callback's guest-edited return frame. Do not
        // restore the pre-event state or replay the event after this path.
        Ok(true)
    }

    fn resume_toolhelp_interrupt(
        &mut self,
        resume: &mut Option<Win16ToolhelpInterruptResume>,
        returned: Win16ToolhelpInterruptReturnFrame,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let event = resume.take().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp interrupt completion lost its deferred event",
            )
        })?;
        match event {
            Win16ToolhelpInterruptResume::Cpu(event) => {
                let segments = Win16Segments {
                    selectors: &self.selectors,
                    memory_len: memory.len(),
                };
                let resolution = match cpu.resume_deferred_event_from_16bit_frame_with_stack(
                    event,
                    CpuGuest16BitReturnFrame {
                        code_segment: returned.code_segment,
                        instruction_pointer: returned.instruction_pointer,
                        flags: returned.flags,
                    },
                    returned.faulting_stack,
                    memory,
                    &segments,
                ) {
                    Ok(resolution) => resolution,
                    Err(failure) => {
                        let (error, deferred) = failure.into_parts();
                        let Some(deferred) = deferred else {
                            return Err(crate::runtime_error(error));
                        };
                        if !toolhelp_return_image_rejection(&error) {
                            *resume = Some(Win16ToolhelpInterruptResume::Cpu(deferred));
                            return Err(crate::runtime_error(error));
                        }
                        // Only an architectural guest-frame rejection or an
                        // explicit compatibility refusal may decline the
                        // observer and chain the exact original CPU event.
                        if let Err(failure) = cpu.resume_deferred_event(deferred, memory, &segments)
                        {
                            let (error, deferred) = failure.into_parts();
                            if let Some(deferred) = deferred {
                                *resume = Some(Win16ToolhelpInterruptResume::Cpu(deferred));
                            }
                            return Err(crate::runtime_error(error));
                        }
                        CpuDeferredEventResolution::DeliveredToOriginalHandler
                    }
                };
                if resolution != CpuDeferredEventResolution::DeliveredToOriginalHandler {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "ToolHelp RETF chain did not deliver the original CPU event",
                    ));
                }
                Ok(())
            }
            Win16ToolhelpInterruptResume::SoftwareInterrupt { vector } => {
                let segments = Win16Segments {
                    selectors: &self.selectors,
                    memory_len: memory.len(),
                };
                if let Err(error) = cpu.apply_guest_16bit_return_frame(
                    CpuGuest16BitReturnFrame {
                        code_segment: returned.code_segment,
                        instruction_pointer: returned.instruction_pointer,
                        flags: returned.flags,
                    },
                    memory,
                    &segments,
                ) {
                    *resume = Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { vector });
                    return Err(crate::runtime_error(error));
                }
                if let Err(error) = self.begin_software_interrupt(vector, cpu, memory) {
                    *resume = Some(Win16ToolhelpInterruptResume::SoftwareInterrupt { vector });
                    return Err(error);
                }
                Ok(())
            }
        }
    }

    fn read_toolhelp_interrupt_return_frame(
        &self,
        frame: &Win16ToolhelpInterruptFrame,
        memory: &Memory,
    ) -> Result<Win16ToolhelpInterruptReturnFrame, RuntimeError> {
        let offset = frame.callback_stack_pointer.checked_add(6).ok_or_else(|| {
            RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp interrupt callback frame offset overflowed",
            )
        })?;
        let pointer = self
            .selectors
            .pointer_from_raw(Selector(frame.callback_stack_selector), offset)
            .map_err(crate::runtime_error)?;
        let frame_bytes = if frame.fault_stack_frame { 14 } else { 10 };
        let mut bytes = [0_u8; 14];
        self.selectors
            .read(memory, pointer, &mut bytes[..frame_bytes])
            .map_err(crate::runtime_error)?;
        let faulting_stack = frame
            .fault_stack_frame
            .then(|| (read_word(&bytes, 12), read_word(&bytes, 10)));
        Ok(Win16ToolhelpInterruptReturnFrame {
            event_vector: read_word(&bytes, 0),
            registration_handle: read_word(&bytes, 2),
            instruction_pointer: read_word(&bytes, 4),
            code_segment: read_word(&bytes, 6),
            flags: read_word(&bytes, 8),
            faulting_stack,
        })
    }

    pub(in crate::win16_runtime) fn cancel_toolhelp_interrupt_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::ToolhelpInterrupt)?;
        let mut frame = self.toolhelp_interrupt_frames.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "terminal ToolHelp interrupt callback lost its frame",
            )
        })?;
        if frame.callback_id != callback_id {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "terminal ToolHelp interrupt frame is not the exact callback LIFO top",
            ));
        }
        if !frame.cpu_restored {
            let restore_result = match frame.cpu_owner.as_mut() {
                Some(Win16ToolhelpInterruptCallOwner::Legacy(owner)) => self
                    .restore_legacy_cpu_frame_after_task_execution_ended(
                        ended, *owner, cpu, memory,
                    ),
                Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) => {
                    let abort_result = match owner.continuation.as_ref() {
                        Some(continuation) => cpu
                            .abort_event_observer_after_execution_ended(continuation)
                            .map_err(toolhelp_cpu_capture_error)
                            .map_err(|error| {
                                error.with_context(
                                "abort architectural ToolHelp observer after task execution ended",
                            )
                            }),
                        None => Ok(()),
                    };
                    if abort_result.is_ok() {
                        owner.continuation = None;
                    }
                    abort_result
                }
                None => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "terminal ToolHelp interrupt frame lost its CPU owner",
                )),
            };
            if let Err(error) = restore_result {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.cpu_restored = true;
        }
        let release_result = match frame.cpu_owner.as_mut() {
            Some(Win16ToolhelpInterruptCallOwner::Legacy(owner)) => {
                self.release_legacy_cpu_frame(*owner, dos, memory)
            }
            Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) => {
                match owner.selector_roots.as_mut() {
                    Some(roots) => self.release_legacy_cpu_binding_owner(roots, dos, memory),
                    None => Ok(()),
                }
            }
            None => Ok(()),
        };
        if let Err(error) = release_result {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(error);
        }
        if let Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) =
            frame.cpu_owner.as_mut()
        {
            owner.selector_roots = None;
        }
        frame.cpu_owner = None;
        if let Some(allocation) = frame.private_stack.as_mut() {
            if let Err(error) = self.release_toolhelp_private_stack(allocation, cpu, memory) {
                self.toolhelp_interrupt_frames.push(frame);
                return Err(error);
            }
            frame.private_stack = None;
        }
        if let Err(error) =
            self.retire_callback_binding(CallbackKind::ToolhelpInterrupt, callback_id)
        {
            self.toolhelp_interrupt_frames.push(frame);
            return Err(error);
        }
        Ok(())
    }

}
