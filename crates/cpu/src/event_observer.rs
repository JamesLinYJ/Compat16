//! Opaque CPU event deferral for runtime-owned guest exception observers.
//!
//! The CPU describes and resumes architectural events but does not know about
//! Win16 handlers, task identities, or callback ABIs.
use guest_core::GuestMemory;
use std::sync::Arc;

use crate::{
    Cpu, CpuError, SegmentResolver, StepOutcome,
    interrupt_delivery::{CpuEvent, EventSource, deliver_event_checked},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuEventSource {
    /// An `INT imm8` software interrupt.
    SoftwareInterrupt,
    /// An `INT3` software breakpoint.
    SoftwareBreakpoint,
    /// The single-byte `F1` debug trap.
    InstructionDebugTrap,
    /// The `INTO` overflow trap.
    SoftwareOverflow,
    /// A processor fault whose delivery normally restarts the instruction.
    Fault,
    /// A processor trap whose saved IP follows the completed instruction.
    Trap,
    /// A maskable interrupt accepted from the emulated external bus.
    ExternalInterrupt,
    /// A fault-class instruction breakpoint.
    InstructionBreakpointFault,
    /// The non-maskable interrupt input.
    NonMaskableInterrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuEventObservation {
    /// Architectural vector accepted by the processor.
    pub vector: u8,
    /// Instruction, fault, trap, or external source classification.
    pub source: CpuEventSource,
    /// Code selector used to form the event's return frame.
    pub saved_cs: u16,
    /// Instruction pointer used to form the event's return frame.
    pub saved_ip: u32,
    /// EFLAGS image used to form the event's return frame.
    pub saved_flags: u32,
    /// Error code, when the architectural exception has one.
    pub error_code: Option<u32>,
}

/// Guest-visible 16-bit return image used by machine-owned event observers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuGuest16BitReturnFrame {
    /// Guest-edited CS word from the 16-bit return image.
    pub code_segment: u16,
    /// Guest-edited IP word from the 16-bit return image.
    pub instruction_pointer: u16,
    /// Guest-edited FLAGS word from the 16-bit return image.
    pub flags: u16,
}

/// Compatibility alias retained for callers that used the initial real-mode
/// observer prototype. The frame itself is mode-neutral.
pub type CpuRealModeReturnFrame = CpuGuest16BitReturnFrame;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuDeferredEventResolution {
    /// The observer chained and the CPU delivered the original event.
    DeliveredToOriginalHandler,
    /// A guest IRET consumed the event and restored its edited return context.
    HandledByGuestIret,
}

/// A deferred event cannot be edited by the runtime. It is replayed only after
/// the callback continuation restores its captured CPU architecture state.
#[derive(Debug)]
pub struct CpuDeferredEvent {
    event: CpuEvent,
    original_error: Option<CpuError>,
    observation: CpuEventObservation,
    // Keep REP-boundary provenance with the event because the guest observer
    // executes with a cleared live boundary while a chained event still needs
    // the original saved-FLAGS rules.
    intermediate_rep_boundary: bool,
    origin: Arc<u8>,
    generation: u64,
}

/// Failed IRET completion returns ownership of the deferred event so a
/// machine observer can preserve the original delivery instead of losing it.
#[derive(Debug)]
pub struct CpuDeferredEventCompletionError {
    error: CpuError,
    deferred: CpuDeferredEvent,
}

impl CpuDeferredEventCompletionError {
    pub fn into_parts(self) -> (CpuError, CpuDeferredEvent) {
        (self.error, self.deferred)
    }
}

/// A return-image preflight failure keeps the deferred CPU event so the
/// machine can still send that exact event through ordinary guest delivery.
/// Once normal delivery begins, a storage failure is terminal and no event is
/// returned for replay.
#[derive(Debug)]
pub struct CpuDeferredEventResumeError {
    error: CpuError,
    deferred: Option<CpuDeferredEvent>,
}

impl CpuDeferredEventResumeError {
    pub fn into_parts(self) -> (CpuError, Option<CpuDeferredEvent>) {
        (self.error, self.deferred)
    }
}

impl CpuDeferredEvent {
    pub const fn observation(&self) -> CpuEventObservation {
        self.observation
    }
}

#[derive(Debug)]
pub enum CpuObservedStepOutcome {
    /// The instruction completed without an event being deferred.
    Executed(StepOutcome),
    /// An event is held until its observer continuation returns.
    EventDeferred(CpuDeferredEvent),
}

impl Cpu {
    /// Capture the origin for a deferred event returned by this CPU. The
    /// event's own REP-boundary provenance is the only authority that can
    /// permit observer entry between REP iterations.
    pub fn capture_deferred_event_observer_continuation(
        &self,
        deferred: &CpuDeferredEvent,
    ) -> Result<crate::CpuEventObserverContinuation, crate::CpuCallResumeError> {
        if !Arc::ptr_eq(&self.call_continuation_origin, &deferred.origin)
            || self.call_continuation_generation != deferred.generation
        {
            return Err(crate::CpuCallResumeError::StaleContinuation);
        }
        self.capture_event_observer_continuation_at_boundary(
            deferred.intermediate_rep_boundary,
        )
    }

    /// Enter a guest-owned 16-bit far callback at a machine-prepared stack
    /// image. Architectural code/stack selectors and the RETF target are
    /// checked by the CPU before any visible register is committed.
    pub fn enter_guest_16bit_callback(
        &mut self,
        target_cs: u16,
        target_ip: u16,
        callback_sp: u16,
        return_frame: CpuGuest16BitReturnFrame,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuError> {
        self.enter_guest_16bit_callback_on_stack(
            target_cs,
            target_ip,
            self.regs.ss,
            callback_sp,
            return_frame,
            memory,
            segments,
        )
    }

    /// Enter a guest callback on an independently validated 16-bit SS:SP.
    /// This supports machine-owned fault stacks without teaching the CPU which
    /// guest subsystem allocated or owns that stack.
    pub fn enter_guest_16bit_callback_on_stack(
        &mut self,
        target_cs: u16,
        target_ip: u16,
        callback_ss: u16,
        callback_sp: u16,
        return_frame: CpuGuest16BitReturnFrame,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuError> {
        crate::execute::enter_checked_16bit_callback(
            self,
            target_cs,
            target_ip,
            callback_ss,
            callback_sp,
            return_frame.code_segment,
            return_frame.instruction_pointer,
            memory,
            segments,
        )
    }

    /// Enter a callback through the machine's legacy selector projection.
    /// Event TF/RF remain in the saved guest image, but must not alter the
    /// observer's first-instruction debug behavior.
    pub fn enter_legacy_guest_16bit_callback(
        &mut self,
        code_segment: u16,
        instruction_pointer: u16,
        stack_pointer: u16,
    ) -> Result<(), CpuError> {
        self.enter_legacy_guest_16bit_callback_on_stack(
            code_segment,
            instruction_pointer,
            self.regs.ss,
            stack_pointer,
        )
    }

    /// Selector-projected counterpart of the checked architectural stack
    /// switch. Runtime ownership validates the guest selector and backing.
    pub fn enter_legacy_guest_16bit_callback_on_stack(
        &mut self,
        code_segment: u16,
        instruction_pointer: u16,
        stack_selector: u16,
        stack_pointer: u16,
    ) -> Result<(), CpuError> {
        if self.architectural_execution_mode().is_some() {
            return Err(CpuError::InvalidMemoryAccessPlan { ip: self.regs.eip });
        }
        self.regs.cs = code_segment;
        self.regs.ss = stack_selector;
        self.regs.eip = u32::from(instruction_pointer);
        self.regs.set_sp(stack_pointer);
        self.regs.eflags &= !(crate::TF | (1 << 16));
        // The event token owns the original REP-boundary provenance; the
        // callback itself starts outside that interrupted instruction.
        self.intermediate_rep_boundary = false;
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(())
    }

    /// Restore only SS:SP after a legacy-selector callback IRET that used a
    /// machine-owned guest stack. The callback's edited CS:IP and FLAGS remain
    /// live; no architectural hidden state is synthesized in legacy mode.
    pub fn restore_legacy_guest_callback_stack(
        &mut self,
        stack_selector: u16,
        stack_pointer: u16,
    ) -> Result<(), CpuError> {
        if self.architectural_execution_mode().is_some() {
            return Err(CpuError::InvalidMemoryAccessPlan { ip: self.regs.eip });
        }
        self.regs.ss = stack_selector;
        self.regs.set_sp(stack_pointer);
        Ok(())
    }

    /// Report whether the live architectural selectors expose the 16-bit
    /// code and stack model required by a machine-owned 16-bit far callback.
    pub fn supports_guest_16bit_callback_context(&self) -> bool {
        match self.architectural_execution_mode() {
            Some(crate::CpuExecutionMode::RealAddress) => true,
            Some(crate::CpuExecutionMode::Protected) => {
                !self
                    .system
                    .segment_cache(crate::registers::SegmentRegister::Cs)
                    .descriptor
                    .default_big
                    && !self
                        .system
                        .segment_cache(crate::registers::SegmentRegister::Ss)
                        .descriptor
                        .default_big
            }
            Some(crate::CpuExecutionMode::Virtual8086) | None => false,
        }
    }

    /// Apply a return image while the machine still owns legacy selectors and
    /// the CPU has no imported architectural descriptor context.
    pub fn apply_legacy_guest_16bit_return_frame(
        &mut self,
        frame: CpuGuest16BitReturnFrame,
    ) -> Result<(), CpuError> {
        crate::execute::apply_legacy_16bit_return_image(
            self,
            crate::execute::Guest16BitReturnImage {
                code_segment: frame.code_segment,
                instruction_pointer: frame.instruction_pointer,
                flags: frame.flags,
            },
        )
    }

    /// Apply a checked guest-edited 16-bit return image using the CPU's live
    /// execution mode. Software-interrupt observers use this after a guest
    /// callback has returned with RETF: RealAddress and protected callers need
    /// architectural descriptor/FLAGS rules, while selector-projected legacy
    /// callers must not acquire synthetic hidden CPU state.
    pub fn apply_guest_16bit_return_frame(
        &mut self,
        frame: CpuGuest16BitReturnFrame,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuError> {
        let image = crate::execute::Guest16BitReturnImage {
            code_segment: frame.code_segment,
            instruction_pointer: frame.instruction_pointer,
            flags: frame.flags,
        };
        if self.architectural_execution_mode().is_some() {
            crate::execute::apply_16bit_return_image(self, image, memory, segments)
        } else {
            crate::execute::apply_legacy_16bit_return_image(self, image)
        }
    }

    /// Create the opaque token for an externally acknowledged vector without
    /// delivering it. The machine decides whether a runtime-owned observer
    /// consumes the event before calling `resume_deferred_event`.
    pub fn deferred_external_interrupt(&self, vector: u8) -> CpuDeferredEvent {
        let event = CpuEvent {
            vector,
            source: EventSource::ExternalInterrupt,
            saved_eip: self.regs.eip,
            instruction_ip: self.regs.eip,
            instruction_opcode: 0,
            error_code: None,
        };
        self.describe_deferred_event(event, None)
    }

    pub(crate) fn defer_step_event(
        &mut self,
        event: CpuEvent,
        original_error: Option<CpuError>,
    ) -> bool {
        if !self.defer_cpu_events {
            return false;
        }
        self.deferred_cpu_event = Some(self.describe_deferred_event(event, original_error));
        true
    }

    fn describe_deferred_event(
        &self,
        event: CpuEvent,
        original_error: Option<CpuError>,
    ) -> CpuDeferredEvent {
        let source = match event.source {
            EventSource::SoftwareInterrupt => CpuEventSource::SoftwareInterrupt,
            EventSource::SoftwareBreakpoint => CpuEventSource::SoftwareBreakpoint,
            EventSource::InstructionDebugTrap => CpuEventSource::InstructionDebugTrap,
            EventSource::SoftwareOverflow => CpuEventSource::SoftwareOverflow,
            EventSource::Fault => CpuEventSource::Fault,
            EventSource::Trap => CpuEventSource::Trap,
            EventSource::ExternalInterrupt => CpuEventSource::ExternalInterrupt,
            EventSource::InstructionBreakpointFault => CpuEventSource::InstructionBreakpointFault,
            EventSource::NonMaskableInterrupt => CpuEventSource::NonMaskableInterrupt,
        };
        let observation = CpuEventObservation {
            vector: event.vector,
            source,
            saved_cs: self.regs.cs,
            saved_ip: event.saved_eip,
            saved_flags: event.saved_eflags(
                self.regs.eflags,
                self.intermediate_rep_boundary,
            ),
            error_code: event.error_code,
        };
        CpuDeferredEvent {
            event,
            original_error,
            observation,
            intermediate_rep_boundary: self.intermediate_rep_boundary,
            origin: Arc::clone(&self.call_continuation_origin),
            generation: self.call_continuation_generation,
        }
    }

    /// Resume the exact event after the runtime restores the captured CPU
    /// context. Nested delivery faults remain owned by the CPU's normal path.
    pub fn resume_deferred_event(
        &mut self,
        deferred: CpuDeferredEvent,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuDeferredEventResumeError> {
        if let Err(error) = self.verify_deferred_event_owner(&deferred) {
            return Err(CpuDeferredEventResumeError {
                error,
                deferred: Some(deferred),
            });
        }
        self.defer_cpu_events = false;
        self.deferred_cpu_event = None;
        self.intermediate_rep_boundary = deferred.intermediate_rep_boundary;
        deliver_event_checked(
            self,
            deferred.event,
            deferred.original_error,
            memory,
            segments,
        )
        // Delivery can commit CPU state or start a nested fault. Only the
        // preflight above may return an event that is safe to try again.
        .map_err(|error| CpuDeferredEventResumeError { error, deferred: None })
    }

    /// Apply a checked 16-bit return image and chain the original event through
    /// the CPU's native delivery path. Protected mode validates the guest code
    /// selector and merges FLAGS with its current CPL; selector-projected mode
    /// never invents a privilege level.
    pub fn resume_deferred_event_from_16bit_frame(
        &mut self,
        deferred: CpuDeferredEvent,
        frame: CpuGuest16BitReturnFrame,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<CpuDeferredEventResolution, CpuDeferredEventResumeError> {
        self.resume_deferred_event_from_16bit_frame_with_stack(
            deferred,
            frame,
            None,
            memory,
            segments,
        )
    }

    /// Apply a guest-edited 16-bit event frame and optional faulting SS:SP
    /// image before chaining the exact deferred event through normal CPU
    /// delivery. A preflight failure returns the token to the runtime.
    pub fn resume_deferred_event_from_16bit_frame_with_stack(
        &mut self,
        mut deferred: CpuDeferredEvent,
        frame: CpuGuest16BitReturnFrame,
        faulting_stack: Option<(u16, u16)>,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<CpuDeferredEventResolution, CpuDeferredEventResumeError> {
        if let Err(error) = self.verify_deferred_event_owner(&deferred) {
            return Err(CpuDeferredEventResumeError {
                error,
                deferred: Some(deferred),
            });
        }
        let prepared_stack = if let Some((stack_selector, stack_pointer)) = faulting_stack {
            if self.architectural_execution_mode().is_some()
                && stack_selector != self.regs.ss
            {
                match crate::execute::prepare_guest_16bit_stack_cache(
                    self,
                    stack_selector,
                    stack_pointer,
                    memory,
                    segments,
                ) {
                    Ok(cache) => Some(cache),
                    Err(error) => {
                        return Err(CpuDeferredEventResumeError {
                            error,
                            deferred: Some(deferred),
                        });
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        let image = crate::execute::Guest16BitReturnImage {
            code_segment: frame.code_segment,
            instruction_pointer: frame.instruction_pointer,
            flags: frame.flags,
        };
        let apply_result = if self.architectural_execution_mode().is_some() {
            crate::execute::apply_16bit_return_image(self, image, memory, segments)
        } else {
            crate::execute::apply_legacy_16bit_return_image(self, image)
        };
        if let Err(error) = apply_result {
            return Err(CpuDeferredEventResumeError {
                error,
                deferred: Some(deferred),
            });
        }
        if let Some((stack_selector, stack_pointer)) = faulting_stack {
            self.regs.ss = stack_selector;
            self.regs.set_sp(stack_pointer);
            if let Some(cache) = prepared_stack {
                self.system.segments[1] = cache;
            }
        }
        deferred.event.saved_eip = u32::from(frame.instruction_pointer);
        self.resume_deferred_event(deferred, memory, segments)?;
        Ok(CpuDeferredEventResolution::DeliveredToOriginalHandler)
    }

    /// Complete an observed event when the guest handler itself executed its
    /// checked 16-bit IRET. IRET has already selected the edited return context;
    /// replaying the same event here would incorrectly repeat a handled fault.
    pub fn complete_deferred_event_after_guest_iret(
        &mut self,
        deferred: CpuDeferredEvent,
    ) -> Result<CpuDeferredEventResolution, CpuDeferredEventCompletionError> {
        if let Err(error) = self.verify_deferred_event_owner(&deferred) {
            return Err(CpuDeferredEventCompletionError { error, deferred });
        }
        if self.defer_cpu_events
            || self.control_transfer != Some(crate::ControlTransfer::InterruptReturn)
            || self.control_transfer_sequence != Some(self.call_boundary_sequence)
        {
            return Err(CpuDeferredEventCompletionError {
                error: CpuError::InvalidMemoryAccessPlan { ip: self.regs.eip },
                deferred,
            });
        }
        Ok(CpuDeferredEventResolution::HandledByGuestIret)
    }

    fn verify_deferred_event_owner(
        &self,
        deferred: &CpuDeferredEvent,
    ) -> Result<(), CpuError> {
        if !Arc::ptr_eq(&self.call_continuation_origin, &deferred.origin)
            || self.call_continuation_generation != deferred.generation
        {
            return Err(CpuError::InvalidMemoryAccessPlan { ip: self.regs.eip });
        }
        Ok(())
    }

    /// Compatibility wrapper for callers of the original real-address API.
    /// The frame is mode-neutral and is checked against the active CPU context.
    pub fn resume_deferred_event_from_real_mode_frame(
        &mut self,
        deferred: CpuDeferredEvent,
        frame: CpuRealModeReturnFrame,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuDeferredEventResumeError> {
        self.resume_deferred_event_from_16bit_frame(deferred, frame, memory, segments)
            .map(|_| ())
    }

}
