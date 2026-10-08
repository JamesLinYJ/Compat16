//! CPU-owned continuations for guest callbacks and parked execution.
//!
//! These tickets are scoped to one `Cpu` instance. They preserve live event
//! state and never serve as whole-machine snapshots or host ABI values.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    ControlTransfer, Cpu, CpuContext, CpuError, SegmentResolver,
    system::DescriptorType,
};
use guest_core::GuestMemory;

/// Selects whether a call boundary keeps callback x87 effects or restores the
/// caller's saved x87 state. Pending CPU events are retained under both policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallEffectPolicy {
    PreserveX87,
    RestoreSavedX87,
}

/// Evidence the owner presents when preparing a CPU call resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallResumeBoundary {
    /// This exact guest-visible return completed through RETF/IRET or a checked
    /// ABI adapter commit. The CPU validates its fresh execution-boundary identity.
    GuestCallReturn { transfer: ControlTransfer },
    /// The native operation completed without executing another guest step.
    NoGuestExecution,
}

/// A rejected or stale continuation request. This type contains no runtime or
/// host state and is safe to move across threads when the owning CPU is idle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuCallResumeError {
    WrongCpu,
    StaleContinuation,
    TicketConsumed,
    UnsafeCpuBoundary,
    ArchitecturalContextUnavailable,
    InvalidExecutionMode,
    IncoherentSegmentSelectors,
    InvalidCodeState,
    InvalidStackState,
    ExecutionRootChanged,
    GuestExecutionOccurred,
    GuestCallReturnNotCompleted,
    UnsupportedGuestTransfer,
    PreparedStateChanged,
    BoundarySequenceExhausted,
    LegacyContextAlreadyInitialized,
    InvalidLegacyExecutionMode,
    InvalidLegacyTransferTarget,
}

impl std::fmt::Display for CpuCallResumeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::WrongCpu => "CPU continuation belongs to another CPU instance",
            Self::StaleContinuation => "CPU continuation predates a whole-context restore",
            Self::TicketConsumed => "CPU continuation was already committed",
            Self::UnsafeCpuBoundary => "CPU is not at a safe continuation boundary",
            Self::ArchitecturalContextUnavailable => {
                "CPU continuation cannot validate a legacy selector projection"
            }
            Self::InvalidExecutionMode => "CPU execution mode is not coherent",
            Self::IncoherentSegmentSelectors => {
                "visible selectors do not match the CPU hidden caches"
            }
            Self::InvalidCodeState => "caller code selector or instruction offset is invalid",
            Self::InvalidStackState => "caller stack selector or stack offset is invalid",
            Self::ExecutionRootChanged => "CPU mode or task roots changed across the continuation",
            Self::GuestExecutionOccurred => {
                "guest execution occurred in a NoGuestExecution continuation"
            }
            Self::GuestCallReturnNotCompleted => {
                "the expected guest call return did not complete at this step boundary"
            }
            Self::UnsupportedGuestTransfer => {
                "a callback resume requires a completed RETF or IRET"
            }
            Self::PreparedStateChanged => {
                "CPU state changed after continuation preparation"
            }
            Self::BoundarySequenceExhausted => {
                "CPU instruction-boundary sequence is exhausted"
            }
            Self::LegacyContextAlreadyInitialized => {
                "legacy continuation requires uninitialized architectural segment state"
            }
            Self::InvalidLegacyExecutionMode => {
                "legacy continuation requires real-address mode with PE and VM clear"
            }
            Self::InvalidLegacyTransferTarget => {
                "legacy register transfer has an invalid explicit stack target"
            }
        })
    }
}

impl std::error::Error for CpuCallResumeError {}

#[derive(Debug)]
pub enum CpuEventObserverCompletionError {
    Continuation(CpuCallResumeError),
    Stack(CpuError),
}

impl std::fmt::Display for CpuEventObserverCompletionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continuation(error) => std::fmt::Display::fmt(error, formatter),
            Self::Stack(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for CpuEventObserverCompletionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Continuation(error) => Some(error),
            Self::Stack(error) => Some(error),
        }
    }
}

/// Opaque caller state captured before a callback or native operation.
pub struct CpuCallContinuation {
    origin: Arc<u8>,
    generation: u64,
    entry_sequence: u64,
    saved: CpuContext,
    consumed: Arc<AtomicBool>,
}

/// CPU-owned origin state for an architectural event observer. Unlike an
/// ordinary callback continuation, this ticket may capture a faulting SS:SP
/// that the event itself reports as invalid; code and execution-root state
/// remain checked, and the caller must provide a separately validated stack.
pub struct CpuEventObserverContinuation {
    origin: Arc<u8>,
    generation: u64,
    entry_sequence: u64,
    saved: CpuContext,
    consumed: Arc<AtomicBool>,
}

/// An opaque call-resume plan bound to the exact live state seen by prepare.
pub struct PreparedCallResume {
    origin: Arc<u8>,
    generation: u64,
    expected_sequence: u64,
    expected_transfer_sequence: Option<u64>,
    expected_current: CpuContext,
    saved: CpuContext,
    policy: CallEffectPolicy,
    consumed: Arc<AtomicBool>,
}

/// Opaque scheduler-owned parked CPU state. It is not constructible from a
/// model-only `CpuContext` and is valid only on its creating CPU instance.
pub struct CpuParkedContinuation {
    origin: Arc<u8>,
    generation: u64,
    parked_sequence: u64,
    saved: CpuContext,
    consumed: Arc<AtomicBool>,
}

/// A parked-resume plan bound to one exact current CPU state.
pub struct PreparedParkedResume {
    origin: Arc<u8>,
    generation: u64,
    expected_sequence: u64,
    expected_transfer_sequence: Option<u64>,
    expected_current: CpuContext,
    saved: CpuContext,
    policy: CallEffectPolicy,
    consumed: Arc<AtomicBool>,
}

impl Cpu {
    /// Capture an architectural event origin while allowing only its source
    /// stack validity to be faulted. This is reserved for exception observers
    /// that switch to an independently validated guest stack.
    pub fn capture_event_observer_continuation(
        &self,
    ) -> Result<CpuEventObserverContinuation, CpuCallResumeError> {
        self.capture_event_observer_continuation_at_boundary(false)
    }

    /// Capture an event observer at an event boundary that may be inside an
    /// architecturally visible REP sequence. Only the deferred-event adapter
    /// may authorize that boundary; ordinary callback continuations still
    /// reject it.
    pub(crate) fn capture_event_observer_continuation_at_boundary(
        &self,
        allow_intermediate_rep_boundary: bool,
    ) -> Result<CpuEventObserverContinuation, CpuCallResumeError> {
        self.check_event_observer_entry_boundary(allow_intermediate_rep_boundary)?;
        let saved = self.capture_context();
        validate_event_observer_context(&saved)?;
        Ok(CpuEventObserverContinuation {
            origin: Arc::clone(&self.call_continuation_origin),
            generation: self.call_continuation_generation,
            entry_sequence: self.call_boundary_sequence,
            saved,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    fn check_event_observer_entry_boundary(
        &self,
        allow_intermediate_rep_boundary: bool,
    ) -> Result<(), CpuCallResumeError> {
        if self.call_boundary_sequence_exhausted {
            return Err(CpuCallResumeError::BoundarySequenceExhausted);
        }
        if !self.system.architectural_context_initialized {
            return Err(CpuCallResumeError::ArchitecturalContextUnavailable);
        }
        if self.shutdown_reason.is_some()
            || self.halted
            || self.pending_task_debug_trap
            || self.deferred_data_breakpoint_hits.enabled != 0
            || self.can_accept_non_maskable_interrupt()
            || self.maskable_interrupt_shadow
            || self.debug_exception_shadow
            || (!allow_intermediate_rep_boundary && self.intermediate_rep_boundary)
        {
            return Err(CpuCallResumeError::UnsafeCpuBoundary);
        }
        Ok(())
    }

    /// Validate the exact same-level IRET used by an event observer without
    /// mutating or consuming either owner ticket.
    pub fn validate_event_observer_guest_iret(
        &self,
        saved: &CpuEventObserverContinuation,
    ) -> Result<(), CpuCallResumeError> {
        self.check_event_observer_ticket(saved)?;
        if self.control_transfer != Some(ControlTransfer::InterruptReturn)
            || self.control_transfer_sequence != Some(self.call_boundary_sequence)
        {
            return Err(CpuCallResumeError::GuestCallReturnNotCompleted);
        }
        let current = self.capture_context();
        validate_event_observer_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)
    }

    /// Consume an observer ticket after its checked guest IRET and apply the
    /// saved or guest-edited SS:SP image while retaining guest-edited CS:IP and
    /// FLAGS. A changed selector is loaded through the active architectural
    /// tables before the callback stack backing is released.
    pub fn complete_event_observer_guest_iret(
        &mut self,
        saved: &CpuEventObserverContinuation,
        faulting_stack: Option<(u16, u16)>,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuEventObserverCompletionError> {
        self.validate_event_observer_guest_iret(saved)
            .map_err(CpuEventObserverCompletionError::Continuation)?;

        let (stack_selector, stack_pointer) = faulting_stack.unwrap_or((
            saved.saved.registers.ss,
            saved.saved.registers.sp(),
        ));
        let stack_cache = if stack_selector == saved.saved.registers.ss {
            // The original SS cache may be unusable precisely because this
            // observer handles #SS. Restore that exact cache when the guest
            // leaves its selector unchanged; the next guest access decides
            // whether its edited SP now succeeds.
            saved.saved.system.segments[1]
        } else {
            crate::execute::prepare_guest_16bit_stack_cache(
                self,
                stack_selector,
                stack_pointer,
                memory,
                segments,
            )
            .map_err(CpuEventObserverCompletionError::Stack)?
        };
        let mut registers = self.regs.clone();
        let mut system = self.system.clone();
        registers.ss = stack_selector;
        registers.set_sp(stack_pointer);
        system.segments[1] = stack_cache;

        claim_ticket(&saved.consumed)
            .map_err(CpuEventObserverCompletionError::Continuation)?;
        self.regs = registers;
        self.system = system;
        Ok(())
    }

    /// Restore the exact event origin after a checked callback RETF chain.
    /// Invalid source SS:SP is restored faithfully so normal event delivery can
    /// apply the architectural fault or chain it to the original handler.
    pub fn restore_event_observer_after_guest_retf(
        &mut self,
        saved: &CpuEventObserverContinuation,
    ) -> Result<(), CpuCallResumeError> {
        self.check_event_observer_ticket(saved)?;
        if self.call_boundary_sequence_exhausted
            || self.call_boundary_sequence <= saved.entry_sequence
            || self.control_transfer != Some(ControlTransfer::FarReturn)
            || self.control_transfer_sequence != Some(self.call_boundary_sequence)
        {
            return Err(CpuCallResumeError::GuestCallReturnNotCompleted);
        }
        let current = self.capture_context();
        validate_event_observer_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)?;
        claim_ticket(&saved.consumed)?;
        self.apply_resume_state(&saved.saved, CallEffectPolicy::RestoreSavedX87);
        Ok(())
    }

    /// Abort a still-owned event observer only after guest execution has
    /// ended. This restores a faulted source stack just like the RETF chain;
    /// callers must discard the deferred event rather than replaying it.
    pub fn abort_event_observer_after_execution_ended(
        &mut self,
        saved: &CpuEventObserverContinuation,
    ) -> Result<(), CpuCallResumeError> {
        self.check_event_observer_ticket(saved)?;
        let current = self.capture_context();
        validate_event_observer_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)?;
        claim_ticket(&saved.consumed)?;
        self.apply_resume_state(&saved.saved, CallEffectPolicy::RestoreSavedX87);
        Ok(())
    }

    fn check_event_observer_ticket(
        &self,
        saved: &CpuEventObserverContinuation,
    ) -> Result<(), CpuCallResumeError> {
        self.check_ticket_origin(&saved.origin)?;
        self.check_ticket_generation(saved.generation)?;
        self.check_ticket_available(&saved.consumed)
    }

    /// Capture the exact caller CPU state before entering a guest callback.
    pub fn capture_call_continuation(
        &self,
    ) -> Result<CpuCallContinuation, CpuCallResumeError> {
        self.check_safe_resume_boundary()?;
        let saved = self.capture_context();
        validate_resume_context(&saved)?;
        Ok(CpuCallContinuation {
            origin: Arc::clone(&self.call_continuation_origin),
            generation: self.call_continuation_generation,
            entry_sequence: self.call_boundary_sequence,
            saved,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Prepare an exact guest callback return or prove that no guest step ran.
    /// This does not mutate CPU state or consume the ticket.
    pub fn prepare_call_resume(
        &self,
        saved: &CpuCallContinuation,
        policy: CallEffectPolicy,
        boundary: CallResumeBoundary,
    ) -> Result<PreparedCallResume, CpuCallResumeError> {
        self.check_ticket_origin(&saved.origin)?;
        self.check_ticket_generation(saved.generation)?;
        self.check_ticket_available(&saved.consumed)?;
        self.check_safe_resume_boundary()?;
        let current = self.capture_context();
        validate_resume_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)?;

        match boundary {
            CallResumeBoundary::NoGuestExecution => {
                if self.call_boundary_sequence != saved.entry_sequence {
                    return Err(CpuCallResumeError::GuestExecutionOccurred);
                }
                if !same_unexecuted_state(&saved.saved, &current) {
                    return Err(CpuCallResumeError::PreparedStateChanged);
                }
            }
            CallResumeBoundary::GuestCallReturn { transfer } => {
                if !transfer.is_call_return() {
                    return Err(CpuCallResumeError::UnsupportedGuestTransfer);
                }
                if self.call_boundary_sequence <= saved.entry_sequence
                    || self.control_transfer != Some(transfer)
                    || self.control_transfer_sequence != Some(self.call_boundary_sequence)
                {
                    return Err(CpuCallResumeError::GuestCallReturnNotCompleted);
                }
            }
        }

        Ok(PreparedCallResume {
            origin: Arc::clone(&saved.origin),
            generation: saved.generation,
            expected_sequence: self.call_boundary_sequence,
            expected_transfer_sequence: self.control_transfer_sequence,
            expected_current: current,
            saved: saved.saved.clone(),
            policy,
            consumed: Arc::clone(&saved.consumed),
        })
    }

    /// Commit a previously prepared call resume if the full live CPU snapshot
    /// and its monotonic boundary sequence are unchanged.
    pub fn commit_call_resume(
        &mut self,
        prepared: PreparedCallResume,
    ) -> Result<(), CpuCallResumeError> {
        self.check_ticket_origin(&prepared.origin)?;
        self.check_ticket_generation(prepared.generation)?;
        self.check_ticket_available(&prepared.consumed)?;
        self.check_prepared_state(
            prepared.expected_sequence,
            prepared.expected_transfer_sequence,
            &prepared.expected_current,
        )?;
        claim_ticket(&prepared.consumed)?;
        self.apply_resume_state(&prepared.saved, prepared.policy);
        Ok(())
    }

    /// Restore an owned call origin after its machine has ended guest
    /// execution. This terminal path intentionally does not require a guest
    /// RETF/IRET marker; callers must already have stopped every CPU step and
    /// must drop any deferred event instead of replaying it.
    pub fn abort_call_continuation_after_execution_ended(
        &mut self,
        saved: &CpuCallContinuation,
        policy: CallEffectPolicy,
    ) -> Result<(), CpuCallResumeError> {
        self.check_ticket_origin(&saved.origin)?;
        self.check_ticket_generation(saved.generation)?;
        self.check_ticket_available(&saved.consumed)?;
        let current = self.capture_context();
        validate_resume_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)?;
        claim_ticket(&saved.consumed)?;
        self.apply_resume_state(&saved.saved, policy);
        Ok(())
    }

    /// Validate the exact guest IRET and ensure it kept the same execution
    /// root as its captured observer. The guest-edited CS:IP and FLAGS remain
    /// live; this check never restores the captured register image.
    pub fn validate_call_continuation_after_guest_iret(
        &self,
        saved: &CpuCallContinuation,
    ) -> Result<(), CpuCallResumeError> {
        self.check_ticket_origin(&saved.origin)?;
        self.check_ticket_generation(saved.generation)?;
        self.check_ticket_available(&saved.consumed)?;
        if self.control_transfer != Some(ControlTransfer::InterruptReturn)
            || self.control_transfer_sequence != Some(self.call_boundary_sequence)
        {
            return Err(CpuCallResumeError::GuestCallReturnNotCompleted);
        }
        let current = self.capture_context();
        validate_resume_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)
    }

    /// Capture an origin-bound ticket for a parked scheduler continuation.
    pub fn capture_parked_continuation(
        &self,
    ) -> Result<CpuParkedContinuation, CpuCallResumeError> {
        self.check_safe_resume_boundary()?;
        let saved = self.capture_context();
        validate_resume_context(&saved)?;
        Ok(CpuParkedContinuation {
            origin: Arc::clone(&self.call_continuation_origin),
            generation: self.call_continuation_generation,
            parked_sequence: self.call_boundary_sequence,
            saved,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Prepare restoration of a parked context after other guest work. The
    /// execution/task roots must still match; live CPU events are not restored.
    pub fn prepare_parked_resume(
        &self,
        saved: &CpuParkedContinuation,
        policy: CallEffectPolicy,
    ) -> Result<PreparedParkedResume, CpuCallResumeError> {
        self.check_ticket_origin(&saved.origin)?;
        self.check_ticket_generation(saved.generation)?;
        self.check_ticket_available(&saved.consumed)?;
        self.check_safe_resume_boundary()?;
        if self.call_boundary_sequence < saved.parked_sequence {
            return Err(CpuCallResumeError::PreparedStateChanged);
        }
        let current = self.capture_context();
        validate_resume_context(&saved.saved)?;
        validate_resume_context(&current)?;
        check_same_execution_root(&saved.saved, &current)?;
        Ok(PreparedParkedResume {
            origin: Arc::clone(&saved.origin),
            generation: saved.generation,
            expected_sequence: self.call_boundary_sequence,
            expected_transfer_sequence: self.control_transfer_sequence,
            expected_current: current,
            saved: saved.saved.clone(),
            policy,
            consumed: Arc::clone(&saved.consumed),
        })
    }

    /// Commit a parked resume against the exact state observed by prepare.
    pub fn commit_parked_resume(
        &mut self,
        prepared: PreparedParkedResume,
    ) -> Result<(), CpuCallResumeError> {
        self.check_ticket_origin(&prepared.origin)?;
        self.check_ticket_generation(prepared.generation)?;
        self.check_ticket_available(&prepared.consumed)?;
        self.check_prepared_state(
            prepared.expected_sequence,
            prepared.expected_transfer_sequence,
            &prepared.expected_current,
        )?;
        claim_ticket(&prepared.consumed)?;
        self.apply_resume_state(&prepared.saved, prepared.policy);
        Ok(())
    }

    fn check_ticket_origin(&self, origin: &Arc<u8>) -> Result<(), CpuCallResumeError> {
        Arc::ptr_eq(&self.call_continuation_origin, origin)
            .then_some(())
            .ok_or(CpuCallResumeError::WrongCpu)
    }

    fn check_ticket_generation(&self, generation: u64) -> Result<(), CpuCallResumeError> {
        (self.call_continuation_generation == generation)
            .then_some(())
            .ok_or(CpuCallResumeError::StaleContinuation)
    }

    fn check_ticket_available(&self, consumed: &AtomicBool) -> Result<(), CpuCallResumeError> {
        (!consumed.load(Ordering::Acquire))
            .then_some(())
            .ok_or(CpuCallResumeError::TicketConsumed)
    }

    fn check_safe_resume_boundary(&self) -> Result<(), CpuCallResumeError> {
        if self.call_boundary_sequence_exhausted {
            return Err(CpuCallResumeError::BoundarySequenceExhausted);
        }
        if !self.system.architectural_context_initialized {
            return Err(CpuCallResumeError::ArchitecturalContextUnavailable);
        }
        if self.shutdown_reason.is_some()
            || self.halted
            || self.pending_task_debug_trap
            || self.deferred_data_breakpoint_hits.enabled != 0
            || self.can_accept_non_maskable_interrupt()
            || self.maskable_interrupt_shadow
            || self.debug_exception_shadow
            || self.intermediate_rep_boundary
        {
            return Err(CpuCallResumeError::UnsafeCpuBoundary);
        }
        Ok(())
    }

    fn check_prepared_state(
        &self,
        expected_sequence: u64,
        expected_transfer_sequence: Option<u64>,
        expected_current: &CpuContext,
    ) -> Result<(), CpuCallResumeError> {
        if self.call_boundary_sequence_exhausted
            || self.call_boundary_sequence != expected_sequence
            || self.control_transfer_sequence != expected_transfer_sequence
            || self.capture_context() != *expected_current
        {
            return Err(CpuCallResumeError::PreparedStateChanged);
        }
        Ok(())
    }

    fn apply_resume_state(&mut self, saved: &CpuContext, policy: CallEffectPolicy) {
        self.regs = saved.registers.clone();
        self.system.segments = saved.system.segments;
        self.system.cpl = saved.system.cpl;
        self.system.architectural_context_initialized =
            saved.system.architectural_context_initialized;
        if policy == CallEffectPolicy::RestoreSavedX87 {
            self.x87 = saved.x87.clone();
        }
        // Never restore a caller's old transfer marker or event ledger.
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        self.intermediate_rep_boundary = false;
        self.normalize_model_eflags();
    }
}

fn claim_ticket(consumed: &AtomicBool) -> Result<(), CpuCallResumeError> {
    consumed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| CpuCallResumeError::TicketConsumed)
}

fn validate_resume_context(context: &CpuContext) -> Result<(), CpuCallResumeError> {
    validate_resume_context_with_stack(context, true)
}

fn validate_event_observer_context(context: &CpuContext) -> Result<(), CpuCallResumeError> {
    validate_resume_context_with_stack(context, false)
}

fn validate_resume_context_with_stack(
    context: &CpuContext,
    require_valid_stack: bool,
) -> Result<(), CpuCallResumeError> {
    let system = &context.system;
    if !system.architectural_context_initialized {
        return Err(CpuCallResumeError::ArchitecturalContextUnavailable);
    }
    let Some(mode) = system.execution_mode(context.registers.eflags) else {
        return Err(CpuCallResumeError::InvalidExecutionMode);
    };
    if system.cpl > 3
        || (mode == crate::CpuExecutionMode::RealAddress && system.cpl != 0)
        || (mode == crate::CpuExecutionMode::Virtual8086 && system.cpl != 3)
    {
        return Err(CpuCallResumeError::InvalidExecutionMode);
    }
    let visible = [
        context.registers.cs,
        context.registers.ss,
        context.registers.ds,
        context.registers.es,
        context.registers.fs,
        context.registers.gs,
    ];
    if system
        .segments
        .iter()
        .zip(visible)
        .any(|(cache, selector)| cache.selector != selector)
    {
        return Err(CpuCallResumeError::IncoherentSegmentSelectors);
    }

    let code = &system.segments[0];
    // Protected and VM86 instruction starts use the full architectural EIP,
    // even when the cached code descriptor is D=16. Only real-address mode
    // applies the code-size wrap used by step_with_context.
    let code_offset = match mode {
        crate::CpuExecutionMode::Protected | crate::CpuExecutionMode::Virtual8086 => {
            context.registers.eip
        }
        crate::CpuExecutionMode::RealAddress if code.descriptor.default_big => {
            context.registers.eip
        }
        crate::CpuExecutionMode::RealAddress => u32::from(context.registers.ip()),
    };
    if code.unusable
        || !code.descriptor.present
        || !matches!(code.descriptor.descriptor_type, DescriptorType::Code { .. })
        || code_offset > code.descriptor.limit
    {
        return Err(CpuCallResumeError::InvalidCodeState);
    }
    if mode == crate::CpuExecutionMode::Protected {
        let code_privilege_valid = match code.descriptor.descriptor_type {
            DescriptorType::Code {
                conforming: true, ..
            } => code.descriptor.dpl <= system.cpl,
            DescriptorType::Code {
                conforming: false, ..
            } => code.descriptor.dpl == system.cpl,
            _ => false,
        };
        if context.registers.cs & 3 != u16::from(system.cpl) || !code_privilege_valid {
            return Err(CpuCallResumeError::InvalidCodeState);
        }
    }

    let stack = &system.segments[1];
    // An event observer may capture an SS:SP whose current offset cannot
    // accept the event frame. The cached selector must still be a usable
    // writable 16-bit stack descriptor; only its current offset bound is
    // allowed to be the faulting part of the context.
    if !require_valid_stack {
        let valid_stack_descriptor = matches!(
            stack.descriptor.descriptor_type,
            DescriptorType::Data {
                writable: true,
                ..
            }
        );
        if stack.unusable
            || !stack.descriptor.present
            || stack.descriptor.default_big
            || !valid_stack_descriptor
            || (mode == crate::CpuExecutionMode::Protected
                && (context.registers.ss & 3 != u16::from(system.cpl)
                    || stack.descriptor.dpl != system.cpl))
        {
            return Err(CpuCallResumeError::InvalidStackState);
        }
        return Ok(());
    }
    let stack_pointer = if stack.descriptor.default_big {
        context.registers.esp
    } else {
        u32::from(context.registers.sp())
    };
    let stack_bound = match stack.descriptor.descriptor_type {
        DescriptorType::Data {
            writable: true,
            expand_down: true,
            ..
        } => stack_pointer > stack.descriptor.limit,
        DescriptorType::Data {
            writable: true,
            expand_down: false,
            ..
        } => u64::from(stack_pointer) <= u64::from(stack.descriptor.limit) + 1,
        _ => false,
    };
    let stack_max = if stack.descriptor.default_big {
        u64::from(u32::MAX)
    } else {
        u64::from(u16::MAX)
    };
    if stack.unusable
        || !stack.descriptor.present
        || !stack_bound
        || u64::from(stack_pointer) > stack_max
        || (mode == crate::CpuExecutionMode::Protected
            && (context.registers.ss & 3 != u16::from(system.cpl)
                || stack.descriptor.dpl != system.cpl))
    {
        return Err(CpuCallResumeError::InvalidStackState);
    }
    Ok(())
}

fn check_same_execution_root(
    saved: &CpuContext,
    current: &CpuContext,
) -> Result<(), CpuCallResumeError> {
    if saved.model != current.model || !same_execution_root(saved, current) {
        return Err(CpuCallResumeError::ExecutionRootChanged);
    }
    Ok(())
}

fn same_execution_root(saved: &CpuContext, current: &CpuContext) -> bool {
    let saved_system = &saved.system;
    let current_system = &current.system;
    saved_system.execution_mode(saved.registers.eflags)
        == current_system.execution_mode(current.registers.eflags)
        && saved_system.cr0 == current_system.cr0
        && saved_system.cr3 == current_system.cr3
        && saved_system.cpl == current_system.cpl
        && saved_system.gdtr == current_system.gdtr
        && saved_system.idtr == current_system.idtr
        && saved_system.ldtr == current_system.ldtr
        && saved_system.task == current_system.task
        && saved_system.architectural_context_initialized
            == current_system.architectural_context_initialized
}

fn same_unexecuted_state(saved: &CpuContext, current: &CpuContext) -> bool {
    saved.registers == current.registers
        && same_execution_root(saved, current)
        && saved.system.segments == current.system.segments
        && saved.maskable_interrupt_shadow == current.maskable_interrupt_shadow
        && saved.debug_exception_shadow == current.debug_exception_shadow
        && saved.intermediate_rep_boundary == current.intermediate_rep_boundary
        && saved.halted == current.halted
        && saved.shutdown_reason == current.shutdown_reason
        && saved.control_transfer == current.control_transfer
}
