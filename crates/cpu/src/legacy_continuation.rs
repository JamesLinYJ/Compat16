//! Checked continuations for runtimes that own legacy segment projection.
//!
//! These tickets restore the visible register file only. The runtime binding
//! owns selector generations and their memory backing; this module never
//! invents hidden descriptor caches or rewinds live CPU event state.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use guest_core::Registers;

use crate::{
    CallEffectPolicy, CallResumeBoundary, ControlTransfer, Cpu, CpuCallResumeError, CpuContext,
    system::CR0_PE,
};

const EFLAGS_VM: u32 = 1 << 17;

/// The logical stack pointer used by a checked final register transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyStackPointerTarget {
    /// Use the 16-bit stack value in the supplied full ESP register.
    RegisterValue,
    /// The returned stack is one byte beyond a full 64-KiB 16-bit segment.
    /// The supplied register must have SP=0; the runtime validates SS extent.
    OnePast16BitSegment,
}

/// A caller-selected final register image. This is a register transfer, not a
/// synthesized RETF or IRET instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRegisterTransfer {
    pub registers: Registers,
    pub stack_pointer: LegacyStackPointerTarget,
}

/// Additional identities the binding must revalidate for a prepared transfer.
pub struct LegacyBindingTransfer<'a, Proof> {
    pub current: &'a Proof,
    pub target: &'a Proof,
    pub current_registers: &'a Registers,
    pub target_registers: &'a Registers,
    pub stack_pointer: LegacyStackPointerTarget,
}

/// Runtime-owned selector and memory evidence required at every ticket phase.
/// Proofs may be cloned, but leases stay in the runtime's separate owner.
pub trait LegacyCpuBinding {
    type Proof: Clone + Eq;
    type Error;

    fn capture(&self, registers: &Registers) -> Result<Self::Proof, Self::Error>;

    /// Revalidate both `saved`'s old roots and `observed` against live owners.
    /// `current` and `target` are separate proofs because callback execution
    /// may legitimately change the visible segment registers.
    fn revalidate(
        &self,
        saved: &Self::Proof,
        observed: &Self::Proof,
        transfer: &LegacyBindingTransfer<'_, Self::Proof>,
    ) -> Result<(), Self::Error>;
}

/// CPU or runtime binding failure without erasing the source error type.
#[derive(Debug)]
pub enum LegacyCpuContinuationError<BindingError> {
    Cpu(CpuCallResumeError),
    Binding(BindingError),
}

impl<E: std::fmt::Display> std::fmt::Display for LegacyCpuContinuationError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cpu(error) => std::fmt::Display::fmt(error, formatter),
            Self::Binding(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LegacyCpuContinuationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cpu(error) => Some(error),
            Self::Binding(error) => Some(error),
        }
    }
}

/// Opaque CPU-origin-bound caller state captured before a legacy callback.
pub struct LegacyCpuCallContinuation<Proof> {
    inner: LegacySavedState<Proof>,
}

/// Opaque scheduler-owned parked legacy register state.
pub struct LegacyCpuParkedContinuation<Proof> {
    inner: LegacySavedState<Proof>,
}

/// A prepared callback register transfer bound to exact CPU and runtime proofs.
pub struct PreparedLegacyCallResume<Proof> {
    inner: LegacyPreparedState<Proof>,
}

/// A prepared parked register transfer bound to exact CPU and runtime proofs.
pub struct PreparedLegacyParkedResume<Proof> {
    inner: LegacyPreparedState<Proof>,
}

struct LegacySavedState<Proof> {
    origin: Arc<u8>,
    generation: u64,
    sequence: u64,
    context: CpuContext,
    binding: Proof,
    consumed: Arc<AtomicBool>,
}

struct LegacyPreparedState<Proof> {
    origin: Arc<u8>,
    generation: u64,
    expected_sequence: u64,
    expected_transfer_sequence: Option<u64>,
    expected_current: CpuContext,
    saved: CpuContext,
    saved_binding: Proof,
    expected_current_binding: Proof,
    target_binding: Proof,
    target: LegacyRegisterTransfer,
    policy: CallEffectPolicy,
    consumed: Arc<AtomicBool>,
}

impl Cpu {
    /// Capture caller state while the CPU still uses the legacy mode owner.
    pub fn capture_legacy_call_continuation<B: LegacyCpuBinding>(
        &self,
        binding: &B,
    ) -> Result<LegacyCpuCallContinuation<B::Proof>, LegacyCpuContinuationError<B::Error>> {
        self.check_legacy_boundary().map_err(LegacyCpuContinuationError::Cpu)?;
        let context = self.capture_context();
        validate_legacy_context(&context).map_err(LegacyCpuContinuationError::Cpu)?;
        let proof = binding.capture(&context.registers).map_err(LegacyCpuContinuationError::Binding)?;
        Ok(LegacyCpuCallContinuation {
            inner: LegacySavedState {
                origin: Arc::clone(&self.call_continuation_origin),
                generation: self.call_continuation_generation,
                sequence: self.call_boundary_sequence,
                context,
                binding: proof,
                consumed: Arc::new(AtomicBool::new(false)),
            },
        })
    }

    /// Prepare a completed instruction/adapter return or exact no-execution result.
    pub fn prepare_legacy_call_resume<B: LegacyCpuBinding>(
        &self,
        saved: &LegacyCpuCallContinuation<B::Proof>,
        policy: CallEffectPolicy,
        boundary: CallResumeBoundary,
        target: LegacyRegisterTransfer,
        binding: &B,
    ) -> Result<PreparedLegacyCallResume<B::Proof>, LegacyCpuContinuationError<B::Error>> {
        let prepared = self.prepare_legacy_resume(
            &saved.inner, policy, Some(boundary), target, binding,
        )?;
        Ok(PreparedLegacyCallResume { inner: prepared })
    }

    /// Commit a checked caller register transfer without fabricating a return.
    pub fn commit_legacy_call_resume<B: LegacyCpuBinding>(
        &mut self,
        prepared: PreparedLegacyCallResume<B::Proof>,
        binding: &B,
    ) -> Result<(), LegacyCpuContinuationError<B::Error>> {
        self.commit_legacy_resume(prepared.inner, binding)
    }

    /// Commit an ABI caller return after the binding has validated its return
    /// address and stack cleanup. Ordinary context restoration uses the separate
    /// resume method and cannot manufacture this event.
    pub fn commit_legacy_call_return<B: LegacyCpuBinding>(
        &mut self,
        prepared: PreparedLegacyCallResume<B::Proof>,
        binding: &B,
    ) -> Result<(), LegacyCpuContinuationError<B::Error>> {
        // An ABI adapter executes outside the decoder, so its checked commit
        // needs its own boundary identity rather than pretending to execute RETF.
        let sequence = self.next_call_boundary_sequence().ok_or(
            LegacyCpuContinuationError::Cpu(CpuCallResumeError::BoundarySequenceExhausted),
        )?;
        self.commit_legacy_resume(prepared.inner, binding)?;
        self.call_boundary_sequence = sequence;
        self.control_transfer = Some(ControlTransfer::AdapterReturn);
        self.control_transfer_sequence = Some(sequence);
        Ok(())
    }

    /// Capture a parked state before leaving this legacy CPU boundary.
    pub fn capture_legacy_parked_continuation<B: LegacyCpuBinding>(
        &self,
        binding: &B,
    ) -> Result<LegacyCpuParkedContinuation<B::Proof>, LegacyCpuContinuationError<B::Error>> {
        self.check_legacy_boundary().map_err(LegacyCpuContinuationError::Cpu)?;
        let context = self.capture_context();
        validate_legacy_context(&context).map_err(LegacyCpuContinuationError::Cpu)?;
        let proof = binding.capture(&context.registers).map_err(LegacyCpuContinuationError::Binding)?;
        Ok(LegacyCpuParkedContinuation {
            inner: LegacySavedState {
                origin: Arc::clone(&self.call_continuation_origin),
                generation: self.call_continuation_generation,
                sequence: self.call_boundary_sequence,
                context,
                binding: proof,
                consumed: Arc::new(AtomicBool::new(false)),
            },
        })
    }

    /// Prepare a parked legacy transfer after other work on the same task root.
    pub fn prepare_legacy_parked_resume<B: LegacyCpuBinding>(
        &self,
        saved: &LegacyCpuParkedContinuation<B::Proof>,
        policy: CallEffectPolicy,
        target: LegacyRegisterTransfer,
        binding: &B,
    ) -> Result<PreparedLegacyParkedResume<B::Proof>, LegacyCpuContinuationError<B::Error>> {
        let prepared = self.prepare_legacy_resume(&saved.inner, policy, None, target, binding)?;
        Ok(PreparedLegacyParkedResume { inner: prepared })
    }

    /// Commit a parked legacy register transfer against its exact prepared state.
    pub fn commit_legacy_parked_resume<B: LegacyCpuBinding>(
        &mut self,
        prepared: PreparedLegacyParkedResume<B::Proof>,
        binding: &B,
    ) -> Result<(), LegacyCpuContinuationError<B::Error>> {
        self.commit_legacy_resume(prepared.inner, binding)
    }

    fn prepare_legacy_resume<B: LegacyCpuBinding>(
        &self,
        saved: &LegacySavedState<B::Proof>,
        policy: CallEffectPolicy,
        boundary: Option<CallResumeBoundary>,
        target: LegacyRegisterTransfer,
        binding: &B,
    ) -> Result<LegacyPreparedState<B::Proof>, LegacyCpuContinuationError<B::Error>> {
        self.check_legacy_ticket(saved).map_err(LegacyCpuContinuationError::Cpu)?;
        self.check_legacy_boundary().map_err(LegacyCpuContinuationError::Cpu)?;
        if boundary.is_none() && self.call_boundary_sequence < saved.sequence {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::PreparedStateChanged,
            ));
        }
        let current = self.capture_context();
        validate_legacy_context(&saved.context).map_err(LegacyCpuContinuationError::Cpu)?;
        validate_legacy_context(&current).map_err(LegacyCpuContinuationError::Cpu)?;
        check_legacy_execution_root(&saved.context, &current)
            .map_err(LegacyCpuContinuationError::Cpu)?;
        if target.registers.eflags & EFLAGS_VM != 0 {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::InvalidLegacyExecutionMode,
            ));
        }
        if target.stack_pointer == LegacyStackPointerTarget::OnePast16BitSegment
            && target.registers.sp() != 0
        {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::InvalidLegacyTransferTarget,
            ));
        }

        if let Some(boundary) = boundary {
            match boundary {
                CallResumeBoundary::NoGuestExecution => {
                    if self.call_boundary_sequence != saved.sequence {
                        return Err(LegacyCpuContinuationError::Cpu(
                            CpuCallResumeError::GuestExecutionOccurred,
                        ));
                    }
                    if !same_unexecuted_state(&saved.context, &current) {
                        return Err(LegacyCpuContinuationError::Cpu(
                            CpuCallResumeError::PreparedStateChanged,
                        ));
                    }
                }
                CallResumeBoundary::GuestCallReturn { transfer } => {
                    if !transfer.is_call_return() {
                        return Err(LegacyCpuContinuationError::Cpu(
                            CpuCallResumeError::UnsupportedGuestTransfer,
                        ));
                    }
                    if self.call_boundary_sequence <= saved.sequence
                        || self.control_transfer != Some(transfer)
                        || self.control_transfer_sequence != Some(self.call_boundary_sequence)
                    {
                        return Err(LegacyCpuContinuationError::Cpu(
                            CpuCallResumeError::GuestCallReturnNotCompleted,
                        ));
                    }
                }
            }
        }

        let observed_saved = binding.capture(&saved.context.registers)
            .map_err(LegacyCpuContinuationError::Binding)?;
        let current_binding = binding.capture(&current.registers)
            .map_err(LegacyCpuContinuationError::Binding)?;
        let target_binding = binding.capture(&target.registers)
            .map_err(LegacyCpuContinuationError::Binding)?;
        let transfer = LegacyBindingTransfer {
            current: &current_binding,
            target: &target_binding,
            current_registers: &current.registers,
            target_registers: &target.registers,
            stack_pointer: target.stack_pointer,
        };
        binding.revalidate(&saved.binding, &observed_saved, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;
        binding.revalidate(&saved.binding, &current_binding, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;
        binding.revalidate(&saved.binding, &target_binding, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;

        Ok(LegacyPreparedState {
            origin: Arc::clone(&saved.origin),
            generation: saved.generation,
            expected_sequence: self.call_boundary_sequence,
            expected_transfer_sequence: self.control_transfer_sequence,
            expected_current: current,
            saved: saved.context.clone(),
            saved_binding: saved.binding.clone(),
            expected_current_binding: current_binding,
            target_binding,
            target,
            policy,
            consumed: Arc::clone(&saved.consumed),
        })
    }

    fn commit_legacy_resume<B: LegacyCpuBinding>(
        &mut self,
        prepared: LegacyPreparedState<B::Proof>,
        binding: &B,
    ) -> Result<(), LegacyCpuContinuationError<B::Error>> {
        self.check_legacy_origin(&prepared.origin).map_err(LegacyCpuContinuationError::Cpu)?;
        self.check_legacy_generation(prepared.generation)
            .map_err(LegacyCpuContinuationError::Cpu)?;
        check_available(&prepared.consumed).map_err(LegacyCpuContinuationError::Cpu)?;
        self.check_legacy_boundary().map_err(LegacyCpuContinuationError::Cpu)?;
        if self.call_boundary_sequence != prepared.expected_sequence
            || self.control_transfer_sequence != prepared.expected_transfer_sequence
            || self.capture_context() != prepared.expected_current
        {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::PreparedStateChanged,
            ));
        }
        validate_legacy_context(&prepared.saved).map_err(LegacyCpuContinuationError::Cpu)?;
        let current_context = self.capture_context();
        validate_legacy_context(&current_context).map_err(LegacyCpuContinuationError::Cpu)?;
        check_legacy_execution_root(&prepared.saved, &current_context)
            .map_err(LegacyCpuContinuationError::Cpu)?;

        let observed_saved = binding.capture(&prepared.saved.registers)
            .map_err(LegacyCpuContinuationError::Binding)?;
        let current = binding.capture(&self.regs).map_err(LegacyCpuContinuationError::Binding)?;
        let target = binding.capture(&prepared.target.registers)
            .map_err(LegacyCpuContinuationError::Binding)?;
        if current != prepared.expected_current_binding || target != prepared.target_binding {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::PreparedStateChanged,
            ));
        }
        let transfer = LegacyBindingTransfer {
            current: &current,
            target: &target,
            current_registers: &self.regs,
            target_registers: &prepared.target.registers,
            stack_pointer: prepared.target.stack_pointer,
        };
        binding.revalidate(&prepared.saved_binding, &observed_saved, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;
        binding.revalidate(&prepared.saved_binding, &current, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;
        binding.revalidate(&prepared.saved_binding, &target, &transfer)
            .map_err(LegacyCpuContinuationError::Binding)?;

        claim_ticket(&prepared.consumed).map_err(LegacyCpuContinuationError::Cpu)?;
        self.regs = prepared.target.registers;
        if prepared.policy == CallEffectPolicy::RestoreSavedX87 {
            self.x87 = prepared.saved.x87;
        }
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(())
    }

    fn check_legacy_ticket<B>(
        &self,
        saved: &LegacySavedState<B>,
    ) -> Result<(), CpuCallResumeError> {
        self.check_legacy_origin(&saved.origin)?;
        self.check_legacy_generation(saved.generation)?;
        check_available(&saved.consumed)
    }

    fn check_legacy_origin(&self, origin: &Arc<u8>) -> Result<(), CpuCallResumeError> {
        Arc::ptr_eq(&self.call_continuation_origin, origin)
            .then_some(())
            .ok_or(CpuCallResumeError::WrongCpu)
    }

    fn check_legacy_generation(&self, generation: u64) -> Result<(), CpuCallResumeError> {
        (self.call_continuation_generation == generation)
            .then_some(())
            .ok_or(CpuCallResumeError::StaleContinuation)
    }

    fn check_legacy_boundary(&self) -> Result<(), CpuCallResumeError> {
        if self.call_boundary_sequence_exhausted {
            return Err(CpuCallResumeError::BoundarySequenceExhausted);
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
}

fn validate_legacy_context(context: &CpuContext) -> Result<(), CpuCallResumeError> {
    if context.system.architectural_context_initialized {
        return Err(CpuCallResumeError::LegacyContextAlreadyInitialized);
    }
    if context.system.cr0 & CR0_PE != 0
        || context.registers.eflags & EFLAGS_VM != 0
        || context.system.execution_mode(context.registers.eflags)
            != Some(crate::CpuExecutionMode::RealAddress)
        || context.system.cpl != 0
    {
        return Err(CpuCallResumeError::InvalidLegacyExecutionMode);
    }
    Ok(())
}

fn check_legacy_execution_root(
    saved: &CpuContext,
    current: &CpuContext,
) -> Result<(), CpuCallResumeError> {
    let a = &saved.system;
    let b = &current.system;
    if saved.model != current.model
        || a.architectural_context_initialized
        || b.architectural_context_initialized
        || a.execution_mode(saved.registers.eflags)
            != b.execution_mode(current.registers.eflags)
        || a.cr0 != b.cr0
        || a.cr3 != b.cr3
        || a.cpl != b.cpl
        || a.gdtr != b.gdtr
        || a.idtr != b.idtr
        || a.ldtr != b.ldtr
        || a.task != b.task
    {
        return Err(CpuCallResumeError::ExecutionRootChanged);
    }
    Ok(())
}

fn same_unexecuted_state(saved: &CpuContext, current: &CpuContext) -> bool {
    saved == current
}

fn check_available(consumed: &AtomicBool) -> Result<(), CpuCallResumeError> {
    (!consumed.load(Ordering::Acquire))
        .then_some(())
        .ok_or(CpuCallResumeError::TicketConsumed)
}

fn claim_ticket(consumed: &AtomicBool) -> Result<(), CpuCallResumeError> {
    consumed.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| CpuCallResumeError::TicketConsumed)
}
