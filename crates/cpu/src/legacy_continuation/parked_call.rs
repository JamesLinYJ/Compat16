//! Resume scheduler work and rearm its enclosing ABI call as one checked
//! operation. Ordinary call tickets still reject intervening guest execution.
use super::*;

/// A parked resume paired with the exact still-owned enclosing call. Both
/// tickets are consumed at commit, and a fresh call ticket describes only the
/// post-resume boundary. No return instruction or adapter event is invented.
pub struct PreparedLegacyParkedCallResume<ParkedProof, CallProof> {
    parked: LegacyPreparedState<ParkedProof>,
    caller: LegacyPreparedState<CallProof>,
    rearmed: LegacyCpuCallContinuation<CallProof>,
}

impl Cpu {
    /// The parked and call register images must be the same original caller.
    /// Each binding validates its own retained roots and growth history; a
    /// scheduler proof cannot substitute for the enclosing caller's leases.
    pub fn prepare_legacy_parked_resume_and_rearm_call<P, C>(
        &self,
        parked: &LegacyCpuParkedContinuation<P::Proof>,
        caller: &LegacyCpuCallContinuation<C::Proof>,
        policy: CallEffectPolicy,
        parked_binding: &P,
        caller_binding: &C,
    ) -> Result<
        PreparedLegacyParkedCallResume<P::Proof, C::Proof>,
        LegacyCpuContinuationError<P::Error>,
    >
    where
        P: LegacyCpuBinding,
        C: LegacyCpuBinding<Error = P::Error>,
    {
        self.check_legacy_ticket(&parked.inner)
            .map_err(LegacyCpuContinuationError::Cpu)?;
        self.check_legacy_ticket(&caller.inner)
            .map_err(LegacyCpuContinuationError::Cpu)?;
        if parked.inner.sequence < caller.inner.sequence
            || parked.inner.context.registers != caller.inner.context.registers
        {
            return Err(LegacyCpuContinuationError::Cpu(
                CpuCallResumeError::InvalidLegacyTransferTarget,
            ));
        }
        let target = LegacyRegisterTransfer {
            registers: parked.inner.context.registers.clone(),
            stack_pointer: LegacyStackPointerTarget::RegisterValue,
        };
        let parked = self.prepare_legacy_resume(
            &parked.inner,
            policy,
            None,
            target.clone(),
            parked_binding,
        )?;
        let caller =
            self.prepare_legacy_resume(&caller.inner, policy, None, target, caller_binding)?;
        let mut context = parked.expected_current.clone();
        context.registers = parked.target.registers.clone();
        if policy == CallEffectPolicy::RestoreSavedX87 {
            context.x87 = parked.saved.x87.clone();
        }
        context.control_transfer = None;
        let rearmed = LegacyCpuCallContinuation {
            inner: LegacySavedState {
                origin: Arc::clone(&caller.origin),
                generation: caller.generation,
                sequence: parked.expected_sequence,
                context,
                binding: caller.target_binding.clone(),
                consumed: Arc::new(AtomicBool::new(false)),
            },
        };
        Ok(PreparedLegacyParkedCallResume {
            parked,
            caller,
            rearmed,
        })
    }

    /// Revalidate both owners before either ticket or the CPU can change.
    /// Pending CPU events remain live; only registers and the selected x87
    /// policy transfer. Full context restores still revoke this preparation.
    pub fn commit_legacy_parked_resume_and_rearm_call<P, C>(
        &mut self,
        prepared: PreparedLegacyParkedCallResume<P::Proof, C::Proof>,
        parked_binding: &P,
        caller_binding: &C,
    ) -> Result<LegacyCpuCallContinuation<C::Proof>, LegacyCpuContinuationError<P::Error>>
    where
        P: LegacyCpuBinding,
        C: LegacyCpuBinding<Error = P::Error>,
    {
        self.validate_prepared_legacy_resume(&prepared.parked, parked_binding)?;
        self.validate_prepared_legacy_resume(&prepared.caller, caller_binding)?;
        // Tickets expose no consumption flag, and consuming methods require
        // the same origin-bound Cpu mutably. This exclusive borrow makes both
        // stores and the register transfer infallible after the two checks.
        prepared.parked.consumed.store(true, Ordering::Release);
        prepared.caller.consumed.store(true, Ordering::Release);
        self.apply_legacy_resume(prepared.parked);
        Ok(prepared.rearmed)
    }
}
