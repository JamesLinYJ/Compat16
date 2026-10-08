//! Win16State COM safe-point and guest-call continuation adapters.

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ComHostCallbackRoute,
    Win16ComHostOwnerIdentity, Win16ComHostShutdownOperation, Win16ComHostShutdownReceipt,
    Win16ComHostShutdownStep,
    Win16ComHostRequest, Win16ComHostResume, Win16ComHostStep,
};
use win16_abi::Win16ReturnKind;
use super::Win16State;

#[path = "win16_com_operation_table.rs"]
mod table;
#[path = "win16_com_terminal_owner_validation.rs"]
mod terminal_owner_validation;
use terminal_owner_validation::validate_com_result_owner;
use table::{PhaseSummary, StepRecord};
pub(in crate::win16_runtime) use table::{
    GuestContinuation, Progress, SafePointResult, StepDisposition, Win16ComGuestOperationId,
    Win16ComOperationOrigin, Win16ComOperationTable,
};

impl Win16State {
    /// Capture the exact guest call and selector roots before publishing the
    /// host operation. The caller must not start host work until this succeeds.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_com_guest_operation(
        &mut self,
        cpu: &x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut guest_core::memory::Memory,
        owner: Win16ComHostOwnerIdentity,
        callback_route: Win16ComHostCallbackRoute,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        origin: Win16ComOperationOrigin,
        request: Win16ComHostRequest,
    ) -> Result<Win16ComGuestOperationId, RuntimeError> {
        let guest_owner = self.current_task_owner()?;
        let id = self.com_operations.reserve_id(owner)?;
        let saved_registers = cpu.regs.clone();
        let saved_context = cpu.capture_context();
        let legacy_cpu_frame = match self.capture_legacy_cpu_call_frame(cpu, dos, memory) {
            Ok(frame) => frame,
            Err(primary) => {
                return match self.com_operations.cancel_reservation(id) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(primary.with_cleanup(
                        "canceling COM operation reservation after CPU-frame capture failed",
                        cleanup,
                    )),
                };
            }
        };
        if let Err(primary) = self.com_operations.insert(
            id,
            owner,
            guest_owner,
            legacy_cpu_frame,
            saved_context,
            saved_registers,
            return_to,
            return_kind,
            callback_route,
            origin,
            request,
        ) {
            let mut failure = primary;
            if let Err(cleanup) = self.release_legacy_cpu_frame(legacy_cpu_frame, dos, memory) {
                failure = failure.with_cleanup(
                    "releasing exact guest CPU roots after COM operation registration failed",
                    cleanup,
                );
            }
            if let Err(cleanup) = self.com_operations.cancel_reservation(id) {
                failure = failure.with_cleanup(
                    "canceling COM operation reservation after registration failed",
                    cleanup,
                );
            }
            return Err(failure);
        }
        Ok(id)
    }

    /// Safe-point draft: submit a prepared request once, or poll the exact
    /// owning STA operation. A returned callback is retained by the operation
    /// journal; an unrelated asynchronous callback is returned intact to the
    /// shared callback router. No step here is translated into guest success.
    pub(super) fn advance_com_guest_operation<'a>(
        &'a mut self,
        id: Win16ComGuestOperationId,
        host: &mut impl RuntimeHost,
    ) -> Result<SafePointResult<'a>, RuntimeError> {
        match self.com_operations.phase_summary(id)? {
            PhaseSummary::Prepared => {
                let owner = self.com_operations.owner(id)?;
                let start = self.com_operations.take_start(id)?;
                match host.win16_com_begin(owner, start) {
                    Ok(step) => {
                        match self
                            .com_operations
                            .record_step_or_forward(id, owner, step)?
                        {
                            StepRecord::Stored(_) => {}
                            StepRecord::Unowned(step) => {
                                self.com_operations.mark_running_after_unowned_step(id)?;
                                return Ok(SafePointResult::UnownedStep(step));
                            }
                        }
                    }
                    Err(failure) => self.com_operations.record_start_failure(id, failure)?,
                }
            }
            PhaseSummary::Starting => {}
            PhaseSummary::Running(owner) => {
                if let Some(step) = host.win16_com_poll_callback(owner)? {
                    match self
                        .com_operations
                        .record_step_or_forward(id, owner, step)?
                    {
                        StepRecord::Stored(_) => {}
                        StepRecord::Unowned(step) => {
                            return Ok(SafePointResult::UnownedStep(step));
                        }
                    }
                    return Ok(SafePointResult::Progress(self.com_operations.progress(id)?));
                }
                if let Some(step) = host.win16_com_poll_terminal(owner, id.host)? {
                    match self
                        .com_operations
                        .record_step_or_forward(id, owner, step)?
                    {
                        StepRecord::Stored(_) => {}
                        StepRecord::Unowned(step) => {
                            return Ok(SafePointResult::UnownedStep(step));
                        }
                    }
                }
            }
            PhaseSummary::CallbackPending
            | PhaseSummary::CallbackResuming
            | PhaseSummary::CallbackFailed
            | PhaseSummary::StartFailed
            | PhaseSummary::Terminal
            | PhaseSummary::GuestReturned => {}
        }
        Ok(SafePointResult::Progress(self.com_operations.progress(id)?))
    }

    /// Resume one checked guest callback on its exact host operation. The STA
    /// may consume a reply before its transport call reports failure, so a
    /// failed continuation is retained as uncertain and must never be resent.
    pub(super) fn resume_com_guest_callback(
        &mut self,
        id: Win16ComGuestOperationId,
        resume: Win16ComHostResume,
        host: &mut impl RuntimeHost,
    ) -> Result<table::StepDisposition, RuntimeError> {
        self.com_operations.prepare_callback_resume(id, &resume)?;
        let owner = self.com_operations.owner(id)?;
        let continuation = crate::Win16ComHostContinue {
            operation: Some(id.host),
            resume: Some(resume),
        };
        let step = host.win16_com_continue(owner, continuation)?;
        match self
            .com_operations
            .record_step_or_forward(id, owner, step)?
        {
            StepRecord::Stored(disposition) => Ok(disposition),
            StepRecord::Unowned(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM callback resume returned a step owned by another operation",
            )),
        }
    }

    pub(super) fn com_guest_continuation(
        &self,
        id: Win16ComGuestOperationId,
    ) -> Result<GuestContinuation<'_>, RuntimeError> {
        self.com_operations.continuation(id)
    }

    /// Validate every exact caller label before OLE1 consumes a saved COM
    /// continuation. The parked architecture snapshot is compared to the
    /// same retained legacy frame, never to the currently running CPU.
    pub(super) fn checked_ole1_com_continuation(
        &self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        callback_route: Win16ComHostCallbackRoute,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        origin: Win16ComOperationOrigin,
    ) -> Result<GuestContinuation<'_>, RuntimeError> {
        let continuation = self.com_guest_continuation(id)?;
        let current_guest_owner = self.current_task_owner()?;
        if continuation.guest_owner != current_guest_owner
            || continuation.callback_route != callback_route
            || continuation.origin != origin
            || continuation.return_to != return_to
            || continuation.return_kind != return_kind
        {
            return Err(invariant(
                "OLE1 COM continuation differs from its exact task, route, origin, or caller frame",
            ));
        }
        if !self.legacy_cpu_frame_matches_context(
            continuation.legacy_cpu_frame,
            continuation.saved_context,
        ) {
            return Err(invariant(
                "OLE1 COM continuation architecture snapshot differs from its retained legacy frame",
            ));
        }
        if self.com_operations.owner(id)? != owner {
            return Err(invariant(
                "OLE1 COM continuation belongs to another native owner incarnation",
            ));
        }
        Ok(continuation)
    }

    pub(super) fn com_guest_operation_for_host(
        &self,
        host: crate::Win16ComHostOperationIdentity,
    ) -> Result<Option<Win16ComGuestOperationId>, RuntimeError> {
        self.com_operations.guest_operation_for_host(host)
    }

    pub(super) fn mark_com_guest_returned(
        &mut self,
        id: Win16ComGuestOperationId,
    ) -> Result<(), RuntimeError> {
        self.com_operations.mark_guest_returned(id)
    }

    /// Acknowledge the native terminal only after the dispatcher has converted
    /// its typed result and reconciled every returned COM/storage token. The
    /// operation table retains the exact result if host acknowledgement fails.
    pub(super) fn acknowledge_com_guest_terminal(
        &mut self,
        id: Win16ComGuestOperationId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let (owner, operation) = self.com_operations.terminal_ack_target(id)?;
        host.win16_com_acknowledge_terminal(owner, operation)?;
        self.com_operations.mark_terminal_acknowledged(id)
    }

    pub(super) fn pending_com_guest_operations_for_owner(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> usize {
        self.com_operations.pending_for_owner(owner)
    }

    pub(super) fn retire_returned_com_guest_call(
        &mut self,
        id: Win16ComGuestOperationId,
        legacy_cpu_frame: u64,
    ) -> Result<(), RuntimeError> {
        self.com_operations
            .retire_guest_returned(id, legacy_cpu_frame)
    }

    pub(super) fn retire_acknowledged_com_guest_step(
        &mut self,
        id: Win16ComGuestOperationId,
        legacy_cpu_frame: u64,
    ) -> Result<(), RuntimeError> {
        self.com_operations
            .retire_acknowledged_step(id, legacy_cpu_frame)
    }

    pub(super) fn record_sealed_com_callback_failure(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<(), RuntimeError> {
        let Win16ComHostStep::CallbackFailed {
            parent: Some(parent),
            ..
        } = &step
        else {
            return Err(invariant(
                "sealed COM callback failure has no exact parent operation",
            ));
        };
        let Some(id) = self.com_operations.guest_operation_for_host(*parent)? else {
            return if self.sealed_com_callback_has_guest_frame(&step) {
                Err(invariant("sealed COM callback parent is absent while its exact guest frame is live"))
            } else {
                // An unentered native callback may outlive its already-retired
                // parent operation. The complete returned receipt remains in
                // the owner journal until native object retirement is proven.
                Ok(())
            };
        };
        if self.com_operations.owner(id)? != owner {
            return Err(invariant(
                "sealed COM callback parent belongs to another owner incarnation",
            ));
        }
        if matches!(self.com_operations.phase_summary(id)?, PhaseSummary::Terminal | PhaseSummary::GuestReturned) {
            return Ok(());
        }
        self.com_operations
            .record_sealed_callback_failure(id, owner, step)?;
        Ok(())
    }

    /// Permanently close every exact COM owner known to this runtime before
    /// USER Abort. The host failure reply is what lets a nested native COM
    /// callback return; its terminal and ACK remain separately journaled.
    pub(super) fn seal_com_owners_for_teardown(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owners = self.com_operations.owners_for_shutdown()?;
        for owner in owners {
            self.com_operations.prepare_owner_seal(owner)?;
            match host.win16_com_shutdown(owner, Win16ComHostShutdownOperation::Seal)? {
                Win16ComHostShutdownStep::Sealed { owner: sealed } if sealed == owner => {
                    self.com_operations.mark_owner_sealed(owner)?;
                }
                Win16ComHostShutdownStep::Retired(receipt) if receipt.owner == owner => {
                    // This can only be a retry after a completed earlier Poll.
                    self.com_operations.prepare_owner_poll(owner)?;
                    self.com_operations.remember_owner_receipt(receipt)?;
                }
                Win16ComHostShutdownStep::Pending { owner: pending } if pending == owner => {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "COM host returned Pending for an exact-owner Seal",
                    ));
                }
                _ => {
                    return Err(invariant(
                        "COM host Seal reply differs from the exact owner incarnation",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Drain the owner's already-sealed cancellation receipts, reconcile all
    /// exact native terminals, then request the destructive owner-table
    /// retirement. `Pending` is a retained retry state, never completion.
    pub(super) fn finish_com_owners_for_teardown(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owners = self.com_operations.owners_for_shutdown()?;
        for owner in owners {
            if let Some(receipt) = self.com_operations.owner_receipt(owner)? {
                self.com_operations.retire_owner_entries_after_receipt(receipt)?;
                self.finish_com_owner_after_receipt(receipt)?;
                continue;
            }
            if !self.com_operations.owner_is_sealed(owner)? {
                return Err(invariant(
                    "COM owner Poll reached teardown before its exact Seal acknowledgement",
                ));
            }
            self.drain_sealed_com_callback_cancellations(owner, host)?;
            self.reconcile_com_owner_terminals(owner, host)?;

            let pending = self.ole1_client_owner_pending(owner).ok_or_else(|| {
                invariant("sealed COM owner has no exact OLE1 client inventory")
            })?;
            if pending.pending_com_callback_resumes != 0
                || pending.active_com_callback_frames != 0
            {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "COM owner still has an exact guest callback frame or uncertain callback reply",
                ));
            }
            if self
                .ole1_client_documents
                .sealed_com_callback_receipts
                .iter()
                .any(|step| callback_step_owner(step) == Some(owner)
                    && self.sealed_com_callback_has_guest_frame(step))
            {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "COM owner still has a sealed callback cancellation not consumed by its exact LIFO frame",
                ));
            }

            self.com_operations.prepare_owner_poll(owner)?;
            let mut step = host.win16_com_shutdown(owner, Win16ComHostShutdownOperation::Poll)?;
            if matches!(step, Win16ComHostShutdownStep::Pending { owner: pending } if pending == owner) {
                // Releasing native owner objects may itself invoke a closed
                // callback proxy. Drain those returned, parentless failures
                // once before retrying the same Poll; persistent native or
                // transport uncertainty remains a retained failure below.
                self.drain_sealed_com_callback_cancellations(owner, host)?;
                step = host.win16_com_shutdown(owner, Win16ComHostShutdownOperation::Poll)?;
            }
            let receipt = match step {
                Win16ComHostShutdownStep::Retired(receipt) if receipt.owner == owner => receipt,
                Win16ComHostShutdownStep::Pending { owner: pending } if pending == owner => {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "COM owner shutdown remains pending native return, terminal ACK, or callback retirement",
                    ));
                }
                _ => {
                    return Err(invariant(
                        "COM host Poll reply differs from the exact owner incarnation",
                    ));
                }
            };
            self.com_operations.remember_owner_receipt(receipt)?;
            self.com_operations.retire_owner_entries_after_receipt(receipt)?;
            self.finish_com_owner_after_receipt(receipt)?;
        }
        Ok(())
    }

    fn drain_sealed_com_callback_cancellations(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        loop {
            // Reserve before polling because the host poll consumes its exact
            // receipt. Keeping the complete step here is the runtime-side ACK
            // journal for parentless callbacks and a cross-check for parented ones.
            self.ole1_client_documents
                .sealed_com_callback_receipts
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve exact sealed COM callback receipt",
                        error,
                    )
                })?;
            let Some(step) = host.win16_com_poll_callback(owner)? else {
                return Ok(());
            };
            if callback_step_owner(&step) != Some(owner) {
                self.ole1_client_documents
                    .sealed_com_callback_receipts
                    .push(step);
                return Err(invariant(
                    "sealed COM callback poll returned another owner incarnation",
                ));
            }
            let Win16ComHostStep::CallbackFailed { frame, parent, failure, .. } = &step else {
                self.ole1_client_documents
                    .sealed_com_callback_receipts
                    .push(step);
                return Err(invariant(
                    "sealed COM callback poll returned a non-failure step",
                ));
            };
            match frame {
                Some(_) if matches!(
                    failure.kind,
                    crate::Win16ComHostCallbackFailureKind::CheckedGuestCallback
                        | crate::Win16ComHostCallbackFailureKind::CallbackTransport
                ) => {}
                None if parent.is_none() => {
                    // Closed-ingress callbacks that occur while owner resources
                    // are released have no guest frame; retain their exact
                    // owner/route failure until the native stack is quiet.
                }
                _ => {
                    self.ole1_client_documents
                        .sealed_com_callback_receipts
                        .push(step);
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "sealed COM callback failure has no exact teardown-owned frame or parentless owner receipt",
                    ));
                }
            }
            self.ole1_client_documents
                .sealed_com_callback_receipts
                .push(step.clone());
            if matches!(step, Win16ComHostStep::CallbackFailed { parent: Some(_), .. }) {
                self.record_sealed_com_callback_failure(owner, step)?;
            }
        }
    }

    pub(super) fn consume_sealed_com_callback_for_teardown(
        &mut self,
        expected: super::ole1::Win16Ole1ComCallbackIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !self.com_operations.owner_is_sealed(expected.owner)? {
            return Err(invariant(
                "OLE1 callback teardown has no exact COM owner Seal",
            ));
        }
        self.drain_sealed_com_callback_cancellations(expected.owner, host)?;
        let receipts = &self.ole1_client_documents.sealed_com_callback_receipts;
        let mut matching_index = None;
        for (index, step) in receipts.iter().enumerate() {
            if sealed_callback_receipt_matches(step, expected) {
                if matching_index.replace(index).is_some() {
                    return Err(invariant(
                        "sealed COM callback cancellation receipt is duplicated",
                    ));
                }
            }
        }
        let Some(matching_index) = matching_index else {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "OLE1 COM guest callback has not received its exact sealed native failure receipt",
            ));
        };
        let step = receipts[matching_index].clone();
        let Win16ComHostStep::CallbackFailed { failure, .. } = &step else {
            return Err(invariant("sealed COM callback receipt changed kind"));
        };
        if !matches!(
            failure.kind,
            crate::Win16ComHostCallbackFailureKind::CheckedGuestCallback
                | crate::Win16ComHostCallbackFailureKind::CallbackTransport
        ) {
            return Err(invariant(
                "OLE1 guest callback cancellation is not a checked callback or transport failure",
            ));
        }
        if expected.parent.is_some() {
            self.record_sealed_com_callback_failure(expected.owner, step)?;
        }
        let mut matching_resumes = self.ole1_com_callback_resumes.iter().filter(|resume| {
            resume.owner == expected.owner && resume.frame == expected.frame
        });
        let matching_resume = matching_resumes.next();
        if matching_resumes.next().is_some()
            || matching_resume.is_some_and(|resume| resume.parent != expected.parent)
        {
            return Err(invariant("sealed COM callback differs from its exact retained guest reply"));
        }
        self.ole1_com_callback_resumes.retain(|resume| {
            resume.owner != expected.owner || resume.frame != expected.frame
        });
        self.ole1_com_callback_resume_failures.retain(|(owner, frame)| {
            *owner != expected.owner || *frame != expected.frame
        });
        self.ole1_client_documents
            .sealed_com_callback_receipts
            .remove(matching_index);
        Ok(())
    }

    fn sealed_com_callback_has_guest_frame(&self, step: &Win16ComHostStep) -> bool {
        self.ole1_callbacks.iter().any(|frame| {
            frame.com_identity().is_some_and(|callback| sealed_callback_receipt_matches(step, callback))
        })
    }

    fn reconcile_com_owner_terminals(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let operations = self.com_operations.operations_for_owner(owner)?;
        for id in operations {
            let phase = self.com_operations.phase_summary(id)?;
            match phase {
                PhaseSummary::Prepared | PhaseSummary::GuestReturned => {}
                PhaseSummary::StartFailed | PhaseSummary::Running(_) => {
                    if let Some(step) = host.win16_com_poll_terminal(owner, id.host)? {
                        self.record_shutdown_terminal(id, owner, step)?;
                    }
                }
                PhaseSummary::CallbackFailed => {
                    if let Some(step) = host.win16_com_poll_terminal(owner, id.host)? {
                        self.record_shutdown_terminal(id, owner, step)?;
                    }
                }
                PhaseSummary::Terminal => {}
                PhaseSummary::Starting
                | PhaseSummary::CallbackPending
                | PhaseSummary::CallbackResuming => {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "COM operation still has an unretired callback or native-call phase during teardown",
                    ));
                }
            }
            if matches!(self.com_operations.phase_summary(id)?, PhaseSummary::Terminal) {
                if !self.com_operations.terminal_acknowledged(id)? {
                    self.validate_com_terminal_owner(id, owner)?;
                    self.acknowledge_com_guest_terminal(id, host)?;
                }
            }
        }
        Ok(())
    }

    fn record_shutdown_terminal(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<(), RuntimeError> {
        if self.com_operations.owner(id)? != owner {
            return Err(invariant(
                "COM shutdown terminal belongs to another exact owner",
            ));
        }
        if matches!(self.com_operations.phase_summary(id)?, PhaseSummary::StartFailed) {
            return self
                .com_operations
                .record_terminal_after_start_failure(id, owner, step);
        }
        match self.com_operations.record_step(id, owner, step)? {
            StepDisposition::Terminal => Ok(()),
            _ => Err(invariant(
                "COM shutdown poll did not return the exact operation terminal",
            )),
        }
    }

    fn validate_com_terminal_owner(
        &self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        let progress = self.com_operations.progress(id)?;
        let step = match progress {
            Progress::Terminal { step } => step,
            _ => return Err(invariant("COM terminal owner validation has no retained terminal")),
        };
        match step {
            Win16ComHostStep::Complete(completion) if completion.operation == id.host => {
                validate_com_result_owner(owner, &completion.result)
            }
            Win16ComHostStep::OperationFailed {
                operation,
                result,
                ..
            } if *operation == id.host => {
                if let Some(result) = result {
                    validate_com_result_owner(owner, result)?;
                }
                Ok(())
            }
            _ => Err(invariant(
                "COM terminal result does not match the exact operation identity",
            )),
        }
    }

    fn finish_com_owner_after_receipt(
        &mut self,
        receipt: Win16ComHostShutdownReceipt,
    ) -> Result<(), RuntimeError> {
        if self.com_operations.owner_receipt(receipt.owner)? != Some(receipt) {
            return Err(invariant(
                "COM guest retirement lacks the cached exact-owner shutdown receipt",
            ));
        }
        self.retire_native_com_owner_proxy_state(receipt)?;
        self.ole1_client_documents
            .sealed_com_callback_receipts
            .retain(|step| callback_step_owner(step) != Some(receipt.owner));
        // The native object table and its owned references are already gone;
        // physical guest frees are retried only after selector aliases and the
        // global legacy CPU frames release their pins.
        Ok(())
    }

    pub(super) fn com_owner_guest_state_retired(&self) -> bool {
        if !self.com_operations.owner_shutdown_complete() {
            return false;
        }
        let Ok(owners) = self.com_operations.owners_for_shutdown() else {
            return false;
        };
        let all_guest_state_detached = owners.iter().copied().all(|owner| {
            self.com_operations.owner_receipt(owner).ok().flatten().is_some()
                && self.ole1_client_owner_pending(owner).is_some_and(|pending| {
                    pending.pending_com_operations == 0
                        && pending.pending_com_callback_resumes == 0
                        && pending.sealed_com_callback_receipts == 0
                        && pending.pending_creation_sequences == 0
                        && pending.pending_object_method_sequences == 0
                        && pending.native_object_proxies == 0
                        && pending.active_com_callback_frames == 0
                })
        });
        all_guest_state_detached
            && self
                .ole1_client_documents
                .pending_native_object_proxy_retirements
                .iter()
                .all(|retirement| {
                    owners.contains(&retirement.owner)
                        && self
                            .com_operations
                            .owner_receipt(retirement.owner)
                            .ok()
                            .flatten()
                            .is_some()
                })
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn exhausted(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, message)
}

fn callback_step_owner(step: &Win16ComHostStep) -> Option<Win16ComHostOwnerIdentity> {
    match step {
        Win16ComHostStep::Callback(callback) => Some(callback.owner),
        Win16ComHostStep::CallbackFrameComplete { owner, .. }
        | Win16ComHostStep::CallbackFailed { owner, .. } => Some(*owner),
        Win16ComHostStep::Running(_)
        | Win16ComHostStep::Complete(_)
        | Win16ComHostStep::OperationFailed { .. } => None,
    }
}

fn sealed_callback_receipt_matches(
    step: &Win16ComHostStep,
    expected: super::ole1::Win16Ole1ComCallbackIdentity,
) -> bool {
    matches!(
        step,
        Win16ComHostStep::CallbackFailed {
            frame: Some(frame),
            parent,
            owner,
            route,
            ..
        } if *frame == expected.frame
            && *parent == expected.parent
            && *owner == expected.owner
            && *route == expected.route
    )
}
