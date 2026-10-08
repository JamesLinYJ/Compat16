//! DDE teardown after callback producers and in-flight owners quiesce.

use guest_core::memory::Memory;

use super::win16_dde_callback::{combine_dde_errors, invariant};
use super::{CallbackKind, Win16State};
use super::windows::WindowReturn;
use crate::{RuntimeError, RuntimeHost};

impl Win16State {
    /// Ask the native DDE owner to stop and retain its real receipt before
    /// task cleanup starts retiring guest callback frames. This deliberately
    /// leaves every runtime DDE frame, operation, and allocation in place.
    pub(in crate::win16_runtime) fn quiesce_dde_callback_owners(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let receipt = match self.dde_abort_receipt.as_ref() {
            Some(receipt) if receipt.is_quiesced() => receipt.clone(),
            _ => host.win16_dde_abort(),
        };
        let has_runtime_native_owner = !self.dde.guest_instances().is_empty()
            || self.dde.has_callback_owners()
            || !self.dde_callbacks.is_empty()
            || !self.dde_guest_contexts.is_empty()
            || !self.dde_context_restores.is_empty()
            || self.window_operations.iter().any(|frame| {
                frame.pending_dde_callback.is_some()
                    || matches!(frame.result.as_ref(), Some(WindowReturn::Dde(continuation))
                        if continuation.host_operation().is_some())
            });
        self.dde_abort_receipt = Some(receipt.clone());
        if receipt.owner.is_none() && receipt.is_quiesced() && has_runtime_native_owner {
            return Err(invariant(
                "native DDE owner reported NotStarted while runtime retains exact DDE native identities",
            ));
        }
        if receipt.is_quiesced() {
            Ok(())
        } else {
            Err(receipt.as_error())
        }
    }

    /// Retire DDE storage only after the callback-family unwind consumed exact
    /// native callback receipts and restored every saved guest context.
    pub(in crate::win16_runtime) fn close_dde(
        &mut self,
        _memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.quiesce_dde_callback_owners(host)?;
        if !self.dde_callbacks.is_empty()
            || self.callback_kinds.contains(&CallbackKind::Dde)
            || self.callback_kinds.len() != self.callback_frame_ids.len()
            || !self.dde_guest_contexts.is_empty()
            || !self.dde_context_restores.is_empty()
            || self.dde.pending_data_transfer_guard_count() != 0
            || self.window_operations.iter().any(|frame| {
                matches!(&frame.result, Some(WindowReturn::Dde(_)))
                    || frame.pending_dde_callback.is_some()
            })
        {
            return Err(invariant(
                "DDE storage cannot close while callback frames, DDE operation frames, or data-transfer guards remain",
            ));
        }
        let receipt = self.dde_abort_receipt.as_ref().filter(|receipt| receipt.is_quiesced())
            .cloned().ok_or_else(|| invariant(
                "DDE owner quiescence receipt disappeared before storage retirement",
            ))?;
        for guest_instance in self.dde.guest_instances() {
            let instance = self.dde.host_instance(guest_instance).ok_or_else(|| {
                invariant("DDE guest instance lost its exact native owner identity")
            })?;
            let mut proofs = receipt
                .native_instances
                .iter()
                .filter(|proof| proof.instance == instance);
            let proof = proofs.next().ok_or_else(|| {
                invariant("DDE abort receipt omitted a live guest instance's native retirement")
            })?;
            if proofs.next().is_some()
                || !matches!(
                    proof.status,
                    crate::Win16DdeCleanupStatus::Released
                        | crate::Win16DdeCleanupStatus::RetriedAndReleased
                )
            {
                return Err(invariant(
                    "DDE abort receipt did not uniquely release the guest instance's exact native owner",
                ));
            }
        }
        self.dde_retired_callback_tokens
            .try_reserve(self.dde.callback_retirement_count_bound())
            .map_err(|error| RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve DDE callback-token retirement before draining guest owners",
                error,
            ))?;
        self.reserve_dde_guest_block_retirements(self.dde.access_block_count())?;

        let mut cleanup_error = None;
        let mut remember = |result: Result<(), RuntimeError>| {
            if let Err(error) = result {
                cleanup_error = Some(match cleanup_error.take() {
                    Some(first) => combine_dde_errors(
                        first,
                        error,
                        "multiple Win16 DDE teardown cleanups failed",
                    ),
                    None => error,
                });
            }
        };
        self.dde.cancel_pending_initializations();
        for instance in self.dde.guest_instances() {
            if let Some((_, blocks)) = self.dde.remove_instance(instance) {
                remember(self.queue_removed_dde_guest_blocks(blocks));
            }
        }
        for token in self.dde.drain_callback_routes() {
            let token = crate::Win16GuestCallbackToken(token);
            if !self.dde_retired_callback_tokens.contains(&token) {
                self.dde_retired_callback_tokens.push(token);
            }
        }
        remember(self.unregister_retired_dde_callbacks());
        remember(self.drain_dde_guest_block_retirements());
        drop(remember);
        if let Some(error) = cleanup_error {
            return Err(error);
        }
        if self.dde.has_callback_owners()
            || !self.dde_retired_callback_tokens.is_empty()
            || !self.dde_retired_guest_blocks.is_empty()
        {
            return Err(invariant(
                "DDE runtime owner ledger remains after its exact native shutdown receipt",
            ));
        }
        let callback_owner = receipt.owner.ok_or_else(|| {
            invariant("DDE callback cleanup receipt omitted its native owner identity")
        })?;
        let worker_generation = receipt.worker_generation.ok_or_else(|| {
            invariant("DDE callback cleanup receipt omitted its worker generation")
        })?;
        for callback in &receipt.cancelled_callbacks {
            if callback.status != crate::Win16DdeCallbackCancellationStatus::FrameAcknowledged
                || !matches!(
                    callback.source,
                    crate::Win16DdeCancellationSource::GuestReply
                        | crate::Win16DdeCancellationSource::OwnerShutdown
                )
            {
                return Err(invariant(
                    "DDE close lacks exact native callback acknowledgement evidence",
                ));
            }
            let instance = callback.instance.ok_or_else(|| {
                invariant("DDE close receipt omitted a callback's exact host instance")
            })?;
            if host.win16_dde_callback_retirement_is_pending(
                callback.frame,
                callback.parent_operation,
                instance,
                callback_owner,
                worker_generation,
            )? {
                host.win16_dde_callback_retired(
                    callback.frame,
                    callback.parent_operation,
                    instance,
                    callback_owner,
                    worker_generation,
                )?;
            }
        }
        host.win16_dde_runtime_resources_retired(&receipt)?;
        Ok(())
    }
}
