//! Exact callback publication, acknowledgement, and terminal DDE retirement.

use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeAbortReceipt,
    Win16DdeOperationCancellationStatus, Win16DdeOperationRetirementProof,
    Win16HostDdeCallbackFrame, Win16HostDdeCallbackStep, Win16HostDdeInstance,
    Win16HostDdeOperation, Win16HostDdeOwner, Win16DdeSourceRetiredProof,
};

use super::{
    DdeSourceLedger, PendingDdeCallbackSource, PendingSource,
    RetiredDdeOperationSource, Win16Windows,
};

impl Win16Windows {
    pub(in crate::windows) fn dde_callback_retirement_is_pending(
        &self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        instance: Win16HostDdeInstance,
        owner: Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<bool, RuntimeError> {
        let Some(dde) = self.dde.as_ref() else {
            return Err(self.dde_start_failure());
        };
        dde.callback_retirement_is_pending(
            frame, parent, instance, owner, worker_generation,
        )
    }

    pub(super) fn reserve_dde_callback_source_capacity(&mut self) -> Result<(), RuntimeError> {
        self.dde_sources.callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact DDE callback source before consuming its native step", error)
        })
    }

    fn dde_callback_index(&self, frame: Win16HostDdeCallbackFrame) -> Option<usize> {
        self.dde_sources.callbacks.iter().position(|source| source.step.frame == frame)
    }

    fn dde_callback_source(
        &self,
        frame: Win16HostDdeCallbackFrame,
    ) -> Option<&PendingDdeCallbackSource> {
        self.dde_sources.callbacks.iter().find(|source| source.step.frame == frame)
    }

    pub(super) fn unpublished_dde_callback(
        &self,
        parent: Option<Win16HostDdeOperation>,
    ) -> Result<Option<Arc<Win16HostDdeCallbackStep>>, RuntimeError> {
        let mut matching = self.dde_sources.callbacks.iter().filter(|source| {
            !source.runtime_published && source.step.parent == parent
        });
        let Some(source) = matching.next() else { return Ok(None) };
        if matching.next().is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source ledger has multiple unpublished callbacks for one parent"));
        }
        Ok(Some(Arc::clone(&source.step)))
    }

    pub(super) fn dde_callback_has_parent(
        &self,
        operation: Win16HostDdeOperation,
    ) -> bool {
        self.dde_sources.callbacks.iter().any(|source| {
            source.step.parent == Some(operation)
        })
    }

    pub(super) fn remember_dde_callback(
        &mut self,
        callback: Arc<Win16HostDdeCallbackStep>,
    ) -> Result<(), RuntimeError> {
        if !callback.has_valid_identity() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback source has an invalid owner, generation, parent, or frame"));
        }
        if !self.dde_host_mut()?.callback_source_matches(&callback) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback step does not match a live native callback owner"));
        }
        if let Some(existing) = self.dde_callback_source(callback.frame) {
            if Arc::ptr_eq(&existing.step, &callback)
                || existing.step.as_ref() == callback.as_ref()
            {
                return Ok(());
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE host reused a live callback frame with different source contents"));
        }
        if self.dde_sources.callbacks.len() == self.dde_sources.callbacks.capacity() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback source capacity was not reserved before consuming its native step"));
        }
        self.dde_sources.callbacks.push(PendingDdeCallbackSource {
            step: callback,
            runtime_published: false,
        });
        Ok(())
    }

    pub(super) fn dde_callback_published_inner(
        &mut self,
        step: &Win16HostDdeCallbackStep,
    ) -> Result<(), RuntimeError> {
        if !step.has_valid_identity() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback publication has an invalid exact source identity"));
        }
        let index = self.dde_callback_index(step.frame).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "DDE callback publication has no cached native source step")
        })?;
        let cached_step_matches = self.dde_sources.callbacks[index].step.as_ref() == step;
        let native_source_matches = self.dde_host_mut()?.callback_source_matches(step);
        if !cached_step_matches || !native_source_matches {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback publication changed or lost its exact native source"));
        }
        self.dde_sources.callbacks[index].runtime_published = true;
        Ok(())
    }

    pub(super) fn dde_callback_retired_inner(
        &mut self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        instance: Win16HostDdeInstance,
        owner: Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        let index = self.dde_callback_index(frame);
        if let Some(index) = index {
            let source = &self.dde_sources.callbacks[index];
            if source.step.parent != parent
                || source.step.callback.host_instance != instance
                || source.step.owner != owner
                || source.step.worker_generation != worker_generation
                || !source.step.has_valid_identity()
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE callback retirement changed its exact frame, parent, instance, or owner"));
            }
        }
        let pending = self.dde_host_mut()?.callback_retirement_is_pending(
            frame, parent, instance, owner, worker_generation,
        )?;
        if pending {
            self.dde_host_mut()?.callback_frame_retired(
                frame, parent, instance, owner, worker_generation,
            )?;
        }
        if let Some(index) = index {
            self.dde_sources.callbacks.remove(index);
        }
        Ok(())
    }

    pub(super) fn dde_operation_retired_inner(
        &mut self,
        proof: &Win16DdeOperationRetirementProof,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        let operation = proof.cancellation.operation;
        if !receipt.is_quiesced()
            || proof.request_id == 0
            || receipt.owner != Some(proof.owner)
            || receipt.request_id != Some(proof.request_id)
            || !proof.matches_receipt(receipt)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE operation retirement proof does not match its exact shutdown receipt"));
        }
        self.dde_host_mut()?.verify_abort_receipt(receipt)?;
        let source = PendingSource::Dde { operation };
        let mut retired = self.dde_sources.retired_operations.iter().enumerate()
            .filter(|(_, entry)| entry.operation() == operation);
        if let Some((index, existing)) = retired.next() {
            if retired.next().is_some()
                || self.dde_sources.pending.contains(&source)
                || self.dde_callback_has_parent(operation)
                || !receipt_matches_sources(receipt, &self.dde_sources)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE retired operation has duplicate or inconsistent source identities"));
            }
            let normal = match existing {
                RetiredDdeOperationSource::Shutdown(cached)
                    if same_retirement_proof(cached, proof) => return Ok(()),
                RetiredDdeOperationSource::Normal(normal)
                    if normal.has_valid_identity()
                        && normal.operation == operation
                        && normal.owner == proof.owner
                        && normal.worker_generation == proof.worker_generation
                        && proof.cancellation.status
                            == Win16DdeOperationCancellationStatus::NativeCompleteReturned
                        && proof.cancellation.failure.is_none() => Arc::clone(normal),
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE operation source was retired with a different exact proof")),
            };
            if !self.dde_host_mut()?.normal_completed_operation_matches(&normal)? {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE normal tombstone lost its exact retained native completion"));
            }
            // Allocate the replacement before the native ACK removes its
            // retained record. The source already retired normally: never pop
            // an unrelated live source while reconciling terminal shutdown.
            let replacement = RetiredDdeOperationSource::Shutdown(proof.clone());
            self.dde_host_mut()?.operation_retired(proof, receipt)?;
            self.dde_sources.retired_operations[index] = replacement;
            return Ok(());
        }
        self.require_source(source,
            "DDE operation source is not the exact shared-ledger top")?;
        if self.dde_sources.pending.iter().filter(|entry| **entry == source).count() != 1
            || self.dde_callback_has_parent(operation)
            || !receipt_matches_sources(receipt, &self.dde_sources)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE operation source, callback ledger, or abort receipt identities disagree"));
        }
        self.dde_sources.retired_operations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve DDE shutdown source tombstone before native ACK", error)
        })?;
        self.dde_host_mut()?.operation_retired(proof, receipt)?;
        let removed = self.dde_sources.pending.pop();
        if removed != Some(source) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source changed after its exact native shutdown ACK"));
        }
        self.dde_sources.retired_operations.push(
            RetiredDdeOperationSource::Shutdown(proof.clone()),
        );
        Ok(())
    }

    pub(super) fn dde_runtime_resources_retired_inner(
        &mut self,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        if !receipt.is_quiesced()
            || !self.dde_sources.callbacks.is_empty()
            || self.dde_sources.pending.iter().any(|source| {
                matches!(source, PendingSource::Dde { .. })
            })
            || !receipt_matches_sources(receipt, &self.dde_sources)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "DDE runtime retirement arrived before exact callback and operation ACKs"));
        }
        match self.dde.as_mut() {
            Some(dde) => dde.verify_runtime_retirement(receipt)?,
            None if receipt.owner.is_none() && receipt.request_id.is_none()
                && receipt.is_quiesced() => {}
            None => return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE retirement receipt names an absent native owner")),
        }
        self.dde_sources.retired_operations.clear();
        Ok(())
    }

    pub(super) fn dde_abort_receipt_inner(&mut self) -> Win16DdeAbortReceipt {
        match self.dde.as_mut() {
            Some(dde) => dde.abort(),
            None => match &self.dde_start_error {
                Some(error) => Win16DdeAbortReceipt::unsupported(RuntimeError::with_source(
                    error.kind(),
                    "Win16 DDE owner initialization did not produce a retirement receipt",
                    Arc::clone(error),
                )),
                None => Win16DdeAbortReceipt::not_started(),
            },
        }
    }

    pub(in crate::windows) fn dde_callback_published(
        &mut self,
        step: &Win16HostDdeCallbackStep,
    ) -> Result<(), RuntimeError> {
        self.dde_callback_published_inner(step)
    }

    pub(in crate::windows) fn dde_callback_retired(
        &mut self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        instance: Win16HostDdeInstance,
        owner: Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        self.dde_callback_retired_inner(frame, parent, instance, owner, worker_generation)
    }

    pub(in crate::windows) fn dde_retire_completed_source(
        &mut self,
        operation: Win16HostDdeOperation,
        result: &runtime::Win16HostDdeResult,
    ) -> Result<runtime::Win16HostDdeStep, RuntimeError> {
        self.retire_completed_dde_source_inner(operation, result)
    }

    pub(in crate::windows) fn dde_operation_retired(
        &mut self,
        proof: &Win16DdeOperationRetirementProof,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        self.dde_operation_retired_inner(proof, receipt)
    }

    pub(in crate::windows) fn dde_source_retirement(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        self.dde_source_retirement_inner(proof)
    }

    pub(in crate::windows) fn dde_source_retirement_consumed(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        self.consume_dde_source_retirement_inner(proof)
    }

    pub(in crate::windows) fn dde_runtime_resources_retired(
        &mut self,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        self.dde_runtime_resources_retired_inner(receipt)
    }

    pub(in crate::windows) fn abort_dde_receipt(&mut self) -> Win16DdeAbortReceipt {
        self.dde_abort_receipt_inner()
    }
}

fn receipt_matches_sources(receipt: &Win16DdeAbortReceipt, sources: &DdeSourceLedger) -> bool {
    for cancelled in &receipt.cancelled_operations {
        if !matches!(cancelled.status,
            Win16DdeOperationCancellationStatus::CompletedDuringAbort
                | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                | Win16DdeOperationCancellationStatus::NativeCompleteError
                | Win16DdeOperationCancellationStatus::NativeCompleteReturned)
        {
            return false;
        }
        let active = sources.pending.iter().filter(|source| {
            matches!(source, PendingSource::Dde { operation }
                if *operation == cancelled.operation)
        }).count();
        let retired: Vec<_> = sources.retired_operations.iter().filter(|source| {
            source.operation() == cancelled.operation
        }).collect();
        if active + retired.len() != 1 {
            return false;
        }
        if let Some(source) = retired.first() {
            match source {
                RetiredDdeOperationSource::Shutdown(proof)
                    if proof.matches_receipt(receipt)
                        && proof.cancellation.operation == cancelled.operation => {}
                RetiredDdeOperationSource::Normal(proof)
                    if proof.has_valid_identity()
                        && receipt.owner == Some(proof.owner)
                        && receipt.worker_generation == Some(proof.worker_generation)
                        && cancelled.status == Win16DdeOperationCancellationStatus::NativeCompleteReturned
                        && cancelled.failure.is_none() => {}
                _ => return false,
            }
        }
    }
    sources.pending.iter().all(|source| {
        let PendingSource::Dde { operation } = source else { return true };
        receipt.cancelled_operations.iter().filter(|entry| entry.operation == *operation).count() == 1
    }) && sources.retired_operations.iter().all(|source| {
        let operation = source.operation();
        receipt.cancelled_operations.iter().filter(|entry| entry.operation == operation).count() == 1
    })
}

fn same_retirement_proof(
    left: &Win16DdeOperationRetirementProof,
    right: &Win16DdeOperationRetirementProof,
) -> bool {
    left.owner == right.owner
        && left.worker_generation == right.worker_generation
        && left.request_id == right.request_id
        && same_operation(&left.cancellation, &right.cancellation)
        && left.callback_receipts.len() == right.callback_receipts.len()
        && left.callback_receipts.iter().all(|expected| {
            right.callback_receipts.iter().filter(|actual| {
                actual.frame == expected.frame
                    && actual.parent_operation == expected.parent_operation
                    && actual.instance == expected.instance
                    && actual.source == expected.source
                    && actual.status == expected.status
                    && same_cause(&actual.failure, &expected.failure)
            }).count() == 1
        })
        && match (&left.transfer_guard, &right.transfer_guard) {
            (Some(a), Some(b)) => a.operation == b.operation && a.data == b.data
                && a.instance == b.instance && a.source == b.source
                && same_cause(&a.failure, &b.failure),
            (None, None) => true,
            _ => false,
        }
}

fn same_operation(
    left: &runtime::Win16DdeOperationCancellation,
    right: &runtime::Win16DdeOperationCancellation,
) -> bool {
    left.operation == right.operation
        && left.instance == right.instance
        && left.status == right.status
        && same_cause(&left.failure, &right.failure)
}

fn same_cause(
    left: &Option<Arc<RuntimeError>>,
    right: &Option<Arc<RuntimeError>>,
) -> bool {
    match (left, right) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}
