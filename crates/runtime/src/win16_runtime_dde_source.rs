//! Cached DDE native completions and exact per-operation source proofs.

use std::sync::Arc;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DdeSourceRetiredProof,
    Win16HostDdeResult, Win16HostDdeStep,
};

use super::{DdeCompletionAccess, Win16DdeContinuation, invariant};

/// Consume every cached normal-source proof after the DDE result has been
/// projected. This free helper also serves callback-owned continuations, whose
/// exact callback frame and nested continuation are borrowed separately.
pub(in crate::win16_runtime) fn consume_source_retirements(
    continuation: &mut Win16DdeContinuation,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    for index in 0..continuation.normal_source_retirements().len() {
        let entry = &continuation.normal_source_retirements()[index];
        if entry.consumed() {
            continue;
        }
        let proof = Arc::clone(entry.proof());
        if !proof.has_valid_identity() {
            return Err(invariant(
                "DDE source tombstone consumption has an invalid exact operation proof",
            ));
        }
        if !host.win16_dde_source_retirement(&proof)? {
            return Err(invariant(
                "DDE normal source-retirement proof is no longer present at its native owner",
            ));
        }
        host.win16_dde_source_retirement_consumed(&proof)?;
        continuation.mark_source_retirement_consumed(&proof)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16DdeNormalCompletionPhase {
    /// The native operation returned while its guest callback still needs
    /// cleanup and exact native callback retirement.
    CallbackCleanupPending,
    /// The callback frame and its host source retired; only the parent DDE
    /// operation source remains to be retired.
    CallbackRetired,
    SourceRetirementPending,
    SourceRetired,
}

#[derive(Clone)]
pub(in crate::win16_runtime) struct Win16DdeNormalCompletion {
    operation: crate::Win16HostDdeOperation,
    result: Win16HostDdeResult,
    phase: Win16DdeNormalCompletionPhase,
    first_failure: Option<Arc<RuntimeError>>,
    /// A native source may already be retired while the exact runtime callback
    /// frame still needs cleanup. Keep the proof here, but do not expose it as
    /// a consumable retirement record until that callback owner retires.
    pending_source_proof: Option<Arc<Win16DdeSourceRetiredProof>>,
}

#[derive(Clone)]
pub(in crate::win16_runtime) struct Win16DdeSourceRetirementRecord {
    proof: Arc<Win16DdeSourceRetiredProof>,
    result: Win16HostDdeResult,
    consumed: bool,
    first_failure: Option<Arc<RuntimeError>>,
}

impl Win16DdeSourceRetirementRecord {
    pub(in crate::win16_runtime) fn proof(&self) -> &Arc<Win16DdeSourceRetiredProof> {
        &self.proof
    }

    pub(in crate::win16_runtime) fn result(&self) -> &Win16HostDdeResult {
        &self.result
    }

    pub(in crate::win16_runtime) fn consumed(&self) -> bool {
        self.consumed
    }

}

impl Win16DdeContinuation {
    /// Cache the exact normal native result before any callback cleanup can
    /// fail. Replays are accepted only for the same operation and result.
    pub(in crate::win16_runtime) fn cache_native_completion(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        result: Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        self.bind_host_operation(operation)?;
        match self.cached_normal_completion.as_ref() {
            Some(existing)
                if existing.operation == operation && existing.result == result => Ok(()),
            Some(_) => Err(invariant(
                "DDE normal completion changed its cached operation or result",
            )),
            None => {
                self.cached_normal_completion = Some(Win16DdeNormalCompletion {
                    operation,
                    result,
                    phase: Win16DdeNormalCompletionPhase::CallbackCleanupPending,
                    first_failure: None,
                    pending_source_proof: None,
                });
                Ok(())
            }
        }
    }

    pub(in crate::win16_runtime) fn cached_native_completion(
        &self,
        operation: crate::Win16HostDdeOperation,
    ) -> Option<&Win16HostDdeResult> {
        self.cached_normal_completion
            .as_ref()
            .filter(|completion| completion.operation == operation)
            .map(|completion| &completion.result)
    }

    pub(in crate::win16_runtime) fn normal_completion_phase(
        &self,
        operation: crate::Win16HostDdeOperation,
    ) -> Option<Win16DdeNormalCompletionPhase> {
        self.cached_normal_completion
            .as_ref()
            .filter(|completion| completion.operation == operation)
            .map(|completion| completion.phase)
    }

    pub(in crate::win16_runtime) fn mark_normal_callback_retired(
        &mut self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<(), RuntimeError> {
        let pending = {
            let completion = self.require_normal_completion_mut(operation)?;
            match completion.phase {
                Win16DdeNormalCompletionPhase::CallbackCleanupPending => {
                    completion.phase = Win16DdeNormalCompletionPhase::CallbackRetired;
                }
                Win16DdeNormalCompletionPhase::CallbackRetired
                | Win16DdeNormalCompletionPhase::SourceRetirementPending => {}
                Win16DdeNormalCompletionPhase::SourceRetired => {
                    return Err(invariant(
                        "DDE callback retirement replayed after parent source retirement",
                    ));
                }
            }
            completion.pending_source_proof.as_ref().map(|proof| {
                (Arc::clone(proof), completion.result.clone())
            })
        };
        if let Some((proof, result)) = pending {
            self.cache_normal_source_retirement(proof, result)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn mark_normal_source_retirement_pending(
        &mut self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<(), RuntimeError> {
        let completion = self.require_normal_completion_mut(operation)?;
        match completion.phase {
            Win16DdeNormalCompletionPhase::CallbackRetired
            | Win16DdeNormalCompletionPhase::SourceRetirementPending => {
                completion.phase = Win16DdeNormalCompletionPhase::SourceRetirementPending;
                Ok(())
            }
            Win16DdeNormalCompletionPhase::SourceRetired => Ok(()),
            Win16DdeNormalCompletionPhase::CallbackCleanupPending => Err(invariant(
                "DDE parent source retirement started before callback source cleanup",
            )),
        }
    }

    pub(in crate::win16_runtime) fn retain_normal_completion_failure(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        error: RuntimeError,
    ) -> Result<RuntimeError, RuntimeError> {
        let completion = self.require_normal_completion_mut(operation)?;
        let reported = if let Some(primary) = completion.first_failure.as_ref() {
            error.with_cleanup(
                "DDE normal completion retry retained its original typed failure",
                super::super::callback_lifo::shared_runtime_error(Arc::clone(primary)),
            )
        } else {
            let primary = Arc::new(error);
            completion.first_failure = Some(Arc::clone(&primary));
            super::super::callback_lifo::shared_runtime_error(Arc::clone(&primary))
        };
        if let Some(record) = self.normal_source_retirements.iter_mut().find(|entry| {
            entry.proof.operation == operation
        }) {
            if record.first_failure.is_none() {
                record.first_failure = self
                    .cached_normal_completion
                    .as_ref()
                    .and_then(|completion| completion.first_failure.clone());
            }
        }
        Ok(reported)
    }

    pub(in crate::win16_runtime) fn clear_completed_phase_for_followup(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if let Some(completion) = self.cached_normal_completion.as_ref() {
            if completion.phase != Win16DdeNormalCompletionPhase::SourceRetired
                || !self.normal_source_retirements.iter().any(|entry| {
                    entry.proof.operation == completion.operation
                        && entry.result == completion.result
                })
            {
                return Err(invariant(
                    "DDE follow-up cannot replace an unretired normal completion",
                ));
            }
        }
        self.cached_normal_completion = None;
        Ok(())
    }

    pub(in crate::win16_runtime) fn normal_source_retirements(
        &self,
    ) -> &[Win16DdeSourceRetirementRecord] {
        &self.normal_source_retirements
    }

    pub(in crate::win16_runtime) fn require_cached_normal_source_result(
        &self,
        result: &Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        let operation = self.host_operation.ok_or_else(|| {
            invariant("DDE completion has no operation bound to its source-retirement proof")
        })?;
        let completion = self.cached_normal_completion.as_ref().filter(|completion| {
            completion.operation == operation && completion.result == *result
        }).ok_or_else(|| invariant(
            "DDE completion result differs from the cached actual native result",
        ))?;
        if completion.phase != Win16DdeNormalCompletionPhase::SourceRetired {
            return Err(invariant(
                "DDE completion reached projection before exact source retirement",
            ));
        }
        let mut matches = self.normal_source_retirements.iter().filter(|entry| {
            entry.proof.operation == operation && entry.result == *result
        });
        let Some(entry) = matches.next() else {
            return Err(invariant(
                "DDE completion result has no cached exact source-retirement proof",
            ));
        };
        if matches.next().is_some() {
            return Err(invariant(
                "DDE completion result matches duplicate source-retirement proofs",
            ));
        }
        if entry.consumed {
            return Err(invariant(
                "DDE completion replayed after its source-retirement proof was consumed",
            ));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cache_normal_source_retirement(
        &mut self,
        proof: Arc<Win16DdeSourceRetiredProof>,
        result: Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        if !proof.has_valid_identity() {
            return Err(invariant(
                "DDE normal source-retirement carrier has an invalid identity",
            ));
        }
        if self.started_failure.as_ref().is_some_and(|failure| {
            failure.owner != proof.owner
                || failure.worker_generation != proof.worker_generation
        }) || self.operation_retirement_proof.as_ref().is_some_and(|retired| {
            retired.owner != proof.owner
                || retired.worker_generation != proof.worker_generation
        }) || self.normal_source_retirements.iter().any(|entry| {
            entry.proof.owner != proof.owner
                || entry.proof.worker_generation != proof.worker_generation
        }) {
            return Err(invariant(
                "DDE normal source proof changed its retained native owner or worker generation",
            ));
        }
        self.bind_host_operation_identity(
            proof.operation,
            proof.owner,
            proof.worker_generation,
        )?;
        if let Some(existing) = self.normal_source_retirements.iter().find(|entry| {
            entry.proof.operation == proof.operation
        }) {
            if existing.proof.as_ref() != proof.as_ref() || existing.result != result {
                return Err(invariant(
                    "DDE normal source retry changed its proof or cached result",
                ));
            }
            match self.cached_normal_completion.as_mut() {
                Some(completion)
                    if completion.operation == proof.operation
                        && completion.result == result =>
                {
                    if completion.phase == Win16DdeNormalCompletionPhase::CallbackCleanupPending {
                        return Err(invariant(
                            "DDE source proof replayed before callback cleanup completed",
                        ));
                    }
                    completion.phase = Win16DdeNormalCompletionPhase::SourceRetired;
                    completion.pending_source_proof = None;
                }
                Some(_) => {
                    return Err(invariant(
                        "DDE normal source retry changed the cached completion",
                    ));
                }
                None => {
                    // The exact cached host tombstone is itself a normal
                    // source-retirement proof for a direct completion path.
                    self.cached_normal_completion = Some(Win16DdeNormalCompletion {
                        operation: proof.operation,
                        result: result.clone(),
                        phase: Win16DdeNormalCompletionPhase::SourceRetired,
                        first_failure: existing.first_failure.clone(),
                        pending_source_proof: None,
                    });
                }
            }
            return Ok(());
        }
        if self.normal_source_retirements.len() == self.normal_source_retirements.capacity() {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE normal source proof capacity was not reserved before native completion",
            ));
        }
        match self.cached_normal_completion.as_ref() {
            Some(completion)
                if completion.operation == proof.operation && completion.result == result => {
                    if completion.phase == Win16DdeNormalCompletionPhase::CallbackCleanupPending {
                        if let Some(existing) = completion.pending_source_proof.as_ref() {
                            if existing.as_ref() != proof.as_ref() {
                                return Err(invariant(
                                    "DDE pending source proof changed before callback cleanup",
                                ));
                            }
                            return Ok(());
                        }
                        self.cached_normal_completion
                            .as_mut()
                            .expect("normal completion checked")
                            .pending_source_proof = Some(Arc::clone(&proof));
                        return Ok(());
                    }
                }
            Some(_) => {
                return Err(invariant(
                    "DDE normal source proof changed the pre-cached operation result",
                ));
            }
            None => {}
        }
        let inherited_failure = self
            .cached_normal_completion
            .as_ref()
            .and_then(|completion| completion.first_failure.clone());
        if self.cached_normal_completion.is_none() {
            // Direct completion has no callback phase; the host carrier
            // itself proves that the exact native source already popped.
            self.cached_normal_completion = Some(Win16DdeNormalCompletion {
                operation: proof.operation,
                result: result.clone(),
                phase: Win16DdeNormalCompletionPhase::SourceRetired,
                first_failure: None,
                pending_source_proof: None,
            });
        } else if let Some(completion) = self.cached_normal_completion.as_mut() {
            completion.phase = Win16DdeNormalCompletionPhase::SourceRetired;
            completion.pending_source_proof = None;
        }
        self.normal_source_retirements.push(Win16DdeSourceRetirementRecord {
            proof,
            result,
            consumed: false,
            first_failure: inherited_failure,
        });
        Ok(())
    }

    pub(in crate::win16_runtime) fn reserve_source_retirement_record(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if self.normal_source_retirements.len() == self.normal_source_retirements.capacity() {
            self.normal_source_retirements.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DDE source proof before native operation entry",
                    error,
                )
            })?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn inherit_source_retirements_from(
        &mut self,
        prior: &Self,
    ) -> Result<(), RuntimeError> {
        if self.cached_normal_completion.is_some() {
            return Err(invariant(
                "new DDE follow-up already owns a different native completion",
            ));
        }
        self.normal_source_retirements
            .try_reserve(prior.normal_source_retirements.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve inherited DDE source proofs before follow-up entry",
                    error,
                )
            })?;
        self.guest_return_transfers
            .try_reserve(prior.guest_return_transfers.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve inherited DDE guest-return provenance before follow-up entry",
                    error,
                )
            })?;
        self.normal_source_retirements
            .extend(prior.normal_source_retirements.iter().cloned());
        self.guest_return_transfers
            .extend(prior.guest_return_transfers.iter().copied());
        match prior.host_owner_identity() {
            Some((owner, generation)) => self.bind_host_owner_identity(owner, generation)?,
            None => {}
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn mark_source_retirement_consumed(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        let mut matches = self.normal_source_retirements.iter_mut().filter(|entry| {
            entry.proof.as_ref() == proof
        });
        let Some(entry) = matches.next() else {
            return Err(invariant(
                "DDE source-consumed receipt does not match a cached normal completion",
            ));
        };
        if matches.next().is_some() {
            return Err(invariant(
                "DDE source proof is duplicated in its runtime continuation",
            ));
        }
        entry.consumed = true;
        Ok(())
    }

    fn require_normal_completion_mut(
        &mut self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<&mut Win16DdeNormalCompletion, RuntimeError> {
        self.cached_normal_completion
            .as_mut()
            .filter(|completion| completion.operation == operation)
            .ok_or_else(|| invariant(
                "DDE completion phase does not match the cached exact native operation",
            ))
    }
}

impl DdeCompletionAccess<'_> {
    /// Retire only a native Complete already cached on this exact continuation.
    /// The host owns the actual source pop and returns its cached tombstone;
    /// callers must retain the same continuation if this operation fails.
    pub(in crate::win16_runtime) fn retire_cached_normal_source(
        &mut self,
        continuation: &mut Win16DdeContinuation,
        operation: crate::Win16HostDdeOperation,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        let attempt = (|| {
            let result = continuation
                .cached_native_completion(operation)
                .cloned()
                .ok_or_else(|| invariant(
                    "DDE source retirement has no cached actual native completion",
                ))?;
            match continuation.normal_completion_phase(operation) {
                Some(Win16DdeNormalCompletionPhase::CallbackRetired)
                | Some(Win16DdeNormalCompletionPhase::SourceRetirementPending) => {}
                Some(Win16DdeNormalCompletionPhase::SourceRetired) => {
                    let mut matches = continuation.normal_source_retirements().iter().filter(|entry| {
                        entry.proof().operation == operation && entry.result() == &result
                    });
                    let record = matches.next().ok_or_else(|| invariant(
                        "retired DDE completion has no exact cached source proof",
                    ))?;
                    if matches.next().is_some() {
                        return Err(invariant(
                            "retired DDE completion has duplicate source proofs",
                        ));
                    }
                    return Ok(Win16HostDdeStep::SourceRetired {
                        proof: Arc::clone(record.proof()),
                        result,
                    });
                }
                Some(Win16DdeNormalCompletionPhase::CallbackCleanupPending) | None => {
                    return Err(invariant(
                        "DDE source retirement preceded exact callback cleanup",
                    ));
                }
            }
            continuation.mark_normal_source_retirement_pending(operation)?;
            let step = host.win16_dde_retire_completed_source(operation, &result)?;
            let Win16HostDdeStep::SourceRetired {
                proof,
                result: returned,
            } = step
            else {
                return Err(invariant(
                    "DDE completed-source API did not return its exact retirement proof",
                ));
            };
            if !proof.has_valid_identity()
                || proof.operation != operation
                || returned != result
            {
                return Err(invariant(
                    "DDE source-retirement proof changed its operation or cached result",
                ));
            }
            continuation.cache_normal_source_retirement(Arc::clone(&proof), result.clone())?;
            Ok(Win16HostDdeStep::SourceRetired { proof, result })
        })();
        match attempt {
            Ok(step) => Ok(step),
            Err(error) => Err(continuation.retain_normal_completion_failure(operation, error)?),
        }
    }
}

impl super::Win16State {
    pub(in crate::win16_runtime) fn cache_foreground_dde_completion(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        result: Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| invariant(
            "native DDE Complete has no exact top runtime parent continuation",
        ))?;
        let Some(super::WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "native DDE Complete reached a non-DDE top runtime frame",
            ));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "native DDE Complete changed the exact top runtime parent operation",
            ));
        }
        continuation.cache_native_completion(operation, result)
    }

    pub(in crate::win16_runtime) fn cache_foreground_dde_source_retirement(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        proof: Arc<Win16DdeSourceRetiredProof>,
        result: Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        if !proof.has_valid_identity() || proof.operation != operation {
            return Err(invariant(
                "DDE source-retirement proof changed its exact operation identity",
            ));
        }
        let frame = self.window_operations.last_mut().ok_or_else(|| invariant(
            "DDE source-retirement proof has no exact top runtime frame",
        ))?;
        let Some(super::WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "DDE source-retirement proof reached a non-DDE top runtime frame",
            ));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "DDE source-retirement proof changed the exact top native operation",
            ));
        }
        continuation.cache_native_completion(operation, result.clone())?;
        continuation.cache_normal_source_retirement(proof, result)
    }

    pub(in crate::win16_runtime) fn mark_foreground_dde_callback_retired(
        &mut self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| invariant(
            "retired DDE callback has no exact top runtime parent continuation",
        ))?;
        let Some(super::WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "retired DDE callback reached a non-DDE top runtime frame",
            ));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "retired DDE callback changed the exact top native operation",
            ));
        }
        if continuation.cached_native_completion(operation).is_some() {
            continuation.mark_normal_callback_retired(operation)
        } else {
            Ok(())
        }
    }

    pub(in crate::win16_runtime) fn retain_foreground_dde_completion_failure(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        error: RuntimeError,
    ) -> Result<RuntimeError, RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| invariant(
            "DDE cleanup failure has no exact top runtime parent continuation",
        ))?;
        let Some(super::WindowReturn::Dde(continuation)) = &mut frame.result else {
            return Err(invariant(
                "DDE cleanup failure reached a non-DDE top runtime frame",
            ));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "DDE cleanup failure changed the exact top native operation",
            ));
        }
        if continuation.cached_native_completion(operation).is_some() {
            continuation.retain_normal_completion_failure(operation, error)
        } else {
            Ok(continuation.retain_finish_failure(error))
        }
    }
}
