//! Exact normal-completion source proofs for DDE operations.

use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeSourceRetiredProof,
    Win16HostDdeOperation, Win16HostDdeResult, Win16HostDdeStep, Win16WindowStep,
};

use super::{PendingSource, RetiredDdeOperationSource, Win16Windows};

pub(super) fn source_retired_window_step(
    host: &mut Win16Windows,
    operation: Win16HostDdeOperation,
    proof: Arc<Win16DdeSourceRetiredProof>,
    result: Win16HostDdeResult,
) -> Result<Win16WindowStep, RuntimeError> {
    validate_source_retired_step(host, operation, &proof, &result)?;
    Ok(Win16WindowStep::DdeSourceRetired {
        proof,
        result: Box::new(Win16WindowStep::Complete(
            runtime::Win16WindowResult::Dde(result),
        )),
    })
}

pub(super) fn validate_source_retired_step(
    host: &mut Win16Windows,
    operation: Win16HostDdeOperation,
    proof: &Win16DdeSourceRetiredProof,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    if proof.operation != operation
        || !proof.has_valid_identity()
        || !host.dde_sources.retired_operations.iter().any(|entry| {
            matches!(entry, RetiredDdeOperationSource::Normal(cached)
                if cached.as_ref() == proof)
        })
        || !host.dde_host_mut()?.normal_completed_operation_matches(&proof)?
        || host.dde_host_mut()?.normal_completion_result(operation).as_ref() != Some(&result)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE source-retired step does not match its cached exact source proof",
        ));
    }
    Ok(())
}

impl Win16Windows {
    pub(super) fn retire_completed_dde_source_inner(
        &mut self,
        operation: Win16HostDdeOperation,
        result: &Win16HostDdeResult,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        let source = PendingSource::Dde { operation };
        let retired: Vec<_> = self.dde_sources.retired_operations.iter().filter(|entry| {
            entry.operation() == operation
        }).collect();
        if let Some(entry) = retired.first() {
            if retired.len() != 1 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE operation has duplicate retired source identities"));
            }
            let RetiredDdeOperationSource::Normal(proof) = *entry else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "normal DDE completion conflicts with a shutdown source tombstone"));
            };
            let cached_proof = Arc::clone(proof);
            drop(retired);
            if !cached_proof.has_valid_identity()
                || self.dde_sources.pending.iter().any(|pending| *pending == source)
                || self.dde_callback_has_parent(operation)
                || !self.dde_host_mut()?.normal_completed_operation_matches(&cached_proof)?
                || self.dde_host_mut()?.normal_completion_result(operation).as_ref() != Some(result)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "cached DDE source proof differs from the exact native completion"));
            }
            return Ok(Win16HostDdeStep::SourceRetired {
                proof: cached_proof,
                result: result.clone(),
            });
        }

        self.require_source(source,
            "normal DDE Complete is blocked until its exact source is the shared-ledger top")?;
        if self.dde_sources.pending.iter().filter(|entry| **entry == source).count() != 1 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "normal DDE Complete has duplicate live source identities"));
        }
        if self.dde_callback_has_parent(operation) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "normal DDE source cannot retire while an exact callback source remains"));
        }
        self.dde_sources.retired_operations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve DDE normal source-retirement tombstone before source pop", error)
        })?;
        let proof = Arc::new(self.dde_host_mut()?.normal_source_retired_proof(operation, result)?);
        if !proof.has_valid_identity() || proof.operation != operation {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native DDE completion returned an invalid source-retirement proof"));
        }
        if self.dde_sources.retired_operations.len()
            == self.dde_sources.retired_operations.capacity()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source-retirement capacity was not reserved before the source pop"));
        }

        let removed = self.dde_sources.pending.pop();
        if removed != Some(source) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source changed after its exact native proof was prepared"));
        }
        self.dde_sources.retired_operations.push(
            RetiredDdeOperationSource::Normal(Arc::clone(&proof)),
        );
        Ok(Win16HostDdeStep::SourceRetired {
            proof,
            result: result.clone(),
        })
    }

    pub(super) fn dde_source_retirement_inner(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        if !proof.has_valid_identity() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE normal source proof has an invalid operation or worker identity"));
        }
        let retired: Vec<_> = self.dde_sources.retired_operations.iter().filter(|entry| {
            entry.operation() == proof.operation
        }).collect();
        if let Some(entry) = retired.first() {
            if retired.len() != 1 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE operation has duplicate active/retired source identities"));
            }
            let RetiredDdeOperationSource::Normal(cached) = *entry else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE normal proof conflicts with a shutdown-retirement tombstone"));
            };
            let cached_proof = Arc::clone(cached);
            drop(retired);
            if cached_proof.as_ref() != proof
                || self.dde_sources.pending.iter().any(|source| {
                    *source == PendingSource::Dde { operation: proof.operation }
                })
                || !self.dde_host_mut()?.normal_completed_operation_matches(proof)?
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE normal proof does not match its unique live tombstone"));
            }
            return Ok(true);
        }
        let matching_sources = self.dde_sources.pending.iter().filter(|source| {
            **source == PendingSource::Dde { operation: proof.operation }
        }).count();
        if matching_sources == 1 {
            if !self.dde_host_mut()?.normal_source_operation_known(proof)? {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE live source has no exact native operation record"));
            }
            return Ok(false);
        }
        Err(RuntimeError::new(Kind::InternalInvariant,
            "DDE normal source proof names an unknown or ambiguous source"))
    }

    pub(super) fn consume_dde_source_retirement_inner(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        if !proof.has_valid_identity() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source-retirement consumption has an invalid identity"));
        }
        let matches: Vec<_> = self.dde_sources.retired_operations.iter().enumerate().filter(|(_, entry)| {
            entry.operation() == proof.operation
        }).collect();
        let Some((index, entry)) = matches.first().copied() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE normal source-retirement tombstone is absent"));
        };
        let exact_normal = matches.len() == 1
            && matches!(entry, RetiredDdeOperationSource::Normal(cached) if cached.as_ref() == proof);
        drop(matches);
        if !exact_normal
            || self.dde_sources.pending.iter().any(|source| {
                *source == PendingSource::Dde { operation: proof.operation }
            })
            || self.dde_callback_has_parent(proof.operation)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source proof changed before checked result cleanup completed"));
        }
        self.dde_host_mut()?.consume_normal_source_retirement(proof)?;
        self.dde_sources.retired_operations.remove(index);
        Ok(())
    }
}
