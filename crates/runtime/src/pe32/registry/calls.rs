//! PE32 procedure leases and state transitions around guest execution.

use super::super::identity::Pe32CallLeaseState;
use super::*;

impl Pe32ModuleRegistry {
    pub(crate) fn prepare_process_attach(
        &mut self,
        module: Pe32ModuleIdentity,
    ) -> Result<Option<Pe32CallLease>, RuntimeError> {
        if self.tearing_down {
            return Err(invariant("PE32 registry is tearing down"));
        }
        let (image, entry_rva, is_dll) = {
            let record = self.record(module)?;
            (record.spec.image, record.spec.entry_rva, record.spec.is_dll)
        };
        if self.record(module)?.stage != Pe32ModuleStage::Linked || !is_dll {
            return Err(invariant(
                "PE32 process-attach requested outside a linked DLL",
            ));
        }
        check_loader_requirements(&self.record(module)?.spec)?;
        let Some(entry_rva) = entry_rva else {
            return Ok(None);
        };
        if self.record(module)?.entrypoint != Pe32EntryPointLifecycle::AttachPending {
            return Err(invariant("PE32 process-attach was prepared more than once"));
        }
        let target = Pe32CallableTarget::GuestCode {
            address: guest_address(image, entry_rva)?,
        };
        let arguments = crate::pe32_call::process_attach_arguments(image.base.0);
        let lease = self.create_lease(
            Some(module),
            None,
            target,
            Pe32CallReason::ProcessAttach,
            Pe32CallConvention::Stdcall,
            &arguments,
        )?;
        let record = self.record_mut(module)?;
        record.entrypoint = Pe32EntryPointLifecycle::AttachPrepared;
        record.stage = Pe32ModuleStage::Initializing;
        Ok(Some(lease))
    }

    /// Select a retiring dependency leaf and prepare DllMain's process-detach
    /// callback before any dependent image can release its import bindings.
    pub(crate) fn next_process_detach(&mut self) -> Result<Option<Pe32CallLease>, RuntimeError> {
        let candidate = self.modules.values().find_map(|record| {
            (record.stage == Pe32ModuleStage::Retiring
                && record.entrypoint == Pe32EntryPointLifecycle::DetachPending
                && record.active_calls == 0
                && !self.has_incoming_dependency(record.identity))
            .then_some((record.identity, record.spec.image, record.spec.entry_rva))
        });
        let Some((module, image, entry_rva)) = candidate else {
            return Ok(None);
        };
        let entry_rva = entry_rva
            .ok_or_else(|| invariant("PE32 module marked for detach has no entrypoint"))?;
        let target = Pe32CallableTarget::GuestCode {
            address: guest_address(image, entry_rva)?,
        };
        let arguments = crate::pe32_call::process_detach_arguments(image.base.0);
        let lease = self.create_lease(
            Some(module),
            None,
            target,
            Pe32CallReason::ProcessDetach,
            Pe32CallConvention::Stdcall,
            &arguments,
        )?;
        self.record_mut(module)?.entrypoint = Pe32EntryPointLifecycle::DetachPrepared;
        Ok(Some(lease))
    }

    pub(crate) fn prepare_call(
        &mut self,
        procedure: Pe32ProcedureToken,
        arguments: &[u32],
        convention: Pe32CallConvention,
    ) -> Result<Option<Pe32CallLease>, RuntimeError> {
        if arguments.len() > MAX_PE32_CALL_ARGUMENTS {
            return Err(loader_failure(
                "PE32 calls support at most 32 explicit DWORD arguments",
            ));
        }
        let Some(record) = self.procedures.get(&procedure).copied() else {
            return Ok(None);
        };
        let Some(module) = record.module else {
            return Err(invariant("PE32 procedure has no guest module owner"));
        };
        let owner = self.record(module)?;
        if owner.stage != Pe32ModuleStage::Published {
            return Ok(None);
        }
        self.create_lease(
            Some(module),
            Some(record.identity),
            record.target,
            Pe32CallReason::Export,
            convention,
            arguments,
        )
        .map(Some)
    }

    /// Mark a lease executing only after the call frame and guest writes are ready.
    pub(crate) fn begin_call(&mut self, lease: &Pe32CallLease) -> Result<(), RuntimeError> {
        let record = self.lease_record(lease)?.clone();
        if record.status != LeaseStatus::Prepared {
            return Err(invariant(
                "PE32 call lease did not enter from Prepared state",
            ));
        }
        match (record.reason, record.module) {
            (Pe32CallReason::Export, Some(identity)) => {
                if self.record(identity)?.stage != Pe32ModuleStage::Published {
                    return Err(invariant("PE32 export call began after module retirement"));
                }
            }
            (Pe32CallReason::Export, None) => {
                return Err(invariant("PE32 export call has no guest module owner"));
            }
            (Pe32CallReason::ProcessAttach, Some(identity)) => {
                let module = self.record(identity)?;
                if module.stage != Pe32ModuleStage::Initializing
                    || module.entrypoint != Pe32EntryPointLifecycle::AttachPrepared
                {
                    return Err(invariant(
                        "PE32 entrypoint call began outside initialization",
                    ));
                }
            }
            (Pe32CallReason::ProcessAttach, None) => {
                return Err(invariant("PE32 entrypoint lease has no module owner"));
            }
            (Pe32CallReason::ProcessDetach, Some(identity)) => {
                let module = self.record(identity)?;
                if module.stage != Pe32ModuleStage::Retiring
                    || module.entrypoint != Pe32EntryPointLifecycle::DetachPrepared
                {
                    return Err(invariant(
                        "PE32 detach call began outside its retirement stage",
                    ));
                }
            }
            (Pe32CallReason::ProcessDetach, None) => {
                return Err(invariant("PE32 detach lease has no module owner"));
            }
        }
        if let Some(identity) = record.module {
            let module = self.record_mut(identity)?;
            module.entrypoint = match record.reason {
                Pe32CallReason::ProcessAttach => Pe32EntryPointLifecycle::AttachExecuting,
                Pe32CallReason::ProcessDetach => Pe32EntryPointLifecycle::DetachExecuting,
                Pe32CallReason::Export => module.entrypoint,
            };
        }
        self.leases
            .get_mut(&lease.id)
            .ok_or_else(|| invariant("PE32 call lease disappeared before execution"))?
            .status = LeaseStatus::Executing;
        Ok(())
    }

    /// Only a Prepared call may be cancelled; executing calls finish on return or fault.
    pub(crate) fn cancel_prepared_call(
        &mut self,
        lease: &Pe32CallLease,
    ) -> Result<(), RuntimeError> {
        let record = self.lease_record(lease)?.clone();
        if record.status != LeaseStatus::Prepared {
            return Err(invariant("only a Prepared PE32 call can be cancelled"));
        }
        self.release_call_lease(lease, false)
    }

    pub(crate) fn finish_guest_call(
        &mut self,
        lease: &Pe32CallLease,
        outcome: Result<u32, RuntimeError>,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let record = match self.lease_record(lease).cloned() {
            Ok(record) => record,
            Err(error) => return Err(preserve_guest_failure(outcome, error)),
        };
        if record.status != LeaseStatus::Executing {
            return Err(preserve_guest_failure(
                outcome,
                invariant("only an Executing PE32 call can be finished"),
            ));
        }
        if let Err(error) = self.release_call_lease(lease, true) {
            return Err(preserve_guest_failure(outcome, error));
        }

        let completion = match record.reason {
            Pe32CallReason::Export => Ok(Pe32CallCompletion::Returned(0)),
            Pe32CallReason::ProcessAttach => {
                let attach_accepted = matches!(&outcome, Ok(value) if *value != 0);
                let tearing_down = self.tearing_down;
                let module_identity = record
                    .module
                    .ok_or_else(|| invariant("PE32 attach lease lost its module owner"));
                module_identity.and_then(|identity| {
                    let module = self.record_mut(identity)?;
                    // A returned FALSE still pairs with PROCESS_DETACH; a guest
                    // fault did not return from PROCESS_ATTACH and skips it.
                    module.entrypoint = if outcome.is_ok() {
                        Pe32EntryPointLifecycle::DetachPending
                    } else {
                        Pe32EntryPointLifecycle::AttachFaulted
                    };
                    module.stage = if attach_accepted && !tearing_down {
                        Pe32ModuleStage::Initialized
                    } else {
                        Pe32ModuleStage::Retiring
                    };
                    Ok(if attach_accepted {
                        Pe32CallCompletion::AttachAccepted
                    } else {
                        Pe32CallCompletion::AttachRejected
                    })
                })
            }
            Pe32CallReason::ProcessDetach => {
                let module_identity = record
                    .module
                    .ok_or_else(|| invariant("PE32 detach lease lost its module owner"));
                module_identity.and_then(|identity| {
                    let module = self.record_mut(identity)?;
                    module.entrypoint = Pe32EntryPointLifecycle::Detached;
                    module.stage = Pe32ModuleStage::Retiring;
                    Ok(Pe32CallCompletion::ProcessDetached)
                })
            }
        };
        match (outcome, completion) {
            (Err(primary), Err(cleanup)) => Err(combine_finalization_errors(primary, cleanup)),
            (Err(primary), Ok(_)) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Ok(value), Ok(completion)) => Ok(match record.reason {
                Pe32CallReason::Export => Pe32CallCompletion::Returned(value),
                _ => completion,
            }),
        }
    }

    pub(crate) fn lease_state(&self, lease: Pe32CallLeaseId) -> Option<Pe32CallLeaseState> {
        self.leases
            .get(&lease)
            .map(|record| match record.status {
                LeaseStatus::Prepared => Pe32CallLeaseState::Prepared,
                LeaseStatus::Executing => Pe32CallLeaseState::Executing,
            })
            .or_else(|| {
                self.next_lease
                    .as_ref()
                    .is_some_and(|next| next.was_issued(lease.raw()))
                    .then_some(Pe32CallLeaseState::Retired)
            })
    }
}

fn preserve_guest_failure(
    outcome: Result<u32, RuntimeError>,
    finalization: RuntimeError,
) -> RuntimeError {
    match outcome {
        Err(primary) => combine_finalization_errors(primary, finalization),
        Ok(_) => finalization,
    }
}

fn combine_finalization_errors(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        "PE32 call failed and registry finalization also failed",
        Pe32CallFinalizationFailure { primary, cleanup },
    )
}

#[derive(Debug)]
struct Pe32CallFinalizationFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for Pe32CallFinalizationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; finalization failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for Pe32CallFinalizationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
