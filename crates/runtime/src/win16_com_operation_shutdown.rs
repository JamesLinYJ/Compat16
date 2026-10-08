//! Exact COM-owner Seal, callback cancellation, and retirement journals.

use super::*;

impl Win16ComOperationTable {
    pub(in crate::win16_runtime) fn record_terminal_after_start_failure(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<(), RuntimeError> {
        let entry = self.entry_mut(id)?;
        if owner != entry.owner || !matches!(entry.phase, Phase::StartFailed(_)) {
            return Err(invariant(
                "late native COM terminal does not match the exact failed start",
            ));
        }
        let matches_operation = match &step {
            Win16ComHostStep::Complete(completion) => completion.operation == id.host,
            Win16ComHostStep::OperationFailed { operation, .. } => *operation == id.host,
            _ => false,
        };
        if !matches_operation {
            return Err(invariant(
                "late native COM terminal has another operation identity",
            ));
        }
        entry.phase = Phase::Terminal(step);
        entry.terminal_acknowledged = false;
        Ok(())
    }

    pub(in crate::win16_runtime) fn record_sealed_callback_failure(
        &mut self,
        id: Win16ComGuestOperationId,
        owner: Win16ComHostOwnerIdentity,
        step: Win16ComHostStep,
    ) -> Result<StepDisposition, RuntimeError> {
        if !self.owner_is_sealed(owner)? {
            return Err(invariant(
                "sealed callback failure arrived before exact COM owner Seal",
            ));
        }
        let Win16ComHostStep::CallbackFailed {
            frame: Some(frame),
            parent: Some(parent),
            owner: failed_owner,
            route,
            failure,
        } = step
        else {
            return Err(invariant(
                "COM owner cancellation is not an exact parented callback failure",
            ));
        };
        let entry = self.entry_mut(id)?;
        if owner != entry.owner
            || failed_owner != entry.owner
            || parent != id.host
            || route != entry.callback_route
        {
            return Err(invariant(
                "sealed callback failure differs from the exact guest operation identity",
            ));
        }
        match &entry.phase {
            Phase::Callback(callback) if callback.frame == frame => {}
            Phase::CallbackResuming { frame: pending_frame } if *pending_frame == frame => {}
            Phase::Running => {}
            Phase::CallbackFailed {
                failure: existing,
                frame: existing_frame,
            } if *existing_frame == frame && *existing == failure => {
                return Ok(StepDisposition::CallbackFailed);
            }
            _ => {
                return Err(invariant(
                    "sealed callback failure does not match a running or suspended exact operation",
                ));
            }
        }
        entry.phase = Phase::CallbackFailed { failure, frame };
        Ok(StepDisposition::CallbackFailed)
    }

    pub(in crate::win16_runtime) fn operations_for_owner(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Vec<Win16ComGuestOperationId>, RuntimeError> {
        let count = self.entries.iter().filter(|entry| entry.owner == owner).count();
        let mut operations = Vec::new();
        operations.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "enumerate exact COM operation frames for owner shutdown",
                error,
            )
        })?;
        operations.extend(
            self.entries
                .iter()
                .filter(|entry| entry.owner == owner)
                .map(|entry| entry.id),
        );
        Ok(operations)
    }

    pub(in crate::win16_runtime) fn owners_for_shutdown(&self) -> Result<Vec<Win16ComHostOwnerIdentity>, RuntimeError> {
        let mut owners = Vec::new();
        owners.try_reserve_exact(self.owner_shutdown.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "enumerate exact COM owner incarnations for teardown",
                error,
            )
        })?;
        owners.extend(self.owner_shutdown.iter().map(|record| record.owner));
        Ok(owners)
    }

    pub(in crate::win16_runtime) fn prepare_owner_seal(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        let record = self.owner_shutdown_record_mut(owner)?;
        match record.phase {
            OwnerShutdownPhase::Open | OwnerShutdownPhase::SealRequested => {
                record.phase = OwnerShutdownPhase::SealRequested;
                Ok(())
            }
            OwnerShutdownPhase::Sealed
            | OwnerShutdownPhase::PollRequested
            | OwnerShutdownPhase::Retired(_) => Ok(()),
        }
    }

    pub(in crate::win16_runtime) fn owner_is_sealed(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<bool, RuntimeError> {
        Ok(matches!(
            self.owner_shutdown_phase(owner)?,
            OwnerShutdownPhase::Sealed
                | OwnerShutdownPhase::PollRequested
                | OwnerShutdownPhase::Retired(_)
        ))
    }

    pub(in crate::win16_runtime) fn mark_owner_sealed(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        let record = self.owner_shutdown_record_mut(owner)?;
        match record.phase {
            OwnerShutdownPhase::SealRequested | OwnerShutdownPhase::Sealed => {
                record.phase = OwnerShutdownPhase::Sealed;
                Ok(())
            }
            OwnerShutdownPhase::PollRequested | OwnerShutdownPhase::Retired(_) => Ok(()),
            OwnerShutdownPhase::Open => Err(invariant(
                "COM owner was sealed without a retained Seal request",
            )),
        }
    }

    pub(in crate::win16_runtime) fn prepare_owner_poll(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        let record = self.owner_shutdown_record_mut(owner)?;
        match record.phase {
            OwnerShutdownPhase::Sealed | OwnerShutdownPhase::PollRequested => {
                record.phase = OwnerShutdownPhase::PollRequested;
                Ok(())
            }
            OwnerShutdownPhase::Retired(_) => Ok(()),
            OwnerShutdownPhase::Open | OwnerShutdownPhase::SealRequested => Err(invariant(
                "COM owner Poll has no exact completed Seal acknowledgement",
            )),
        }
    }

    pub(in crate::win16_runtime) fn remember_owner_receipt(
        &mut self,
        receipt: Win16ComHostShutdownReceipt,
    ) -> Result<(), RuntimeError> {
        if !receipt.owner.is_valid()
            || !receipt.callback_ingress_closed
            || !receipt.native_objects_shutdown
        {
            return Err(invariant("COM owner shutdown receipt is incomplete"));
        }
        let record = self.owner_shutdown_record_mut(receipt.owner)?;
        match record.phase {
            OwnerShutdownPhase::PollRequested => {
                record.phase = OwnerShutdownPhase::Retired(receipt);
                Ok(())
            }
            OwnerShutdownPhase::Retired(existing) if existing == receipt => Ok(()),
            _ => Err(invariant(
                "COM owner receipt does not match a pending exact Poll",
            )),
        }
    }

    pub(in crate::win16_runtime) fn owner_receipt(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Option<Win16ComHostShutdownReceipt>, RuntimeError> {
        Ok(match self.owner_shutdown_phase(owner)? {
            OwnerShutdownPhase::Retired(receipt) => Some(receipt),
            _ => None,
        })
    }

    pub(in crate::win16_runtime) fn retire_owner_entries_after_receipt(
        &mut self,
        receipt: Win16ComHostShutdownReceipt,
    ) -> Result<(), RuntimeError> {
        if self.owner_receipt(receipt.owner)? != Some(receipt) {
            return Err(invariant(
                "COM guest operation retirement has no cached exact owner receipt",
            ));
        }
        for entry in self.entries.iter().filter(|entry| entry.owner == receipt.owner) {
            let safe = match &entry.phase {
                Phase::Prepared | Phase::StartFailed(_) | Phase::GuestReturned => true,
                Phase::Terminal(_) => entry.terminal_acknowledged,
                Phase::Starting
                | Phase::Running
                | Phase::Callback(_)
                | Phase::CallbackResuming { .. }
                | Phase::CallbackFailed { .. } => false,
            };
            if !safe {
                return Err(invariant(
                    "COM guest operation remains active or lacks an exact terminal acknowledgement after owner shutdown",
                ));
            }
        }
        self.entries.retain(|entry| entry.owner != receipt.owner);
        Ok(())
    }

    pub(in crate::win16_runtime) fn owner_shutdown_complete(&self) -> bool {
        self.owner_shutdown.iter().all(|record| {
            matches!(record.phase, OwnerShutdownPhase::Retired(_))
                && !self.entries.iter().any(|entry| entry.owner == record.owner)
        })
    }

    pub(super) fn ensure_owner_open(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        if self
            .owner_shutdown
            .iter()
            .find(|record| record.owner == owner)
            .is_some_and(|record| !matches!(record.phase, OwnerShutdownPhase::Open))
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 COM owner is sealed for teardown",
            ));
        }
        Ok(())
    }

    pub(super) fn remember_owner(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<(), RuntimeError> {
        if self.owner_shutdown.iter().any(|record| record.owner == owner) {
            return Ok(());
        }
        self.owner_shutdown.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 COM owner-ending journal entry",
                error,
            )
        })?;
        self.owner_shutdown.push(OwnerShutdownRecord {
            owner,
            phase: OwnerShutdownPhase::Open,
        });
        Ok(())
    }

    fn owner_shutdown_phase(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<OwnerShutdownPhase, RuntimeError> {
        self.owner_shutdown
            .iter()
            .find(|record| record.owner == owner)
            .map(|record| record.phase)
            .ok_or_else(|| invariant("COM owner-ending journal has no exact owner record"))
    }

    fn owner_shutdown_record_mut(
        &mut self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<&mut OwnerShutdownRecord, RuntimeError> {
        self.owner_shutdown
            .iter_mut()
            .find(|record| record.owner == owner)
            .ok_or_else(|| invariant("COM owner-ending journal has no exact owner record"))
    }
}
