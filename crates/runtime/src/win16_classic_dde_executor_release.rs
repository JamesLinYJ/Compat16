//! Classic DDE executor support for endpoint and API release waits.

use super::*;

impl Win16State {
    pub(super) fn drive_one_unpublished_cleanup(
        &mut self,
        owner: OwnerId,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let cleanups = self.pending_ole1_unpublished_cleanups(owner);
        let Some(cleanup) = cleanups.first() else {
            return Ok(false);
        };
        let Some(action) = self.next_ole1_unpublished_cleanup_action(cleanup.id)? else {
            return Ok(false);
        };
        match action {
            Ole1UnpublishedCleanupAction::RetireEndpoint {
                id,
                owner,
                endpoint,
                worker_generation: _,
                receipt_revision,
            } => {
                self.begin_classic_dde_host_call(
                    Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint },
                    ClassicDdeOperationOwner::UnpublishedCleanupRetire {
                        cleanup_id: id,
                        owner,
                        expected_revision: receipt_revision,
                    },
                    None,
                    host,
                )?;
                Ok(true)
            }
            Ole1UnpublishedCleanupAction::DeleteAtom {
                id,
                owner,
                worker_generation,
                atom,
                receipt_revision,
            } => {
                host.win16_global_delete_atom(atom)?;
                let _ = self.record_ole1_unpublished_cleanup_atom_deleted(
                    id,
                    owner,
                    worker_generation,
                    receipt_revision,
                    atom,
                )?;
                Ok(true)
            }
        }
    }

    /// Drive an API-originated OLESERVER/OLESERVERDOC Release continuation.
    /// The OLE callback journal owns the checked Release frame; this runtime
    /// lane only polls its exact endpoint EventIds and retries that same
    /// journal after EventAcknowledged. The retained return/cancellation
    /// journal drives cleanup without re-entering the guest callback.
    pub(super) fn drive_one_api_release_wait(
        &mut self,
        owner: OwnerId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let mut endpoints = Vec::new();
        for endpoint in self.ole1_server_state.owner_endpoints(owner) {
            endpoints.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "snapshot owner OLE1 Release endpoints",
                    error,
                )
            })?;
            endpoints.push(endpoint);
        }
        for endpoint in endpoints {
            let Some(wait) = self.pending_ole1_release_for_endpoint(owner, endpoint)? else {
                continue;
            };
            if wait.pending_events.is_empty() {
                match self.retry_pending_ole1_server_release(
                    wait.callback_id,
                    wait.owner,
                    wait.target,
                    wait.receipt_revision,
                    cpu,
                    dos,
                    memory,
                    host,
                )? {
                    super::super::win16_ole1_server_dde::Ole1PendingServerReleaseRetry::Completed => {
                        return Ok(true);
                    }
                    super::super::win16_ole1_server_dde::Ole1PendingServerReleaseRetry::Pending(next) => {
                        if !next.pending_events.is_empty() {
                            self.retain_classic_dde_pending_endpoint_poll(
                                next.owner, endpoint, &next.pending_events,
                            )?;
                            return Ok(false);
                        }
                    }
                }
            } else {
                self.retain_classic_dde_pending_endpoint_poll(
                    wait.owner,
                    endpoint,
                    &wait.pending_events,
                )?;
                return Ok(false);
            }
        }
        Ok(false)
    }
}
