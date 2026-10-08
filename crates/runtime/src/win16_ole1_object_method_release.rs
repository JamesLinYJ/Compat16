//! Exact native-reference and proxy retirement after OLE1 Release.

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn finish_ole1_object_release(
        &mut self,
        index: usize,
    ) -> Result<(), RuntimeError> {
        let record = self.ole1_client_documents.pending_object_methods[index].record;
        let native_count = self.ole1_client_documents.native_object_proxies
            .iter()
            .filter(|candidate| candidate.id == record.id)
            .count();
        if native_count > 1 {
            return Err(protocol_error("OLE1 Release has duplicate native proxy identities"));
        }
        if let Some(live) = self.ole1_client_documents.native_object_proxies
            .iter()
            .find(|candidate| candidate.id == record.id)
            .copied()
        {
            if live.allocation != record.allocation
                || live.object.owner != record.object.owner
                || live.document != record.document
                || live.object_far != record.object_far
                || live.client_far != record.client_far
                || live.client_proxy_id != record.client_proxy_id
                || live.client_proxy_allocation != record.client_proxy_allocation
            {
                return Err(protocol_error("OLE1 Release native proxy ownership changed"));
            }
            // Reserve while the live record still owns both membership and
            // allocation, so a failed reserve leaves the whole step retryable.
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve OLE1 native proxy allocation retirement",
                        error,
                    )
                })?;
            self.ole1_client_documents.remove_native_object_membership(
                record.document,
                record.object_far,
                record.client_far,
                record.client_proxy_id,
            )?;
            self.retire_ole1_native_object_proxy(record.id)?;
        } else if let Some(queued) = self.ole1_client_documents
            .pending_native_object_proxy_retirements
            .iter()
            .find(|queued| queued.native_proxy_id == Some(record.id))
        {
            if queued.owner != record.object.owner || queued.allocation != record.allocation {
                return Err(protocol_error("OLE1 Release native retirement ownership changed"));
            }
        }
        // Absence from the never-reused native proxy registry means its
        // allocation is already queued or freed. The retained method record
        // identifies the remaining client cleanup, not another native free.
        if let Some(binding) = self.ole1_client_documents.client_proxies
            .iter()
            .find(|binding| binding.id == record.client_proxy_id)
            .copied()
        {
            if binding.allocation != record.client_proxy_allocation
                || binding.operation_id != Some(record.operation_id)
            {
                return Err(protocol_error("OLE1 Release client proxy ownership changed"));
            }
            self.retire_ole1_client_operation_proxy(record.client_proxy_id)?;
        }
        Ok(())
    }

    fn retire_ole1_native_object_proxy(
        &mut self,
        id: u64,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self
            .ole1_client_documents
            .native_object_proxies
            .iter()
            .position(|record| record.id == id)
        else {
            return Err(protocol_error("OLE1 native proxy disappeared before retirement"));
        };
        let record = self.ole1_client_documents.native_object_proxies[index];
        // The caller reserved this queue slot before detaching membership.
        self.ole1_client_documents.native_object_proxies.remove(index);
        if let Err(error) = self.heap.free(record.allocation, &mut self.selectors) {
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(super::object_proxy::Win16Ole1PendingObjectProxyRetirement {
                    owner: record.object.owner,
                    native_proxy_id: Some(record.id),
                    client_proxy_id: None,
                    allocation: record.allocation,
                    unlocks_pending: 0,
                });
            return Err(crate::runtime_error(error)
                .with_context("free released OLE1 native object proxy allocation"));
        }
        Ok(())
    }
}

fn protocol_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
