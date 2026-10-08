//! Exact owner attribution for DDE client operations and proxy cleanup.

use super::{OwnerId, RuntimeError, Win16State};
use crate::DiagnosticKind as Kind;

pub(super) fn query(state: &Win16State, owner: OwnerId) -> Result<usize, RuntimeError> {
    if owner.0 == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "OLE1 DDE owner inventory requires a valid task owner",
        ));
    }
    let documents = &state.ole1_client_documents;
    if documents
        .pending_dde_creations
        .iter()
        .any(|entry| entry.owner.0 == 0)
        || documents
            .pending_dde_methods
            .iter()
            .any(|entry| entry.owner.0 == 0)
        || documents
            .dde_object_proxies
            .iter()
            .any(|entry| entry.owner.0 == 0)
        || documents
            .pending_dde_object_proxy_retirements
            .iter()
            .any(|entry| entry.owner.0 == 0)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "pending OLE1 DDE state lost its exact task owner",
        ));
    }
    for pending in &documents.pending_dde_client_proxy_retirements {
        if pending.owner.0 == 0 || pending.client_proxy_id.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "pending DDE client-proxy retirement lost its exact owner or proxy identity",
            ));
        }
        let binding = documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == pending.client_proxy_id);
        let queued = documents
            .pending_proxy_retirements
            .iter()
            .any(|entry| entry.allocation == pending.allocation);
        if binding.is_some_and(|binding| binding.allocation != pending.allocation)
            || (binding.is_none() && !queued && state.heap.info(pending.allocation).is_ok())
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "pending DDE client-proxy retirement no longer matches its exact binding or allocation",
            ));
        }
    }
    for proxy in &documents.dde_object_proxies {
        let binding = documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == proxy.client_proxy_id);
        let queued = documents
            .pending_proxy_retirements
            .iter()
            .any(|entry| entry.allocation == proxy.client_proxy_allocation);
        if proxy.owner.0 == 0
            || proxy.client_proxy_id.0 == 0
            || binding.is_some_and(|binding| {
                binding.allocation != proxy.client_proxy_allocation
                    || (proxy.client_proxy_retire_requested && !binding.retire_requested)
            })
            || (!proxy.client_proxy_retire_requested && binding.is_none())
            || (proxy.client_proxy_retire_requested
                && binding.is_none()
                && !queued
                && state.heap.info(proxy.client_proxy_allocation).is_ok())
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE OLE1 object lost the exact client-proxy retirement binding",
            ));
        }
    }
    let counts = [
        documents.client_dde.owner_pending(owner)?,
        documents
            .pending_dde_creations
            .iter()
            .filter(|entry| entry.owner == owner)
            .count(),
        documents
            .pending_dde_methods
            .iter()
            .filter(|entry| entry.owner == owner)
            .count(),
        documents
            .dde_object_proxies
            .iter()
            .filter(|entry| entry.owner == owner)
            .count(),
        documents
            .pending_dde_object_proxy_retirements
            .iter()
            .filter(|entry| entry.owner == owner)
            .count(),
        documents
            .pending_dde_client_proxy_retirements
            .iter()
            .filter(|entry| entry.owner == owner)
            .count(),
    ];
    Ok(counts.into_iter().fold(0usize, usize::saturating_add))
}
