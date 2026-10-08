//! Exact terminal cleanup and guest return for failed DDE-backed creation.

use super::*;

pub(super) fn finish_failed_creation(
    state: &mut Win16State,
    index: usize,
    cpu: &mut Cpu,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let operation = sequence.operation;
    let status = sequence.failure_status.unwrap_or(OLE1_ERROR_OPEN);
    let detail = sequence
        .failure_detail
        .unwrap_or("OLE1 DDE object creation failed");
    let client_proxy = sequence.client_proxy_id;
    let return_to = sequence.return_to;
    let return_kind = sequence.return_kind;
    state.ole1_client_documents.finish_operation(operation);
    if state.ole1_client_documents.pending_dde_creations[index]
        .fatal
        .is_some()
    {
        if !state.ole1_client_documents.pending_dde_creations[index].client_proxy_retired {
            let allocation =
                state.ole1_client_documents.pending_dde_creations[index].client_proxy_allocation;
            if !state.try_retire_ole1_dde_client_proxy(client_proxy, allocation)? {
                return Err(dde_error(
                    Kind::HostFailure,
                    "retry OLE1 client-proxy retirement; callback still pins the original creation failure",
                ));
            }
            state.ole1_client_documents.pending_dde_creations[index].client_proxy_retired = true;
        }
        let primary = state.ole1_client_documents.pending_dde_creations[index]
            .fatal
            .take()
            .ok_or_else(|| {
                dde_error(
                    Kind::InternalInvariant,
                    "OLE1 fatal creation error disappeared during exact cleanup",
                )
            })?;
        state
            .ole1_client_documents
            .pending_dde_creations
            .remove(index);
        return Err(primary);
    }
    if !state.ole1_client_documents.pending_dde_creations[index].client_proxy_retired {
        let allocation =
            state.ole1_client_documents.pending_dde_creations[index].client_proxy_allocation;
        if !state.try_retire_ole1_dde_client_proxy(client_proxy, allocation)? {
            return Err(dde_error(
                Kind::HostFailure,
                "OLE1 DDE create cleanup waits for its exact client callback proxy retirement",
            ));
        }
        state.ole1_client_documents.pending_dde_creations[index].client_proxy_retired = true;
    }
    host.report_diagnostic(&Diagnostic::warning(
        Kind::HostFailure,
        format!("OLE1 DDE creation returned guest status {status}: {detail}"),
    ));
    state.complete_return(
        &mut cpu.regs,
        return_to.0,
        return_to.1,
        return_to.2,
        u32::from(status),
        return_kind,
    )?;
    state
        .ole1_client_documents
        .pending_dde_creations
        .remove(index);
    Ok(Some(Win16Ole1ClientDdeDisposition::ApiCompleted {
        operation,
    }))
}
