use super::*;

pub(super) fn finish_successful_creation(
    state: &mut Win16State,
    index: usize,
    cpu: &mut Cpu,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    if sequence.stage != Stage::PublishedReturn {
        return Err(dde_error(
            Kind::InternalInvariant,
            "OLE1 DDE create guest return began before checked object publication",
        ));
    }
    let object_far = sequence.published_object_far.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 DDE create lost its published object FAR",
        )
    })?;
    if !state
        .ole1_client_documents
        .dde_object_proxies
        .iter()
        .any(|record| {
            record.owner == sequence.owner
                && record.object_far == object_far
                && record.operation_id == sequence.operation
        })
    {
        return Err(dde_error(
            Kind::InternalInvariant,
            "OLE1 DDE create published FAR no longer matches its owner/operation proxy",
        ));
    }
    let (operation, return_to, return_kind) =
        (sequence.operation, sequence.return_to, sequence.return_kind);
    state.complete_return(
        &mut cpu.regs,
        return_to.0,
        return_to.1,
        return_to.2,
        u32::from(OLE1_OK),
        return_kind,
    )?;
    state.ole1_client_documents.finish_operation(operation);
    state
        .ole1_client_documents
        .pending_dde_creations
        .remove(index);
    Ok(Some(Win16Ole1ClientDdeDisposition::ApiCompleted {
        operation,
    }))
}
