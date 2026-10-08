use super::*;

pub(super) fn route_data_terminal(
    journal: &mut Win16Ole1ClientDdeJournal,
    binding_operation: Win16Ole1OperationId,
    action: Win16Ole1ClientHostAction,
    result: Win16HostClassicDdeResult,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    match action {
        Win16Ole1ClientHostAction::PostTransaction {
            owner,
            endpoint,
            peer,
            conversation,
            call,
            sent_message,
        } => {
            let Win16HostClassicDdeResult::Posted(receipt) = result else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 DDE transaction did not return a post receipt",
                ));
            };
            if receipt.owner != owner
                || receipt.endpoint != endpoint
                || receipt.peer != peer
                || receipt.conversation != Some(conversation)
                || receipt.message != sent_message
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 DDE transaction post receipt is not exact",
                ));
            }
            if !receipt.queued {
                journal.cancel_call(call).map_err(|message| {
                    RuntimeError::new(Kind::InternalInvariant, message)
                })?;
                Ok(Win16Ole1ClientDdeDisposition::DdeCallRejected {
                    operation: binding_operation,
                    call,
                })
            } else {
                journal.bind_post_receipt(call, &receipt).map_err(|message| {
                    RuntimeError::new(Kind::InternalInvariant, message)
                })?;
                Ok(Win16Ole1ClientDdeDisposition::DdeCallPosted {
                    operation: binding_operation,
                    call,
                })
            }
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "non-data OLE1 DDE action reached the data terminal router",
        )),
    }
}

pub(super) fn terminal_identity_matches(
    host: Win16ClassicDdeOperationIdentity,
    terminal: &Win16HostClassicDdeTerminal,
) -> bool {
    match terminal {
        Win16HostClassicDdeTerminal::Complete { source_retired, .. } => {
            source_retired.operation == host
        }
        Win16HostClassicDdeTerminal::StartedFailure(failure) => {
            failure.operation == host && failure.source_retired.operation == host
        }
    }
}
