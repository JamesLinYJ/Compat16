//! Checked method operations for DDE-backed OLE1 client objects.

#[path = "win16_ole1_dde_object_method_events.rs"]
mod events;
#[path = "win16_ole1_dde_object_host_names.rs"]
mod host_names;
#[path = "win16_ole1_dde_object_method_local.rs"]
mod local;
pub(super) use events::{advance_event_ack, advance_sequence, process_committed_event};

use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use win16_abi::{Win16Argument, Win16ReturnKind};
use x86_cpu::Cpu;

use super::client_dde::{Win16Ole1ClientDdeCommittedResponse, Win16Ole1ExpectedReply};
use super::{
    OLE1_BUSY, OLE1_ERROR_ADDRESS, OLE1_ERROR_COMMAND, OLE1_ERROR_MEMORY, OLE1_ERROR_NOT_LINK,
    OLE1_ERROR_TERMINATE, OLE1_ERROR_UPDATE, OLE1_OK, Win16Ole1ClientDdeDisposition,
    Win16Ole1OperationId, Win16Ole1Status, Win16State,
    dde_object_proxy::Win16Ole1DdeObjectProxyRecord,
    stdexecute::{self, Win16Ole1StdExecuteCommand},
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ClassicDdeDeliveryKind,
    Win16HostClassicDdeEvent,
};

const WM_DDE_EXECUTE: u16 = 0x03e8;
const WM_DDE_POKE: u16 = 0x03e7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    AwaitExecutePost,
    AwaitResponse,
    AwaitDeliveryAck {
        event_id: crate::Win16ClassicDdeEventId,
        status: Win16Ole1Status,
    },
    RetireDocumentConversation,
    RetireSystemConversation,
    RetireEndpoint,
    ReleaseLocalRetired,
}

#[derive(Debug)]
pub(super) struct Win16Ole1DdeObjectMethodSequence {
    pub(super) owner: OwnerId,
    pub(super) operation: Win16Ole1OperationId,
    pub(super) object_id: u64,
    pub(super) slot: u8,
    call: Option<super::client_dde::Win16Ole1ClientDdeCallId>,
    item_atom: Option<u16>,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    next_application: Option<Vec<u8>>,
    next_document: Option<Vec<u8>>,
    endpoint: Option<crate::Win16HostClassicDdeEndpoint>,
    endpoint_operation: Option<Win16Ole1OperationId>,
    document_responder: Option<super::Win16Ole1InitiateResponder>,
    system_responder: Option<super::Win16Ole1InitiateResponder>,
    retirement_status: Win16Ole1Status,
    stage: Stage,
}

impl Win16State {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_ole1_dde_object_method(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        record: Win16Ole1DdeObjectProxyRecord,
        slot: u8,
        arguments: &[Win16Argument],
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if self
            .ole1_client_documents
            .pending_dde_methods
            .iter()
            .any(|sequence| sequence.object_id == record.id)
        {
            return self.complete_dde_method_return(cpu, return_to, OLE1_BUSY);
        }
        if record.owner
            != self.tasks.current().ok_or_else(|| {
                dde_error(
                    Kind::InternalInvariant,
                    "DDE-backed OLE1 method has no current task owner",
                )
            })?
        {
            return Err(dde_error(
                Kind::InvalidInput,
                "DDE-backed OLE1 method ran under a different task owner",
            ));
        }
        if slot == 1 {
            return self.begin_dde_object_release(cpu, host, memory, record, return_to);
        }
        if matches!(slot, 24 | 25) {
            return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_NOT_LINK);
        }
        if slot == 21 {
            return self.return_dde_method_gap(
                cpu, host, return_to, OLE1_ERROR_UPDATE,
                "OLE1 Update requires a checked linked-item request/ACK or object-local update contract",
            );
        }
        if !matches!(slot, 11 | 20) {
            return self.complete_dde_method_gap_slot(
                cpu, host, return_to, slot, &record, arguments, memory,
            );
        }
        if slot == 20 && record.closed {
            return self.complete_dde_method_return(cpu, return_to, OLE1_OK);
        }

        let mut next_application = None;
        let mut next_document = None;
        if slot != 20 {
            let (
                Some(Win16Argument::Dword(application_far)),
                Some(Win16Argument::Dword(document_far)),
            ) = (arguments.get(1), arguments.get(2))
            else {
                return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_ADDRESS);
            };
            let application = match self.decode_dde_host_name(*application_far, memory) {
                Ok(name) => name,
                Err(status) => return self.complete_dde_method_return(cpu, return_to, status),
            };
            let document = match self.decode_dde_host_name(*document_far, memory) {
                Ok(name) => name,
                Err(status) => return self.complete_dde_method_return(cpu, return_to, status),
            };
            next_application = Some(application);
            next_document = Some(document);
        }
        if slot == 11 && record.closed {
            let current = self
                .ole1_client_documents
                .dde_object_proxies
                .iter_mut()
                .find(|current| current.id == record.id)
                .ok_or_else(|| {
                    dde_error(
                        Kind::InternalInvariant,
                        "closed OLE1 object lost its host-name storage",
                    )
                })?;
            current.client_application = next_application.unwrap_or_default();
            current.document_name = next_document.unwrap_or_default();
            return self.complete_dde_method_return(cpu, return_to, OLE1_OK);
        }
        let mut message = if let (Some(application), Some(document)) =
            (next_application.as_deref(), next_document.as_deref())
        {
            let format = host.win16_register_clipboard_format(Some(b"Binary"))?;
            if format == 0 {
                return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_MEMORY);
            }
            match host_names::poke_message(format, application, document) {
                Ok(message) => message,
                Err(status) => return self.complete_dde_method_return(cpu, return_to, status),
            }
        } else {
            match stdexecute::encode_win16_ole1_std_execute(
                Win16Ole1StdExecuteCommand::CloseDocument,
            ) {
                Ok(bytes) => crate::Win16ClassicDdeMessage::Execute {
                    global: crate::Win16ClassicDdeGlobalBlock {
                        transfer: None,
                        guest_global: None,
                        bytes,
                    },
                },
                Err(error) => {
                    let (status, detail) = match error {
                        stdexecute::Win16Ole1StdExecuteError::Syntax => (
                            OLE1_ERROR_ADDRESS,
                            "host/document names cannot be encoded as a valid StdExecute command",
                        ),
                        stdexecute::Win16Ole1StdExecuteError::SizeLimit => (
                            OLE1_ERROR_MEMORY,
                            "StdExecute command exceeds DDE block capacity",
                        ),
                        stdexecute::Win16Ole1StdExecuteError::ResourceExhausted => {
                            (OLE1_ERROR_MEMORY, "StdExecute command allocation failed")
                        }
                    };
                    return self.return_dde_method_gap(cpu, host, return_to, status, detail);
                }
            }
        };
        let operation = self
            .ole1_client_documents
            .reserve_operation()
            .map_err(|status| {
                dde_error(
                    Kind::ResourceExhausted,
                    format!("reserve DDE-backed OLE1 method operation (status {status})"),
                )
            })?;
        self.ole1_client_documents
            .pending_dde_methods
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DDE-backed OLE1 method continuation",
                    error,
                )
            })?;
        let index = self.ole1_client_documents.pending_dde_methods.len();
        self.ole1_client_documents
            .pending_dde_methods
            .push(Win16Ole1DdeObjectMethodSequence {
                owner: record.owner,
                operation,
                object_id: record.id,
                slot,
                call: None,
                item_atom: None,
                return_to,
                return_kind: Win16ReturnKind::Word,
                next_application,
                next_document,
                endpoint: Some(record.endpoint),
                endpoint_operation: Some(record.operation_id),
                document_responder: (!record.document_conversation_retired).then_some(
                    super::Win16Ole1InitiateResponder {
                        peer: record.document_peer,
                        conversation: record.document_conversation,
                    },
                ),
                system_responder: (!record.system_conversation_retired).then_some(
                    super::Win16Ole1InitiateResponder {
                        peer: record.system_peer,
                        conversation: record.system_conversation,
                    },
                ),
                retirement_status: OLE1_OK,
                stage: Stage::AwaitExecutePost,
            });
        let (sent_message, expected) = if let crate::Win16ClassicDdeMessage::Poke { item, .. } =
            &mut message
        {
            let name = host_names::HOST_NAMES_ITEM.to_vec();
            let atom =
                match self.global_add_atom(win16_abi::Win16AtomName::String(name.clone()), host) {
                    Ok(0) => {
                        self.ole1_client_documents.pending_dde_methods.remove(index);
                        return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_MEMORY);
                    }
                    Ok(atom) => atom,
                    Err(error) => {
                        self.ole1_client_documents.pending_dde_methods.remove(index);
                        return Err(error);
                    }
                };
            // Record the exact reference before POST preparation or begin can
            // fail. Owner inventory keeps this sequence until its atom retires.
            self.ole1_client_documents.pending_dde_methods[index].item_atom = Some(atom);
            *item = Some(crate::Win16ClassicDdeAtom::Name {
                guest_value: Some(atom),
                name_bytes: name.clone(),
            });
            (
                WM_DDE_POKE,
                Win16Ole1ExpectedReply::ItemAck {
                    item_atom: atom,
                    item_name: name,
                },
            )
        } else {
            (WM_DDE_EXECUTE, Win16Ole1ExpectedReply::ExecuteAck)
        };
        let disposition = match self
            .ole1_client_documents
            .client_dde
            .prepare_post_transaction(
                operation,
                record.owner,
                record.endpoint,
                record.document_peer,
                record.document_conversation,
                sent_message,
                expected,
                message,
            ) {
            Ok(disposition) => disposition,
            Err(message) => {
                host_names::retire_item_atom(self, index, host)?;
                self.ole1_client_documents.pending_dde_methods.remove(index);
                return Err(dde_error(Kind::InvalidInput, message));
            }
        };
        let call_id = self
            .ole1_client_documents
            .client_dde
            .pending_call_for_operation(operation, record.owner)
            .map_err(|message| dde_error(Kind::InternalInvariant, message))?;
        let Win16Ole1ClientDdeDisposition::HostCall { call, .. } = disposition else {
            return Err(dde_error(
                Kind::InternalInvariant,
                "DDE-backed OLE1 method did not prepare an exact host POST",
            ));
        };
        self.ole1_client_documents.pending_dde_methods[index].call = Some(call_id);
        self.begin_classic_dde_host_call(
            call,
            super::super::classic_dde_dispatch::ClassicDdeOperationOwner::Client {
                owner: record.owner,
                operation,
                bind_initiate: false,
            },
            None,
            host,
        )?;
        let _ = (dos, memory);
        Ok(None)
    }

    fn begin_dde_object_release(
        &mut self,
        cpu: &mut Cpu,
        host: &mut impl RuntimeHost,
        _memory: &mut Memory,
        record: Win16Ole1DdeObjectProxyRecord,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if self
            .ole1_client_documents
            .client_dde
            .endpoint_has_pending_traffic(record.owner, record.endpoint)
        {
            return self.complete_dde_method_return(cpu, return_to, OLE1_BUSY);
        }
        if self
            .ole1_client_documents
            .pending_dde_methods
            .try_reserve(1)
            .is_err()
        {
            return self.complete_dde_method_return(cpu, return_to, OLE1_ERROR_MEMORY);
        }
        let operation = match self.ole1_client_documents.reserve_operation() {
            Ok(operation) => operation,
            Err(status) => return self.complete_dde_method_return(cpu, return_to, status),
        };
        if let Err(status) = self
            .ole1_client_documents
            .reserve_pending_operation(record.document)
        {
            self.ole1_client_documents.finish_operation(operation);
            return self.complete_dde_method_return(cpu, return_to, status);
        }
        if let Err(status) = self.ole1_client_documents.begin_pending_release(
            record.document,
            operation,
            None,
            record.object_far,
        ) {
            self.ole1_client_documents.finish_operation(operation);
            return self.complete_dde_method_return(cpu, return_to, status);
        }
        self.ole1_client_documents
            .pending_dde_methods
            .push(Win16Ole1DdeObjectMethodSequence {
                owner: record.owner,
                operation,
                object_id: record.id,
                slot: 1,
                call: None,
                item_atom: None,
                return_to,
                return_kind: Win16ReturnKind::Word,
                next_application: None,
                next_document: None,
                endpoint: Some(record.endpoint),
                endpoint_operation: Some(record.operation_id),
                document_responder: (!record.document_conversation_retired).then_some(
                    super::Win16Ole1InitiateResponder {
                        peer: record.document_peer,
                        conversation: record.document_conversation,
                    },
                ),
                system_responder: (!record.system_conversation_retired).then_some(
                    super::Win16Ole1InitiateResponder {
                        peer: record.system_peer,
                        conversation: record.system_conversation,
                    },
                ),
                retirement_status: OLE1_OK,
                stage: if !record.document_conversation_retired {
                    Stage::RetireDocumentConversation
                } else if !record.system_conversation_retired {
                    Stage::RetireSystemConversation
                } else {
                    Stage::RetireEndpoint
                },
            });
        let prepared = if !record.document_conversation_retired {
            self.prepare_ole1_client_dde_conversation_retirement(
                operation,
                record.owner,
                record.endpoint,
                record.document_peer,
                record.document_conversation,
            )
        } else if !record.system_conversation_retired {
            self.prepare_ole1_client_dde_conversation_retirement(
                operation,
                record.owner,
                record.endpoint,
                record.system_peer,
                record.system_conversation,
            )
        } else {
            self.ole1_client_documents
                .client_dde
                .prepare_client_endpoint_retirement(
                    operation,
                    record.operation_id,
                    record.owner,
                    record.endpoint,
                )
                .map_err(|message| dde_error(Kind::InvalidInput, message))
        };
        let disposition = match prepared {
            Ok(disposition) => disposition,
            Err(primary) => {
                return Err(primary.with_context(
                    "prepare exact DDE-backed OLE1 Release conversation retirement",
                ));
            }
        };
        self.begin_dde_release_host_call(disposition, record.owner, operation, host)?;
        Ok(None)
    }

    fn begin_dde_release_host_call(
        &mut self,
        disposition: Win16Ole1ClientDdeDisposition,
        owner: OwnerId,
        operation: Win16Ole1OperationId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Win16Ole1ClientDdeDisposition::HostCall { call, .. } = disposition else {
            return Err(dde_error(
                Kind::InternalInvariant,
                "DDE-backed OLE1 Release did not produce its exact host action",
            ));
        };
        self.begin_classic_dde_host_call(
            call,
            super::super::classic_dde_dispatch::ClassicDdeOperationOwner::Client {
                owner,
                operation,
                bind_initiate: false,
            },
            None,
            host,
        )
        .map(|_| ())
    }

    pub(super) fn complete_dde_method_return(
        &mut self,
        cpu: &mut Cpu,
        return_to: (u16, u16, u32),
        status: Win16Ole1Status,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            u32::from(status),
            Win16ReturnKind::Word,
        )
    }
}

fn dde_error(kind: Kind, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(kind, message)
}
