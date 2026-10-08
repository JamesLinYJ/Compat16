//! Owner-scoped OLE1 `StdFileEditing` creation over the checked classic-DDE
//! client journal. An object FAR is published only after both the system
//! execute ACK and the exact document-topic conversation have completed.

#[path = "win16_ole1_creation_dde_actions.rs"]
mod actions;
#[path = "win16_ole1_creation_dde_events.rs"]
mod events;

use actions::*;
pub(super) use events::{advance_event_ack, advance_sequence, process_committed_event};

#[path = "win16_ole1_creation_dde_cleanup.rs"]
mod cleanup;
#[path = "win16_ole1_creation_dde_return.rs"]
mod return_path;

use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use win16_abi::{SegmentedPointer, Win16ReturnKind};
use x86_cpu::Cpu;

use self::cleanup::finish_failed_creation;
use self::return_path::finish_successful_creation;
use super::creation_dde_helpers::{copy_bytes, dde_error, dde_status_error};
use super::{
    OLE1_ERROR_COMMAND, OLE1_ERROR_LAUNCH, OLE1_ERROR_MEMORY, OLE1_ERROR_OPEN, OLE1_OK,
    Win16Ole1ClientDocHandle, Win16Ole1ClientProxyId, Win16Ole1OperationId, Win16Ole1Status,
    Win16State,
    client_dde::{
        Win16Ole1ClientDdeCallId, Win16Ole1ClientDdeCommittedResponse,
        Win16Ole1ClientDdeDisposition, Win16Ole1ExpectedReply, Win16Ole1InitiatePurpose,
        Win16Ole1InitiateResponder,
    },
    dde_object_proxy::Win16Ole1DdeObjectProxySpec,
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeEventId, Win16ClassicDdeMessage, Win16HostClassicDdeEndpoint,
    Win16HostClassicDdeEvent,
};

const WM_DDE_EXECUTE: u16 = 0x03e8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    AwaitEndpoint,
    AwaitInitiate,
    PublishedReturn,
    AwaitExecutePost,
    AwaitExecuteResponse,
    AwaitExecuteDeliveryAck(Win16ClassicDdeEventId),
    AwaitClosePost,
    AwaitCloseResponse,
    AwaitCloseDeliveryAck(Win16ClassicDdeEventId),
    RetireDocumentConversation,
    RetireSystemConversation,
    RetireEndpoint,
}

/// State for one checked OLE1 create call. Owner IDs, conversations, event
/// IDs and the public OLE sequence remain independent exact identities.
#[derive(Debug)]
pub(super) struct Win16Ole1DdeCreateSequence {
    pub(super) owner: OwnerId,
    operation: Win16Ole1OperationId,
    document: Win16Ole1ClientDocHandle,
    client_far: u32,
    client_proxy_id: Win16Ole1ClientProxyId,
    client_proxy_allocation: win16_abi::GlobalHandle,
    output: SegmentedPointer,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    endpoint: Option<Win16HostClassicDdeEndpoint>,
    system: Option<Win16Ole1InitiateResponder>,
    document_conversation: Option<Win16Ole1InitiateResponder>,
    initiate_purpose: Option<Win16Ole1InitiatePurpose>,
    stage: Stage,
    execute_call: Option<Win16Ole1ClientDdeCallId>,
    close_call: Option<Win16Ole1ClientDdeCallId>,
    close_target: Option<Win16Ole1InitiateResponder>,
    execute_accepted: bool,
    close_accepted: bool,
    failure_status: Option<Win16Ole1Status>,
    failure_detail: Option<&'static str>,
    fatal: Option<RuntimeError>,
    server_application: Vec<u8>,
    client_application: Vec<u8>,
    document_name: Vec<u8>,
    class_name: Vec<u8>,
    object_name: Vec<u8>,
    document_topic: Vec<u8>,
    published_object_far: Option<u32>,
    client_proxy_retired: bool,
}

impl Win16State {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_dde_ole1_creation(
        &mut self,
        owner: OwnerId,
        document: Win16Ole1ClientDocHandle,
        client_far: u32,
        output: SegmentedPointer,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        server_application: Vec<u8>,
        class_name: Vec<u8>,
        object_name: Vec<u8>,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u8>, RuntimeError> {
        if owner.0 == 0 || client_far == 0 {
            return Err(dde_error(
                Kind::InternalInvariant,
                "OLE1 DDE creation requires an exact task owner and client callback",
            ));
        }
        let Some(document_record) = self.ole1_client_documents.documents.get(&document) else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(super::OLE1_ERROR_HANDLE),
                return_kind,
            );
        };
        let client_application =
            copy_bytes(&document_record.class_name, "copy OLE1 client application")?;
        let document_name = copy_bytes(
            &document_record.document_name,
            "copy OLE1 client document name",
        )?;
        if client_application.is_empty() || document_name.is_empty() {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(super::OLE1_ERROR_NAME),
                return_kind,
            );
        }
        let serial = self
            .ole1_client_documents
            .next_embedded_topic_serial
            .take_next();
        let document_topic = match super::client_dde::embedded_document_topic(
            &client_application,
            &document_name,
            &object_name,
            serial,
        ) {
            Ok(topic) => topic,
            Err(_) => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(super::OLE1_ERROR_NAME),
                    return_kind,
                );
            }
        };
        self.ole1_client_documents
            .pending_dde_creations
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DDE-backed OLE1 creation sequence",
                    error,
                )
            })?;
        self.ole1_client_documents
            .pending_dde_client_proxy_retirements
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DDE OLE1 client-proxy cleanup lease",
                    error,
                )
            })?;
        if let Err(status) = self
            .ole1_client_documents
            .reserve_pending_operation(document)
        {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(status),
                return_kind,
            );
        }
        let operation = match self.ole1_client_documents.reserve_operation() {
            Ok(operation) => operation,
            Err(status) => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    return_kind,
                );
            }
        };
        let (proxy_far, client_proxy_id) =
            match self.ole1_client_proxy_for_call(client_far, Some(operation), memory) {
                Ok(proxy) => proxy,
                Err(error) => {
                    self.ole1_client_documents.finish_operation(operation);
                    return match error.status_or_runtime() {
                        Ok(status) => self.complete_return(
                            &mut cpu.regs,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            u32::from(status),
                            return_kind,
                        ),
                        Err(error) => Err(error),
                    };
                }
            };
        let _ = proxy_far;
        let client_proxy_allocation = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| {
                binding.id == client_proxy_id
                    && binding.operation_id == Some(operation)
                    && binding.client_far == client_far
            })
            .map(|binding| binding.allocation)
            .ok_or_else(|| {
                dde_error(
                    Kind::InternalInvariant,
                    "DDE creation callback proxy lost its exact operation allocation",
                )
            })?;
        if let Err(status) = self
            .ole1_client_documents
            .begin_pending_creation(
                document,
                operation,
                None,
                None,
                super::Win16Ole1SourceProbePolicy::ProbeCreateAsync,
                None,
                None,
                client_far,
                super::Win16Ole1ReleaseMethodExpectation::FromNotification,
            )
            .and_then(|()| {
                self.ole1_client_documents
                    .set_pending_creation_proxy(operation, client_proxy_id)
            })
        {
            self.ole1_client_documents.finish_operation(operation);
            match self.try_retire_ole1_dde_client_proxy(client_proxy_id, client_proxy_allocation) {
                Ok(true) => {}
                Ok(false) => {
                    self.track_ole1_dde_client_proxy_retirement(
                        owner,
                        client_proxy_id,
                        client_proxy_allocation,
                    )?;
                    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "OLE1 DDE creation setup failed; its callback proxy remains pinned until callback retirement"));
                }
                Err(cleanup) => {
                    if let Err(track) = self.track_ole1_dde_client_proxy_retirement(
                        owner,
                        client_proxy_id,
                        client_proxy_allocation,
                    ) {
                        return Err(cleanup.with_cleanup(
                            "retain exact owner for failed OLE1 DDE callback-proxy retirement",
                            track,
                        ));
                    }
                    return Err(dde_status_error(status, "bind OLE1 DDE creation proxy")
                        .with_cleanup("retire failed OLE1 DDE client proxy", cleanup));
                }
            }
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(status),
                return_kind,
            );
        }
        let sequence = Win16Ole1DdeCreateSequence {
            owner,
            operation,
            document,
            client_far,
            client_proxy_id,
            output,
            return_to,
            return_kind,
            endpoint: None,
            system: None,
            document_conversation: None,
            initiate_purpose: None,
            stage: Stage::AwaitEndpoint,
            execute_call: None,
            close_call: None,
            close_target: None,
            execute_accepted: false,
            close_accepted: false,
            failure_status: None,
            failure_detail: None,
            fatal: None,
            server_application,
            client_application,
            document_name,
            class_name,
            object_name,
            document_topic,
            published_object_far: None,
            client_proxy_allocation,
            client_proxy_retired: false,
        };
        self.ole1_client_documents
            .pending_dde_creations
            .push(sequence);
        let disposition = self
            .ole1_client_documents
            .client_dde
            .prepare_endpoint_call(operation, owner)
            .map_err(|message| dde_error(Kind::InternalInvariant, message))?;
        let Win16Ole1ClientDdeDisposition::HostCall { call, .. } = disposition else {
            return Err(dde_error(
                Kind::InternalInvariant,
                "OLE1 DDE endpoint preparation did not return a host call",
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
        )?;
        let _ = (dos, host);
        Ok(None)
    }
}
