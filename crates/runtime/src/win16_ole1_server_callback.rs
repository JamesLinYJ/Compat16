//! Checked OLE1 server callback plans and resumable DDE completion data.
//!
//! This module never calls guest code directly. It returns a FAR procedure
//! plus ABI-typed arguments for the runtime's existing checked callback gate,
//! and retains the exact DDE endpoint/event/global-memory generations until
//! the callback and protocol response have both completed.

use super::far_callback::{Win16FarCallbackArgument, Win16FarCallbackReturn};
use crate::{
    Win16ClassicDdeAckStatus, Win16ClassicDdeAckValue, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeEventId, Win16ClassicDdeMessage, Win16ClassicDdeOperationIdentity,
    Win16ClassicDdeTransactionId, Win16ClassicDdeTransferId, Win16HostClassicDdeCall,
    Win16HostClassicDdeCallbackReply, Win16HostClassicDdeCallbackResult,
    Win16HostClassicDdeCallbackStep, Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
    Win16HostClassicDdePeer, Win16HostClassicDdePostReceipt, Win16HostClassicDdeResult,
    Win16HostClassicDdeResume, Win16HostClassicDdeStep,
};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use std::sync::Arc;
use win16_abi::{Access, AllocationFlags};

use super::win16_ole1_server_callbacks::{
    ServerCallbackArguments, ServerCallbackMethod, ServerDocumentCallbackArguments,
    ServerDocumentCallbackMethod,
};
use super::win16_ole1_server_execute::{ServerExecuteCommand, parse_server_execute};
use super::win16_ole1_server_registration::server_has_protocol;
use super::win16_ole1_server_state::{
    OLE_BUSY, OLE_ERROR_COMMAND, OLE_ERROR_HANDLE, OLE_ERROR_MEMORY, OLE_ERROR_NAME,
    OLE_ERROR_OBJECT, OLE_ERROR_PROTOCOL, OLE_ERROR_SERVER_BLOCKED, OLE_ERROR_TERMINATE, OLE_OK,
    Ole1ReleaseTarget, Ole1ServerDocumentHandle, Ole1ServerHandle,
    Ole1ServerPreparedCallbackScratch,
};
use crate::{RuntimeError, RuntimeHost, Win16HostAtomName};

/// One exact server/document callback target. Generations are checked again
/// after guest code returns because callbacks may re-enter OLE and revoke or
/// replace unrelated records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerCallbackTarget {
    Server {
        handle: Ole1ServerHandle,
        generation: u64,
    },
    Document {
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    },
}

/// Identity for a provisional document created only to satisfy an Open,
/// Create, CreateFromTemplate, or Edit callback. The output FAR and endpoint
/// are bound to the exact owner/server/document generations; neither is
/// reconstructed from guest LONGs after callback re-entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Ole1ServerPreparedDocumentCallback {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) server: Ole1ServerHandle,
    pub(in crate::win16_runtime) server_generation: u64,
    pub(in crate::win16_runtime) document: Ole1ServerDocumentHandle,
    pub(in crate::win16_runtime) document_generation: u64,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) worker_generation: u64,
    pub(in crate::win16_runtime) method: ServerCallbackMethod,
    pub(in crate::win16_runtime) output_far: u32,
}

/// Protocol action retained while an OLESERVER/OLESERVERDOC slot executes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerCallbackCompletion {
    /// A guest `Execute` callback must be followed by the real DDE ACK whose
    /// high word is correlated to this exact transfer. Posting that ACK is a
    /// separate host operation; it is not inferred from the callback return.
    DdeExecute {
        event: Win16HostClassicDdeEvent,
        target: Ole1ServerCallbackTarget,
        transfer: Win16ClassicDdeTransferId,
        global_handle: u16,
        global_generation: u64,
        /// Only StdCloseDocument may synchronously revoke its own exact
        /// document while its Execute callback is active.
        allow_document_self_retirement: bool,
        /// Present only while a provisional document Open/Create/Edit callback
        /// owns its exact output buffer and child endpoint.
        prepared_document: Option<Ole1ServerPreparedDocumentCallback>,
    },
    /// A queued peer TERMINATE closed the last conversation for a revoking
    /// server/document. The callback and following atom/endpoint cleanup are
    /// owned by that exact EventId until its delivery acknowledgement.
    DdeRelease {
        event: Win16HostClassicDdeEvent,
        target: Ole1ServerCallbackTarget,
        release_target: Ole1ReleaseTarget,
        journal_id: u64,
    },
}

/// Runtime-owned callback plan. `procedure` remains a guest FAR token and is
/// revalidated by `enter_guest_far_callback_checked` at entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Ole1ServerGuestCallbackPlan {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) target: Ole1ServerCallbackTarget,
    pub(in crate::win16_runtime) procedure: u32,
    pub(in crate::win16_runtime) arguments: Vec<Win16FarCallbackArgument>,
    pub(in crate::win16_runtime) return_kind: Win16FarCallbackReturn,
    pub(in crate::win16_runtime) completion: Ole1ServerCallbackCompletion,
}

// Preparation stays private to checked callback frames while its document
// allocation and publication logic lives in a separate responsibility module.
#[path = "win16_ole1_server_callback/document.rs"]
mod document;
#[path = "win16_ole1_server_callback/prepare.rs"]
mod prepare;

/// Exact continuation from a host DDE callback through guest code and back to
/// the suspended native WndProc. The endpoint/frame/event identity must not be
/// reconstructed from guest HWNDs or copied command bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Ole1ServerDdeContinuation {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) event_id: Win16ClassicDdeEventId,
    /// The host-owned exact callback source. This remains live until the
    /// runtime calls `win16_classic_dde_resume` with a reply derived from it.
    pub(in crate::win16_runtime) callback_step: Option<Win16HostClassicDdeCallbackStep>,
    pub(in crate::win16_runtime) operation: Option<Win16ClassicDdeOperationIdentity>,
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
    pub(in crate::win16_runtime) server: Ole1ServerHandle,
    pub(in crate::win16_runtime) server_generation: u64,
    pub(in crate::win16_runtime) document: Option<Ole1ServerDocumentHandle>,
    pub(in crate::win16_runtime) document_generation: Option<u64>,
    /// Exact StdCloseDocument identity reserved before checked guest entry.
    /// The dispatcher cancels it if entry fails; the matching Execute ACK
    /// terminal receipt consumes it after the guest callback returns.
    pub(in crate::win16_runtime) close_document_proof:
        Option<(OwnerId, Ole1ServerDocumentHandle, u64)>,
    pub(in crate::win16_runtime) completion: Ole1ServerCallbackCompletion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerDdeAfterPost {
    ResumeSynchronousWindow {
        reply: Win16HostClassicDdeCallbackReply,
        expected_conversation: crate::Win16ClassicDdeConversationId,
        expected_transaction: Option<Win16ClassicDdeTransactionId>,
        expected_transfer: Win16ClassicDdeTransferId,
        close_document_proof: Option<(OwnerId, Ole1ServerDocumentHandle, u64)>,
    },
    AcknowledgeQueuedEvent {
        event: Win16HostClassicDdeEvent,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: Win16ClassicDdeEventId,
        worker_generation: u64,
        peer: Win16HostClassicDdePeer,
        conversation: Option<crate::Win16ClassicDdeConversationId>,
        transaction: Option<Win16ClassicDdeTransactionId>,
        transfer: Win16ClassicDdeTransferId,
        close_document_proof: Option<(OwnerId, Ole1ServerDocumentHandle, u64)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerGuestCallbackFinish {
    /// Start a separate classic-DDE operation. Its receipt must be checked
    /// against the retained continuation before the next action is returned.
    BeginHostCall {
        call: Win16HostClassicDdeCall,
        continuation: Ole1ServerDdeHostContinuation,
    },
    /// Resume the exact suspended native DDE WndProc. This is not a new
    /// operation and must be sent through `win16_classic_dde_resume`.
    Resume { resume: Win16HostClassicDdeResume },
    /// A queued mailbox event may be acknowledged only after its exact
    /// business continuation has completed.
    Complete,
    /// Continue the same queued TERMINATE after one Release callback. A
    /// document release may be followed by other ready documents and finally
    /// its revoking parent server.
    GuestCallback {
        plan: Ole1ServerGuestCallbackPlan,
        continuation: Ole1ServerDdeContinuation,
    },
    /// Keep the release cascade alive while the dispatcher drains the exact
    /// mailbox EventIds that prevent endpoint retirement.
    PendingEndpointEvents {
        event: Win16HostClassicDdeEvent,
        target: super::win16_ole1_server_state::Ole1ReleaseTarget,
        endpoint: Win16HostClassicDdeEndpoint,
        pending_events: Vec<crate::Win16ClassicDdeEventId>,
    },
    /// A queued release remains retained while the dispatcher waits for the
    /// server to unblock. It must not acknowledge or discard the EventId.
    DeferredQueuedEvent { event: Win16HostClassicDdeEvent },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerDdeHostContinuation {
    ExecuteAcknowledgement(Ole1ServerDdeAfterPost),
    QueuedEventAcknowledgement {
        event: Win16HostClassicDdeEvent,
    },
    TerminateResponse {
        event: Win16HostClassicDdeEvent,
        target: super::win16_ole1_server_state::Ole1TerminationTarget,
        callback_step: Option<Win16HostClassicDdeCallbackStep>,
    },
    EventAcknowledgement {
        event: Win16HostClassicDdeEvent,
        /// A release chain remains live until this exact delivery receipt.
        /// Other queued deliveries only retire their mailbox EventId.
        release_chain: bool,
    },
}

include!("win16_ole1_server_callback_finish.rs");

pub(super) fn validate_execute_ack_receipt(
    expected: &Ole1ServerDdeAfterPost,
    receipt: &Win16HostClassicDdePostReceipt,
) -> bool {
    match expected {
        Ole1ServerDdeAfterPost::ResumeSynchronousWindow {
            reply,
            expected_conversation,
            expected_transaction,
            expected_transfer,
            ..
        } => {
            receipt.owner == reply.owner
                && receipt.endpoint == reply.endpoint
                && receipt.peer == reply.peer
                && receipt.conversation == Some(*expected_conversation)
                && receipt.transaction == *expected_transaction
                && receipt.transfer == Some(*expected_transfer)
                && receipt.message == crate::WM_DDE_ACK
                && receipt.queued
        }
        Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
            owner,
            endpoint,
            peer,
            conversation,
            transaction,
            transfer,
            ..
        } => {
            receipt.owner == *owner
                && receipt.endpoint == *endpoint
                && receipt.peer == *peer
                && receipt.conversation == *conversation
                && receipt.transaction == *transaction
                && receipt.transfer == Some(*transfer)
                && receipt.message == crate::WM_DDE_ACK
                && receipt.queued
        }
    }
}

pub(super) fn next_execute_completion_action(
    after: &Ole1ServerDdeAfterPost,
    receipt: &Win16HostClassicDdePostReceipt,
) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
    if !validate_execute_ack_receipt(after, receipt) {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 Execute acknowledgement receipt does not match its exact DDE continuation",
        ));
    }
    match after {
        Ole1ServerDdeAfterPost::ResumeSynchronousWindow { reply, .. } => {
            let operation = Win16ClassicDdeOperationIdentity {
                owner: reply.owner,
                id: reply.operation_id,
                worker_generation: reply.worker_generation,
            };
            Ok(Ole1ServerGuestCallbackFinish::Resume {
                resume: Win16HostClassicDdeResume {
                    operation,
                    reply: Some(reply.clone()),
                },
            })
        }
        Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
            event,
            owner,
            endpoint,
            event_id,
            ..
        } => Ok(Ole1ServerGuestCallbackFinish::BeginHostCall {
            call: Win16HostClassicDdeCall::AcknowledgeEvent {
                owner: *owner,
                endpoint: *endpoint,
                event_id: *event_id,
            },
            continuation: Ole1ServerDdeHostContinuation::QueuedEventAcknowledgement {
                event: event.clone(),
            },
        }),
    }
}

/// Consume the terminal proof for one host operation started by the OLE1
/// server route. A receipt without its matching operation/source-retirement
/// identity cannot resume the guest callback or retire a mailbox event.
pub(in crate::win16_runtime) fn finish_ole1_server_dde_host_call(
    state: &mut super::Win16State,
    continuation: &Ole1ServerDdeHostContinuation,
    expected_operation: Win16ClassicDdeOperationIdentity,
    step: &Win16HostClassicDdeStep,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
    let Win16HostClassicDdeStep::Complete {
        operation,
        result,
        source_retired,
    } = step
    else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 server host continuation received a nonterminal classic-DDE step",
        ));
    };
    if *operation != expected_operation || *operation != source_retired.operation {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "classic-DDE terminal step lost its exact source-retirement operation identity",
        ));
    }
    if !source_retired.callbacks.is_empty() {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 queued host continuation unexpectedly retired a guest DDE callback",
        ));
    }
    match continuation {
        Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(after) => {
            let Win16HostClassicDdeResult::Posted(receipt) = result else {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 Execute ACK operation completed without a Post receipt",
                ));
            };
            let finish = next_execute_completion_action(after, receipt)?;
            let close_document_proof = match after {
                Ole1ServerDdeAfterPost::ResumeSynchronousWindow {
                    close_document_proof,
                    ..
                }
                | Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
                    close_document_proof,
                    ..
                } => *close_document_proof,
            };
            if let Some((owner, handle, generation)) = close_document_proof {
                state
                    .ole1_server_state
                    .finish_close_document_callback_post(owner, handle, generation)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("StdCloseDocument identity proof changed ({status})"),
                        )
                    })?;
            }
            Ok(finish)
        }
        Ole1ServerDdeHostContinuation::QueuedEventAcknowledgement { event } => {
            if operation.owner != event.owner
                || operation.worker_generation != event.worker_generation
                || event.delivery != crate::Win16ClassicDdeDeliveryKind::Queued
                || !matches!(result, Win16HostClassicDdeResult::EventAcknowledged(actual) if *actual == event.event_id)
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 queued DDE EventId acknowledgement did not match its exact owner/generation",
                ));
            }
            state.finish_pending_dde_release_after_event_ack(event, memory, host)
        }
        Ole1ServerDdeHostContinuation::TerminateResponse {
            event,
            target,
            callback_step,
        } => {
            if operation.owner != event.owner
                || operation.worker_generation != event.worker_generation
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 TERMINATE response operation changed event owner or worker generation",
                ));
            }
            let exact_sync_source = match (event.delivery, callback_step.as_ref()) {
                (Win16ClassicDdeDeliveryKind::Queued, None) => true,
                (
                    Win16ClassicDdeDeliveryKind::Synchronous {
                        operation_id,
                        callback,
                        frame,
                    },
                    Some(step),
                ) => {
                    step.owner == event.owner
                        && step.endpoint == event.endpoint
                        && step.worker_generation == event.worker_generation
                        && step.operation_id == operation_id
                        && step.callback == callback
                        && step.frame == frame
                        && step.event == *event
                }
                _ => false,
            };
            if !exact_sync_source {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 TERMINATE response lost its exact synchronous source step",
                ));
            }
            let Win16ClassicDdeMessage::Terminate = &event.message else {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 TERMINATE response continuation lost its message",
                ));
            };
            let Some(conversation) = event.conversation else {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 TERMINATE response continuation lost its conversation",
                ));
            };
            let Win16HostClassicDdeResult::Posted(receipt) = result else {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 peer TERMINATE response completed without a Post receipt",
                ));
            };
            if receipt.owner != event.owner
                || receipt.endpoint != event.endpoint
                || receipt.peer != event.peer
                || receipt.conversation != Some(conversation)
                || receipt.message != crate::WM_DDE_TERMINATE
                || !receipt.queued
                || receipt.transfer.is_some()
                || receipt.transaction.is_some()
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 peer TERMINATE Post receipt changed its exact target",
                ));
            }
            let retired = state
                .ole1_server_state
                .retire_terminated_conversation(
                    event.owner,
                    *target,
                    conversation,
                    event.peer,
                    false,
                )
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("cannot retire exact OLE1 TERMINATE conversation ({status})"),
                    )
                })?;
            if !retired {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 TERMINATE response receipt found no exact live conversation",
                ));
            }
            let disposition = state.begin_release_after_terminate(
                event,
                callback_step.as_ref().map(|step| Arc::new(step.clone())),
                *target,
                memory,
                host,
            )?;
            super::win16_ole1_server_dde::disposition_into_callback_finish(disposition)
        }
        Ole1ServerDdeHostContinuation::EventAcknowledgement {
            event,
            release_chain,
        } => {
            if operation.owner != event.owner
                || operation.worker_generation != event.worker_generation
                || event.delivery != crate::Win16ClassicDdeDeliveryKind::Queued
                || !matches!(result, Win16HostClassicDdeResult::EventAcknowledged(actual) if *actual == event.event_id)
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 queued event acknowledgement lost its exact owner/EventId proof",
                ));
            }
            if *release_chain
                && state
                    .ole1_server_state
                    .dde_release_chain_for_pending_event(
                        event.owner,
                        event.endpoint,
                        event.event_id,
                    )
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 DDE release EventId chain changed ({status})"),
                        )
                    })?
                    .is_none()
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "release-chain EventId ACK has no matching endpoint-retirement wait",
                ));
            }
            state.finish_pending_dde_release_after_event_ack(event, memory, host)
        }
    }
}

/// Validate completion of the separate callback-resume operation. The host
/// must return the same callback frame and retire the exact source described
/// by the reply; USER callback proof is not interchangeable with DDE proof.
pub(super) fn validate_ole1_server_callback_resume(
    resume: &Win16HostClassicDdeResume,
    step: &Win16HostClassicDdeStep,
) -> Result<(), RuntimeError> {
    let Win16HostClassicDdeStep::Complete {
        operation,
        result,
        source_retired,
    } = step
    else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 callback resume received a nonterminal classic-DDE step",
        ));
    };
    if operation != &resume.operation || source_retired.operation != resume.operation {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 callback resume terminal proof belongs to another classic-DDE operation",
        ));
    }
    match (&resume.reply, result) {
        (Some(reply), Win16HostClassicDdeResult::CallbackResumed(frame))
            if *frame == reply.frame
                && reply.owner == resume.operation.owner
                && reply.worker_generation == resume.operation.worker_generation
                && source_retired.callbacks.iter().any(|retired| {
                    retired.callback == reply.callback
                        && retired.frame == reply.frame
                        && retired.event_id == reply.event_id
                        && retired.endpoint == reply.endpoint
                        && retired.peer == reply.peer
                        && retired.result == reply.result
                }) =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 callback resume lacks the exact callback-frame retirement proof",
        )),
    }
}
