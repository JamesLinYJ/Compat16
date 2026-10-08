//! Server-side WM_DDE_INITIATE routing against exact OLE endpoint generations.
//!
//! This module only decides which runtime-owned server/document record owns an
//! INITIATE. The host still performs the original synchronous SendMessage
//! exchange through ReplyInitiate/ForwardInitiateToChild, and only its exact
//! receipt is allowed to publish a conversation binding.

use std::sync::Arc;

use super::far_callback::{Win16FarCallbackArgument, Win16FarCallbackReturn};
use super::win16_ole1_server_callback::{
    Ole1ServerCallbackCompletion, Ole1ServerCallbackTarget, Ole1ServerDdeContinuation,
    Ole1ServerDdeHostContinuation, Ole1ServerGuestCallbackFinish, Ole1ServerGuestCallbackPlan,
};
use super::win16_ole1_server_callbacks::{
    ServerCallbackArguments, ServerCallbackMethod, ServerDocumentCallbackArguments,
    ServerDocumentCallbackMethod,
};
use crate::{RuntimeError, RuntimeHost, Win16HostAtomName};
use crate::{
    Win16ClassicDdeAtom, Win16ClassicDdeConversationId, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeOperationId, Win16ClassicDdeOperationIdentity, Win16HostClassicDdeCall,
    Win16HostClassicDdeCallbackStep, Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
    Win16HostClassicDdePeer, Win16HostClassicDdeRetirementReceipt,
};
use dos_kernel::DosKernel;
use guest_core::OwnerId;
use guest_core::memory::Memory;
use x86_cpu::Cpu;

use super::CallbackFrameId;
use super::win16_ole1_server_state::{
    Ole1ConversationBinding, Ole1DocumentState, Ole1PendingReleaseEvents, Ole1RegistrationState,
    Ole1ReleasePhase, Ole1ReleaseTarget, Ole1ServerDocumentHandle, Ole1ServerHandle,
    Ole1ServerState, Ole1ServerUse, Ole1TerminationTarget, Ole1UnpublishedCleanup,
    Ole1UnpublishedCleanupAction, Ole1UnpublishedCleanupId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1PendingServerReleaseRetry {
    Completed,
    Pending(Ole1PendingReleaseEvents),
}

fn release_target_endpoint(target: Ole1ReleaseTarget) -> Win16HostClassicDdeEndpoint {
    match target {
        Ole1ReleaseTarget::Document { endpoint, .. }
        | Ole1ReleaseTarget::Server { endpoint, .. } => endpoint,
    }
}

fn validate_callback_causal_parents(
    step: &Win16HostClassicDdeCallbackStep,
) -> Result<(), RuntimeError> {
    let mut seen = Vec::with_capacity(step.causal_parents.len());
    for parent in &step.causal_parents {
        if parent.owner != step.owner
            || parent.worker_generation != step.worker_generation
            || parent.id == step.operation_id
            || seen.iter().any(|previous| previous == parent)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE callback parent chain changed owner, worker generation, or identity",
            ));
        }
        seen.push(*parent);
    }
    Ok(())
}

fn finish_exact_dde_release_chain(
    state: &mut Ole1ServerState,
    event: &Win16HostClassicDdeEvent,
) -> Result<(), RuntimeError> {
    let retired = state.finish_dde_release_chain(event).map_err(|status| {
        RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            format!("cannot retire exact OLE1 DDE release chain ({status})"),
        )
    })?;
    if !retired {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 DDE release chain disappeared before its exact terminal receipt",
        ));
    }
    Ok(())
}

// DDE route pieces are included in this module so exact event, endpoint, and
// callback-continuation identity remains private to the server family.
include!("win16_ole1_server_dde_event_and_cleanup_ledger.rs");
include!("win16_ole1_server_dde_event_routes_and_termination.rs");
include!("win16_ole1_server_dde_release_callbacks_and_continuations.rs");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct ServerInitTarget {
    pub(in crate::win16_runtime) server: Ole1ServerHandle,
    pub(in crate::win16_runtime) server_generation: u64,
    pub(in crate::win16_runtime) document: Option<Ole1ServerDocumentHandle>,
    pub(in crate::win16_runtime) document_generation: Option<u64>,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerDdeDisposition {
    /// The endpoint has a guest-window caller waiting in its exact WndProc
    /// callback frame. The runtime must issue this call before resuming it.
    HostCall {
        call: Win16HostClassicDdeCall,
        /// Present when this call's receipt should publish a runtime OLE
        /// conversation. ForwardInitiateToChild creates its own exact child
        /// event and therefore carries no parent-side binding target.
        target: Option<ServerInitTarget>,
        continuation: Option<Ole1ServerInitiateContinuation>,
    },
    /// One queued DDE business operation. Its event delivery remains owned by
    /// the caller until this continuation emits the separate AcknowledgeEvent
    /// operation. Unlike INITIATE, this is not a suspended-window host call.
    BeginHostCall {
        call: Win16HostClassicDdeCall,
        continuation: Ole1ServerDdeHostContinuation,
    },
    /// The exact queued TERMINATE arrived while the matching revocation Post
    /// is still in flight. Keep this EventId published and retry this route
    /// only after that Post's terminal receipt is consumed.
    AwaitHostOperation {
        event: Win16HostClassicDdeEvent,
        callback_step: Option<Win16HostClassicDdeCallbackStep>,
    },
    /// A server vtable method must be entered through the runtime's checked
    /// FAR gate. The continuation owns the exact event and protocol lease.
    GuestCallback {
        far: u32,
        args: Vec<Win16FarCallbackArgument>,
        return_kind: Win16FarCallbackReturn,
        continuation: Ole1ServerDdeContinuation,
    },
    /// The exact synchronous endpoint WndProc can return after its typed
    /// response host operation has completed.
    ResumeCallback {
        resume: crate::Win16HostClassicDdeResume,
    },
    /// The original queued EventId is already acknowledged; keep the runtime
    /// release journal and allow the endpoint mailbox to drain before retrying
    /// native endpoint retirement.
    ReleaseEndpointPending {
        event: Win16HostClassicDdeEvent,
        target: Ole1ReleaseTarget,
        endpoint: Win16HostClassicDdeEndpoint,
        pending_events: Vec<crate::Win16ClassicDdeEventId>,
    },
    /// A queued release chain completed after its exact EventId and endpoint
    /// retirement receipts were both consumed.
    ReleaseComplete,
    /// The endpoint was created for a registration attempt that never became
    /// guest-visible. Its exact cleanup journal owns this event: queued events
    /// are acknowledged without entering a guest vtable, and synchronous
    /// callbacks resume as untranslated WndProc messages.
    UnpublishedCleanupEvent {
        cleanup_id: Ole1UnpublishedCleanupId,
        event: Win16HostClassicDdeEvent,
    },
    /// OLE1 status for a well-formed, owned DDE Execute, including OLE_OK when
    /// a standard command is already satisfied without entering a guest slot.
    /// The dispatcher encodes the exact DDEACK/execute-transfer response and
    /// resumes or acknowledges only after its terminal receipt.
    ProtocolResult {
        event: Win16HostClassicDdeEvent,
        status: u16,
    },
    /// A blocked server holds the exact synchronous initiate until unblocked.
    /// The caller must retain the event/frame and must not send an ACK yet.
    Deferred,
    /// A blocked server retained a queued host mailbox EventId. It remains
    /// published/unacknowledged and must be routed again after unblock rather
    /// than being converted into a synchronous deferred-window record.
    DeferredEvent(Win16HostClassicDdeEvent),
    /// The event did not match a live OLE server/document endpoint.
    NotOwned,
    /// The exact endpoint is an OLE server or document, but this message needs
    /// the server protocol handler rather than INITIATE matching. Keeping the
    /// owned event here prevents client routing or a generic success reply.
    OwnedMessage(Win16HostClassicDdeEvent),
}

fn event_delivery_complete(
    event: &Win16HostClassicDdeEvent,
    release_chain: bool,
    callback_step: Option<&Arc<Win16HostClassicDdeCallbackStep>>,
) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
    match event.delivery {
        Win16ClassicDdeDeliveryKind::Queued => {
            if callback_step.is_some() {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "queued classic-DDE event unexpectedly retained a synchronous callback step",
                ));
            }
            Ok(Ole1ServerDdeDisposition::BeginHostCall {
                call: Win16HostClassicDdeCall::AcknowledgeEvent {
                    owner: event.owner,
                    endpoint: event.endpoint,
                    event_id: event.event_id,
                },
                continuation: Ole1ServerDdeHostContinuation::EventAcknowledgement {
                    event: event.clone(),
                    release_chain,
                },
            })
        }
        Win16ClassicDdeDeliveryKind::Synchronous {
            operation_id,
            callback,
            frame,
        } => {
            let step = callback_step
                .filter(|step| {
                    step.owner == event.owner
                        && step.endpoint == event.endpoint
                        && step.worker_generation == event.worker_generation
                        && step.operation_id == operation_id
                        && step.callback == callback
                        && step.frame == frame
                        && step.event == *event
                })
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "synchronous classic-DDE completion lost its exact callback step",
                    )
                })?;
            Ok(Ole1ServerDdeDisposition::ResumeCallback {
                resume: crate::Win16HostClassicDdeResume {
                    operation: Win16ClassicDdeOperationIdentity {
                        owner: event.owner,
                        id: operation_id,
                        worker_generation: event.worker_generation,
                    },
                    reply: Some(crate::Win16HostClassicDdeCallbackReply {
                        owner: event.owner,
                        endpoint: event.endpoint,
                        operation_id,
                        worker_generation: event.worker_generation,
                        callback,
                        frame,
                        event_id: event.event_id,
                        peer: event.peer,
                        causal_parents: step.causal_parents.clone(),
                        result: crate::Win16HostClassicDdeCallbackResult::WindowProcedure(0),
                    }),
                },
            })
        }
    }
}

pub(super) fn disposition_into_callback_finish(
    disposition: Ole1ServerDdeDisposition,
) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
    match disposition {
        Ole1ServerDdeDisposition::BeginHostCall { call, continuation } => {
            Ok(Ole1ServerGuestCallbackFinish::BeginHostCall { call, continuation })
        }
        Ole1ServerDdeDisposition::GuestCallback {
            far,
            args,
            return_kind,
            continuation,
        } => {
            let target = match &continuation.completion {
                Ole1ServerCallbackCompletion::DdeRelease { target, .. } => *target,
                _ => {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 release continuation lost its Release callback target",
                    ));
                }
            };
            Ok(Ole1ServerGuestCallbackFinish::GuestCallback {
                plan: Ole1ServerGuestCallbackPlan {
                    owner: continuation.owner,
                    target,
                    procedure: far,
                    arguments: args,
                    return_kind,
                    completion: continuation.completion.clone(),
                },
                continuation,
            })
        }
        Ole1ServerDdeDisposition::ResumeCallback { resume } => {
            Ok(Ole1ServerGuestCallbackFinish::Resume { resume })
        }
        Ole1ServerDdeDisposition::DeferredEvent(event) => {
            Ok(Ole1ServerGuestCallbackFinish::DeferredQueuedEvent { event })
        }
        Ole1ServerDdeDisposition::ReleaseEndpointPending {
            event,
            target,
            endpoint,
            pending_events,
        } => Ok(Ole1ServerGuestCallbackFinish::PendingEndpointEvents {
            event,
            target,
            endpoint,
            pending_events,
        }),
        Ole1ServerDdeDisposition::ReleaseComplete => Ok(Ole1ServerGuestCallbackFinish::Complete),
        _ => Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 release continuation produced an unsupported DDE disposition",
        )),
    }
}

fn release_target_for_termination(
    state: &Ole1ServerState,
    owner: guest_core::OwnerId,
    target: Ole1TerminationTarget,
) -> Option<Ole1ReleaseTarget> {
    match target {
        Ole1TerminationTarget::Server { handle, .. } => {
            state.server_release_target(owner, handle).ok()
        }
        Ole1TerminationTarget::Document { handle, .. } => {
            state.document_release_target(owner, handle).ok()
        }
    }
}

fn callback_target_matches_release(
    callback: Ole1ServerCallbackTarget,
    release: Ole1ReleaseTarget,
) -> bool {
    match (callback, release) {
        (
            Ole1ServerCallbackTarget::Document { handle, generation },
            Ole1ReleaseTarget::Document {
                handle: expected_handle,
                generation: expected_generation,
                ..
            },
        ) => handle == expected_handle && generation == expected_generation,
        (
            Ole1ServerCallbackTarget::Server { handle, generation },
            Ole1ReleaseTarget::Server {
                handle: expected_handle,
                generation: expected_generation,
                ..
            },
        ) => handle == expected_handle && generation == expected_generation,
        _ => false,
    }
}

/// Exact suspended INITIATE source retained while a nested host DDE call
/// performs either the synchronous ACK or XP's server-to-document forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ServerInitiateContinuation {
    Reply {
        step: Arc<Win16HostClassicDdeCallbackStep>,
        accepted: bool,
        target: Option<ServerInitTarget>,
    },
    Forward {
        step: Arc<Win16HostClassicDdeCallbackStep>,
        child: Win16HostClassicDdeEndpoint,
    },
}

impl super::Win16State {
    /// Bind the exact synchronous source to a host call produced by INITIATE
    /// routing. A queued event can never manufacture a suspended WndProc.
    fn bind_server_initiate_continuation(
        &self,
        disposition: Ole1ServerDdeDisposition,
        step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        let Ole1ServerDdeDisposition::HostCall {
            call,
            target,
            continuation: None,
        } = disposition
        else {
            return Ok(disposition);
        };
        let step = step.ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 INITIATE host call lost its checked synchronous callback source",
            )
        })?;
        let continuation = match &call {
            Win16HostClassicDdeCall::ReplyInitiate {
                owner,
                endpoint,
                worker_generation,
                operation_id,
                callback,
                frame,
                event_id,
                peer,
                accepted,
                application_atom,
                topic_atom,
            } => {
                let exact = *owner == step.owner
                    && *endpoint == step.endpoint
                    && *worker_generation == step.worker_generation
                    && *operation_id == step.operation_id
                    && *callback == step.callback
                    && *frame == step.frame
                    && *event_id == step.event.event_id
                    && *peer == step.event.peer
                    && matches!(
                        &step.event.message,
                        crate::Win16ClassicDdeMessage::Initiate {
                            application,
                            topic,
                        } if application == application_atom && topic == topic_atom
                    );
                if !exact {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 ReplyInitiate was not built from its exact callback step",
                    ));
                }
                Ole1ServerInitiateContinuation::Reply {
                    step,
                    accepted: *accepted,
                    target,
                }
            }
            Win16HostClassicDdeCall::ForwardInitiateToChild {
                owner,
                parent,
                worker_generation,
                operation_id,
                callback,
                frame,
                event_id,
                child,
                peer,
                application_atom,
                topic_atom,
            } => {
                let exact = *owner == step.owner
                    && *parent == step.endpoint
                    && *worker_generation == step.worker_generation
                    && *operation_id == step.operation_id
                    && *callback == step.callback
                    && *frame == step.frame
                    && *event_id == step.event.event_id
                    && *peer == step.event.peer
                    && matches!(
                        &step.event.message,
                        crate::Win16ClassicDdeMessage::Initiate {
                            application,
                            topic,
                        } if application == application_atom && topic == topic_atom
                    );
                if !exact {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 child INITIATE forward was not built from its exact callback step",
                    ));
                }
                Ole1ServerInitiateContinuation::Forward {
                    step,
                    child: *child,
                }
            }
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 INITIATE routing produced a non-INITIATE host call",
                ));
            }
        };
        Ok(Ole1ServerDdeDisposition::HostCall {
            call,
            target,
            continuation: Some(continuation),
        })
    }

    /// Complete one nested INITIATE host call after its source-retirement
    /// proof. Accepted conversations are installed only from the exact
    /// InitiateReplied receipt; forwarding has its own nested child callback.
    pub(in crate::win16_runtime) fn finish_server_initiate_host_call(
        &mut self,
        continuation: &Ole1ServerInitiateContinuation,
        expected_operation: crate::Win16ClassicDdeOperationIdentity,
        step: &crate::Win16HostClassicDdeStep,
    ) -> Result<crate::Win16HostClassicDdeResume, RuntimeError> {
        let crate::Win16HostClassicDdeStep::Complete {
            operation,
            result,
            source_retired,
        } = step
        else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 INITIATE continuation received a nonterminal host step",
            ));
        };
        if *operation != expected_operation || *operation != source_retired.operation {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 INITIATE host result lost its exact operation retirement proof",
            ));
        }
        let source = match continuation {
            Ole1ServerInitiateContinuation::Reply {
                step,
                accepted,
                target,
            } => {
                let crate::Win16HostClassicDdeResult::InitiateReplied(receipt) = result else {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 ReplyInitiate did not return its typed initiate receipt",
                    ));
                };
                let crate::Win16ClassicDdeMessage::Initiate { application, topic } =
                    &step.event.message
                else {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 initiate continuation no longer owns INITIATE atoms",
                    ));
                };
                if receipt.owner != step.owner
                    || receipt.endpoint != step.endpoint
                    || receipt.event_id != step.event.event_id
                    || receipt.peer != step.event.peer
                    || receipt.accepted != *accepted
                    || receipt.application_atom != *application
                    || receipt.topic_atom != *topic
                    || *accepted != target.is_some()
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 INITIATE receipt does not match its exact request and target",
                    ));
                }
                if let Some(target) = target {
                    let conversation = receipt.conversation.ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "accepted OLE1 INITIATE receipt has no conversation identity",
                        )
                    })?;
                    bind_server_initiate_receipt(
                        &mut self.ole1_server_state,
                        step.owner,
                        *target,
                        conversation,
                    )
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot publish accepted OLE1 conversation ({status})"),
                        )
                    })?;
                } else if receipt.conversation.is_some() {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "rejected OLE1 INITIATE receipt unexpectedly owns a conversation",
                    ));
                }
                step
            }
            Ole1ServerInitiateContinuation::Forward { step, child } => {
                let crate::Win16HostClassicDdeResult::ForwardInitiateReturned {
                    owner,
                    parent,
                    child: returned_child,
                    peer,
                    ..
                } = result
                else {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 child INITIATE forward did not return its typed receipt",
                    ));
                };
                if *owner != step.owner
                    || *parent != step.endpoint
                    || *returned_child != *child
                    || *peer != step.event.peer
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 child INITIATE receipt changed its exact endpoint or peer",
                    ));
                }
                step
            }
        };
        let Win16ClassicDdeDeliveryKind::Synchronous {
            operation_id,
            callback,
            frame,
        } = source.event.delivery
        else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 initiate source is not a synchronous callback",
            ));
        };
        let reply = crate::Win16HostClassicDdeCallbackReply {
            owner: source.owner,
            endpoint: source.endpoint,
            operation_id,
            worker_generation: source.worker_generation,
            callback,
            frame,
            event_id: source.event.event_id,
            peer: source.event.peer,
            causal_parents: source.causal_parents.clone(),
            result: crate::Win16HostClassicDdeCallbackResult::WindowProcedure(0),
        };
        Ok(crate::Win16HostClassicDdeResume {
            operation: crate::Win16ClassicDdeOperationIdentity {
                owner: source.owner,
                id: operation_id,
                worker_generation: source.worker_generation,
            },
            reply: Some(reply),
        })
    }
}

// Build a sync server/topic answer for a checked classic DDE INITIATE event.
// `system_topic` and `ole_topic` are the Win16 atom identities obtained from
// the task's global-atom API, never native ATOMs. Server/document ownership is
// verified against `OwnerId` and the opaque endpoint token before constructing
// any host operation.

include!("win16_ole1_server_dde_initiate_route.rs");
