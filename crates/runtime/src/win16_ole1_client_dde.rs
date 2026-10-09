//! Exact OLE1 client-side classic-DDE conversation and reply correlation.
//!
//! This journal owns OLE1 meaning across independent host operations. It never
//! treats a host Send/Post receipt as a DDE acknowledgement, and it never
//! correlates by a guest selector, native HWND value, or raw atom number.

#[path = "win16_ole1_client_dde_runtime.rs"]
mod runtime;
#[path = "win16_ole1_client_dde_termination.rs"]
mod termination;

use super::{Win16Ole1OperationId, Win16State};
use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use x86_cpu::Cpu;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16ClassicDdeAckValue, Win16ClassicDdeAtom, Win16ClassicDdeCallbackSource,
    Win16ClassicDdeConversationId, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeGlobalBlock, Win16ClassicDdeMessage, Win16ClassicDdeOperationIdentity,
    Win16ClassicDdeTransactionId, Win16ClassicDdeTransferId, Win16HostClassicDdeCall,
    Win16HostClassicDdeCallbackReply, Win16HostClassicDdeCallbackResult,
    Win16HostClassicDdeCallbackStep, Win16HostClassicDdeConversationReceipt,
    Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent, Win16HostClassicDdePeer,
    Win16HostClassicDdePostReceipt, Win16HostClassicDdeResult,
    Win16HostClassicDdeRetirementReceipt, Win16HostClassicDdeTarget,
    Win16HostClassicDdeTerminal,
};

const WM_DDE_EXECUTE: u16 = 0x03e8;
const WM_DDE_ADVISE: u16 = 0x03e2;
const WM_DDE_UNADVISE: u16 = 0x03e3;
const WM_DDE_POKE: u16 = 0x03e7;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdeCallId(pub(in crate::win16_runtime) u64);

/// A client route action always names the exact OLE API journal entry. The
/// dispatcher records the returned host operation identity against this id;
/// terminal completion must come back through that mapping.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) enum Win16Ole1ClientDdeDisposition {
    NotOwned,
    Deferred,
    CallbackReply(Win16HostClassicDdeCallbackResult),
    /// A nested host terminal was committed to the OLE1 journal; resume this
    /// exact suspended parent callback without completing its public API.
    ResumeCallback(Win16HostClassicDdeCallbackReply),
    HostCall {
        operation: Win16Ole1OperationId,
        call: crate::Win16HostClassicDdeCall,
        /// Present when a nested host call must finish before resuming this
        /// exact suspended classic-DDE callback (such as terminating an
        /// extra INITIATE responder).
        resume_callback: Option<Win16HostClassicDdeCallbackReply>,
    },
    ApiCompleted {
        operation: Win16Ole1OperationId,
    },
    /// A single synchronous broadcast transaction has returned. This only
    /// reports whether a responder was selected so the owning creation
    /// continuation can choose fallback/next DDE work; it is not OLE API
    /// completion and does not create an OLEOBJECT.
    InitiateCompleted {
        operation: Win16Ole1OperationId,
        purpose: Win16Ole1InitiatePurpose,
        responder: Option<Win16Ole1InitiateResponder>,
    },
    /// Owner-bound setup progress; this is neither a peer conversation nor
    /// public OLE API success.
    EndpointCreated {
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    },
    EndpointRetired {
        operation: Win16Ole1OperationId,
        receipt: crate::Win16HostClassicDdeRetirementReceipt,
    },
    ConversationRetired {
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        terminate_queued: bool,
    },
    /// A DDE send was accepted by the native queue and its exact transaction
    /// and transfer identities are now journaled. This is transport progress;
    /// the caller must still wait for the matching protocol response event.
    DdeCallPosted {
        operation: Win16Ole1OperationId,
        call: Win16Ole1ClientDdeCallId,
    },
    DdeCallRejected {
        operation: Win16Ole1OperationId,
        call: Win16Ole1ClientDdeCallId,
    },
    /// The client operation has committed this exact queued response and no
    /// additional WM_DDE_ACK is required. The Classic DDE executor must first
    /// commit this EventId's delivery ACK before the owning OLE sequence may
    /// advance.
    EventAcknowledgementReady {
        operation: Win16Ole1OperationId,
        event_id: crate::Win16ClassicDdeEventId,
    },
}

#[derive(Debug)]
struct Win16Ole1ClientHostOperation {
    operation: Win16Ole1OperationId,
    host: Win16ClassicDdeOperationIdentity,
    action: Option<Win16Ole1ClientHostAction>,
    /// Keep an exact terminal here until the business journal consumes it.
    /// If a checked allocation fails while preparing the commit, the same
    /// terminal can be retried without asking the host to repeat a completed
    /// operation or losing its source-retirement proof.
    terminal: Option<Win16HostClassicDdeTerminal>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Win16Ole1PendingHostAction {
    operation: Win16Ole1OperationId,
    owner: OwnerId,
    action: Win16Ole1ClientHostAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Win16Ole1ClientHostAction {
    CreateEndpoint {
        owner: OwnerId,
    },
    RetireEndpoint {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    },
    TerminateClientConversation {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
    },
    RetireClientConversation {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        terminate_queued: bool,
    },
    InitiateBroadcast,
    BindFirstResponder {
        candidate: Win16Ole1InitiateCandidate,
        resume_callback: Win16HostClassicDdeCallbackReply,
    },
    BindExtraResponder {
        candidate: Win16Ole1InitiateCandidate,
        resume_callback: Win16HostClassicDdeCallbackReply,
    },
    TerminateExtraResponder {
        candidate: Win16Ole1InitiateCandidate,
        conversation: Win16ClassicDdeConversationId,
        resume_callback: Win16HostClassicDdeCallbackReply,
    },
    RetireExtraResponder {
        candidate: Win16Ole1InitiateCandidate,
        conversation: Win16ClassicDdeConversationId,
        resume_callback: Win16HostClassicDdeCallbackReply,
    },
    PostTransaction {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        call: Win16Ole1ClientDdeCallId,
        sent_message: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1InitiatePurpose {
    SystemOleTopic,
    SystemFallbackTopic,
    DocumentTopic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1InitiateResponder {
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
    pub(in crate::win16_runtime) conversation: Win16ClassicDdeConversationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1InitiateCandidate {
    operation: Win16Ole1OperationId,
    source_operation: Win16ClassicDdeOperationIdentity,
    endpoint: Win16HostClassicDdeEndpoint,
    event_id: crate::Win16ClassicDdeEventId,
    peer: Win16HostClassicDdePeer,
    callback: crate::Win16HostCallback,
    frame: crate::Win16HostClassicDdeCallbackFrame,
    causal_parents: Vec<Win16ClassicDdeOperationIdentity>,
    application: Win16ClassicDdeAtom,
    topic: Win16ClassicDdeAtom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1InitiateAckDecision {
    NotOwned,
    AtomIdentityPending,
    BindingInProgress,
    FirstResponder(Win16Ole1InitiateCandidate),
    ExtraResponder(Win16Ole1InitiateCandidate),
    DuplicateResponder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Win16Ole1InitiateAttempt {
    operation: Win16Ole1OperationId,
    host: Option<Win16ClassicDdeOperationIdentity>,
    owner: OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    application_atom: Option<u16>,
    topic_atom: Option<u16>,
    application_name: Vec<u8>,
    topic_name: Vec<u8>,
    purpose: Win16Ole1InitiatePurpose,
    first_responder: Option<Win16Ole1InitiateResponder>,
    pending_first_responder: Option<Win16Ole1InitiateCandidate>,
    extra_responders: Vec<Win16Ole1InitiateResponder>,
    pending_extra_responders: Vec<Win16Ole1InitiateCandidate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Win16Ole1ClientDdeEndpoint {
    operation: Win16Ole1OperationId,
    owner: OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdeConversation {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
    pub(in crate::win16_runtime) id: Win16ClassicDdeConversationId,
    pub(in crate::win16_runtime) initiate_event_id: crate::Win16ClassicDdeEventId,
    pub(in crate::win16_runtime) application_atom: u16,
    pub(in crate::win16_runtime) topic_atom: u16,
    pub(in crate::win16_runtime) application: Vec<u8>,
    pub(in crate::win16_runtime) topic: Vec<u8>,
}

/// Runtime atom WORDs materialized from one exact INITIATE ACK event and
/// retained for this bound conversation. The classic-DDE dispatcher uses
/// this identity to transfer the EventId atom references into conversation
/// ownership and release them only after exact conversation retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdeConversationAtoms {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) conversation: Win16ClassicDdeConversationId,
    pub(in crate::win16_runtime) source_event_id: crate::Win16ClassicDdeEventId,
    pub(in crate::win16_runtime) application_atom: u16,
    pub(in crate::win16_runtime) topic_atom: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1ExpectedReply {
    /// An execute command owns an exact transferred HGLOBAL. The host must
    /// preserve that transfer correlation on the ACK; item atoms are not an
    /// acceptable substitute for an execute handle.
    ExecuteAck,
    /// Advise/unadvise/poke ACKs identify the exact task-local GlobalAddAtom WORD.
    /// The caller retains the corresponding atom reference until completion.
    ItemAck { item_atom: u16, item_name: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdePendingCall {
    pub(in crate::win16_runtime) id: Win16Ole1ClientDdeCallId,
    pub(in crate::win16_runtime) operation: Option<Win16Ole1OperationId>,
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
    pub(in crate::win16_runtime) conversation: Win16ClassicDdeConversationId,
    pub(in crate::win16_runtime) sent_message: u16,
    pub(in crate::win16_runtime) expected: Win16Ole1ExpectedReply,
    pub(in crate::win16_runtime) transaction: Option<Win16ClassicDdeTransactionId>,
    pub(in crate::win16_runtime) transfer: Option<Win16ClassicDdeTransferId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1ClientDdeResponse {
    Ack {
        operation: Option<Win16Ole1OperationId>,
        call: Win16Ole1ClientDdeCallId,
        raw_status: u16,
        acknowledged: bool,
        busy: bool,
        application_return_code: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1ClientDdeMatch {
    NotOwned,
    /// More than one pending call has identical wire-visible fields. The
    /// event stays pending; serialization or an exact host transaction id is
    /// required before it can complete either OLE operation.
    Ambiguous,
    Matched(Win16Ole1ClientDdeResponse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Win16Ole1ClientDdeInitiateMatch<'a> {
    peer: Win16HostClassicDdePeer,
    application: &'a Win16ClassicDdeAtom,
    topic: &'a Win16ClassicDdeAtom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Win16Ole1InitiateAtomMatch<'a> {
    NotMatch,
    GuestIdentityPending,
    Matched(Win16Ole1ClientDdeInitiateMatch<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1ClientDdeCommittedResponse {
    Terminate {
        operation: Win16Ole1OperationId,
    },
    Ack {
        operation: Option<Win16Ole1OperationId>,
        call: Win16Ole1ClientDdeCallId,
        raw_status: u16,
        acknowledged: bool,
        busy: bool,
        application_return_code: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdeCommittedEvent {
    pub(in crate::win16_runtime) event_id: crate::Win16ClassicDdeEventId,
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) endpoint: Win16HostClassicDdeEndpoint,
    pub(in crate::win16_runtime) peer: Win16HostClassicDdePeer,
    pub(in crate::win16_runtime) conversation: Win16ClassicDdeConversationId,
    pub(in crate::win16_runtime) transaction: Option<Win16ClassicDdeTransactionId>,
    pub(in crate::win16_runtime) response: Win16Ole1ClientDdeCommittedResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16Ole1ClientDdeEventCommit {
    /// Ownership is returned intact so another protocol route may inspect
    /// the queued event. The DDE business journal must not consume it merely
    /// to discover that the event belongs elsewhere.
    NotOwned(Win16HostClassicDdeEvent),
    /// Wire-visible fields do not select a unique pending operation. Preserve
    /// the event and its transfer payload for serialization/retry.
    Ambiguous(Win16HostClassicDdeEvent),
    /// The exact response is retained in this journal
    /// until the exact delivery event is acknowledged. The caller reads it
    /// through `committed_event`; it is not returned as an ephemeral payload.
    Committed(crate::Win16ClassicDdeEventId),
    /// The same delivery event was committed before its business continuation
    /// or host delivery-ACK step completed. Re-read the retained event and
    /// retry that exact continuation instead of dropping its payload.
    AlreadyCommitted(crate::Win16ClassicDdeEventId),
}

#[derive(Debug)]
pub(in crate::win16_runtime) struct Win16Ole1ClientDdeJournal {
    next_call_id: Option<u64>,
    host_operations: Vec<Win16Ole1ClientHostOperation>,
    pending_host_actions: Vec<Win16Ole1PendingHostAction>,
    initiate_attempts: Vec<Win16Ole1InitiateAttempt>,
    endpoints: Vec<Win16Ole1ClientDdeEndpoint>,
    conversations: Vec<Win16Ole1ClientDdeConversation>,
    pending: Vec<Win16Ole1ClientDdePendingCall>,
    committed_events: Vec<Win16Ole1ClientDdeCommittedEvent>,
    terminations: Vec<termination::ClientTermination>,
}

impl Default for Win16Ole1ClientDdeJournal {
    fn default() -> Self {
        Self {
            next_call_id: Some(1),
            host_operations: Vec::new(),
            pending_host_actions: Vec::new(),
            initiate_attempts: Vec::new(),
            endpoints: Vec::new(),
            conversations: Vec::new(),
            pending: Vec::new(),
            committed_events: Vec::new(),
            terminations: Vec::new(),
        }
    }
}

impl Win16Ole1ClientDdeJournal {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.host_operations.is_empty()
            || !self.pending_host_actions.is_empty()
            || !self.initiate_attempts.is_empty()
            || !self.endpoints.is_empty()
            || !self.conversations.is_empty()
            || !self.pending.is_empty()
            || !self.committed_events.is_empty()
            || !self.terminations.is_empty()
    }

    pub(super) fn owner_pending(&self, owner: OwnerId) -> Result<usize, RuntimeError> {
        if owner.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "OLE1 client DDE owner inventory requires a valid task owner",
            ));
        }
        if self
            .host_operations
            .iter()
            .any(|entry| entry.host.owner.0 == 0)
            || self
                .initiate_attempts
                .iter()
                .any(|entry| entry.owner.0 == 0)
            || self.endpoints.iter().any(|entry| entry.owner.0 == 0)
            || self.conversations.iter().any(|entry| entry.owner.0 == 0)
            || self.pending.iter().any(|entry| entry.owner.0 == 0)
            || self.committed_events.iter().any(|entry| entry.owner.0 == 0)
            || self.terminations.iter().any(|entry| entry.owner.0 == 0)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "active OLE1 client DDE journal entry lost its exact owner",
            ));
        }
        for pending in &self.pending_host_actions {
            if pending.owner.0 == 0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client DDE pending host action lost its exact owner",
                ));
            }
            if self.host_action_owner(pending.operation, &pending.action) != Some(pending.owner) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client DDE pending host action owner disagrees with its typed action",
                ));
            }
        }
        let counts = [
            self.terminations
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.host_operations
                .iter()
                .filter(|entry| entry.host.owner == owner)
                .count(),
            self.pending_host_actions
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.initiate_attempts
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.endpoints
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.conversations
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.pending
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
            self.committed_events
                .iter()
                .filter(|entry| entry.owner == owner)
                .count(),
        ];
        Ok(counts.into_iter().fold(0usize, usize::saturating_add))
    }
}

pub(super) fn clone_atom(atom: &Win16ClassicDdeAtom) -> Result<Win16ClassicDdeAtom, &'static str> {
    match atom {
        Win16ClassicDdeAtom::Integer(value) => Ok(Win16ClassicDdeAtom::Integer(*value)),
        Win16ClassicDdeAtom::Name {
            guest_value,
            name_bytes,
        } => {
            let mut copy = Vec::new();
            copy.try_reserve_exact(name_bytes.len())
                .map_err(|_| "OLE1 INITIATE atom name cannot grow")?;
            copy.extend_from_slice(name_bytes);
            Ok(Win16ClassicDdeAtom::Name {
                guest_value: *guest_value,
                name_bytes: copy,
            })
        }
    }
}

pub(super) fn clone_initiate_candidate(
    candidate: &Win16Ole1InitiateCandidate,
) -> Result<Win16Ole1InitiateCandidate, &'static str> {
    let mut causal_parents = Vec::new();
    causal_parents
        .try_reserve_exact(candidate.causal_parents.len())
        .map_err(|_| "OLE1 DDE callback causal chain cannot grow")?;
    causal_parents.extend_from_slice(&candidate.causal_parents);
    Ok(Win16Ole1InitiateCandidate {
        operation: candidate.operation,
        source_operation: candidate.source_operation,
        endpoint: candidate.endpoint,
        event_id: candidate.event_id,
        peer: candidate.peer,
        callback: candidate.callback,
        frame: candidate.frame,
        causal_parents,
        application: clone_atom(&candidate.application)?,
        topic: clone_atom(&candidate.topic)?,
    })
}

#[path = "win16_ole1_client_dde_copy.rs"]
mod copy;
#[path = "win16_ole1_client_dde_host.rs"]
mod host;
#[path = "win16_ole1_client_dde_host_data.rs"]
mod host_data;
#[path = "win16_ole1_client_dde_lifecycle.rs"]
mod lifecycle;
#[path = "win16_ole1_client_dde_transactions.rs"]
mod transactions;

#[path = "win16_ole1_client_dde_initiate.rs"]
mod initiate;
#[path = "win16_ole1_client_dde_owner_inventory.rs"]
mod owner_inventory;
pub(super) use initiate::{
    Win16Ole1EmbeddedTopicSerial, embedded_document_topic, new_document_execute,
};
