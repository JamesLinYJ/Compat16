//! Pointer-free classic Win16 WM_DDE boundary.
//!
//! DDEML deliberately has a different boundary. These types preserve Win16
//! atoms, global-memory blocks, peers and protocol acknowledgements without
//! exposing native HWND/HGLOBAL pointers or guest FAR values to the host.

use guest_core::OwnerId;
use crate::{Win16HostCallback, Win16HostWindow};

pub const WM_DDE_INITIATE: u16 = 0x03e0;
pub const WM_DDE_TERMINATE: u16 = 0x03e1;
pub const WM_DDE_ADVISE: u16 = 0x03e2;
pub const WM_DDE_UNADVISE: u16 = 0x03e3;
pub const WM_DDE_ACK: u16 = 0x03e4;
pub const WM_DDE_DATA: u16 = 0x03e5;
pub const WM_DDE_REQUEST: u16 = 0x03e6;
pub const WM_DDE_POKE: u16 = 0x03e7;
pub const WM_DDE_EXECUTE: u16 = 0x03e8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostClassicDdeEndpoint(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeConversationId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeTransferId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeEventId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeOperationId(pub u64);
/// Host-issued barrier identity for one owner's classic-DDE producer shutdown.
/// It uses the shared host identity source and is stable across retry calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeQuiescenceId(pub u64);
/// Host/runtime correlation identity for one serialized classic DDE
/// transaction. It is never put on the Windows wire and is assigned only
/// after the host has a protocol-grounded peer/conversation/message match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeTransactionId(pub u64);
/// Opaque identity for an external native HWND. The HWND value remains inside
/// the USER worker and is never confused with a guest-window token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostClassicDdeNativeWindow(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeOperationIdentity {
    pub owner: OwnerId,
    pub id: Win16ClassicDdeOperationId,
    pub worker_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostClassicDdeCallbackFrame(pub u64);

/// Guest atom identity plus its spelling. Integer atoms are protocol integer
/// atoms. For string atoms, host ingress carries `guest_value: None`; the
/// runtime atom service materializes an actual task-local atom before guest
/// callbacks. Host egress may carry `Some` for ownership bookkeeping, but the
/// native host uses only `name_bytes` and never treats the guest word as a
/// Windows ATOM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeAtom {
    Integer(u16),
    Name { guest_value: Option<u16>, name_bytes: Vec<u8> },
}

/// Exact live GlobalHeap generation retained while the guest-side DDE protocol
/// owns or borrows a memory block. The raw WORD is never sufficient by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16ClassicDdeGuestGlobal {
    pub owner: OwnerId,
    pub handle: u16,
    pub generation: u64,
}

/// Exact GlobalSize snapshot. `guest_global` is Some only after the runtime
/// has materialized an inbound host block into a checked guest HGLOBAL.
/// `transfer` is an opaque correlation token, not an HGLOBAL value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdeGlobalBlock {
    pub transfer: Option<Win16ClassicDdeTransferId>,
    pub guest_global: Option<Win16ClassicDdeGuestGlobal>,
    pub bytes: Vec<u8>,
}

/// DDE.H DDEACK bit layout, preserving reserved bits exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdeAckStatus {
    pub raw: u16,
    pub application_return_code: u8,
    pub reserved: u8,
    pub busy: bool,
    pub acknowledged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeAckValue {
    /// WM_DDE_ACK sent in response to WM_DDE_INITIATE: raw application/topic
    /// atom pair, not PackDDElParam and not DDEACK status bits.
    InitiateAtoms {
        application: Option<Win16ClassicDdeAtom>,
        topic: Option<Win16ClassicDdeAtom>,
    },
    /// Normal ACKs identify the item atom. Atom spelling is carried in the
    /// event's resolved payload where applicable.
    ItemAtom(Option<Win16ClassicDdeAtom>),
    /// An execute ACK's high field was correlated against the exact native
    /// HGLOBAL transfer ledger. The native handle itself never crosses.
    ExecuteTransfer(Option<Win16ClassicDdeTransferId>),
    /// Preserve an unrecognized protocol context without reinterpreting its
    /// native high field as an atom, guest handle, or host pointer.
    Unmatched,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdeAdviseOptions {
    pub raw_flags: u16,
    pub unused_bits: u16,
    pub defer_updates: bool,
    pub acknowledge_each_update: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdeDataFlags {
    pub raw_flags: u16,
    pub unused_bits: u16,
    pub response: bool,
    pub release_after_receive: bool,
    pub reserved: bool,
    pub acknowledge_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdePokeFlags {
    pub raw_flags: u16,
    pub unused_bits: u16,
    pub release_after_receive: bool,
    pub reserved_bits: u16,
}

/// Full classic DDE message family. `global.bytes` always covers the whole
/// exact HGLOBAL size, including its DDEADVISE/DDEDATA/DDEPOKE header where
/// present; no value length is guessed from the DDE format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeMessage {
    Initiate {
        application: Option<Win16ClassicDdeAtom>,
        topic: Option<Win16ClassicDdeAtom>,
    },
    Terminate,
    Ack {
        status: Win16ClassicDdeAckStatus,
        value: Win16ClassicDdeAckValue,
    },
    Advise {
        item: Option<Win16ClassicDdeAtom>,
        format: u16,
        options: Win16ClassicDdeAdviseOptions,
        global: Win16ClassicDdeGlobalBlock,
    },
    Unadvise {
        item: Option<Win16ClassicDdeAtom>,
        /// WM_DDE_UNADVISE carries a reserved low WORD, not cfFormat.
        reserved: u16,
    },
    Request {
        item: Option<Win16ClassicDdeAtom>,
        format: u16,
    },
    Poke {
        item: Option<Win16ClassicDdeAtom>,
        format: u16,
        flags: Win16ClassicDdePokeFlags,
        global: Win16ClassicDdeGlobalBlock,
    },
    Data {
        item: Option<Win16ClassicDdeAtom>,
        format: u16,
        flags: Win16ClassicDdeDataFlags,
        global: Win16ClassicDdeGlobalBlock,
    },
    Execute {
        global: Win16ClassicDdeGlobalBlock,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Win16HostClassicDdePeer {
    Endpoint(Win16HostClassicDdeEndpoint),
    GuestWindow(Win16HostWindow),
    NativeWindow(Win16HostClassicDdeNativeWindow),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostClassicDdeTarget {
    Peer(Win16HostClassicDdePeer),
    /// Valid only for a synchronous WM_DDE_INITIATE Send operation.
    BroadcastInitiate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeDeliveryKind {
    /// The exact EventId remains at the head of its owner mailbox until the
    /// runtime publishes a bounded copy and owned continuation, then ACKs it.
    Queued,
    /// A private endpoint WndProc is synchronously suspended in this exact
    /// USER operation until a typed runtime continuation resumes it.
    Synchronous {
        operation_id: Win16ClassicDdeOperationId,
        callback: Win16HostCallback,
        frame: Win16HostClassicDdeCallbackFrame,
    },
}

/// Provenance for a synchronous private-endpoint callback. Callbacks caused
/// by a host DDE Send are retired with that operation. A callback received
/// while the USER worker is servicing a parked GetMessage/WaitMessage must
/// first resume the exact native WndProc and retire later, after the outer
/// wait continuation is allowed to continue. This tag carries no USER
/// operation identity and cannot consume its proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeCallbackSource {
    HostOperation,
    ParkedUserWait,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeEvent {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub worker_generation: u64,
    pub event_id: Win16ClassicDdeEventId,
    pub peer: Win16HostClassicDdePeer,
    pub conversation: Option<Win16ClassicDdeConversationId>,
    /// Present only when exact protocol fields identify one internal pending
    /// transaction; this value is not received from or sent to Windows.
    pub transaction: Option<Win16ClassicDdeTransactionId>,
    pub delivery: Win16ClassicDdeDeliveryKind,
    pub message: Win16ClassicDdeMessage,
}

/// A synchronous endpoint WndProc yield. The callback/event/frame tuple is
/// exact to one operation and worker incarnation; it is not a guest WndProc
/// or guest FAR callback identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeCallbackStep {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub worker_generation: u64,
    pub operation_id: Win16ClassicDdeOperationId,
    pub callback: Win16HostCallback,
    pub frame: Win16HostClassicDdeCallbackFrame,
    pub source: Win16ClassicDdeCallbackSource,
    /// Exact host-operation ancestry from the live USER worker command stack,
    /// nearest parent first. This internal causal chain is not present on the
    /// WM_DDE wire and never substitutes for a protocol transaction identity.
    pub causal_parents: Vec<Win16ClassicDdeOperationIdentity>,
    pub event: Win16HostClassicDdeEvent,
}

/// Callback answer committed through the independent classic-DDE resume
/// operation. It does not use `Win16WindowReply` or retire the outer USER
/// source proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeCallbackReply {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub operation_id: Win16ClassicDdeOperationId,
    pub worker_generation: u64,
    pub callback: Win16HostCallback,
    pub frame: Win16HostClassicDdeCallbackFrame,
    pub event_id: Win16ClassicDdeEventId,
    pub peer: Win16HostClassicDdePeer,
    /// Must exactly echo the callback step's validated same-owner ancestry.
    pub causal_parents: Vec<Win16ClassicDdeOperationIdentity>,
    pub result: Win16HostClassicDdeCallbackResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeCallbackRetirement {
    pub callback: Win16HostCallback,
    pub frame: Win16HostClassicDdeCallbackFrame,
    pub event_id: Win16ClassicDdeEventId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub peer: Win16HostClassicDdePeer,
    pub result: Win16HostClassicDdeCallbackResult,
}

/// Exact source-retirement evidence for one completed classic DDE operation.
/// It remains distinct from a DDE protocol ACK and from ordinary USER source
/// retirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeSourceRetiredProof {
    pub operation: Win16ClassicDdeOperationIdentity,
    pub callbacks: Vec<Win16HostClassicDdeCallbackRetirement>,
}

#[derive(Clone, Debug)]
pub struct Win16HostClassicDdeStartedFailure {
    pub operation: Win16ClassicDdeOperationIdentity,
    pub cause: std::sync::Arc<crate::RuntimeError>,
    /// The WndProc/callback source has unwound even though the requested
    /// operation failed. Pending DDE transfer/global-memory leases remain a
    /// separate retirement concern.
    pub source_retired: std::sync::Arc<Win16HostClassicDdeSourceRetiredProof>,
}

#[derive(Clone, Debug)]
pub enum Win16HostClassicDdeStep {
    Started(Win16ClassicDdeOperationIdentity),
    Callback(std::sync::Arc<Win16HostClassicDdeCallbackStep>),
    Complete {
        operation: Win16ClassicDdeOperationIdentity,
        result: Win16HostClassicDdeResult,
        source_retired: std::sync::Arc<Win16HostClassicDdeSourceRetiredProof>,
    },
    StartedFailure(std::sync::Arc<Win16HostClassicDdeStartedFailure>),
}

/// Terminal payload separated from the Started/Callback progress steps. The
/// runtime business journal consumes this exact result before the host source
/// retirement proof is acknowledged. It is never a DDE protocol ACK.
#[derive(Clone, Debug)]
pub enum Win16HostClassicDdeTerminal {
    Complete {
        result: Win16HostClassicDdeResult,
        source_retired: std::sync::Arc<Win16HostClassicDdeSourceRetiredProof>,
    },
    StartedFailure(std::sync::Arc<Win16HostClassicDdeStartedFailure>),
}

impl Win16HostClassicDdeTerminal {
    pub fn from_step(step: Win16HostClassicDdeStep) -> Result<Self, crate::RuntimeError> {
        match step {
            Win16HostClassicDdeStep::Complete { result, source_retired, .. } => {
                Ok(Self::Complete { result, source_retired })
            }
            Win16HostClassicDdeStep::StartedFailure(failure) => Ok(Self::StartedFailure(failure)),
            Win16HostClassicDdeStep::Started(_) | Win16HostClassicDdeStep::Callback(_) => {
                Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "classic DDE terminal hook received a nonterminal host step"))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeResume {
    pub operation: Win16ClassicDdeOperationIdentity,
    pub reply: Option<Win16HostClassicDdeCallbackReply>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdePostReceipt {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub peer: Win16HostClassicDdePeer,
    pub conversation: Option<Win16ClassicDdeConversationId>,
    pub message: u16,
    /// Native PostMessage success only. It is not a WM_DDE_ACK or transaction
    /// completion and does not retire any transfer/global-memory lease.
    pub queued: bool,
    pub transfer: Option<Win16ClassicDdeTransferId>,
    pub transaction: Option<Win16ClassicDdeTransactionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeSendReceipt {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub target: Win16HostClassicDdeTarget,
    pub conversation: Option<Win16ClassicDdeConversationId>,
    pub message: u16,
    /// SendMessage return value only. It does not mean the remote DDE protocol
    /// has completed or that a later ACK has been received.
    pub native_result: isize,
    pub transfer: Option<Win16ClassicDdeTransferId>,
    pub transaction: Option<Win16ClassicDdeTransactionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeInitiateReplyReceipt {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub event_id: Win16ClassicDdeEventId,
    pub peer: Win16HostClassicDdePeer,
    pub accepted: bool,
    pub application_atom: Option<Win16ClassicDdeAtom>,
    pub topic_atom: Option<Win16ClassicDdeAtom>,
    /// Nested SendMessage(WM_DDE_ACK) return value, not peer completion.
    pub native_result: Option<isize>,
    pub conversation: Option<Win16ClassicDdeConversationId>,
}

/// Host conversation binding for one responder explicitly selected by the
/// runtime OLE client journal from an outstanding broadcast INITIATE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeConversationReceipt {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub conversation: Win16ClassicDdeConversationId,
    pub peer: Win16HostClassicDdePeer,
    pub application: Option<Win16ClassicDdeAtom>,
    pub topic: Option<Win16ClassicDdeAtom>,
    pub source_operation: Win16ClassicDdeOperationIdentity,
    pub initiate_event_id: Win16ClassicDdeEventId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeRetirementReceipt {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub worker_generation: u64,
    pub retired: bool,
    pub pending_events: Vec<Win16ClassicDdeEventId>,
    pub retained_callbacks: Vec<Win16HostClassicDdeCallbackFrame>,
    pub retained_transfers: Vec<Win16ClassicDdeTransferId>,
}

/// Inventory of one endpoint while its task owner is behind the classic-DDE
/// shutdown barrier. These are exact guest-independent identities; payloads
/// remain in their existing event/frame/transfer ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeEndpointQuiescence {
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub parent: Option<Win16HostClassicDdeEndpoint>,
    pub pending_events: Vec<Win16ClassicDdeEventId>,
    pub callbacks: Vec<Win16HostClassicDdePendingCallback>,
    pub transfers: Vec<Win16HostClassicDdePendingTransfer>,
    pub conversations: Vec<Win16HostClassicDdePendingConversation>,
    pub transactions: Vec<Win16HostClassicDdePendingTransaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdePendingCallback {
    pub operation: Win16ClassicDdeOperationIdentity,
    pub callback: Win16HostCallback,
    pub frame: Win16HostClassicDdeCallbackFrame,
    pub event_id: Win16ClassicDdeEventId,
    pub peer: Win16HostClassicDdePeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdePendingTransfer {
    pub id: Win16ClassicDdeTransferId,
    pub peer: Win16HostClassicDdePeer,
    pub conversation: Option<Win16ClassicDdeConversationId>,
    pub message: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdePendingConversation {
    pub id: Win16ClassicDdeConversationId,
    pub peer: Win16HostClassicDdePeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdePendingTransaction {
    pub id: Win16ClassicDdeTransactionId,
    pub peer: Win16HostClassicDdePeer,
    pub conversation: Win16ClassicDdeConversationId,
    pub message: u16,
    pub transfer: Option<Win16ClassicDdeTransferId>,
}

/// A worker snapshot taken after the owner barrier was installed. Runtime
/// uses the exact IDs to continue draining published work and retiring OLE
/// endpoints; a nonempty snapshot is never treated as quiescence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeOwnerQuiescence {
    pub owner: OwnerId,
    pub worker_generation: u64,
    pub id: Win16ClassicDdeQuiescenceId,
    pub endpoints: Vec<Win16HostClassicDdeEndpointQuiescence>,
    pub active_operations: Vec<Win16ClassicDdeOperationIdentity>,
}

/// Worker-issued proof that the owner barrier is still installed and the
/// worker observed no endpoint, callback, mailbox event, transfer,
/// conversation, transaction, or active operation for this owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostClassicDdeOwnerQuiesced {
    pub owner: OwnerId,
    pub worker_generation: u64,
    pub id: Win16ClassicDdeQuiescenceId,
    pub operation: Win16ClassicDdeOperationIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClassicDdeCall {
    /// Install or retry an owner-scoped producer barrier on the USER worker.
    /// `None` is idempotent for allocation-failure retry; `Some` must echo the
    /// stable barrier identity returned by the worker.
    QuiesceOwner {
        owner: OwnerId,
        id: Option<Win16ClassicDdeQuiescenceId>,
    },
    /// Multiple independent endpoints may belong to one task. `parent` is
    /// None for an OLE client/server root and Some(server) for a per-document
    /// child endpoint with an exact parent incarnation.
    CreateEndpoint { owner: OwnerId, parent: Option<Win16HostClassicDdeEndpoint> },
    RetireEndpoint { owner: OwnerId, endpoint: Win16HostClassicDdeEndpoint },
    Send {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        target: Win16HostClassicDdeTarget,
        conversation: Option<Win16ClassicDdeConversationId>,
        /// Existing internal transaction when answering an inbound event;
        /// None asks the host to reserve a new transaction where the DDE
        /// message family has an exact response relationship.
        transaction: Option<Win16ClassicDdeTransactionId>,
        message: Win16ClassicDdeMessage,
    },
    Post {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        target: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        transaction: Option<Win16ClassicDdeTransactionId>,
        message: Win16ClassicDdeMessage,
    },
    /// Re-delivers the oldest exact queued event until AcknowledgeEvent.
    Poll { owner: OwnerId, endpoint: Win16HostClassicDdeEndpoint },
    /// Poll the oldest queued event among one owner's live endpoints. This is
    /// the runtime safe-point entry and avoids a second endpoint inventory.
    PollOwner { owner: OwnerId },
    /// Delivery acknowledgement only; it is distinct from WM_DDE_ACK.
    AcknowledgeEvent {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: Win16ClassicDdeEventId,
    },
    /// Synchronously answer the exact live WM_DDE_INITIATE WndProc frame.
    /// Host validates event/peer/worker generation and SendMessages WM_DDE_ACK
    /// to that peer before returning this receipt.
    ReplyInitiate {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        operation_id: Win16ClassicDdeOperationId,
        callback: Win16HostCallback,
        frame: Win16HostClassicDdeCallbackFrame,
        event_id: Win16ClassicDdeEventId,
        peer: Win16HostClassicDdePeer,
        accepted: bool,
        application_atom: Option<Win16ClassicDdeAtom>,
        topic_atom: Option<Win16ClassicDdeAtom>,
    },
    /// Create a client conversation only after its exact OLE business journal
    /// selected one responder to the outstanding broadcast INITIATE.
    BindConversation {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        source_operation: Win16ClassicDdeOperationIdentity,
        initiate_event_id: Win16ClassicDdeEventId,
        application: Option<Win16ClassicDdeAtom>,
        topic: Option<Win16ClassicDdeAtom>,
    },
    RetireConversation {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
    },
    /// Re-enter one exact child endpoint with the original incoming peer and
    /// atom pair, as OLE1 SrvrWndProc forwards non-System INITIATE to its
    /// registered document child windows. This is a synchronous nested send.
    ForwardInitiateToChild {
        owner: OwnerId,
        parent: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        operation_id: Win16ClassicDdeOperationId,
        callback: Win16HostCallback,
        frame: Win16HostClassicDdeCallbackFrame,
        event_id: Win16ClassicDdeEventId,
        child: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        application_atom: Option<Win16ClassicDdeAtom>,
        topic_atom: Option<Win16ClassicDdeAtom>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClassicDdeCallbackResult {
    /// WndProc's Win16 DWORD result; no native pointer or host handle.
    WindowProcedure(u32),
    /// Runtime declined to translate/accept this incoming message. Host may
    /// apply the exact documented DefWindowProc default for the message.
    Untranslated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostClassicDdeResult {
    OwnerQuiescing(Win16HostClassicDdeOwnerQuiescence),
    OwnerQuiesced(Win16HostClassicDdeOwnerQuiesced),
    Endpoint(Win16HostClassicDdeEndpoint),
    Retired(Win16HostClassicDdeRetirementReceipt),
    Posted(Win16HostClassicDdePostReceipt),
    Sent(Win16HostClassicDdeSendReceipt),
    Event(Option<Win16HostClassicDdeEvent>),
    EventAcknowledged(Win16ClassicDdeEventId),
    InitiateReplied(Win16HostClassicDdeInitiateReplyReceipt),
    ConversationBound(Win16HostClassicDdeConversationReceipt),
    ConversationRetired {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
    },
    ForwardInitiateReturned {
        owner: OwnerId,
        parent: Win16HostClassicDdeEndpoint,
        child: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        native_result: isize,
    },
    CallbackResumed(Win16HostClassicDdeCallbackFrame),
}

/// Runtime publication state for one exact mailbox event. The implementation
/// must keep this key through callback publication and failed Event ACK retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ClassicDdeEventPhase {
    Received,
    Publishing,
    Published,
    AcknowledgementPending,
    /// Host confirmed EventId delivery retirement. Guest atom/global copies
    /// still require their exact local cleanup before the journal is removed.
    HostAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16ClassicDdeEventProgress {
    pub owner: OwnerId,
    pub endpoint: Win16HostClassicDdeEndpoint,
    pub worker_generation: u64,
    pub event_id: Win16ClassicDdeEventId,
    pub phase: Win16ClassicDdeEventPhase,
}

/// Runtime-side exact-once publication journal for queued events. It does not
/// own protocol data or replace the host mailbox; it prevents a retried poll
/// from publishing the same callback twice. The host EventId is acknowledged
/// only after the business owner and any requested protocol ACK have committed.
#[derive(Default)]
pub struct Win16ClassicDdeEventTracker {
    entries: Vec<Win16ClassicDdeEventProgress>,
}

impl Win16ClassicDdeEventTracker {
    pub fn admit(&mut self, event: &Win16HostClassicDdeEvent) -> Result<bool, crate::RuntimeError> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "synchronous classic DDE callbacks cannot enter the queued-event tracker"));
        }
        if let Some(existing) = self.entries.iter().find(|existing| {
            existing.owner == event.owner
                && existing.endpoint == event.endpoint
                && existing.event_id == event.event_id
        }) {
            if existing.worker_generation != event.worker_generation {
                return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "classic DDE EventId was replayed by a different endpoint generation"));
            }
            return Ok(false);
        }
        self.entries.try_reserve(1).map_err(|error| crate::RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve exact classic DDE event publication state",
            error,
        ))?;
        self.entries.push(Win16ClassicDdeEventProgress {
            owner: event.owner,
            endpoint: event.endpoint,
            worker_generation: event.worker_generation,
            event_id: event.event_id,
            phase: Win16ClassicDdeEventPhase::Received,
        });
        Ok(true)
    }

    /// Returns true only to the caller that acquired publication ownership.
    /// Reentrant/replayed calls while Publishing or after publication do no
    /// second guest callback/frame publication.
    pub fn begin_publication(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<bool, crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::Received { return Ok(false); }
        entry.phase = Win16ClassicDdeEventPhase::Publishing;
        Ok(true)
    }

    /// A failed bounded snapshot/frame allocation leaves the same EventId
    /// retryable. No host acknowledgement may happen before Published.
    pub fn publication_failed(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::Publishing {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE publication failure has no active exact publication"));
        }
        entry.phase = Win16ClassicDdeEventPhase::Received;
        Ok(())
    }

    pub fn publication_succeeded(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::Publishing {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE event was published without its exact publication lease"));
        }
        entry.phase = Win16ClassicDdeEventPhase::Published;
        Ok(())
    }

    /// Move a published event into delivery-ACK only after its protocol
    /// consumer has committed every required action. In particular, a
    /// WM_DDE_ACK posted for DDEDATA is a separate host operation and must
    /// reach its exact terminal receipt before this transition.
    pub fn acknowledgement_started(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::Published {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE delivery ACK started before exact business publication"));
        }
        entry.phase = Win16ClassicDdeEventPhase::AcknowledgementPending;
        Ok(())
    }

    /// A host call that tried to retire a published EventId failed after
    /// starting. Preserve the exact publication and make only that delivery
    /// ACK retryable; this is not a protocol WM_DDE_ACK and does not clear any
    /// associated transfer or guest-memory lease.
    pub fn acknowledgement_failed(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::AcknowledgementPending {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE delivery ACK failure has no exact pending ACK"));
        }
        entry.phase = Win16ClassicDdeEventPhase::Published;
        Ok(())
    }

    /// Remove the exact delivery record only after host confirms EventId ACK.
    /// Protocol global blocks and atoms remain tracked by their separate
    /// transfer/conversation leases.
    pub fn acknowledge_succeeded(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let index = self.entries.iter().position(|entry| entry.owner == owner
            && entry.endpoint == endpoint && entry.event_id == event_id).ok_or_else(|| crate::RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "classic DDE event acknowledgement has no exact published event",
        ))?;
        let entry = &self.entries[index];
        if entry.worker_generation != worker_generation
            || entry.phase != Win16ClassicDdeEventPhase::HostAcknowledged
        {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE event acknowledgement does not match the exact published generation"));
        }
        self.entries.remove(index);
        Ok(())
    }

    pub fn host_acknowledgement_succeeded(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<(), crate::RuntimeError> {
        let entry = self.exact_mut(owner, endpoint, worker_generation, event_id)?;
        if entry.phase != Win16ClassicDdeEventPhase::AcknowledgementPending {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE host acknowledged an event outside its exact ACK operation"));
        }
        entry.phase = Win16ClassicDdeEventPhase::HostAcknowledged;
        Ok(())
    }

    pub fn pending(&self) -> impl Iterator<Item = &Win16ClassicDdeEventProgress> {
        self.entries.iter()
    }

    fn exact_mut(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<&mut Win16ClassicDdeEventProgress, crate::RuntimeError> {
        let entry = self.entries.iter_mut().find(|entry| entry.owner == owner
            && entry.endpoint == endpoint && entry.event_id == event_id).ok_or_else(|| {
            crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE publication state has no exact owner/endpoint/EventId")
        })?;
        if entry.worker_generation != worker_generation {
            return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "classic DDE publication state belongs to a different worker generation"));
        }
        Ok(entry)
    }
}
