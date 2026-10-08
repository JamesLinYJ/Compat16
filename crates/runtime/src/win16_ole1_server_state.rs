//! Runtime-owned identities and lifecycle bookkeeping for Win16 OLE 1.0 servers.
//!
//! Guest `LHSERVER` and `LHSERVERDOC` are positive LONG tokens allocated by
//! this table. They are never native pointers, selectors, HWNDs, or HGLOBALs.
//! `OwnerId` is retained on each record so handles cannot cross Win16 task
//! incarnations inside a shared runtime.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use guest_core::OwnerId;
use win16_abi::GlobalHandle;

use crate::Win16HostClassicDdePeer;
use crate::{
    Win16ClassicDdeConversationId, Win16ClassicDdeDeliveryKind, Win16ClassicDdeEventId,
    Win16HostClassicDdeCallbackStep, Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
    Win16HostClassicDdeRetirementReceipt,
};

pub(crate) type Ole1Status = u16;

pub(crate) const OLE_OK: Ole1Status = 0;
pub(crate) const OLE_WAIT_FOR_RELEASE: Ole1Status = 1;
pub(crate) const OLE_BUSY: Ole1Status = 2;
pub(crate) const OLE_ERROR_MEMORY: Ole1Status = 4;
pub(crate) const OLE_ERROR_OBJECT: Ole1Status = 13;
pub(crate) const OLE_ERROR_OPTION: Ole1Status = 14;
pub(crate) const OLE_ERROR_PROTOCOL: Ole1Status = 15;
pub(crate) const OLE_ERROR_ADDRESS: Ole1Status = 16;
pub(crate) const OLE_ERROR_HANDLE: Ole1Status = 18;
pub(crate) const OLE_ERROR_CLASS: Ole1Status = 20;
pub(crate) const OLE_ERROR_NAME: Ole1Status = 29;
pub(crate) const OLE_ERROR_COMMAND: Ole1Status = 38;
pub(crate) const OLE_ERROR_SERVER_BLOCKED: Ole1Status = 47;
pub(crate) const OLE_ERROR_REGISTRATION: Ole1Status = 48;
pub(crate) const OLE_ERROR_ALREADY_REGISTERED: Ole1Status = 49;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Ole1ServerHandle(i32);

impl Ole1ServerHandle {
    pub(crate) const fn from_guest_long(bits: u32) -> Self {
        Self(bits as i32)
    }

    pub(crate) const fn to_guest_long(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Ole1ServerDocumentHandle(i32);

impl Ole1ServerDocumentHandle {
    pub(crate) const fn from_guest_long(bits: u32) -> Self {
        Self(bits as i32)
    }

    pub(crate) const fn to_guest_long(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ServerUse {
    Multi,
    Single,
}

impl Ole1ServerUse {
    pub(crate) fn from_guest_word(value: u16) -> Result<Self, Ole1Status> {
        match value {
            0 => Ok(Self::Multi),
            1 => Ok(Self::Single),
            _ => Err(OLE_ERROR_OPTION),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1RegistrationState {
    Active,
    /// Revoke has begun; records stay live until the exact outstanding
    /// conversations acknowledge termination and the checked Release callback
    /// has completed.
    Revoking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1DocumentState {
    Active,
    /// Revoke/close has begun. The entry cannot be reused while any exact DDE
    /// conversation is still retiring.
    Revoking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Ole1ConversationBinding {
    pub(crate) id: Win16ClassicDdeConversationId,
    pub(crate) generation: u64,
    /// Exact peer window incarnation. It is needed for later TERMINATE/ACK
    /// routing and is never reconstructed from a guest HWND value.
    pub(crate) peer: Win16HostClassicDdePeer,
}

/// The outgoing DDE TERMINATE handshake is tracked per exact conversation
/// identity. A scalar `termNo` cannot distinguish duplicate events or a stale
/// peer/window incarnation, so the server state retains the binding itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1TerminationPhase {
    PostPending,
    /// A unique host post is underway. Retried API calls must not post a
    /// second TERMINATE while its exact receipt is outstanding.
    PostInFlight,
    AwaitingPeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1PendingTermination {
    pub(crate) binding: Ole1ConversationBinding,
    pub(crate) phase: Ole1TerminationPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1TerminationTarget {
    Server {
        handle: Ole1ServerHandle,
        generation: u64,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
    },
    Document {
        handle: Ole1ServerDocumentHandle,
        generation: u64,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1TerminationPost {
    pub(crate) target: Ole1TerminationTarget,
    pub(crate) binding: Ole1ConversationBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1TerminateDisposition {
    /// The peer's event acknowledges an exact outgoing TERMINATE.
    RevocationAck(Ole1TerminationTarget),
    /// The peer TERMINATE arrived after a post was sent but before the
    /// runtime consumed that post's exact terminal receipt. Keep its queued
    /// event pending until that host operation is committed.
    RevocationPostInFlight(Ole1TerminationTarget),
    /// The peer initiated TERMINATE while this endpoint was not revoking.
    PeerInitiated(Ole1TerminationTarget),
    /// The exact endpoint/conversation/peer tuple is not in this registry.
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerRecord {
    pub(crate) owner: OwnerId,
    pub(crate) generation: u64,
    pub(crate) class_name: Vec<u8>,
    /// Runtime-allocated Win16 global atom for the registered OLE class.
    pub(crate) class_atom: u16,
    /// Executable basename atom derived from the validated HKCR server value.
    /// XP allows this alternate application atom only for SINGLE servers.
    pub(crate) executable_atom: u16,
    pub(crate) server_far: u32,
    /// False only when registration succeeded but the guest output handle
    /// could not be published. Such a record remains cleanup-owned and is
    /// never eligible for INITIATE or a Release callback.
    pub(crate) guest_handle_published: bool,
    pub(crate) instance: u16,
    pub(crate) use_mode: Ole1ServerUse,
    pub(crate) endpoint: Win16HostClassicDdeEndpoint,
    pub(crate) endpoint_worker_generation: u64,
    pub(crate) state: Ole1RegistrationState,
    pub(crate) blocked: bool,
    pub(crate) documents: Vec<Ole1ServerDocumentHandle>,
    pub(crate) conversations: BTreeMap<Win16ClassicDdeConversationId, Ole1ConversationBinding>,
    /// For the server root endpoint only. Document-channel conversations are
    /// counted on their document records to avoid double-posting TERMINATE
    /// when RevokeServer revokes both scopes.
    pub(crate) pending_terminations:
        BTreeMap<Win16ClassicDdeConversationId, Ole1PendingTermination>,
    /// XP's OleBlockServer retains synchronous DDE WndProc messages and
    /// OleUnblockServer dispatches exactly one per call.
    pub(crate) deferred_events: VecDeque<Ole1DeferredClassicDdeEvent>,
    pub(crate) in_flight_deferred: Option<Ole1DeferredClassicDdeEvent>,
    pub(crate) processing_deferred_message: bool,
    /// WIN.INI/ClassesRoot registration query output is retained as bytes for
    /// OLE's server-topic registration rules; it is not used as a host path.
    pub(crate) registered_server_value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1DeferredClassicDdeEvent {
    pub(crate) event: Win16HostClassicDdeEvent,
    pub(crate) step: Arc<Win16HostClassicDdeCallbackStep>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerDocumentRecord {
    pub(crate) owner: OwnerId,
    pub(crate) generation: u64,
    pub(crate) server: Ole1ServerHandle,
    /// Exact host child endpoint created for this document. It is not a guest
    /// HWND; it is an opaque endpoint incarnation bound to this doc generation.
    pub(crate) endpoint: Win16HostClassicDdeEndpoint,
    pub(crate) endpoint_worker_generation: u64,
    pub(crate) name: Vec<u8>,
    /// Global atom owned by this exact registered document generation.
    pub(crate) document_atom: u16,
    /// Private application-side `LPOLESERVERDOC`. It is intentionally optional:
    /// NTVDM calls `OleRegisterServerDoc(NULL, ...)` while a DDE open/create
    /// callback is in progress, then publishes the pointer only after that
    /// callback returns OLE_OK.
    pub(crate) server_document_far: Option<u32>,
    /// False only when the public registration output could not be written.
    /// The record is retained for owner-scoped endpoint/atom cleanup but is
    /// not a guest-visible server document.
    pub(crate) guest_handle_published: bool,
    pub(crate) state: Ole1DocumentState,
    pub(crate) conversations: BTreeMap<Win16ClassicDdeConversationId, Ole1ConversationBinding>,
    pub(crate) pending_terminations:
        BTreeMap<Win16ClassicDdeConversationId, Ole1PendingTermination>,
    pub(crate) items: Vec<Ole1ServerItemBinding>,
    pub(crate) embedded: bool,
    /// Guest buffers retained while a checked Open/Create/Edit callback owns
    /// this exact provisional document. Shutdown and pre-entry rollback use
    /// the typed GlobalHandle rather than reconstructing it from a raw WORD.
    pub(crate) prepared_callback_scratch: Option<Ole1ServerPreparedCallbackScratch>,
    /// A returned or pre-entry-cancelled callback owns every following finish
    /// phase. In particular, a scratch-free retry must not reread a retired
    /// selector or turn a failed callback into a second guest invocation.
    pub(crate) prepared_callback_completion: Option<Ole1ServerPreparedCallbackCompletion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerPreparedCallbackScratch {
    pub(crate) allocation: GlobalHandle,
    pub(crate) locked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ServerPreparedCallbackResult {
    Returned(Ole1Status),
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ServerPreparedCallbackPhase {
    ReadOutput,
    ValidateInterface,
    PublishInterface,
    SetEmbedded,
    Quarantine,
    ReleaseScratch,
    CleanupDocument,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerPreparedCallbackCompletion {
    pub(crate) result: Ole1ServerPreparedCallbackResult,
    pub(crate) output_far: u32,
    pub(crate) embedded: bool,
    pub(crate) document_far: Option<u32>,
    pub(crate) status: Option<Ole1Status>,
    pub(crate) phase: Ole1ServerPreparedCallbackPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerItemBinding {
    pub(crate) client_far: u32,
    pub(crate) object_far: u32,
    pub(crate) conversation: Win16ClassicDdeConversationId,
    pub(crate) item_atom: u16,
    pub(crate) generation: u64,
    pub(crate) revoking: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ItemCallbackIdentity {
    pub(crate) owner: OwnerId,
    pub(crate) document: Ole1ServerDocumentHandle,
    pub(crate) document_generation: u64,
    pub(crate) item_generation: u64,
    pub(crate) client_far: u32,
    pub(crate) object_far: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ole1ItemRetirementPhase {
    AtomDeletePending,
    AtomDeleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ItemReleaseCallbackResult {
    Returned(Ole1Status),
    CancelledByOwnerExit,
}

/// Completion evidence retained after the guest OLEOBJECT::Release callback
/// has returned. The callback frame ID prevents a retry from re-entering the
/// same guest method, while the full owner and generation tuple prevents an
/// atom cleanup from being applied to a later item that reused guest FARs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerCompletionJournalEntry {
    pub(crate) callback_id: u64,
    pub(crate) identity: Ole1ItemCallbackIdentity,
    pub(crate) item_atom: u16,
    pub(crate) callback_result: Ole1ItemReleaseCallbackResult,
    phase: Ole1ItemRetirementPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ReleaseTarget {
    Document {
        handle: Ole1ServerDocumentHandle,
        generation: u64,
        server: Ole1ServerHandle,
        server_generation: u64,
        endpoint: Win16HostClassicDdeEndpoint,
        endpoint_worker_generation: u64,
        document_atom: u16,
    },
    Server {
        handle: Ole1ServerHandle,
        generation: u64,
        endpoint: Win16HostClassicDdeEndpoint,
        endpoint_worker_generation: u64,
        class_atom: u16,
        executable_atom: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ReleasePhase {
    DeleteFirstAtom,
    DeleteSecondAtom,
    RetireEndpoint,
    CommitRegistry,
    /// Registry records and native endpoint are gone, but the checked
    /// callback frame still owns the Win16 return continuation.
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1ReleaseCallbackResult {
    Returned(Ole1Status),
    /// Registration used a null interface pointer; no guest Release method
    /// exists to call. This is not an OLE_OK callback result.
    NotRegistered,
    /// Owner teardown aborted an in-flight Release; cleanup may retire host
    /// resources without reentering the exited guest or claiming a result.
    CancelledByOwnerExit,
}

/// The checked OLESERVER/OLESERVERDOC::Release callback has returned. This
/// journal binds all following host side effects to the exact callback and
/// record generation, so a failed atom delete/endpoint retirement can be
/// retried without calling guest Release a second time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ReleaseCompletionJournalEntry {
    pub(crate) callback_id: u64,
    pub(crate) owner: OwnerId,
    pub(crate) target: Ole1ReleaseTarget,
    pub(crate) callback_result: Ole1ReleaseCallbackResult,
    pub(crate) phase: Ole1ReleasePhase,
}

/// EventId delivery obligations discovered while exact Release cleanup is
/// waiting for endpoint retirement. This record is separate from protocol
/// transactions: acknowledging an EventId never implies that WM_DDE_ACK was
/// received or that an HGLOBAL/atom lease was released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1PendingReleaseEvents {
    pub(crate) callback_id: u64,
    pub(crate) owner: OwnerId,
    pub(crate) target: Ole1ReleaseTarget,
    pub(crate) worker_generation: u64,
    pub(crate) pending_events: Vec<Win16ClassicDdeEventId>,
    /// Monotonic per callback. A dispatcher retries only against the exact
    /// pending receipt revision it admitted.
    pub(crate) receipt_revision: u64,
    acknowledged_events: BTreeSet<Win16ClassicDdeEventId>,
}

/// A host resource not represented by a live guest-visible server/document
/// record: either registration failed before publication or a document rename
/// detached its previous atom. The runtime keeps this exact owner until each
/// required RetireEndpoint and GlobalDeleteAtom operation succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1UnpublishedCleanupPhase {
    RetireEndpoint,
    DeleteAtom { index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct Ole1UnpublishedCleanupId(pub(crate) u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1UnpublishedCleanup {
    pub(crate) id: Ole1UnpublishedCleanupId,
    pub(crate) owner: OwnerId,
    /// Endpoint-less cleanup is used when endpoint creation failed after one
    /// or more atoms had already been acquired.
    pub(crate) endpoint: Option<Win16HostClassicDdeEndpoint>,
    /// The host worker incarnation that created `endpoint`; absent only when
    /// no endpoint was successfully created.
    pub(crate) worker_generation: Option<u64>,
    /// Exact global-atom references in retirement order. Duplicates are
    /// significant because separate GlobalAddAtom calls own separate refs.
    pub(crate) atoms: Vec<u16>,
    pub(crate) phase: Ole1UnpublishedCleanupPhase,
    pub(crate) pending_events: Vec<Win16ClassicDdeEventId>,
    pub(crate) receipt_revision: u64,
    acknowledged_events: BTreeSet<Win16ClassicDdeEventId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ole1UnpublishedCleanupAction {
    RetireEndpoint {
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        receipt_revision: u64,
    },
    DeleteAtom {
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        worker_generation: Option<u64>,
        atom: u16,
        receipt_revision: u64,
    },
}

/// Event-owned Release cascade for a queued WM_DDE_TERMINATE. The host
/// EventId remains unacknowledged while `next_target` is Some. A None target
/// means all required checked Release callbacks and native cleanup completed
/// and only the separate EventId acknowledgement remains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ServerDdeReleaseChain {
    /// The original exact queued event is retained as lifecycle provenance,
    /// even after its mailbox delivery is acknowledged.
    pub(crate) event: Win16HostClassicDdeEvent,
    pub(crate) next_target: Option<Ole1ReleaseTarget>,
    pub(crate) pending_events: Vec<Win16ClassicDdeEventId>,
    pub(crate) event_acknowledged: bool,
}

fn release_target_endpoint(target: Ole1ReleaseTarget) -> Win16HostClassicDdeEndpoint {
    match target {
        Ole1ReleaseTarget::Document { endpoint, .. }
        | Ole1ReleaseTarget::Server { endpoint, .. } => endpoint,
    }
}

fn release_target_worker_generation(target: Ole1ReleaseTarget) -> u64 {
    match target {
        Ole1ReleaseTarget::Document {
            endpoint_worker_generation,
            ..
        }
        | Ole1ReleaseTarget::Server {
            endpoint_worker_generation,
            ..
        } => endpoint_worker_generation,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ole1ConversationTarget {
    pub(crate) server: Ole1ServerHandle,
    pub(crate) server_generation: u64,
    pub(crate) document: Option<Ole1ServerDocumentHandle>,
    pub(crate) document_generation: Option<u64>,
}

/// The state object is owned by the Win16 runtime. Handles monotonically
/// increase and are not recycled, so a stale guest LONG cannot alias a later
/// registration even after its record is removed.
#[derive(Debug)]
pub(crate) struct Ole1ServerState {
    next_handle: Option<i32>,
    next_generation: Option<u64>,
    servers: BTreeMap<Ole1ServerHandle, Ole1ServerRecord>,
    documents: BTreeMap<Ole1ServerDocumentHandle, Ole1ServerDocumentRecord>,
    /// Exact document generations retired reentrantly from StdCloseDocument.
    /// The Execute continuation consumes this proof only after its matching
    /// DDE acknowledgement Post has a terminal receipt.
    retired_documents: BTreeMap<(OwnerId, Ole1ServerDocumentHandle), u64>,
    close_callback_documents: BTreeSet<(OwnerId, Ole1ServerDocumentHandle, u64)>,
    /// Exact Release callbacks whose guest call returned but whose global
    /// item-atom retirement or registry commit still needs completion.
    completion_journal: BTreeMap<u64, Ole1ServerCompletionJournalEntry>,
    release_completion_journal: BTreeMap<u64, Ole1ReleaseCompletionJournalEntry>,
    release_pending_events: BTreeMap<u64, Ole1PendingReleaseEvents>,
    next_unpublished_cleanup_id: Option<u64>,
    unpublished_cleanups: BTreeMap<Ole1UnpublishedCleanupId, Ole1UnpublishedCleanup>,
    dde_release_chains: Vec<Ole1ServerDdeReleaseChain>,
}

impl Default for Ole1ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl Ole1ServerState {
    pub(crate) fn new() -> Self {
        Self {
            next_handle: Some(1),
            next_generation: Some(1),
            servers: BTreeMap::new(),
            documents: BTreeMap::new(),
            retired_documents: BTreeMap::new(),
            close_callback_documents: BTreeSet::new(),
            completion_journal: BTreeMap::new(),
            release_completion_journal: BTreeMap::new(),
            release_pending_events: BTreeMap::new(),
            next_unpublished_cleanup_id: Some(1),
            unpublished_cleanups: BTreeMap::new(),
            dde_release_chains: Vec::new(),
        }
    }
}

// These fragments are included in this module to keep the private owner and
// generation ledgers together while keeping each source file reviewable.
include!("win16_ole1_server_state_cleanup_dde_chain.rs");
include!("win16_ole1_server_state_registry_and_conversations.rs");
include!("win16_ole1_server_state_termination_and_targets.rs");
include!("win16_ole1_server_state_release_completion.rs");
include!("win16_ole1_server_state_blocking_and_deferred.rs");
include!("win16_ole1_server_state_items_and_retirement.rs");

fn seed_pending_terminations(
    conversations: &BTreeMap<Win16ClassicDdeConversationId, Ole1ConversationBinding>,
    pending: &mut BTreeMap<Win16ClassicDdeConversationId, Ole1PendingTermination>,
) {
    for (id, binding) in conversations {
        pending.entry(*id).or_insert(Ole1PendingTermination {
            binding: *binding,
            phase: Ole1TerminationPhase::PostPending,
        });
    }
}

pub(crate) const OLE_ERROR_TERMINATE: Ole1Status = 37;
