//! Ownership records for the independent classic WM_DDE USER-worker lane.
//!
//! This state deliberately keeps classic-DDE host operation identities,
//! callback frames, queued EventIds, guest atom references, and guest HGLOBAL
//! copies separate from DDEML and ordinary USER operation state.

use crate::{
    Win16ClassicDdeEventTracker, Win16ClassicDdeOperationIdentity, Win16HostClassicDdeCall,
    Win16HostClassicDdeCallbackReply, Win16HostClassicDdeCallbackStep, Win16HostClassicDdeEvent,
    Win16HostClassicDdeStep,
};

use super::ole1::Win16Ole1ClientDdeDisposition;
use super::{
    CallbackFrameId,
    far_callback::Win16FarCallbackFrame,
    ole1::Win16Ole1OperationId,
    win16_ole1_server_callback::{
        Ole1ServerDdeContinuation, Ole1ServerDdeHostContinuation, Ole1ServerGuestCallbackFinish,
    },
    win16_ole1_server_dde::Ole1ServerInitiateContinuation,
    win16_ole1_server_state::Ole1UnpublishedCleanupId,
};
use crate::Win16HostClassicDdeResume;
use super::ole1::Ole1ServerShutdownPending;

pub(super) struct ClassicDdeRuntimeState {
    pub(super) event_tracker: Win16ClassicDdeEventTracker,
    pub(super) operations: Vec<ClassicDdeOperationFrame>,
    pub(super) pending_begins: Vec<ClassicDdePendingBegin>,
    pub(super) callbacks: Vec<ClassicDdeGuestCallbackFrame>,
    pub(super) atoms: super::classic_dde_atoms::ClassicDdeAtomLeases,
    pub(super) guest_globals: Vec<super::classic_dde_memory::ClassicDdeGuestGlobalLease>,
    /// A synchronous source can be retained by an OLE server while blocked.
    /// It remains paired with its exact host operation and is re-routed only
    /// after the server's own continuation says it is ready.
    pub(super) deferred_sync: Vec<std::sync::Arc<crate::Win16HostClassicDdeCallbackStep>>,
    /// Queued entries that are published to an OLE journal or guest callback
    /// remain here until a separate EventAcknowledged terminal is consumed.
    pub(super) queued_events: Vec<ClassicDdeQueuedEvent>,
    /// Exact endpoint/EventId waits returned by RetireEndpoint. The endpoint
    /// may differ from the endpoint that began a server/document release.
    pub(super) pending_endpoint_polls: Vec<ClassicDdePendingEndpointPoll>,
    /// Events temporarily held by OLE while a prerequisite host operation is
    /// in flight. They are retried only after that exact operation terminal.
    pub(super) deferred_queued_events: Vec<Win16HostClassicDdeEvent>,
    /// Recoverable task-exit owner barrier. The host-issued ID and latest
    /// inventory are retained until the USER worker itself proves quiescence.
    pub(super) owner_shutdown: Option<ClassicDdeOwnerShutdown>,
}

impl Default for ClassicDdeRuntimeState {
    fn default() -> Self {
        Self {
            event_tracker: Win16ClassicDdeEventTracker::default(),
            operations: Vec::new(),
            pending_begins: Vec::new(),
            callbacks: Vec::new(),
            atoms: super::classic_dde_atoms::ClassicDdeAtomLeases::default(),
            guest_globals: Vec::new(),
            deferred_sync: Vec::new(),
            queued_events: Vec::new(),
            pending_endpoint_polls: Vec::new(),
            deferred_queued_events: Vec::new(),
            owner_shutdown: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum ClassicDdeOperationOwner {
    /// A bounded mailbox poll. Its result is either no event or one exact
    /// queued event; it does not complete an OLE API or USER wait.
    PollOwner { owner: guest_core::OwnerId },
    PollEndpoint {
        owner: guest_core::OwnerId,
        endpoint: crate::Win16HostClassicDdeEndpoint,
        expected_event_ids: Vec<crate::Win16ClassicDdeEventId>,
    },
    Client {
        owner: guest_core::OwnerId,
        operation: Win16Ole1OperationId,
        bind_initiate: bool,
    },
    ClientEventAcknowledgement {
        owner: guest_core::OwnerId,
        operation: Win16Ole1OperationId,
    },
    ServerInitiate {
        continuation: Ole1ServerInitiateContinuation,
    },
    ServerDde {
        continuation: Ole1ServerDdeHostContinuation,
    },
    /// A well-formed owned Execute resolved to an OLE status without entering
    /// its guest vtable. The matching positive, busy, or negative WM_DDE_ACK
    /// must be posted before the synchronous callback resumes or queued
    /// EventId retires.
    ServerProtocolResultPost {
        event: Win16HostClassicDdeEvent,
        status: u16,
        callback_step: Option<std::sync::Arc<Win16HostClassicDdeCallbackStep>>,
    },
    /// Separate host EventId retirement after a queued protocol ACK was
    /// posted. It is not the DDE wire WM_DDE_ACK itself.
    ServerProtocolResultEventAcknowledgement { event: Win16HostClassicDdeEvent },
    UnpublishedCleanupEvent {
        cleanup_id: Ole1UnpublishedCleanupId,
        event: Win16HostClassicDdeEvent,
    },
    UnpublishedCleanupRetire {
        cleanup_id: Ole1UnpublishedCleanupId,
        owner: guest_core::OwnerId,
        expected_revision: u64,
    },
    ClassicDdeOwnerShutdown {
        owner: guest_core::OwnerId,
    },
}

pub(super) struct ClassicDdeOwnerShutdown {
    pub(super) owner: guest_core::OwnerId,
    pub(super) barrier: Option<crate::Win16ClassicDdeQuiescenceId>,
    pub(super) worker_generation: Option<u64>,
    /// True only when OLESVR server/document shutdown returned its explicit
    /// server-side drained state. This is not an owner-wide quiescence proof.
    pub(super) server_side_drained: bool,
    pub(super) server_pending: Option<Ole1ServerShutdownPending>,
    /// The worker can be quiesced while guest-side ownership still prevents
    /// task retirement. Keep that distinction explicit and retryable.
    pub(super) host_quiesced: bool,
    pub(super) worker_quiesced: bool,
    pub(super) runtime_pending: Option<ClassicDdeOwnerRuntimePending>,
    pub(super) latest_snapshot: Option<crate::Win16HostClassicDdeOwnerQuiescence>,
    /// Preserve the typed host cause when a barrier query must be retried.
    /// It is diagnostic state only and never changes the proof requirement.
    pub(super) last_failure: Option<std::sync::Arc<crate::Win16HostClassicDdeStartedFailure>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ClassicDdeOwnerRuntimePending {
    HostOperation { count: usize },
    PendingBegin { count: usize },
    QueuedEvent { count: usize },
    DeferredEvent { count: usize },
    GuestCallback { count: usize },
    GuestGlobal { count: usize },
    EndpointPoll { count: usize },
    AtomLease,
    /// Exact OLESVR CloseDocument callbacks remain pending until their DDE
    /// ACK Post reaches the protocol terminal path.
    ServerCloseDocumentProof { count: usize },
    ServerEndpoint { count: usize },
    /// The native worker still reports exact endpoints or operations after
    /// server/document OLE shutdown. `latest_snapshot` retains their full
    /// host identities; this count records the explicit client/other endpoint
    /// gap instead of treating an empty mailbox poll as quiescence.
    NativeHostInventory {
        endpoints: usize,
        active_operations: usize,
    },
    ClientDdeOwnerPending { count: usize },
}

pub(super) struct ClassicDdePendingEndpointPoll {
    pub(super) owner: guest_core::OwnerId,
    pub(super) endpoint: crate::Win16HostClassicDdeEndpoint,
    pub(super) event_ids: Vec<crate::Win16ClassicDdeEventId>,
}

pub(super) struct ClassicDdeOperationFrame {
    pub(super) identity: Win16ClassicDdeOperationIdentity,
    pub(super) call: Win16HostClassicDdeCall,
    pub(super) step: Win16HostClassicDdeStep,
    pub(super) owner: ClassicDdeOperationOwner,
    /// Exact parent callback reply, present only for a nested operation whose
    /// business journal has already selected the reply but must wait for this
    /// operation's terminal receipt before returning it to the worker.
    pub(super) resume_parent: Option<Win16HostClassicDdeCallbackReply>,
    /// Persist host proof consumption across local lease-cleanup retries.
    pub(super) source_retirement_consumed: bool,
    /// Host begin and operation-table insertion precede client-journal bind.
    /// If that allocation fails, the exact live identity remains here and the
    /// binding is retried before resuming or routing its terminal.
    pub(super) client_binding_pending: bool,
    /// Terminal consumers can mutate their business journals before local
    /// source/lease cleanup succeeds. Retain each successful result here so a
    /// retry never replays a committed journal transition.
    pub(super) client_terminal_disposition: Option<Win16Ole1ClientDdeDisposition>,
    pub(super) client_receipt_committed: bool,
    pub(super) server_initiate_resume: Option<Win16HostClassicDdeResume>,
    pub(super) server_initiate_receipt_committed: bool,
    pub(super) server_dde_finish: Option<Ole1ServerGuestCallbackFinish>,
    pub(super) server_protocol_result_global_retired: bool,
    pub(super) unpublished_retirement_recorded: bool,
    /// If the host rejects a callback-resume command before returning a step,
    /// retry this exact reply instead of routing the still-suspended callback
    /// through business code a second time.
    pub(super) pending_callback_resume: Option<Win16HostClassicDdeCallbackReply>,
    /// An accepted Untranslated reply is a retained fact until the host's
    /// matching callback/source retirement is consumed. Parked USER waits may
    /// return Started before their terminal receipt can be collected.
    pub(super) accepted_untranslated_callbacks: Vec<Win16HostClassicDdeCallbackReply>,
    /// Exact local cleanup phases after the host accepted a synchronous
    /// callback reply. Keep this journal through guest GlobalFree and atom
    /// deletion failures so a terminal operation cannot be popped while either
    /// resource class remains owned.
    pub(super) pending_callback_event_cleanup: Option<ClassicDdeCallbackEventCleanup>,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ClassicDdeCallbackEventCleanup {
    pub(super) event: Win16HostClassicDdeEvent,
    pub(super) accepted_untranslated: bool,
    pub(super) guest_global_pending: bool,
    pub(super) atoms_pending: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ClassicDdePendingBegin {
    pub(super) call: Win16HostClassicDdeCall,
    pub(super) owner: ClassicDdeOperationOwner,
    pub(super) resume_parent: Option<Win16HostClassicDdeCallbackReply>,
}

pub(super) struct ClassicDdeGuestCallbackFrame {
    pub(super) callback_id: CallbackFrameId,
    pub(super) guest_frame: Win16FarCallbackFrame,
    pub(super) continuation: Ole1ServerDdeContinuation,
    /// Persist the checked guest return before CPU-owner or business cleanup
    /// can fail. A safe-point retry must never execute this guest again.
    pub(super) returned_value: Option<u32>,
    pub(super) binding_retired: bool,
    /// Once the server helper commits its business phases, retain only its
    /// generated action; retrying the action must not replay that helper.
    pub(super) server_finish: Option<Ole1ServerGuestCallbackFinish>,
    /// Exact nested poll draining EventIds that prevent a provisional
    /// document's finish cleanup. Retrying the helper must let this poll run.
    pub(super) cleanup_poll: Option<Win16ClassicDdeOperationIdentity>,
}

#[derive(Clone)]
pub(super) struct ClassicDdeQueuedEvent {
    pub(super) event: Win16HostClassicDdeEvent,
}
