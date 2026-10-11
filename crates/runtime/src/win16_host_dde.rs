//! Pointer-free DDEML host protocol. Native HDDEDATA/HSZ/HCONV values remain
//! opaque tokens, and all data crossing this boundary is copied and owned.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::{DiagnosticKind, RuntimeError};

#[path = "win16_host_dde_retirement.rs"]
mod retirement;
pub use retirement::{
    Win16DdeOperationRequestPhase, Win16DdeOperationStartedFailure,
    Win16DdeSourceRetiredProof, Win16HostDdeCallbackStep, Win16HostDdeResume,
    Win16HostDdeStep,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeInstance(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeString(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeConversation(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeConversationList(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeData(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeOwner(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeOperation(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeAbortOwnerStatus {
    NotStarted,
    Active,
    Quiesced,
    Retained,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeAbortWorkerStatus {
    NotStarted,
    Running,
    Joined,
    Panicked,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeAbortPhase {
    StartOwner,
    CancelCallback,
    CancelOperation,
    ReleaseCallbackReply,
    DisconnectConversation,
    UninitializeInstance,
    DestroyControlWindow,
    JoinWorker,
    ReceiveReceipt,
    ReconcileRuntimeLedger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeCleanupStatus {
    Released,
    Retained,
    RetriedAndReleased,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeCallbackReplyRole {
    ReturnedData,
    WildConnectSource,
    WildConnectReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeCallbackCancellationStatus {
    Requested,
    NativeCallbackReturned,
    FrameAcknowledged,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeCancellationSource {
    OwnerShutdown,
    GuestReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeOperationCancellationStatus {
    Requested,
    CompletedDuringAbort,
    CancelledByOwnerShutdown,
    /// The owner reported the exact native operation's terminal error before
    /// shutdown. It is terminal evidence, not a cancellation acknowledgement.
    NativeCompleteError,
    /// The exact native operation returned a normal result. This proves the
    /// worker call ended, while the separate source-retirement proof tracks
    /// whether its DDE source was popped.
    NativeCompleteReturned,
    Retained,
}

#[derive(Clone, Debug)]
pub struct Win16DdeCleanupFailure {
    pub phase: Win16DdeAbortPhase,
    pub frame: Option<Win16HostDdeCallbackFrame>,
    pub operation: Option<Win16HostDdeOperation>,
    pub instance: Option<Win16HostDdeInstance>,
    pub status: Win16DdeCleanupStatus,
    pub cause: Arc<RuntimeError>,
}

#[derive(Clone, Debug)]
pub struct Win16DdeCallbackCancellation {
    pub frame: Win16HostDdeCallbackFrame,
    pub parent_operation: Option<Win16HostDdeOperation>,
    pub instance: Option<Win16HostDdeInstance>,
    pub source: Win16DdeCancellationSource,
    pub status: Win16DdeCallbackCancellationStatus,
    pub failure: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Debug)]
pub struct Win16DdeOperationCancellation {
    pub operation: Win16HostDdeOperation,
    pub instance: Option<Win16HostDdeInstance>,
    pub status: Win16DdeOperationCancellationStatus,
    pub failure: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeNativeTransferGuardSource {
    /// The exact worker command was cancelled before its native call started.
    NotEntered,
    /// Native protocol preflight rejected the handle before DDEML entry.
    PreflightRejected,
    /// DDEML returned and the exact native transfer map entry was consumed.
    NativeCompletion(Win16HostDdeDataTransferOutcome),
    /// The exact successful DdeUninitialize released the instance-owned map.
    InstanceUninitialized,
    /// The guard remains in its exact native owner map.
    Retained,
}

#[derive(Clone, Debug)]
pub struct Win16DdeNativeTransferGuardReceipt {
    pub operation: Win16HostDdeOperation,
    pub data: Win16HostDdeData,
    pub instance: Win16HostDdeInstance,
    pub source: Win16DdeNativeTransferGuardSource,
    pub failure: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Debug)]
pub struct Win16DdeOperationRetirementProof {
    pub owner: Win16HostDdeOwner,
    /// Stable worker incarnation assigned independently of the owner token.
    pub worker_generation: u64,
    pub request_id: u64,
    pub cancellation: Win16DdeOperationCancellation,
    /// Exact callback frames nested under this native operation. The frames
    /// remain part of the proof after their active callback sources retire.
    pub callback_receipts: Vec<Win16DdeCallbackCancellation>,
    pub transfer_guard: Option<Win16DdeNativeTransferGuardReceipt>,
}

impl PartialEq for Win16DdeCallbackCancellation {
    fn eq(&self, other: &Self) -> bool {
        self.frame == other.frame
            && self.parent_operation == other.parent_operation
            && self.instance == other.instance
            && self.source == other.source
            && self.status == other.status
            && same_retirement_failure(&self.failure, &other.failure)
    }
}

impl PartialEq for Win16DdeOperationCancellation {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.instance == other.instance
            && self.status == other.status
            && same_retirement_failure(&self.failure, &other.failure)
    }
}

impl PartialEq for Win16DdeNativeTransferGuardReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.data == other.data
            && self.instance == other.instance
            && self.source == other.source
            && same_retirement_failure(&self.failure, &other.failure)
    }
}

impl PartialEq for Win16DdeOperationRetirementProof {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.worker_generation == other.worker_generation
            && self.request_id == other.request_id
            && self.cancellation == other.cancellation
            && self.callback_receipts == other.callback_receipts
            && self.transfer_guard == other.transfer_guard
    }
}

fn same_retirement_failure(
    left: &Option<Arc<RuntimeError>>,
    right: &Option<Arc<RuntimeError>>,
) -> bool {
    // A cached proof must retain the same owned cause. RuntimeError carries a
    // source chain and has no value equality; comparing Display text loses it.
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

impl Win16DdeOperationRetirementProof {
    /// Read-only exact identity check used by runtime and host consumers
    /// before they pop the matching guest continuation frame.
    pub fn matches_receipt(&self, receipt: &Win16DdeAbortReceipt) -> bool {
        if !receipt.is_quiesced()
            || self.worker_generation == 0
            || receipt.owner != Some(self.owner)
            || receipt.worker_generation != Some(self.worker_generation)
            || receipt.request_id != Some(self.request_id)
            || self.request_id == 0
            || !matches!(
                self.cancellation.status,
                Win16DdeOperationCancellationStatus::CompletedDuringAbort
                    | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                    | Win16DdeOperationCancellationStatus::NativeCompleteError
                    | Win16DdeOperationCancellationStatus::NativeCompleteReturned
            )
        {
            return false;
        }
        let mut cancellations = receipt
            .cancelled_operations
            .iter()
            .filter(|entry| entry.operation == self.cancellation.operation);
        let Some(cancellation) = cancellations.next() else {
            return false;
        };
        if cancellations.next().is_some() || !same_operation_cancellation(cancellation, &self.cancellation) {
            return false;
        }
        let actual_callbacks: Vec<_> = receipt.cancelled_callbacks.iter().filter(|callback| {
            callback.parent_operation == Some(self.cancellation.operation)
        }).collect();
        if actual_callbacks.len() != self.callback_receipts.len()
            || self.callback_receipts.iter().any(|expected| {
                !matches!(
                    expected.status,
                    Win16DdeCallbackCancellationStatus::FrameAcknowledged
                ) || !matches!(
                    expected.source,
                    Win16DdeCancellationSource::GuestReply | Win16DdeCancellationSource::OwnerShutdown
                ) || actual_callbacks.iter().filter(|actual| same_callback_cancellation(actual, expected)).count() != 1
            })
            || actual_callbacks.iter().any(|actual| {
                self.callback_receipts.iter().filter(|expected| same_callback_cancellation(actual, expected)).count() != 1
            })
        {
            return false;
        }
        let mut guards = receipt.native_transfer_guards.iter().filter(|guard| {
            guard.operation == self.cancellation.operation
        });
        match (&self.transfer_guard, guards.next()) {
            (None, None) => guards.next().is_none(),
            (Some(expected), Some(actual)) => {
                guards.next().is_none()
                    && actual.source != Win16DdeNativeTransferGuardSource::Retained
                    && same_transfer_guard(actual, expected)
            }
            _ => false,
        }
    }

    /// Match a typed Begin failure to this exact owner, worker incarnation,
    /// operation and terminal report. A NativeCompleteError carries the same
    /// original cause Arc from the worker completion record; SubmittedPending
    /// may later resolve to shutdown cancellation or an actual normal return.
    pub fn matches_started_failure(
        &self,
        failure: &Win16DdeOperationStartedFailure,
    ) -> bool {
        if self.owner != failure.owner
            || self.worker_generation != failure.worker_generation
            || self.cancellation.operation != failure.operation
        {
            return false;
        }
        match failure.request_phase {
            Win16DdeOperationRequestPhase::SubmittedPending => matches!(
                self.cancellation.status,
                Win16DdeOperationCancellationStatus::CompletedDuringAbort
                    | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                    | Win16DdeOperationCancellationStatus::NativeCompleteError
                    | Win16DdeOperationCancellationStatus::NativeCompleteReturned
            ) && (self.cancellation.status
                != Win16DdeOperationCancellationStatus::NativeCompleteError
                || self.cancellation.failure.is_some()),
            Win16DdeOperationRequestPhase::NativeCompleteError => {
                self.cancellation.status
                    == Win16DdeOperationCancellationStatus::NativeCompleteError
                    && self
                        .cancellation
                        .failure
                        .as_ref()
                        .is_some_and(|cause| Arc::ptr_eq(cause, &failure.cause))
            }
            // The native API returned normally, but the adapter failed before it
            // could publish a normal source-retirement carrier. That adapter
            // error is separate from the exact native cancellation record.
            Win16DdeOperationRequestPhase::NativeCompleteReturned => {
                self.cancellation.status
                    == Win16DdeOperationCancellationStatus::NativeCompleteReturned
                    && self.cancellation.failure.is_none()
            }
        }
    }
}

fn same_operation_cancellation(
    left: &Win16DdeOperationCancellation,
    right: &Win16DdeOperationCancellation,
) -> bool {
    left.operation == right.operation
        && left.instance == right.instance
        && left.status == right.status
        && same_optional_error(&left.failure, &right.failure)
}

fn same_callback_cancellation(
    left: &Win16DdeCallbackCancellation,
    right: &Win16DdeCallbackCancellation,
) -> bool {
    left.frame == right.frame
        && left.parent_operation == right.parent_operation
        && left.instance == right.instance
        && left.source == right.source
        && left.status == right.status
        && same_optional_error(&left.failure, &right.failure)
}

fn same_transfer_guard(
    left: &Win16DdeNativeTransferGuardReceipt,
    right: &Win16DdeNativeTransferGuardReceipt,
) -> bool {
    left.operation == right.operation
        && left.data == right.data
        && left.instance == right.instance
        && left.source == right.source
        && same_optional_error(&left.failure, &right.failure)
}

fn same_optional_error(
    left: &Option<Arc<RuntimeError>>,
    right: &Option<Arc<RuntimeError>>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub enum Win16DdeOperationRetirement {
    Released(Win16DdeOperationRetirementProof),
    Retained {
        operation: Option<Win16HostDdeOperation>,
        proof: Option<Win16DdeOperationRetirementProof>,
        cause: Arc<RuntimeError>,
    },
}

#[derive(Clone, Debug)]
pub struct Win16DdeNativeInstanceReceipt {
    pub instance: Win16HostDdeInstance,
    pub status: Win16DdeCleanupStatus,
    pub failure: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Debug)]
pub struct Win16DdeNativeReplyReceipt {
    pub frame: Win16HostDdeCallbackFrame,
    pub operation: Option<Win16HostDdeOperation>,
    pub instance: Win16HostDdeInstance,
    pub role: Win16DdeCallbackReplyRole,
    pub status: Win16DdeCleanupStatus,
    pub failure: Option<Arc<RuntimeError>>,
}

/// Final evidence emitted by the DDE owner after callback, reply, conversation,
/// and instance cleanup has completed on its initializing thread. Worker join
/// remains a separate host-side fact in `Win16DdeAbortReceipt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16DdeNativeOwnerShutdownReceipt {
    pub owner: Win16HostDdeOwner,
    pub worker_generation: u64,
    pub request_id: u64,
    pub all_native_callbacks_returned: bool,
    pub all_active_operations_returned: bool,
    pub all_native_replies_released_or_transferred: bool,
    pub all_native_transfer_guards_retired: bool,
    pub all_native_instances_uninitialized: bool,
    pub control_window_destroyed: bool,
}

/// Evidence returned by DDE abort even when cleanup remains incomplete.
/// Worker termination and native resource release are independent facts.
#[derive(Clone, Debug)]
pub struct Win16DdeAbortReceipt {
    pub owner: Option<Win16HostDdeOwner>,
    pub worker_generation: Option<u64>,
    pub request_id: Option<u64>,
    pub native_owner_receipt: Option<Win16DdeNativeOwnerShutdownReceipt>,
    pub owner_status: Win16DdeAbortOwnerStatus,
    pub worker_status: Win16DdeAbortWorkerStatus,
    pub cancelled_callbacks: Vec<Win16DdeCallbackCancellation>,
    pub cancelled_operations: Vec<Win16DdeOperationCancellation>,
    pub native_instances: Vec<Win16DdeNativeInstanceReceipt>,
    pub native_replies: Vec<Win16DdeNativeReplyReceipt>,
    pub native_transfer_guards: Vec<Win16DdeNativeTransferGuardReceipt>,
    pub cleanup_failures: Vec<Win16DdeCleanupFailure>,
}

impl Win16DdeAbortReceipt {
    pub fn not_started() -> Self {
        Self {
            owner: None,
            worker_generation: None,
            request_id: None,
            native_owner_receipt: None,
            owner_status: Win16DdeAbortOwnerStatus::NotStarted,
            worker_status: Win16DdeAbortWorkerStatus::NotStarted,
            cancelled_callbacks: Vec::new(),
            cancelled_operations: Vec::new(),
            native_instances: Vec::new(),
            native_replies: Vec::new(),
            native_transfer_guards: Vec::new(),
            cleanup_failures: Vec::new(),
        }
    }

    pub fn unsupported(cause: RuntimeError) -> Self {
        Self {
            owner: None,
            worker_generation: None,
            request_id: None,
            native_owner_receipt: None,
            owner_status: Win16DdeAbortOwnerStatus::Unsupported,
            worker_status: Win16DdeAbortWorkerStatus::Unsupported,
            cancelled_callbacks: Vec::new(),
            cancelled_operations: Vec::new(),
            native_instances: Vec::new(),
            native_replies: Vec::new(),
            native_transfer_guards: Vec::new(),
            cleanup_failures: vec![Win16DdeCleanupFailure {
                phase: Win16DdeAbortPhase::StartOwner,
                frame: None,
                operation: None,
                instance: None,
                status: Win16DdeCleanupStatus::Unresolved,
                cause: Arc::new(cause),
            }],
        }
    }

    pub fn is_quiesced(&self) -> bool {
        let never_created = self.owner.is_none()
            && self.worker_generation.is_none()
            && self.request_id.is_none()
            && self.native_owner_receipt.is_none()
            && self.owner_status == Win16DdeAbortOwnerStatus::NotStarted
            && self.worker_status == Win16DdeAbortWorkerStatus::NotStarted
            && self.cancelled_callbacks.is_empty()
            && self.cancelled_operations.is_empty()
            && self.native_instances.is_empty()
            && self.native_replies.is_empty()
            && self.native_transfer_guards.is_empty()
            && self.cleanup_failures.is_empty();
        if never_created {
            return true;
        }
        self.owner_status == Win16DdeAbortOwnerStatus::Quiesced
            && self.quiescence_evidence_ready()
    }

    /// Complete worker and native evidence before the shutdown loop promotes
    /// the owner status from Active to Quiesced.
    pub fn quiescence_evidence_ready(&self) -> bool {
        let never_created = self.owner.is_none()
            && self.worker_generation.is_none()
            && self.request_id.is_none()
            && self.native_owner_receipt.is_none()
            && self.owner_status == Win16DdeAbortOwnerStatus::NotStarted
            && self.worker_status == Win16DdeAbortWorkerStatus::NotStarted;
        let native_owner_done = never_created || self.native_owner_receipt.is_some_and(|receipt| {
            self.owner == Some(receipt.owner)
                && self.worker_generation == Some(receipt.worker_generation)
                && self.request_id == Some(receipt.request_id)
                && receipt.request_id != 0
                && receipt.all_native_callbacks_returned
                && receipt.all_active_operations_returned
                && receipt.all_native_replies_released_or_transferred
                && receipt.all_native_transfer_guards_retired
                && receipt.all_native_instances_uninitialized
                && receipt.control_window_destroyed
        });
        (never_created || self.worker_status == Win16DdeAbortWorkerStatus::Joined)
            && native_owner_done
            && self
                .cancelled_callbacks
                .iter()
                .all(|callback| callback.status == Win16DdeCallbackCancellationStatus::FrameAcknowledged)
            && self.cancelled_operations.iter().all(|operation| {
                matches!(
                    operation.status,
                    Win16DdeOperationCancellationStatus::CompletedDuringAbort
                        | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                        | Win16DdeOperationCancellationStatus::NativeCompleteError
                        | Win16DdeOperationCancellationStatus::NativeCompleteReturned
                )
            })
            && self.native_instances.iter().all(|instance| {
                matches!(
                    instance.status,
                    Win16DdeCleanupStatus::Released | Win16DdeCleanupStatus::RetriedAndReleased
                )
            })
            && self.native_replies.iter().all(|reply| {
                matches!(
                    reply.status,
                    Win16DdeCleanupStatus::Released | Win16DdeCleanupStatus::RetriedAndReleased
                )
            })
            && self.native_transfer_guards.iter().all(|guard| {
                if guard.source == Win16DdeNativeTransferGuardSource::Retained
                {
                    return false;
                }
                let mut matches = self
                    .cancelled_operations
                    .iter()
                    .filter(|entry| entry.operation == guard.operation);
                let Some(operation) = matches.next() else {
                    return false;
                };
                matches.next().is_none()
                    && operation.instance == Some(guard.instance)
                    && matches!(
                        operation.status,
                        Win16DdeOperationCancellationStatus::CompletedDuringAbort
                            | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                            | Win16DdeOperationCancellationStatus::NativeCompleteError
                            | Win16DdeOperationCancellationStatus::NativeCompleteReturned
                    )
                    && (guard.source != Win16DdeNativeTransferGuardSource::NotEntered
                        || operation.status
                            == Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown)
            })
            && self.native_transfer_guards.iter().enumerate().all(|(index, guard)| {
                !self.native_transfer_guards[..index].iter().any(|prior| {
                    prior.operation == guard.operation
                        && prior.data == guard.data
                        && prior.instance == guard.instance
                })
            })
            && self.cleanup_failures.iter().all(|failure| {
                matches!(
                    failure.status,
                    Win16DdeCleanupStatus::Released | Win16DdeCleanupStatus::RetriedAndReleased
                )
            })
    }

    pub fn as_error(&self) -> RuntimeError {
        RuntimeError::with_source(
            DiagnosticKind::HostFailure,
            "Win16 DDE abort did not prove native owner quiescence",
            self.clone(),
        )
    }
}

impl fmt::Display for Win16DdeAbortReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DDE abort receipt owner={:?} request={:?} owner-status={:?} worker-status={:?}, native-receipt={}; {} callback cancellation(s), {} operation cancellation(s), {} transfer guard receipt(s), {} retained native instance(s), {} retained callback reply handle(s), {} cleanup failure(s)",
            self.owner,
            self.request_id,
            self.owner_status,
            self.worker_status,
            self.native_owner_receipt.is_some(),
            self.cancelled_callbacks.len(),
            self.cancelled_operations.len(),
            self.native_transfer_guards.len(),
            self.native_instances
                .iter()
                .filter(|entry| entry.status == Win16DdeCleanupStatus::Retained)
                .count(),
            self.native_replies
                .iter()
                .filter(|entry| entry.status == Win16DdeCleanupStatus::Retained)
                .count(),
            self.cleanup_failures
                .iter()
                .filter(|entry| entry.status == Win16DdeCleanupStatus::Unresolved)
                .count(),
        )
    }
}

impl Error for Win16DdeAbortReceipt {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup_failures
            .iter()
            .find(|failure| failure.status == Win16DdeCleanupStatus::Unresolved)
            .map(|failure| failure.cause.as_ref() as &(dyn Error + 'static))
    }
}

/// Native DDE conversation context fields after conversion from Win16 layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDdeContext {
    pub flags: u16,
    pub country_id: u16,
    pub code_page: i16,
    pub language_id: u32,
    pub security: u32,
}

/// Host callback values contain no guest addresses or callback FARPROC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16DdeCallbackCall {
    pub host_instance: Win16HostDdeInstance,
    /// The callback route captured by the native adapter when this callback
    /// began. It stays stable while a later DdeInitialize replaces a route.
    pub callback_route: u64,
    pub transaction_type: u32,
    pub format: u16,
    pub host_conversation: Option<Win16HostDdeConversation>,
    pub host_string_1: Option<Win16HostDdeString>,
    pub host_string_2: Option<Win16HostDdeString>,
    /// DDEML's callback hData has a small number of transaction-specific
    /// scalar meanings. Keep those distinct from an opaque native HDDEDATA.
    pub data: Win16HostDdeCallbackData,
    pub conversation_context: Option<Win16HostDdeContext>,
    pub data_1: Option<u32>,
    pub data_2: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDdeCallbackData {
    /// Native callback hData was NULL.
    Null,
    /// XTYP_XACT_COMPLETE reports successful completion without data using
    /// the scalar TRUE value. This is not an HDDEDATA handle.
    SuccessNoData,
    /// Native callback hData is a borrowed HDDEDATA valid for this callback.
    Borrowed {
        handle: Win16HostDdeData,
        snapshot: Option<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDdeStringPair {
    pub service: Option<Win16HostDdeString>,
    pub topic: Option<Win16HostDdeString>,
}

/// Pointer-free projection of native CONVINFO for Win16 layout conversion.
/// Handles are host tokens, while `user_handle` remains an application scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDdeConversationInfo {
    pub user_handle: u32,
    pub partner: Option<Win16HostDdeConversation>,
    /// The DDEML instance that owns a native partner HCONV, if known. A
    /// query-only alias has no native owner and therefore uses None.
    pub partner_instance: Option<Win16HostDdeInstance>,
    /// The partner is a query-only alias when the native adapter could not
    /// associate it with an already known owned conversation.
    pub partner_query_only: bool,
    pub service_partner: Option<Win16HostDdeString>,
    pub service_requested: Option<Win16HostDdeString>,
    pub topic: Option<Win16HostDdeString>,
    pub item: Option<Win16HostDdeString>,
    pub format: u16,
    pub transaction_type: u16,
    pub status: u16,
    pub conversation_state: u16,
    pub last_error: u16,
    pub conversation_list: Option<Win16HostDdeConversationList>,
    pub context: Win16HostDdeContext,
}

/// Reply values are checked guest return values. The native adapter maps only
/// an opaque host data token to the corresponding HDDEDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16DdeCallbackReply {
    NoData,
    /// The owner is quiescing and cancelled this suspended callback. Native
    /// DDEML receives the same null result as a no-data reply, while the
    /// shutdown receipt preserves that this was an abort response.
    CancelledByOwnerShutdown,
    Data(Win16HostDdeData),
    /// Guest XTYP_WILDCONNECT returned a Win16 HSZPAIR array. The runtime
    /// validates each guest token; the owner builds native-width HSZPAIRs.
    WildConnect {
        /// Guest HDDEDATA whose Win16 HSZPAIR bytes were converted to native
        /// HSZPAIR records. The native owner consumes it using the same
        /// provenance rules as an ordinary data callback return.
        source: Win16HostDdeData,
        pairs: Vec<Win16HostDdeStringPair>,
    },
    Scalar(u32),
}

/// Identity of a suspended native callback frame. It has a separate Rust type
/// from the foreground DDE operation so nested calls cannot confuse the two.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostDdeCallbackFrame(pub u64);

/// Operations needed by the 27 DDEML exports in the selected inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDdeTransactionData {
    None,
    Bytes(Vec<u8>),
    Data(Win16HostDdeData),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDdeCall {
    Initialize { existing: Option<Win16HostDdeInstance>, callback_route: u64, flags: u32, reserved: u32 },
    Uninitialize { instance: Win16HostDdeInstance },
    ConnectList { instance: Win16HostDdeInstance, service: Option<Win16HostDdeString>, topic: Option<Win16HostDdeString>, list: Option<Win16HostDdeConversationList>, context: Option<Win16HostDdeContext> },
    QueryNextServer { list: Win16HostDdeConversationList, previous: Option<Win16HostDdeConversation> },
    DisconnectList { list: Win16HostDdeConversationList },
    Connect { instance: Win16HostDdeInstance, service: Option<Win16HostDdeString>, topic: Option<Win16HostDdeString>, context: Option<Win16HostDdeContext> },
    Disconnect { conversation: Win16HostDdeConversation },
    QueryConversationInfo { conversation: Win16HostDdeConversation, transaction: u32 },
    SetUserHandle { conversation: Win16HostDdeConversation, transaction: u32, user_data: u32 },
    ClientTransaction { instance: Win16HostDdeInstance, data: Win16HostDdeTransactionData, conversation: Win16HostDdeConversation, item: Option<Win16HostDdeString>, format: u16, transaction_type: u16, timeout: u32, return_result: bool, copyback: Option<Vec<u8>> },
    AbandonTransaction { instance: Win16HostDdeInstance, conversation: Option<Win16HostDdeConversation>, transaction: u32 },
    PostAdvise { instance: Win16HostDdeInstance, topic: Option<Win16HostDdeString>, item: Option<Win16HostDdeString> },
    CreateData { instance: Win16HostDdeInstance, data: Option<Vec<u8>>, count: u32, offset: u32, item: Option<Win16HostDdeString>, format: u16, flags: u16 },
    AddData { data: Win16HostDdeData, bytes: Vec<u8>, offset: u32 },
    GetData { data: Win16HostDdeData, capacity: Option<u32>, offset: u32 },
    AccessData { data: Win16HostDdeData },
    /// `copyback` is present only for a guest-access snapshot whose DDEML
    /// ownership state allowed writes when that snapshot was opened.
    UnaccessData { data: Win16HostDdeData, copyback: Option<Vec<u8>> },
    FreeData { data: Win16HostDdeData },
    GetLastError { instance: Win16HostDdeInstance },
    CreateString { instance: Win16HostDdeInstance, value: Vec<u8>, code_page: i16 },
    FreeString { instance: Win16HostDdeInstance, string: Win16HostDdeString },
    QueryString { instance: Win16HostDdeInstance, string: Win16HostDdeString, capacity: Option<u32>, code_page: i16 },
    KeepString { instance: Win16HostDdeInstance, string: Win16HostDdeString },
    EnableCallback { instance: Win16HostDdeInstance, conversation: Option<Win16HostDdeConversation>, command: u16 },
    NameService { instance: Win16HostDdeInstance, service: Option<Win16HostDdeString>, reserved: Option<Win16HostDdeString>, command: u16 },
    CompareStrings { left: Win16HostDdeString, right: Win16HostDdeString },
    Reconnect { conversation: Win16HostDdeConversation },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDdeValue {
    None,
    Boolean(bool),
    Scalar(u32),
    Instance(Option<Win16HostDdeInstance>),
    String(Option<Win16HostDdeString>),
    Conversation(Option<Win16HostDdeConversation>),
    ConversationList(Option<Win16HostDdeConversationList>),
    Data(Option<Win16HostDdeData>),
    DisconnectedList { succeeded: bool, members: Vec<Win16HostDdeConversation> },
    ClientTransaction { data: Option<Win16HostDdeData>, succeeded: bool, entered_native: bool },
    AccessData { bytes: Vec<u8>, writable: bool },
    GetData { bytes: Vec<u8>, copied: u32 },
    Text { bytes: Vec<u8>, characters: u32 },
    ConversationInfo(Win16HostDdeConversationInfo),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDdeResult {
    pub value: Win16HostDdeValue,
    pub dde_error: u16,
    /// DdeClientTransaction's optional `pdwResult` output.
    pub transaction_result: Option<u32>,
    /// Exact ownership receipt for an existing Data token supplied to
    /// DdeClientTransaction. Other input forms and calls never carry one.
    pub data_transfer: Option<Win16HostDdeDataTransfer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostDdeDataTransferOutcome {
    /// Native preflight rejected the call before passing the token to DDEML.
    NotPassed,
    /// DDEML consumed the unowned handle when the call was made.
    Consumed,
    /// The guest APPOWNED policy retained the handle, but it is read-only.
    RetainedReadOnly,
    /// CallbackBorrowed or ClientResult source tokens remain owned by the
    /// guest while a safe byte copy in a fresh Created non-APPOWNED handle is
    /// passed to DDEML.
    CopiedInputRetained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDdeDataTransfer {
    pub token: Win16HostDdeData,
    pub outcome: Win16HostDdeDataTransferOutcome,
}
