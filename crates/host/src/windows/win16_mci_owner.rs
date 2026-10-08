//! Host-owned MCI identity, continuation, and notification queues.

#[path = "win16_mci_worker.rs"]
mod worker;
#[path = "win16_mci_owner_ack.rs"]
mod notification_ack;
#[path = "win16_mci_owner_ledger.rs"]
mod notification_ledger;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::sync::atomic::AtomicU64;

use super::multimedia_wake::MultimediaWakeSender;
use super::guest_text::GuestTextCodec;
use notification_ledger::combine_failure_kind;
use runtime::{
    RuntimeError, Win16HostMciCall, Win16HostMciDevice, Win16HostMciNotification,
    Win16HostMciNotificationId, Win16HostMciResume, Win16HostMciStep,
    Win16GuestNotificationSource, Win16HostWindow,
};
#[path = "win16_mci_owner_failure.rs"]
mod failure;

#[derive(Debug)]
struct NotificationRoute {
    id: Win16HostMciNotificationId,
    native_device: Option<u32>,
    device: Option<Win16HostMciDevice>,
    target: Win16HostWindow,
    allow_new_device: bool,
    source_id: Option<u64>,
    tombstone: bool,
}

#[derive(Clone, Copy)]
pub(super) struct NotificationDispatch {
    pub(super) id: Win16HostMciNotificationId,
    pub(super) device: Option<Win16HostMciDevice>,
    pub(super) allow_new_device: bool,
    pub(super) source_id: Option<u64>,
    pub(super) tombstone: bool,
}

#[derive(Default)]
pub(super) struct MciNotificationLedger {
    next_id: u64,
    source_admission_closed: bool,
    pending_count: usize,
    by_device: HashMap<u32, VecDeque<NotificationRoute>>,
    any_device: VecDeque<NotificationRoute>,
    events: VecDeque<Win16HostMciNotification>,
    failed_callbacks: VecDeque<MciCallbackFailure>,
    wake_failures: VecDeque<Arc<RuntimeError>>,
    worker_wait_failure: Option<Arc<RuntimeError>>,
    // Keep republishing a wake until peek snapshots this retained cause.
    worker_wait_wake_failure: Option<Arc<RuntimeError>>,
    worker_wait_wake_pending: bool,
    entered_yield_failure: Option<Arc<RuntimeError>>,
    entered_yield_wake_failure: Option<Arc<RuntimeError>>,
    entered_yield_client_failure: Option<Arc<RuntimeError>>,
    entered_yield_wake_pending: bool,
}

struct MciCallbackFailure {
    native_device: u32,
    id: Option<Win16HostMciNotificationId>,
    status: usize,
    cause: Arc<RuntimeError>,
}

/// Native worker is the sole MCI caller and native-device owner. Its worker
/// pumps nested runtime commands while a real MCI yield procedure is active.
pub(super) struct Win16MciHost {
    worker: worker::Win16MciWorker,
    notifications: Arc<Mutex<MciNotificationLedger>>,
}

impl Win16MciHost {
    pub(super) fn new(
        multimedia_wake: MultimediaWakeSender,
        identity_source: Arc<AtomicU64>,
        text_codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        let notifications = Arc::new(Mutex::new(MciNotificationLedger::default()));
        let worker = worker::Win16MciWorker::spawn(
            Arc::clone(&notifications),
            multimedia_wake,
            identity_source,
            text_codec,
        )?;
        Ok(Self {
            worker,
            notifications,
        })
    }

    pub(super) fn execute(
        &mut self,
        call: Win16HostMciCall,
    ) -> Result<Win16HostMciStep, RuntimeError> {
        self.worker.execute(call)
    }

    pub(super) fn reconcile_begin(
        &mut self,
        operation: runtime::Win16HostMciOperationId,
    ) -> Result<Option<Win16HostMciStep>, RuntimeError> {
        self.worker.reconcile_begin(operation)
    }

    pub(super) fn resume(
        &mut self,
        resume: Win16HostMciResume,
    ) -> Result<runtime::Win16HostMciResumeReceipt, RuntimeError> {
        self.worker.resume(resume)
    }

    pub(super) fn peek_notification(
        &mut self,
    ) -> Result<Option<Win16HostMciNotification>, RuntimeError> {
        self.notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .peek()
    }

    pub(super) fn acknowledge_notification(
        &self,
        source: Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        self.notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .acknowledge(source)
    }

    pub(super) fn quiesce_owned(
        &mut self,
        request: runtime::Win16HostMciQuiesceRequest,
    ) -> Result<runtime::Win16HostMciQuiescenceReceipt, RuntimeError> {
        self.worker.quiesce_owned(request)
    }

    pub(super) fn quiesce_producers(
        &mut self,
        request: runtime::Win16HostMciProducerQuiescenceRequest,
    ) -> Result<runtime::Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        self.worker.quiesce_producers(request)
    }
}
