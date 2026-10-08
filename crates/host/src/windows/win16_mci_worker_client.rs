//! Public-side MCI owner client and retained worker receipts.

#[path = "win16_mci_worker_client_quiesce.rs"]
mod quiesce;
#[path = "win16_mci_worker_client_producer_quiesce.rs"]
mod producer_quiesce;
#[path = "win16_mci_worker_client_receipts.rs"]
mod receipts;
#[path = "win16_mci_worker_client_resume.rs"]
mod resume;
#[path = "win16_mci_worker_client_reconcile.rs"]
mod reconcile;

use std::sync::{Arc, OnceLock};

use super::error::combine_worker_failures;
use super::*;

static MCI_WORKER_QUARANTINE: OnceLock<Mutex<Vec<super::MciWorkerQuarantineSlot>>> =
    OnceLock::new();

fn mci_worker_quarantine() -> &'static Mutex<Vec<super::MciWorkerQuarantineSlot>> {
    MCI_WORKER_QUARANTINE.get_or_init(|| Mutex::new(Vec::new()))
}

struct WorkerQuarantineSlotReservation {
    slot: Option<usize>,
}

impl WorkerQuarantineSlotReservation {
    fn new() -> Result<Self, RuntimeError> {
        reap_loop_returned_mci_workers();
        let mut slots = mci_worker_quarantine()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((index, slot)) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.reserved && slot.owner.is_none())
        {
            slot.reserved = true;
            slot.worker_loop_returned = false;
            slot.worker_thread_joined = false;
            slot.worker_shutdown_receipt_valid = false;
            return Ok(Self { slot: Some(index) });
        }
        slots.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI worker receipt quarantine slot",
                error,
            )
        })?;
        let index = slots.len();
        slots.push(super::MciWorkerQuarantineSlot {
            reserved: true,
            worker_loop_returned: false,
            worker_thread_joined: false,
            worker_shutdown_receipt_valid: false,
            owner: None,
        });
        Ok(Self { slot: Some(index) })
    }

    fn commit(mut self) -> usize {
        self.slot
            .take()
            .expect("MCI worker quarantine reservation commits once")
    }

    fn index(&self) -> usize {
        self.slot
            .expect("MCI worker quarantine reservation remains active")
    }
}

fn reap_loop_returned_mci_workers() {
    loop {
        let candidate = {
            let mut slots = mci_worker_quarantine()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            slots.iter_mut().enumerate().find_map(|(index, slot)| {
                if slot.worker_loop_returned
                    && !slot.worker_thread_joined
                    && slot.owner.is_some()
                {
                    slot.reserved = true;
                    slot.owner.take().map(|owner| (index, owner))
                } else {
                    None
                }
            })
        };
        let Some((index, mut owner)) = candidate else {
            return;
        };
        let joined = owner.thread.take().is_some_and(|thread| thread.join().is_ok());
        if joined {
            let mut progress = owner
                .shutdown_progress
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(mut receipt) = progress.clone() {
                receipt.owner_thread_joined = true;
                *progress = Some(receipt.clone());
                owner.shutdown_receipt = Some(receipt);
            } else if let Some(receipt) = &mut owner.shutdown_receipt {
                receipt.owner_thread_joined = true;
            }
            drop(progress);
            let shutdown_complete = owner.shutdown_receipt.as_ref().is_some_and(|receipt| {
                receipt.device_registry_drained
                    && receipt.yield_source_history_complete
                    && receipt.notification_ledger_drained
                    && receipt.notification_window_destroyed
                    && receipt.notification_class_unregistered
                    && receipt.owner_loop_returned
                    && receipt.owner_thread_joined
            });
            if shutdown_complete {
                let mut slots = mci_worker_quarantine()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(slot) = slots.get_mut(index) {
                    slot.reserved = false;
                    slot.worker_loop_returned = false;
                    slot.worker_thread_joined = false;
                    slot.worker_shutdown_receipt_valid = false;
                    slot.owner = None;
                }
                drop(slots);
                drop(owner);
            } else {
                if owner.shutdown_failures.len() < RETAINED_SHUTDOWN_FAILURE_CAPACITY {
                    owner.shutdown_failures.push(Arc::new(
                        owner
                            .shutdown_receipt
                            .clone()
                            .map(super::receipt::shutdown_receipt_error)
                            .unwrap_or_else(|| RuntimeError::new(
                                Kind::HostFailure,
                                "MCI worker loop returned without a complete native shutdown receipt",
                            )),
                    ));
                }
                let mut slots = mci_worker_quarantine()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let Some(slot) = slots.get_mut(index) {
                    slot.reserved = true;
                    slot.worker_loop_returned = true;
                    slot.worker_thread_joined = true;
                    slot.worker_shutdown_receipt_valid = false;
                    slot.owner = Some(owner);
                }
                drop(slots);
                return;
            }
        } else {
            if owner.shutdown_failures.len() < RETAINED_SHUTDOWN_FAILURE_CAPACITY {
                owner.shutdown_failures.push(Arc::new(RuntimeError::new(
                    Kind::InternalInvariant,
                    "quarantined MCI owner thread panicked or lost its join handle after loop return",
                )));
            }
            let mut slots = mci_worker_quarantine()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(slot) = slots.get_mut(index) {
                slot.reserved = true;
                slot.worker_loop_returned = true;
                slot.worker_thread_joined = false;
                slot.owner = Some(owner);
            }
            return;
        }
    }
}

impl Drop for WorkerQuarantineSlotReservation {
    fn drop(&mut self) {
        if let Some(index) = self.slot.take() {
            release_mci_worker_quarantine_slot(index);
        }
    }
}

pub(super) fn release_mci_worker_quarantine_slot(index: usize) {
    let mut slots = mci_worker_quarantine()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(slot) = slots.get_mut(index) {
        debug_assert!(slot.owner.is_none());
        slot.reserved = false;
        slot.worker_loop_returned = false;
        slot.worker_thread_joined = false;
        slot.worker_shutdown_receipt_valid = false;
    }
}

pub(super) fn retain_mci_worker_quarantine_slot(index: usize, owner: super::Win16MciWorkerState) {
    let mut owner = Some(owner);
    {
        let mut slots = mci_worker_quarantine()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let slot = slots
            .get_mut(index)
            .expect("MCI worker reserved its process-scope quarantine slot before startup");
        debug_assert!(slot.reserved && slot.owner.is_none());
        if slot.worker_thread_joined && slot.worker_shutdown_receipt_valid {
            slot.reserved = false;
            slot.worker_loop_returned = false;
            slot.worker_thread_joined = false;
            slot.worker_shutdown_receipt_valid = false;
        } else {
            slot.owner = owner.take();
        }
    }
    drop(owner);
}

pub(super) fn mark_worker_loop_returned(index: usize) {
    let mut slots = mci_worker_quarantine()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(slot) = slots.get_mut(index) {
        slot.worker_loop_returned = true;
    }
}

pub(super) fn mark_worker_shutdown_receipt(
    index: usize,
    receipt: &super::MciWorkerShutdownReceipt,
) {
    let mut slots = mci_worker_quarantine()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(slot) = slots.get_mut(index) {
        slot.worker_shutdown_receipt_valid = receipt.device_registry_drained
            && receipt.yield_source_history_complete
            && receipt.notification_ledger_drained
            && receipt.notification_window_destroyed
            && receipt.notification_class_unregistered
            && receipt.owner_loop_returned;
    }
}

pub(super) fn mark_worker_thread_joined(index: usize) {
    let owner = {
        let mut slots = mci_worker_quarantine()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = slots.get_mut(index) else {
            return;
        };
        slot.worker_loop_returned = true;
        slot.worker_thread_joined = true;
        let owner = if slot.owner.is_some() && slot.worker_shutdown_receipt_valid {
            let owner = slot.owner.take();
            slot.reserved = false;
            slot.worker_loop_returned = false;
            slot.worker_thread_joined = false;
            slot.worker_shutdown_receipt_valid = false;
            owner
        } else {
            None
        };
        owner
    };
    drop(owner);
}

pub(super) fn worker_is_joined(index: usize) -> bool {
    mci_worker_quarantine()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(index)
        .is_some_and(|slot| {
            slot.worker_loop_returned
                && slot.worker_thread_joined
                && slot.worker_shutdown_receipt_valid
        })
}

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn spawn(
        notifications: Arc<Mutex<MciNotificationLedger>>,
        multimedia_wake: MultimediaWakeSender,
        identity_source: Arc<AtomicU64>,
        text_codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        // Reserve the process-scope receipt owner before creating native
        // worker resources. Drop can transfer unresolved channels and the
        // JoinHandle without allocating during a failed shutdown.
        let quarantine = WorkerQuarantineSlotReservation::new()?;
        let mut shutdown_failures = Vec::new();
        shutdown_failures
            .try_reserve_exact(RETAINED_SHUTDOWN_FAILURE_CAPACITY)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native MCI shutdown failure receipts before worker startup",
                    error,
                )
            })?;
        let raw_event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if raw_event.is_null() {
            return Err(super::worker_loop::last_error(
                "create native MCI worker event",
            ));
        }
        let wake_event = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw_event as RawHandle) });
        let worker_event = Arc::clone(&wake_event);
        let quarantine_notifications = Arc::clone(&notifications);
        let (sender, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let quarantine_slot = quarantine.index();
        let shutdown_progress = Arc::new(Mutex::new(None));
        let worker_shutdown_progress = Arc::clone(&shutdown_progress);
        let thread = thread::Builder::new()
            .name("Win16 MCI owner".to_owned())
            .spawn(move || {
                worker_loop::worker_main(
                    receiver,
                    worker_event,
                    notifications,
                    multimedia_wake,
                    identity_source,
                    ready_sender,
                    worker_shutdown_progress,
                    text_codec,
                );
                mark_worker_loop_returned(quarantine_slot);
            })
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "start the native MCI owner thread",
                    error,
                )
            })?;
        let quarantine_slot = quarantine.commit();
        let mut state = super::Win16MciWorkerState {
            sender,
            wake_event,
            notifications: quarantine_notifications,
            thread_id: 0,
            thread: Some(thread),
            next_operation: 0,
            pending: HashMap::new(),
            deferred_receipts: Vec::new(),
            completed_quiescences: Vec::new(),
            pending_producer_quiescence: None,
            completed_producer_quiescence: None,
            shutdown_receipt: None,
            shutdown_progress,
            unclaimed: Vec::new(),
            shutdown_failures,
        };
        match ready_receiver.recv() {
            Ok(Ok(thread_id)) => {
                state.thread_id = thread_id;
                Ok(Self {
                    state: Some(state),
                    quarantine_slot,
                })
            }
            Ok(Err(error)) => {
                // Startup cleanup may still be retrying a registered class.
                // Keep the JoinHandle, wake handle, and channel endpoints in
                // the process-scope receipt owner until its thread returns.
                let error = Arc::new(error);
                state.shutdown_failures.push(Arc::clone(&error));
                retain_mci_worker_quarantine_slot(quarantine_slot, state);
                Err(RuntimeError::with_source(
                    error.kind(),
                    "native MCI worker startup failed; its cleanup owner remains retained",
                    super::quarantine::RetainedMciRuntimeError::new(error),
                ))
            }
            Err(error) => {
                let error = Arc::new(RuntimeError::with_source(
                    Kind::HostFailure,
                    "receive native MCI worker readiness",
                    error,
                ));
                state.shutdown_failures.push(Arc::clone(&error));
                retain_mci_worker_quarantine_slot(quarantine_slot, state);
                Err(RuntimeError::with_source(
                    error.kind(),
                    "native MCI worker readiness failed; its cleanup owner remains retained",
                    super::quarantine::RetainedMciRuntimeError::new(error),
                ))
            }
        }
    }

    pub(in crate::windows::win16_mci_owner) fn execute(
        &mut self,
        call: Win16HostMciCall,
    ) -> Result<Win16HostMciStep, RuntimeError> {
        self.pending.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI yield operation ownership",
                error,
            )
        })?;
        self.deferred_receipts.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI queued-command receipt owner",
                error,
            )
        })?;
        self.unclaimed.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve retained MCI result reconciliation",
                error,
            )
        })?;
        self.retry_wake()?;
        let operation =
            Win16HostMciOperationId(self.next_operation.checked_add(1).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "MCI operation identity space is exhausted",
                )
            })?);
        let (response, receive) = mpsc::channel();
        self.next_operation = operation.0;
        self.enqueue(WorkerCommand::Begin {
            operation,
            call,
            response,
        })?;
        if let Err(error) = self.wake_owner() {
            self.deferred_receipts.push(DeferredWorkerReceipt::Begin {
                operation,
                response: receive,
            });
            let cause = Arc::new(error);
            return Err(RuntimeError::with_source(
                cause.kind(),
                format!(
                    "MCI operation {} was enqueued; its original result remains owned for reconciliation",
                    operation.0
                ),
                runtime::Win16HostMciBeginFailure {
                    operation,
                    phase: runtime::Win16HostMciBeginFailurePhase::EnqueuedAwaitingOriginalResult,
                    cause,
                },
            ));
        }
        self.receive_step(operation, receive)
    }


    fn receive_step(
        &mut self,
        operation: Win16HostMciOperationId,
        receive: Receiver<Result<MciWorkerStep, RuntimeError>>,
    ) -> Result<Win16HostMciStep, RuntimeError> {
        let worker_step = match receive.recv() {
            Ok(Ok(worker_step)) => worker_step,
            Ok(Err(error)) => {
                let frame = reconcile::entered_yield_failure_frame(&error);
                let error = Arc::new(error);
                self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: None,
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::clone(&error),
                        frame,
                        submitted_return: None,
                    },
                });
                return Err(RuntimeError::with_source(
                    error.kind(),
                    "queued native MCI operation returned a typed failure while its exact owner remains retained",
                    runtime::Win16HostMciBeginFailure {
                        operation,
                        phase: runtime::Win16HostMciBeginFailurePhase::EnqueuedWorkerFailure,
                        cause: error,
                    },
                ));
            }
            Err(error) => {
                let error = Arc::new(RuntimeError::with_source(
                    Kind::HostFailure,
                    "receive native MCI operation result; exact operation identity remains retained",
                    error,
                ));
                self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: None,
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::clone(&error),
                        frame: None,
                        submitted_return: None,
                    },
                });
                return Err(RuntimeError::with_source(
                    error.kind(),
                    "native MCI Begin response channel was disconnected; the enqueued operation remains retained",
                    runtime::Win16HostMciBeginFailure {
                        operation,
                        phase: runtime::Win16HostMciBeginFailurePhase::EnqueuedAwaitingOriginalResult,
                        cause: error,
                    },
                ));
            }
        };
        if worker_step.returned_yield.is_some() {
            let cause = Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "new MCI call reported a yield-return ACK without a submitted resume",
            ));
            if let Win16HostMciStep::Yield(event) = &worker_step.step {
                self.pending.insert(
                    operation,
                    PendingOperation {
                        response: receive,
                        frame: event.frame,
                        device: event.device,
                        registration: event.registration,
                        resume_in_flight: None,
                    },
                );
            }
            self.unclaimed.push(UnclaimedMciOperation {
                operation,
                source_frame: None,
                outcome: UnclaimedMciOutcome::UnexpectedBeginStep {
                    actual: worker_step,
                    error: Arc::clone(&cause),
                },
            });
            return Err(RuntimeError::with_source(
                cause.kind(),
                "native MCI begin returned a yield ACK without a submitted response; worker receipt remains retained",
                runtime::Win16HostMciBeginFailure {
                    operation,
                    phase: runtime::Win16HostMciBeginFailurePhase::EnqueuedMalformedResult,
                    cause,
                },
            ));
        }
        match worker_step.step {
            Win16HostMciStep::Yield(event) => {
                if event.operation != operation {
                    self.pending.insert(
                        operation,
                        PendingOperation {
                            response: receive,
                            frame: event.frame,
                            device: event.device,
                            registration: event.registration,
                            resume_in_flight: None,
                        },
                    );
                    let cause = Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "new MCI operation yielded under a different operation identity",
                    ));
                    self.unclaimed.push(UnclaimedMciOperation {
                        operation,
                        source_frame: None,
                        outcome: UnclaimedMciOutcome::UnexpectedBeginStep {
                            actual: MciWorkerStep {
                            step: Win16HostMciStep::Yield(event),
                            returned_yield: None,
                            },
                            error: Arc::clone(&cause),
                        },
                    });
                    return Err(RuntimeError::with_source(
                        cause.kind(),
                        "new MCI operation yielded under a different identity and remains retained",
                        runtime::Win16HostMciBeginFailure {
                            operation,
                            phase: runtime::Win16HostMciBeginFailurePhase::EnqueuedMalformedResult,
                            cause,
                        },
                    ));
                }
                self.pending.insert(
                    operation,
                    PendingOperation {
                        response: receive,
                        frame: event.frame,
                        device: event.device,
                        registration: event.registration,
                        resume_in_flight: None,
                    },
                );
                Ok(Win16HostMciStep::Yield(event))
            }
            complete @ Win16HostMciStep::Complete(_) => Ok(complete),
        }
    }

    fn enqueue(&self, command: WorkerCommand) -> Result<(), RuntimeError> {
        self.sender.send(command).map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "enqueue native MCI worker command",
                error,
            )
        })?;
        Ok(())
    }

    fn retry_wake(&mut self) -> Result<(), RuntimeError> {
        let wake_error = self.drain_deferred_receipts()?;
        if !self.deferred_receipts.is_empty()
            || !self.completed_quiescences.is_empty()
            || !self.unclaimed.is_empty()
        {
            return Err(self.receipt_blocker(wake_error));
        }
        if let Some(error) = wake_error {
            return Err(error);
        }
        Ok(())
    }


    pub(super) fn wake_owner(&self) -> Result<(), RuntimeError> {
        if unsafe { SetEvent(self.wake_event.as_raw_handle() as HANDLE) } == 0 {
            // A thread message is an independent wake path if the owned event
            // was externally invalidated; the queued command remains owned.
            let posted = unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::PostThreadMessageW(
                    self.thread_id,
                    0x8001,
                    0,
                    0,
                )
            };
            if posted == 0 {
                return Err(super::worker_loop::last_error(
                    "wake native MCI owner thread",
                ));
            }
        }
        Ok(())
    }
}
