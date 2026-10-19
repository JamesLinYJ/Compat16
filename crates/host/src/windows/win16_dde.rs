//! Owner-thread DDEML adapter and synchronous callback continuation bridge.

#[path = "win16_dde_errors.rs"]
mod errors;
#[path = "win16_dde_native.rs"]
mod native;
#[path = "win16_dde_operation_lifecycle.rs"]
mod operation_lifecycle;
#[path = "win16_dde_shutdown.rs"]
mod shutdown;
#[cfg(test)]
#[path = "win16_dde_test_support.rs"]
mod test_support;
#[path = "win16_dde_worker.rs"]
mod worker;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use super::guest_text::GuestTextCodec;
use runtime::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, Win16DdeAbortOwnerStatus, Win16DdeAbortPhase,
    Win16DdeAbortReceipt, Win16DdeAbortWorkerStatus, Win16DdeCallbackCancellation,
    Win16DdeCallbackCancellationStatus, Win16DdeCallbackReply, Win16DdeCancellationSource,
    Win16DdeCleanupFailure, Win16DdeCleanupStatus, Win16DdeNativeInstanceReceipt,
    Win16DdeNativeOwnerShutdownReceipt, Win16DdeNativeReplyReceipt,
    Win16DdeNativeTransferGuardReceipt, Win16DdeNativeTransferGuardSource,
    Win16DdeOperationCancellation, Win16DdeOperationCancellationStatus,
    Win16DdeOperationRequestPhase, Win16DdeOperationStartedFailure, Win16HostDdeCall,
    Win16HostDdeCallbackFrame, Win16HostDdeCallbackStep, Win16HostDdeData, Win16HostDdeInstance,
    Win16HostDdeOperation, Win16HostDdeOwner, Win16HostDdeResult, Win16HostDdeStep,
    Win16HostDdeTransactionData,
};

const WAKE_MESSAGE: u32 = 0xBFFE;

fn allocate_id(source: &AtomicU64) -> Result<u64, RuntimeError> {
    source
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE operation and callback frame identities are exhausted",
            )
        })
}

pub(super) enum WorkerCommand {
    Execute {
        operation: Win16HostDdeOperation,
        call: Win16HostDdeCall,
    },
    Shutdown {
        request_id: u64,
    },
}

pub(super) enum WorkerEvent {
    Callback {
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        callback: runtime::Win16DdeCallbackCall,
        reply: Sender<Win16DdeCallbackReply>,
    },
    Complete {
        operation: Win16HostDdeOperation,
        entered_worker: bool,
        result: Result<Win16HostDdeResult, RuntimeError>,
    },
    CallbackFrameComplete {
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        result: Result<(), RuntimeError>,
    },
    Diagnostic(Diagnostic),
    Failure(RuntimeError),
    /// Mirror of the exact error sent through the positive shutdown receipt.
    /// This lets an operation waiter surface shutdown while keeping receipt
    /// de-duplication explicit rather than comparing display strings.
    ShutdownFailure(RuntimeError),
}

#[derive(Clone)]
pub(super) struct WorkerShutdownReport {
    pub(super) native_owner_receipt: Win16DdeNativeOwnerShutdownReceipt,
    pub(super) native_instances: Vec<Win16DdeNativeInstanceReceipt>,
    pub(super) native_transfer_guards: Vec<Win16DdeNativeTransferGuardReceipt>,
    pub(super) native_replies: Vec<Win16DdeNativeReplyReceipt>,
    pub(super) cleanup_failures: Vec<Win16DdeCleanupFailure>,
    pub(super) terminal_error: Option<Arc<RuntimeError>>,
}

#[derive(Clone)]
struct PendingDdeOperationRecord {
    instance: Option<Win16HostDdeInstance>,
    /// Original ClientTransaction input survives removal of the active native
    /// transfer guard so shutdown can prove the actual returned disposition.
    transfer_data: Option<Win16HostDdeData>,
    request_phase: Option<Win16DdeOperationRequestPhase>,
    failure: Option<Arc<RuntimeError>>,
    completed_result: Option<Win16HostDdeResult>,
    source_retirement_failure: Option<Arc<Win16DdeOperationStartedFailure>>,
}

pub(super) enum DdeBeginFailure {
    NotSubmitted(RuntimeError),
    Submitted(Arc<Win16DdeOperationStartedFailure>),
}

#[derive(Debug)]
struct SharedDdeRuntimeFailure(Arc<RuntimeError>);

impl std::fmt::Display for SharedDdeRuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedDdeRuntimeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) fn shared_runtime_error(
    cause: Arc<RuntimeError>,
    context: &'static str,
) -> RuntimeError {
    RuntimeError::with_source(cause.kind(), context, SharedDdeRuntimeFailure(cause))
}

struct PendingCallback {
    parent: Option<Win16HostDdeOperation>,
    instance: Win16HostDdeInstance,
    reply: Sender<Win16DdeCallbackReply>,
    /// The exact guest response accepted for this native callback. The
    /// sender receives an owned copy, while this record rejects a retry that
    /// changes the response after a lost wait/return.
    resume_reply: Option<Win16DdeCallbackReply>,
    reply_sent: bool,
    acknowledgement_result: Option<Result<(), Arc<RuntimeError>>>,
    abort_reply_sent: bool,
    acknowledged: bool,
    acknowledgement_failure: Option<Arc<RuntimeError>>,
    /// Native operation result retained before returning it to the runtime.
    /// A second resume returns the same step rather than consuming another
    /// worker event or attempting another callback reply.
    resume_step: Option<Win16HostDdeStep>,
    resume_failure: Option<Arc<RuntimeError>>,
}

/// DDEML operations and their callbacks stay on a dedicated Windows message
/// thread. Guest callbacks return through `resume`, which releases the native
/// callback frame and continues the same DDEML operation.
pub struct Win16DdeHost {
    command_sender: Sender<WorkerCommand>,
    event_receiver: Receiver<WorkerEvent>,
    identity_source: Arc<AtomicU64>,
    owner: Win16HostDdeOwner,
    worker_generation: u64,
    control_window: usize,
    shutdown_receiver: Option<Receiver<WorkerShutdownReport>>,
    shutdown_report: Option<WorkerShutdownReport>,
    shutdown_requested: bool,
    abort_request_id: Option<u64>,
    abort_receipt: Option<Win16DdeAbortReceipt>,
    worker: Option<JoinHandle<()>>,
    pending_callbacks: BTreeMap<Win16HostDdeCallbackFrame, PendingCallback>,
    pending_operations: BTreeSet<Win16HostDdeOperation>,
    pending_operation_instances: BTreeMap<Win16HostDdeOperation, PendingDdeOperationRecord>,
    pending_transfer_guards:
        BTreeMap<Win16HostDdeOperation, (Win16HostDdeData, Win16HostDdeInstance)>,
    pending_events: BTreeMap<Win16HostDdeOperation, VecDeque<WorkerEvent>>,
    unsolicited_callbacks: VecDeque<Arc<Win16HostDdeCallbackStep>>,
    pending_callback_completions: BTreeMap<
        Win16HostDdeCallbackFrame,
        (Option<Win16HostDdeOperation>, Result<(), RuntimeError>),
    >,
    diagnostics: VecDeque<Diagnostic>,
}

impl Win16DdeHost {
    pub fn new(
        identity_source: Arc<AtomicU64>,
        guest_ansi_codec: GuestTextCodec,
    ) -> Result<Self, RuntimeError> {
        let owner = Win16HostDdeOwner(allocate_id(&identity_source)?);
        let worker_generation = allocate_id(&identity_source)?;
        let (command_sender, command_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("Win16 DDEML owner".to_owned())
            .spawn({
                let worker_ids = Arc::clone(&identity_source);
                move || {
                    worker::run(
                        command_receiver,
                        event_sender,
                        started_sender,
                        shutdown_sender,
                        worker_ids,
                        owner,
                        worker_generation,
                        guest_ansi_codec,
                    )
                }
            })
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "start the Win16 DDEML owner thread",
                    error,
                )
            })?;
        let ready = match started_receiver.recv() {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error);
            }
            Err(error) => {
                let _ = worker.join();
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "initialize the Win16 DDEML owner thread",
                    error,
                ));
            }
        };
        Ok(Self {
            command_sender,
            event_receiver,
            identity_source,
            owner,
            worker_generation,
            control_window: ready.control_window,
            shutdown_receiver: Some(shutdown_receiver),
            shutdown_report: None,
            shutdown_requested: false,
            abort_request_id: None,
            abort_receipt: None,
            worker: Some(worker),
            pending_callbacks: BTreeMap::new(),
            pending_operations: BTreeSet::new(),
            pending_operation_instances: BTreeMap::new(),
            pending_transfer_guards: BTreeMap::new(),
            pending_events: BTreeMap::new(),
            unsolicited_callbacks: VecDeque::new(),
            pending_callback_completions: BTreeMap::new(),
            diagnostics: VecDeque::new(),
        })
    }

    pub(super) fn matches_owner_generation(
        &self,
        owner: Win16HostDdeOwner,
        worker_generation: u64,
    ) -> bool {
        self.owner == owner && worker_generation != 0 && self.worker_generation == worker_generation
    }

    /// Start a host operation using the runtime's operation identity. Keeping
    /// the identity outside this owner lets the runtime resume the same native
    /// operation after an unrelated parentless callback has been acknowledged.
    pub(super) fn begin_owned_tracked(
        &mut self,
        operation: Win16HostDdeOperation,
        call: Win16HostDdeCall,
    ) -> Result<Win16HostDdeStep, DdeBeginFailure> {
        if operation.0 == 0
            || self.pending_operations.contains(&operation)
            || self.pending_operation_instances.contains_key(&operation)
            || self.pending_transfer_guards.contains_key(&operation)
        {
            return Err(DdeBeginFailure::NotSubmitted(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation identity is zero or already owned by the native host",
            )));
        }
        self.pending_operations.insert(operation);
        let instance = match &call {
            Win16HostDdeCall::Initialize { existing, .. } => *existing,
            Win16HostDdeCall::ClientTransaction { instance, .. }
            | Win16HostDdeCall::AbandonTransaction { instance, .. }
            | Win16HostDdeCall::PostAdvise { instance, .. }
            | Win16HostDdeCall::CreateData { instance, .. }
            | Win16HostDdeCall::GetLastError { instance }
            | Win16HostDdeCall::CreateString { instance, .. }
            | Win16HostDdeCall::FreeString { instance, .. }
            | Win16HostDdeCall::QueryString { instance, .. }
            | Win16HostDdeCall::KeepString { instance, .. }
            | Win16HostDdeCall::EnableCallback { instance, .. }
            | Win16HostDdeCall::NameService { instance, .. }
            | Win16HostDdeCall::Uninitialize { instance }
            | Win16HostDdeCall::ConnectList { instance, .. }
            | Win16HostDdeCall::Connect { instance, .. } => Some(*instance),
            _ => None,
        };
        let transfer_data = match &call {
            Win16HostDdeCall::ClientTransaction {
                data: Win16HostDdeTransactionData::Data(data),
                ..
            } => Some(*data),
            _ => None,
        };
        self.pending_operation_instances.insert(
            operation,
            PendingDdeOperationRecord {
                instance,
                transfer_data,
                request_phase: None,
                failure: None,
                completed_result: None,
                source_retirement_failure: None,
            },
        );
        if let Win16HostDdeCall::ClientTransaction {
            instance,
            data: Win16HostDdeTransactionData::Data(data),
            ..
        } = &call
        {
            self.pending_transfer_guards
                .insert(operation, (*data, *instance));
        }
        if self
            .command_sender
            .send(WorkerCommand::Execute { operation, call })
            .is_err()
        {
            self.pending_operations.remove(&operation);
            self.pending_operation_instances.remove(&operation);
            self.pending_transfer_guards.remove(&operation);
            return Err(DdeBeginFailure::NotSubmitted(disconnected(
                "send a DDEML operation to its owner thread",
            )));
        }
        if let Some(record) = self.pending_operation_instances.get_mut(&operation) {
            record.request_phase = Some(Win16DdeOperationRequestPhase::SubmittedPending);
        }
        match self.continue_operation(operation) {
            Ok(step) => Ok(step),
            Err(error) => {
                let record = self
                    .pending_operation_instances
                    .entry(operation)
                    .or_insert_with(|| PendingDdeOperationRecord {
                        instance,
                        transfer_data,
                        request_phase: Some(Win16DdeOperationRequestPhase::SubmittedPending),
                        failure: None,
                        completed_result: None,
                        source_retirement_failure: None,
                    });
                let phase = record
                    .request_phase
                    .unwrap_or(Win16DdeOperationRequestPhase::SubmittedPending);
                let cause = record.failure.clone().unwrap_or_else(|| Arc::new(error));
                record.request_phase = Some(phase);
                record.failure = Some(Arc::clone(&cause));
                Err(DdeBeginFailure::Submitted(Arc::new(
                    Win16DdeOperationStartedFailure {
                        operation,
                        owner: self.owner,
                        worker_generation: self.worker_generation,
                        request_phase: phase,
                        cause,
                    },
                )))
            }
        }
    }

    /// Continue waiting for an operation yielded by `begin_owned_tracked`. A callback
    /// frame with no native parent is acknowledged separately and never
    /// completes or replaces this operation.
    pub fn continue_operation(
        &mut self,
        operation: Win16HostDdeOperation,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        if !self.pending_operations.contains(&operation) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE continuation does not name a pending operation",
            ));
        }
        self.wake_worker()?;
        self.wait_for_operation(operation)
    }

    /// Poll callbacks raised while the DDEML owner thread pumps its message
    /// queue outside a foreground host operation.
    pub fn poll_callback(&mut self) -> Result<Option<Arc<Win16HostDdeCallbackStep>>, RuntimeError> {
        if let Some(step) = self.unsolicited_callbacks.pop_front() {
            return Ok(Some(step));
        }
        loop {
            match self.event_receiver.try_recv() {
                Ok(event) => match event {
                    WorkerEvent::Callback {
                        parent: None,
                        frame,
                        callback,
                        reply,
                    } => {
                        return self.callback_step(frame, None, callback, reply).map(Some);
                    }
                    WorkerEvent::Failure(error) | WorkerEvent::ShutdownFailure(error) => {
                        return Err(error);
                    }
                    WorkerEvent::Diagnostic(diagnostic) => self.diagnostics.push_back(diagnostic),
                    other => self.queue_unmatched(other)?,
                },
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(disconnected(
                        "receive DDEML callbacks from the owner thread",
                    ));
                }
            }
        }
    }

    /// Diagnostics are drained by the runtime at each DDE operation/callback
    /// safe boundary and reported through its configured diagnostics sink.
    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        self.diagnostics.drain(..).collect()
    }

    fn wake_worker(&self) -> Result<(), RuntimeError> {
        // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
        let posted = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW(
                self.control_window as _,
                WAKE_MESSAGE,
                0,
                0,
            )
        };
        if posted == 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "wake the Win16 DDEML owner thread",
            ));
        }
        Ok(())
    }

    fn wait_for_operation(
        &mut self,
        operation: Win16HostDdeOperation,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        if let Some(event) = self
            .pending_events
            .get_mut(&operation)
            .and_then(VecDeque::pop_front)
        {
            if self
                .pending_events
                .get(&operation)
                .is_some_and(VecDeque::is_empty)
            {
                self.pending_events.remove(&operation);
            }
            return self.operation_step(operation, event);
        }
        loop {
            let event = match self.event_receiver.recv() {
                Ok(event) => event,
                Err(_) => {
                    // The request was already submitted. A disconnected
                    // result channel does not prove native completion or
                    // cancellation, so retain the exact operation owner for
                    // the shutdown receipt.
                    return Err(disconnected("receive a DDEML operation result"));
                }
            };
            match event {
                WorkerEvent::Failure(error) | WorkerEvent::ShutdownFailure(error) => {
                    // A worker-level failure does not identify whether this
                    // exact native call entered or returned. Keep it live so
                    // abort can report Retained unless the owner proves a
                    // terminal state.
                    return Err(error);
                }
                WorkerEvent::Diagnostic(diagnostic) => self.diagnostics.push_back(diagnostic),
                WorkerEvent::Callback {
                    parent: None,
                    frame,
                    callback,
                    reply,
                } => {
                    // An owner-thread callback can be blocked waiting for the
                    // guest while this foreground operation is already live.
                    // Yield it now; the caller will acknowledge it and resume
                    // this exact operation identity with continue_operation.
                    return self
                        .callback_step(frame, None, callback, reply)
                        .map(Win16HostDdeStep::Callback);
                }
                event @ WorkerEvent::CallbackFrameComplete { .. } => {
                    self.queue_unmatched(event)?;
                }
                event
                    if event_parent(&event) == Some(operation)
                        || event_operation(&event) == Some(operation) =>
                {
                    return self.operation_step(operation, event);
                }
                other => self.queue_unmatched(other)?,
            }
        }
    }

    fn operation_step(
        &mut self,
        operation: Win16HostDdeOperation,
        event: WorkerEvent,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        match event {
            WorkerEvent::Callback {
                frame,
                parent,
                callback,
                reply,
            } if parent == Some(operation) => self
                .callback_step(frame, parent, callback, reply)
                .map(Win16HostDdeStep::Callback),
            WorkerEvent::Complete {
                operation: completed,
                result,
                ..
            } if completed == operation => {
                self.pending_operations.remove(&operation);
                match result {
                    Ok(result) => {
                        if let Some(record) = self.pending_operation_instances.get_mut(&operation) {
                            record.request_phase =
                                Some(Win16DdeOperationRequestPhase::NativeCompleteReturned);
                            record.failure = None;
                            record.completed_result = Some(result.clone());
                        }
                        if self.completed_transfer_guard_matches(operation, &result) {
                            self.pending_transfer_guards.remove(&operation);
                        }
                        Ok(Win16HostDdeStep::Complete(result))
                    }
                    Err(error) => {
                        let cause = Arc::new(error);
                        if let Some(record) = self.pending_operation_instances.get_mut(&operation) {
                            record.request_phase =
                                Some(Win16DdeOperationRequestPhase::NativeCompleteError);
                            record.failure = Some(Arc::clone(&cause));
                        }
                        Err(RuntimeError::with_source(
                            cause.kind(),
                            "native DDE operation completed with an error",
                            SharedDdeRuntimeFailure(cause),
                        ))
                    }
                }
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDEML owner returned an event for a different operation",
            )),
        }
    }

    fn completed_transfer_guard_matches(
        &self,
        operation: Win16HostDdeOperation,
        result: &Win16HostDdeResult,
    ) -> bool {
        match (
            self.pending_transfer_guards.get(&operation),
            result.data_transfer.as_ref(),
        ) {
            (Some((expected, _instance)), Some(actual)) => actual.token == *expected,
            (None, None) => true,
            _ => false,
        }
    }

    fn callback_step(
        &mut self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        callback: runtime::Win16DdeCallbackCall,
        reply: Sender<Win16DdeCallbackReply>,
    ) -> Result<Arc<Win16HostDdeCallbackStep>, RuntimeError> {
        if self.pending_callbacks.contains_key(&frame) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDEML owner reused a live callback frame token",
            ));
        }
        let instance = callback.host_instance;
        self.pending_callbacks.insert(
            frame,
            PendingCallback {
                parent,
                instance,
                reply,
                resume_reply: None,
                reply_sent: false,
                acknowledgement_result: None,
                abort_reply_sent: false,
                acknowledged: false,
                acknowledgement_failure: None,
                resume_step: None,
                resume_failure: None,
            },
        );
        let step = Arc::new(Win16HostDdeCallbackStep {
            frame,
            parent,
            owner: self.owner,
            worker_generation: self.worker_generation,
            callback,
        });
        if !step.has_valid_identity() {
            self.pending_callbacks.remove(&frame);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback step has an invalid native owner identity",
            ));
        }
        Ok(step)
    }

    fn wait_for_callback_completion(
        &mut self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
    ) -> Result<Result<(), RuntimeError>, RuntimeError> {
        if let Some((actual_parent, _)) = self.pending_callback_completions.get(&frame) {
            if *actual_parent != parent {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback cleanup acknowledgement changed its origin",
                ));
            }
            let (_, result) = self
                .pending_callback_completions
                .remove(&frame)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE callback cleanup acknowledgement disappeared after validation",
                    )
                })?;
            return Ok(result);
        }
        loop {
            match self
                .event_receiver
                .recv()
                .map_err(|_| disconnected("receive native DDE callback cleanup acknowledgement"))?
            {
                WorkerEvent::CallbackFrameComplete {
                    frame: completed,
                    parent: actual_parent,
                    result,
                } if completed == frame => {
                    if actual_parent != parent {
                        let origin_error = RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback cleanup acknowledgement changed its origin",
                        );
                        let retained_error = match result {
                            Ok(()) => RuntimeError::new(
                                Kind::InternalInvariant,
                                "DDE callback cleanup acknowledgement changed its origin",
                            ),
                            Err(cleanup_error) => errors::combine_cleanup_errors(
                                origin_error,
                                cleanup_error,
                                "DDE callback ACK origin and cleanup both failed",
                            ),
                        };
                        self.pending_callback_completions
                            .insert(completed, (actual_parent, Err(retained_error)));
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback cleanup acknowledgement changed its origin",
                        ));
                    }
                    return Ok(result);
                }
                WorkerEvent::Failure(error) | WorkerEvent::ShutdownFailure(error) => {
                    return Err(error);
                }
                WorkerEvent::Diagnostic(diagnostic) => self.diagnostics.push_back(diagnostic),
                other => self.queue_unmatched(other)?,
            }
        }
    }

    fn queue_unmatched(&mut self, event: WorkerEvent) -> Result<(), RuntimeError> {
        match event {
            WorkerEvent::Failure(error) | WorkerEvent::ShutdownFailure(error) => return Err(error),
            WorkerEvent::Diagnostic(diagnostic) => self.diagnostics.push_back(diagnostic),
            WorkerEvent::Callback {
                parent: None,
                frame,
                callback,
                reply,
            } => {
                let callback = self.callback_step(frame, None, callback, reply)?;
                self.unsolicited_callbacks.push_back(callback);
            }
            WorkerEvent::CallbackFrameComplete {
                frame,
                parent,
                result,
            } => {
                if self
                    .pending_callback_completions
                    .insert(frame, (parent, result))
                    .is_some()
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE callback cleanup acknowledgement was delivered twice",
                    ));
                }
            }
            event => {
                if let Some(operation) = event_parent(&event).or_else(|| event_operation(&event)) {
                    self.pending_events
                        .entry(operation)
                        .or_default()
                        .push_back(event);
                }
            }
        }
        Ok(())
    }
}

fn event_parent(event: &WorkerEvent) -> Option<Win16HostDdeOperation> {
    match event {
        WorkerEvent::Callback { parent, .. } => *parent,
        WorkerEvent::Complete { operation, .. } => Some(*operation),
        WorkerEvent::CallbackFrameComplete { .. } => None,
        WorkerEvent::Diagnostic(_) => None,
        WorkerEvent::Failure(_) => None,
        WorkerEvent::ShutdownFailure(_) => None,
    }
}

fn event_operation(event: &WorkerEvent) -> Option<Win16HostDdeOperation> {
    match event {
        WorkerEvent::Callback { .. }
        | WorkerEvent::CallbackFrameComplete { .. }
        | WorkerEvent::Diagnostic(_)
        | WorkerEvent::Failure(_)
        | WorkerEvent::ShutdownFailure(_) => None,
        WorkerEvent::Complete { operation, .. } => Some(*operation),
    }
}

fn disconnected(context: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, context)
}
