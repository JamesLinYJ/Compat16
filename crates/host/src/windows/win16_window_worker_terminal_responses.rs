//! Own terminal responses until their native worker has actually retired.

use std::sync::mpsc::{self, Receiver};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::{TerminalProofSnapshot, WorkerState};
use super::shutdown::ShutdownResult;

#[derive(Clone, Copy)]
pub(super) struct TerminalQuiescence {
    operation_stack_empty: bool,
    callback_stack_empty: bool,
    modal_scope_stack_empty: bool,
}

pub(super) fn terminal_evidence(state: &WorkerState) -> (
    u64,
    Option<TerminalProofSnapshot>,
    Option<Arc<RuntimeError>>,
    TerminalQuiescence,
) {
    (
        state.worker_retirement_id,
        state.terminal_proof.clone(),
        state.terminal_proof_error.as_ref().map(Arc::clone),
        TerminalQuiescence {
            // This receipt covers USER operations and callback scopes. COM
            // terminal journals remain owned until runtime unwinds its shared
            // callback stack and acknowledges their exact results. Requiring
            // those ACKs here would prevent that unwind from obtaining USER
            // quiescence. Native COM stacks must still have returned; full
            // worker shutdown and COM owner retirement also require their
            // exact terminal journals to be acknowledged.
            operation_stack_empty: state.active_operations.is_empty()
                && state.com.native_stacks_quiet(),
            callback_stack_empty: state.live_callbacks.is_empty(),
            modal_scope_stack_empty:
                super::super::super::win16_modal::modal_stack_is_empty(),
        },
    )
}

pub(super) fn send_terminal_results(
    waiters: Vec<(u64, std::sync::mpsc::Sender<ShutdownResult>)>,
    mut errors: Vec<Arc<RuntimeError>>,
    cancelled_modals: Vec<runtime::Win16NativeModalCancellation>,
    worker_generation: u64,
    proof: Option<TerminalProofSnapshot>,
    proof_error: Option<Arc<RuntimeError>>,
    quiescence: TerminalQuiescence,
) {
    if let Some(error) = proof_error {
        errors.push(Arc::new(RuntimeError::with_source(
            error.kind(),
            "retain Win16 USER terminal identity snapshot failure",
            error,
        )));
    }
    for (request_id, waiter) in waiters {
        let result = terminal_result(
            errors.clone(),
            cancelled_modals.clone(),
            worker_generation,
            request_id,
            proof.clone(),
            quiescence.operation_stack_empty,
            quiescence.callback_stack_empty,
            quiescence.modal_scope_stack_empty,
        );
        let _ = waiter.send(result);
    }
}

fn terminal_result(
    errors: Vec<Arc<RuntimeError>>,
    cancelled_modals: Vec<runtime::Win16NativeModalCancellation>,
    worker_generation: u64,
    request_id: u64,
    proof: Option<TerminalProofSnapshot>,
    operation_stack_empty: bool,
    callback_stack_empty: bool,
    modal_scope_stack_empty: bool,
) -> ShutdownResult {
    let mut errors = errors;
    if worker_generation == 0 || request_id == 0 {
        errors.push(Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 USER terminal receipt has a zero native worker/request identity",
        )));
    }
    if proof.is_none() {
        errors.push(Arc::new(RuntimeError::new(
            Kind::HostFailure,
            "Win16 USER terminal receipt lacks the pre-abort operation/source snapshot",
        )));
    }
    if !operation_stack_empty || !callback_stack_empty || !modal_scope_stack_empty {
        errors.push(Arc::new(RuntimeError::new(
            Kind::HostFailure,
            "Win16 USER terminal receipt does not prove all native USER callback scopes quiesced",
        )));
    }
    if errors.is_empty() {
        let proof = proof.expect("proof presence validated above");
        return Ok(runtime::Win16WindowAbortReceipt {
            worker_generation,
            request_id,
            active_operations: proof.active_operations,
            cancelled_callbacks: proof.cancelled_callbacks,
            cancelled_modals,
            active_operation_stack_empty: operation_stack_empty,
            callback_stack_empty,
            modal_scope_stack_empty,
            resources: proof.resources,
            resource_retirement: runtime::Win16NativeResourceRetirement::Deferred,
        });
    }
    let kind = errors.iter().skip(1).fold(errors[0].kind(), |kind, error|
        kind.with_cleanup(error.kind()));
    Err(Arc::new(RuntimeError::with_source(
        kind,
        "Win16 USER terminal operation failed after preserving modal receipts",
        TerminalFailureReceipt {
            worker_generation,
            request_id,
            proof,
            operation_stack_empty,
            callback_stack_empty,
            modal_scope_stack_empty,
            cancelled_modals,
            failures: errors,
        },
    )))
}

#[derive(Debug)]
struct TerminalFailureReceipt {
    worker_generation: u64,
    request_id: u64,
    proof: Option<TerminalProofSnapshot>,
    operation_stack_empty: bool,
    callback_stack_empty: bool,
    modal_scope_stack_empty: bool,
    cancelled_modals: Vec<runtime::Win16NativeModalCancellation>,
    failures: Vec<Arc<RuntimeError>>,
}

impl std::fmt::Display for TerminalFailureReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Win16 USER terminal request {} for worker generation {} retained {} modal cancellation receipt(s); pre-abort proof {}; operation/callback/modal scopes empty={}/{}/{}; {} terminal failure(s)",
            self.request_id,
            self.worker_generation,
            self.cancelled_modals.len(),
            if self.proof.is_some() { "present" } else { "missing" },
            self.operation_stack_empty,
            self.callback_stack_empty,
            self.modal_scope_stack_empty,
            self.failures.len()
        )?;
        for (index, error) in self.failures.iter().enumerate() {
            if index != 0 {
                write!(formatter, "; additional failure: ")?;
            } else {
                write!(formatter, "; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TerminalFailureReceipt {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failures
            .first()
            .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
    }
}

pub(super) struct PendingTerminalResponse {
    request_id: u64,
    receiver: Option<Receiver<ShutdownResult>>,
    state: Arc<Mutex<PendingTerminalResponseState>>,
    canonical_abort: Option<Arc<CanonicalAbortResponse>>,
}

#[derive(Debug, Default)]
pub(super) struct PendingTerminalResponseState {
    response: Option<ShutdownResult>,
    retired: bool,
    receiving: bool,
    receive_failure: Option<Arc<RuntimeError>>,
    join_failure: Option<Arc<RuntimeError>>,
    supervisor_failure: Option<Arc<RuntimeError>>,
}

/// One Abort command and its one real worker response, shared by modal ingress
/// and the outer USER owner. Later callers replay this cached response.
pub(super) struct CanonicalAbortResponse {
    request_id: AtomicU64,
    receiver: Mutex<Option<Receiver<ShutdownResult>>>,
    state: Arc<Mutex<PendingTerminalResponseState>>,
    ready: Condvar,
}

impl CanonicalAbortResponse {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            request_id: AtomicU64::new(0),
            receiver: Mutex::new(None),
            state: Arc::new(Mutex::new(PendingTerminalResponseState::default())),
            ready: Condvar::new(),
        })
    }

    pub(super) fn publish(
        &self,
        request_id: u64,
        receiver: Receiver<ShutdownResult>,
    ) -> Result<(), (RuntimeError, Receiver<ShutdownResult>)> {
        if request_id == 0 || self.request_id.load(Ordering::Acquire) != 0 {
            return Err((RuntimeError::new(Kind::InternalInvariant,
                "canonical Win16 USER Abort response was published with a changed identity"),
                receiver));
        }
        *self.receiver.lock().unwrap_or_else(
            std::sync::PoisonError::into_inner,
        ) = Some(receiver);
        self.request_id.store(request_id, Ordering::Release);
        Ok(())
    }

    pub(super) fn request_id(&self) -> Option<u64> {
        match self.request_id.load(Ordering::Acquire) {
            0 => None,
            request_id => Some(request_id),
        }
    }

    pub(super) fn wait_for_response(&self) -> Result<ShutdownResult, RuntimeError> {
        let request_id = self.request_id().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "canonical Win16 USER Abort response has no published request identity",
        ))?;
        loop {
            let mut state = self.state.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
            if let Some(response) = &state.response {
                return Ok(response.clone());
            }
            if let Some(error) = &state.receive_failure {
                return Err(shared_terminal_response_failure(
                    error,
                    "receive the retained canonical Win16 USER Abort response",
                ));
            }
            if state.retired {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "canonical Win16 USER Abort response retired without a real result"));
            }
            if state.receiving {
                state = self.ready.wait(state).unwrap_or_else(
                    std::sync::PoisonError::into_inner,
                );
                drop(state);
                continue;
            }
            state.receiving = true;
            drop(state);

            let receiver = self.receiver.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            ).take();
            let received = match receiver {
                Some(receiver) => receiver.recv().map_err(|_| RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("Win16 USER Abort response channel for request {request_id} disconnected before publishing its result"),
                )),
                None => Err(RuntimeError::new(Kind::InternalInvariant,
                    "canonical Win16 USER Abort response lost its original receiver")),
            };
            let mut state = self.state.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
            state.receiving = false;
            match received {
                Ok(response) => state.response = Some(response),
                Err(error) => state.receive_failure = Some(Arc::new(error)),
            }
            self.ready.notify_all();
        }
    }

    pub(super) fn response_if_ready(&self) -> Result<Option<ShutdownResult>, RuntimeError> {
        let request_id = self.request_id().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "canonical Win16 USER Abort response has no published request identity",
        ))?;
        {
            let mut state = self.state.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
            if let Some(response) = &state.response {
                return Ok(Some(response.clone()));
            }
            if let Some(error) = &state.receive_failure {
                return Err(shared_terminal_response_failure(
                    error,
                    "read the retained canonical Win16 USER Abort response failure",
                ));
            }
            if state.retired {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "canonical Win16 USER Abort retired without a response or channel failure"));
            }
            if state.receiving {
                return Ok(None);
            }
            state.receiving = true;
        }

        let receiver = self.receiver.lock().unwrap_or_else(
            std::sync::PoisonError::into_inner,
        ).take();
        let Some(receiver) = receiver else {
            let error = Arc::new(RuntimeError::new(Kind::InternalInvariant,
                "canonical Win16 USER Abort response lost its original receiver"));
            let mut state = self.state.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
            state.receiving = false;
            state.receive_failure = Some(Arc::clone(&error));
            self.ready.notify_all();
            return Err(shared_terminal_response_failure(
                &error,
                "read the retained canonical Win16 USER Abort response failure",
            ));
        };

        match receiver.try_recv() {
            Ok(response) => {
                let mut state = self.state.lock().unwrap_or_else(
                    std::sync::PoisonError::into_inner,
                );
                state.response = Some(response.clone());
                state.receiving = false;
                self.ready.notify_all();
                Ok(Some(response))
            }
            Err(mpsc::TryRecvError::Empty) => {
                *self.receiver.lock().unwrap_or_else(
                    std::sync::PoisonError::into_inner,
                ) = Some(receiver);
                let mut state = self.state.lock().unwrap_or_else(
                    std::sync::PoisonError::into_inner,
                );
                state.receiving = false;
                self.ready.notify_all();
                Ok(None)
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                let error = Arc::new(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("Win16 USER Abort response channel for request {request_id} disconnected before publishing its result"),
                ));
                let mut state = self.state.lock().unwrap_or_else(
                    std::sync::PoisonError::into_inner,
                );
                state.receive_failure = Some(Arc::clone(&error));
                state.receiving = false;
                self.ready.notify_all();
                Err(shared_terminal_response_failure(
                    &error,
                    "read the retained canonical Win16 USER Abort response failure",
                ))
            }
        }
    }

    fn finish_after_join(
        &self,
        request_id: u64,
        join_failure: Option<Arc<RuntimeError>>,
        supervisor_failure: Option<Arc<RuntimeError>>,
    ) {
        let mut state = self.state.lock().unwrap_or_else(
            std::sync::PoisonError::into_inner,
        );
        while state.receiving {
            state = self.ready.wait(state).unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
        }
        if state.response.is_none() && state.receive_failure.is_none() {
            state.receiving = true;
            drop(state);
            let receiver = self.receiver.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            ).take();
            let received = match receiver {
                Some(receiver) => match receiver.try_recv() {
                    Ok(response) => Ok(response),
                    Err(mpsc::TryRecvError::Disconnected) => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("Win16 USER Abort response channel for request {request_id} disconnected before publishing its result"),
                    )),
                    Err(mpsc::TryRecvError::Empty) => Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("Win16 USER worker exited without resolving Abort request {request_id}"),
                    )),
                },
                None => Err(RuntimeError::new(Kind::InternalInvariant,
                    "canonical Win16 USER Abort response lost its original receiver before join")),
            };
            state = self.state.lock().unwrap_or_else(
                std::sync::PoisonError::into_inner,
            );
            state.receiving = false;
            match received {
                Ok(response) => state.response = Some(response),
                Err(error) => state.receive_failure = Some(Arc::new(error)),
            }
        }
        state.retired = true;
        if let Some(error) = join_failure {
            state.join_failure = Some(error);
        }
        if let Some(error) = supervisor_failure {
            state.supervisor_failure = Some(error);
        }
        self.ready.notify_all();
    }
}

pub(super) fn retain_pending_terminal_response(
    cause: RuntimeError,
    request_id: u64,
    receive: Receiver<ShutdownResult>,
    state: Arc<Mutex<PendingTerminalResponseState>>,
) -> (RuntimeError, PendingTerminalResponse) {
    let (receiver, response, disconnected) = match receive.try_recv() {
        Ok(response) => (None, Some(response), false),
        Err(mpsc::TryRecvError::Empty) => (Some(receive), None, false),
        Err(mpsc::TryRecvError::Disconnected) => (None, None, true),
    };
    let response_kind = response.as_ref().and_then(|response| response.as_ref().err())
        .map(|error| error.kind());
    {
        let mut pending = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.response = response;
        pending.retired = disconnected;
        if disconnected {
            pending.receive_failure = Some(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 worker response channel disconnected before publishing a terminal result",
            )));
        }
    }
    let kind = match (response_kind, disconnected) {
        (Some(response_kind), _) => cause.kind().with_cleanup(response_kind),
        (None, true) => cause.kind().with_cleanup(Kind::InternalInvariant),
        (None, false) => cause.kind(),
    };
    let error = RuntimeError::with_source(
        kind,
        "owner-thread wake failed; retaining its terminal response slot",
        PendingTerminalResponseFailure {
            cause,
            request_id,
        },
    );
    (
        error,
        PendingTerminalResponse {
            request_id,
            receiver,
            state,
            canonical_abort: None,
        },
    )
}

pub(super) fn retain_canonical_abort_pending_response(
    cause: RuntimeError,
    owner: Arc<CanonicalAbortResponse>,
) -> (RuntimeError, PendingTerminalResponse) {
    let request_id = owner.request_id().unwrap_or(0);
    let state = Arc::clone(&owner.state);
    let (response_kind, disconnected) = {
        let state = state.lock().unwrap_or_else(
            std::sync::PoisonError::into_inner,
        );
        (
            state.response.as_ref().and_then(|response| response.as_ref().err())
                .map(|error| error.kind()),
            state.receive_failure.is_some(),
        )
    };
    let kind = match (response_kind, disconnected) {
        (Some(response_kind), _) => cause.kind().with_cleanup(response_kind),
        (None, true) => cause.kind().with_cleanup(Kind::InternalInvariant),
        (None, false) => cause.kind(),
    };
    let error = RuntimeError::with_source(
        kind,
        "owner-thread wake failed; retaining its canonical Abort response",
        PendingTerminalResponseFailure {
            cause,
            request_id,
        },
    );
    (error, canonical_abort_slot(request_id, owner))
}

pub(super) fn retain_canonical_abort_response_slot(
    owner: Arc<CanonicalAbortResponse>,
) -> PendingTerminalResponse {
    canonical_abort_slot(owner.request_id().unwrap_or(0), owner)
}

fn canonical_abort_slot(
    request_id: u64,
    owner: Arc<CanonicalAbortResponse>,
) -> PendingTerminalResponse {
    PendingTerminalResponse {
        request_id,
        receiver: None,
        state: Arc::clone(&owner.state),
        canonical_abort: Some(owner),
    }
}

pub(super) fn finish_terminal_response_slots(
    mut slots: Vec<PendingTerminalResponse>,
    join_failure: Option<Arc<RuntimeError>>,
    supervisor_failure: Option<Arc<RuntimeError>>,
) {
    for slot in &mut slots {
        if let Some(owner) = &slot.canonical_abort {
            owner.finish_after_join(
                slot.request_id,
                join_failure.as_ref().map(Arc::clone),
                supervisor_failure.as_ref().map(Arc::clone),
            );
            continue;
        }
        let received = match slot.receiver.take() {
            Some(receiver) => match receiver.try_recv() {
                Ok(response) => Some(Ok(response)),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!(
                        "Win16 worker response channel for terminal request {} disconnected before publishing its result",
                        slot.request_id
                    ),
                ))),
                Err(mpsc::TryRecvError::Empty) => Some(Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!(
                        "Win16 worker exited without resolving terminal request {}",
                        slot.request_id
                    ),
                ))),
            },
            None => None,
        };
        let mut state = slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match received {
            Some(Ok(response)) => state.response = Some(response),
            Some(Err(error)) if state.receive_failure.is_none() => {
                state.receive_failure = Some(Arc::new(error));
            }
            Some(Err(_)) | None => {}
        }
        state.retired = true;
        if let Some(error) = &join_failure {
            state.join_failure = Some(Arc::clone(error));
        }
        if let Some(error) = &supervisor_failure {
            state.supervisor_failure = Some(Arc::clone(error));
        }
    }
}

pub(super) fn shared_terminal_response_failure(
    error: &Arc<RuntimeError>,
    context: &'static str,
) -> RuntimeError {
    RuntimeError::with_source(
        error.kind(),
        context,
        SharedTerminalResponseFailure(Arc::clone(error)),
    )
}

pub(super) fn preserve_abort_receipt_after_publication_failure(
    cause: RuntimeError,
    request_id: u64,
    receipt: runtime::Win16WindowAbortReceipt,
) -> RuntimeError {
    RuntimeError::with_source(
        cause.kind(),
        "canonical Win16 USER Abort retained its receipt after wake publication failed",
        CanonicalAbortPublicationReceiptFailure {
            cause,
            request_id,
            receipt,
        },
    )
}

#[derive(Debug)]
struct CanonicalAbortPublicationReceiptFailure {
    cause: RuntimeError,
    request_id: u64,
    receipt: runtime::Win16WindowAbortReceipt,
}

impl std::fmt::Display for CanonicalAbortPublicationReceiptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; canonical Abort request {} retained {} modal cancellation receipt(s)",
            self.cause,
            self.request_id,
            self.receipt.cancelled_modals.len(),
        )
    }
}

impl std::error::Error for CanonicalAbortPublicationReceiptFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug)]
struct SharedTerminalResponseFailure(Arc<RuntimeError>);

impl std::fmt::Display for SharedTerminalResponseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedTerminalResponseFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) fn worker_join_failure(payload: Box<dyn std::any::Any + Send>) -> Arc<RuntimeError> {
    let detail = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("no textual panic information");
    Arc::new(RuntimeError::new(
        Kind::InternalInvariant,
        format!("native window worker panicked: {detail}"),
    ))
}

#[derive(Debug)]
struct PendingTerminalResponseFailure {
    cause: RuntimeError,
    request_id: u64,
}

impl std::fmt::Display for PendingTerminalResponseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; terminal request {} response slot retained",
            self.cause, self.request_id
        )
    }
}

impl std::error::Error for PendingTerminalResponseFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
