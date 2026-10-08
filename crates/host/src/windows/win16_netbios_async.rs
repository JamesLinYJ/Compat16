//! Native event-owned asynchronous NetBIOS NCBs.
//!
//! A worker creates and retains each native NCB and buffer on its own stack
//! lifetime. This avoids sending Windows pointer-bearing records between
//! threads and keeps the native request alive if the runtime disappears.

use super::*;
use super::super::multimedia_wake::MultimediaWakeSender;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const NRC_CANCEL: u8 = 0x26;
const WORKER_REPLY_TIMEOUT: Duration = Duration::from_secs(1);

#[path = "win16_netbios_worker.rs"]
mod worker;
#[path = "win16_netbios_wake_state.rs"]
mod wake_state;
use wake_state::{
    completion_publication_is, mark_no_consumer, publish_pending_wake,
    remember_native_event_close_error, remember_teardown_handoff_error,
    remember_worker_join_error, request_wake,
    retained_runtime_error, teardown_receipt,
};

pub(in crate::windows) struct HostState {
    next_id: u64,
    active: Vec<PendingRequest>,
    multimedia_wake: MultimediaWakeSender,
}

struct PendingRequest {
    id: runtime::Win16HostNetbiosId,
    commands: Sender<WorkerCommand>,
    completions: Receiver<WorkerCompletion>,
    thread: Option<JoinHandle<()>>,
    completion_result: Option<runtime::Win16HostNetbiosResult>,
    // First typed source failure, including a failed startup receipt retained
    // after native ownership began.
    completion_error: Option<Arc<RuntimeError>>,
    wake_status: Arc<Mutex<WakeStatus>>,
    completion_delivered: bool,
    cancel_requested: bool,
    teardown_receipt: Option<runtime::Win16HostNetbiosTeardownReceipt>,
}

#[derive(Default)]
pub(super) struct WakeStatus {
    // This receipt belongs to one exact PendingRequest. MultimediaWakeSender
    // remains the only shared USER/modal wake channel.
    pending: bool,
    terminal_pending: bool,
    completion_publication: runtime::Win16HostNetbiosCompletionPublication,
    // Current retry state may clear after a successful signal. Keep the first
    // wake failure separately so an exact teardown receipt never loses it.
    wake_retry_error: Option<Arc<RuntimeError>>,
    first_wake_error: Option<Arc<RuntimeError>>,
    teardown_reason: Option<runtime::Win16HostNetbiosTeardownReason>,
    teardown_requested: bool,
    native_wait_failed: bool,
    native_wait_error: Option<Arc<RuntimeError>>,
    native_probe_pending: bool,
    native_terminal: bool,
    event_closed: bool,
    worker_joined: bool,
    teardown_error: Option<Arc<RuntimeError>>,
    // First wake error after the primary cause; never wrapped recursively.
    additional_wake_error: Option<Arc<RuntimeError>>,
    failure_diagnostics: runtime::Win16HostNetbiosFailureDiagnostics,
    native_owner_created: bool,
    no_consumer: bool,
    no_consumer_error: Option<Arc<RuntimeError>>,
}

pub(super) type SharedWakeStatus = Arc<Mutex<WakeStatus>>;

pub(super) enum WorkerCommand {
    Cancel(SyncSender<Result<runtime::Win16HostNetbiosResult, RuntimeError>>),
    Ack {
        allow_release: bool,
        reply: SyncSender<Result<bool, RuntimeError>>,
    },
    Teardown {
        reason: runtime::Win16HostNetbiosTeardownReason,
        issue_cancel: bool,
    },
    ProbeTerminal,
}

pub(super) enum WorkerStart {
    Accepted(runtime::Win16HostNetbiosResult),
    Immediate(runtime::Win16HostNetbiosResult),
    InlineTerminal {
        raw: runtime::Win16HostNetbiosResult,
        projected: Option<runtime::Win16HostNetbiosResult>,
    },
}

/// Completion transport keeps the producer phase attached to each cause.
/// Native wait failures already have a native_wait slot before they are sent.
pub(super) enum WorkerCompletion {
    Completed(runtime::Win16HostNetbiosResult),
    ProjectionFailure(Arc<RuntimeError>),
    NativeWaitFailure(Arc<RuntimeError>),
}

impl HostState {
    pub(in crate::windows) fn new(multimedia_wake: MultimediaWakeSender) -> Self {
        Self {
            next_id: 0,
            active: Vec::new(),
            multimedia_wake,
        }
    }

    pub(in crate::windows) fn terminal_wake_unavailable(&self) -> Result<bool, RuntimeError> {
        Ok(self.multimedia_wake.terminal_requested())
    }

    pub(in crate::windows) fn submit(
        &mut self,
        call: runtime::Win16HostNetbiosCall,
    ) -> Result<runtime::Win16HostNetbiosSubmission, RuntimeError> {
        if !call.asynchronous {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "asynchronous NetBIOS host submission received a synchronous NCB",
            ));
        }
        self.active.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain asynchronous Windows NetBIOS worker receipt",
                error,
            )
        })?;
        let id_value = self.next_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Windows NetBIOS request identities exhausted",
            )
        })?;
        let id = runtime::Win16HostNetbiosId(id_value);
        let (command_tx, command_rx) = mpsc::channel();
        let (completion_tx, completion_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::sync_channel(1);
        let worker_commands = command_tx.clone();
        let wake_status = Arc::new(Mutex::new(WakeStatus::default()));
        let worker_wake_status = Arc::clone(&wake_status);
        let multimedia_wake = self.multimedia_wake.clone();
        let worker = thread::Builder::new()
            .name(format!("win16-netbios-{}", id_value))
            .spawn(move || {
                worker::native_worker(
                    call,
                    command_rx,
                    completion_tx,
                    start_tx,
                    multimedia_wake,
                    worker_wake_status,
                )
            })
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "start owned Windows NetBIOS request worker",
                    error,
                )
            })?;
        self.active.push(PendingRequest {
            id,
            commands: worker_commands,
            completions: completion_rx,
            thread: Some(worker),
            completion_result: None,
            completion_error: None,
            wake_status,
            completion_delivered: false,
            cancel_requested: false,
            teardown_receipt: None,
        });
        self.next_id = id_value;

        match start_rx.recv() {
            Ok(Ok(WorkerStart::Accepted(initial))) => Ok(runtime::Win16HostNetbiosSubmission {
                id,
                initial,
                completion: None,
                inline_terminal: false,
            }),
            Ok(Ok(WorkerStart::Immediate(result))) => {
                let index = self.active.iter().position(|entry| entry.id == id)
                    .ok_or_else(|| unknown_request(id))?;
                join_worker(&mut self.active[index])?;
                self.active.remove(index);
                Ok(runtime::Win16HostNetbiosSubmission {
                    id: runtime::Win16HostNetbiosId(0),
                    initial: result.clone(),
                    completion: Some(result),
                    inline_terminal: false,
                })
            }
            Ok(Ok(WorkerStart::InlineTerminal { raw, projected })) => {
                let index = self.active.iter().position(|entry| entry.id == id)
                    .ok_or_else(|| unknown_request(id))?;
                self.active[index].completion_delivered = projected.is_some();
                if projected.is_some() {
                    let mut status = self.active[index].wake_status
                        .lock().unwrap_or_else(PoisonError::into_inner);
                    status.completion_publication =
                        runtime::Win16HostNetbiosCompletionPublication::InlineReturn;
                }
                Ok(runtime::Win16HostNetbiosSubmission {
                    id,
                    initial: projected.clone().unwrap_or(raw),
                    completion: projected,
                    inline_terminal: true,
                })
            }
            Ok(Err(error)) => {
                let index = self.active.iter().position(|entry| entry.id == id)
                    .ok_or_else(|| unknown_request(id))?;
                let pending = &mut self.active[index];
                let (owner_created, native_close_proof) = {
                    let status = pending.wake_status
                        .lock().unwrap_or_else(PoisonError::into_inner);
                    (status.native_owner_created, status.native_terminal && status.event_closed)
                };
                let worker_finished = pending.thread.as_ref().is_some_and(JoinHandle::is_finished);
                if !worker_finished && owner_created && !native_close_proof {
                    // A failed startup receipt can race the worker's Drop
                    // quarantine. Do not block on or detach a native owner
                    // whose terminal/event-close proof is still absent.
                    let cause = Arc::new(error);
                    retain_completion_error(pending, Arc::clone(&cause));
                    return Err(retained_runtime_error(
                        Arc::clone(&cause),
                        "NetBIOS startup failed while its native owner remains retained",
                    ).with_cleanup(
                        "NetBIOS startup source remains owned by the host row",
                        RuntimeError::new(
                            Kind::HostFailure,
                            format!("Windows NetBIOS request {} was retained without a join proof", id.0),
                        ),
                    ));
                }
                let join = join_worker(pending);
                let mut status = pending.wake_status
                    .lock().unwrap_or_else(PoisonError::into_inner);
                status.worker_joined = true;
                let safely_retired = !owner_created || status.native_terminal && status.event_closed;
                if safely_retired {
                    drop(status);
                    self.active.remove(index);
                    return Err(match join {
                        Ok(()) => error,
                        Err(join_error) => error.with_cleanup(
                            "NetBIOS startup failed and its worker join also reported a panic",
                            join_error,
                        ),
                    });
                }
                mark_no_consumer(
                    &mut status,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!("Windows NetBIOS request {} ended without terminal and event-close proof", id.0),
                    ),
                );
                drop(status);
                let cause = Arc::new(error);
                retain_completion_error(pending, Arc::clone(&cause));
                let retained = RuntimeError::new(
                    Kind::HostFailure,
                    format!("Windows NetBIOS request {} remains retained without native retirement proof", id.0),
                );
                Err(retained_runtime_error(
                    cause,
                    "NetBIOS startup failed but native retirement is unproven",
                ).with_cleanup("NetBIOS source remains retained", retained))
            }
            Err(_) => {
                let index = self.active.iter().position(|entry| entry.id == id)
                    .ok_or_else(|| unknown_request(id))?;
                let pending = &mut self.active[index];
                let worker_finished = pending.thread.as_ref().is_some_and(JoinHandle::is_finished);
                if !worker_finished {
                    let mut status = pending.wake_status
                        .lock().unwrap_or_else(PoisonError::into_inner);
                    mark_no_consumer(
                        &mut status,
                        RuntimeError::new(
                            Kind::HostFailure,
                            format!("Windows NetBIOS worker {} did not publish its startup receipt; source remains retained", id.0),
                        ),
                    );
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        format!("Windows NetBIOS worker {} has no startup consumer; native owner was not joined", id.0),
                    ));
                }
                let owner_created = pending.wake_status
                    .lock().unwrap_or_else(PoisonError::into_inner).native_owner_created;
                let join = join_worker(pending);
                let mut status = pending.wake_status
                    .lock().unwrap_or_else(PoisonError::into_inner);
                status.worker_joined = true;
                let safely_retired = !owner_created || status.native_terminal && status.event_closed;
                if safely_retired {
                    drop(status);
                    self.active.remove(index);
                    return Err(join.err().unwrap_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("Windows NetBIOS worker {} exited before reporting submission", id.0),
                    )));
                }
                mark_no_consumer(
                    &mut status,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!("Windows NetBIOS worker {} ended without native terminal and event-close proof", id.0),
                    ),
                );
                Err(join.err().unwrap_or_else(|| RuntimeError::new(
                    Kind::HostFailure,
                    format!("Windows NetBIOS worker {} source remains retained without terminal proof", id.0),
                )))
            }
        }
    }

    pub(in crate::windows) fn completion(
        &mut self,
        id: runtime::Win16HostNetbiosId,
    ) -> Result<Option<runtime::Win16HostNetbiosResult>, RuntimeError> {
        let Some(pending) = self.active.iter_mut().find(|pending| pending.id == id) else {
            return Err(unknown_request(id));
        };
        if pending.teardown_receipt.is_some()
            || pending.wake_status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .teardown_requested
        {
            return Ok(None);
        }
        if pending.completion_delivered {
            return Ok(None);
        }
        {
            let mut status = pending.wake_status
                .lock().unwrap_or_else(PoisonError::into_inner);
            if status.native_wait_failed
                && !status.native_terminal
                && !status.teardown_requested
                && !status.native_probe_pending
            {
                status.native_probe_pending = true;
                if pending.commands.send(WorkerCommand::ProbeTerminal).is_err() {
                    status.native_probe_pending = false;
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("Windows NetBIOS worker {} cannot receive a terminal probe", id.0),
                    ));
                }
            }
        }
        if pending.completion_result.is_none() {
            loop {
                match pending.completions.try_recv() {
                    Ok(WorkerCompletion::Completed(result)) => {
                        pending.completion_result = Some(result);
                        break;
                    }
                    Ok(WorkerCompletion::ProjectionFailure(error)) => {
                        retain_projection_error(pending, error);
                    }
                    Ok(WorkerCompletion::NativeWaitFailure(cause)) => {
                        remember_native_wait_forwarding(pending, cause);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) if pending.completion_error.is_none() => {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            format!("Windows NetBIOS worker {} lost its completion receipt", id.0),
                        ));
                    }
                    Err(TryRecvError::Disconnected) => break,
                }
            }
        }
        // A later actual terminal snapshot supersedes a recoverable wait or
        // projection diagnostic. The typed cause remains in this exact host
        // row (and the Runtime NCB row) until normal ACK or teardown ACK.
        if pending.completion_result.is_some() {
            request_wake(&pending.wake_status, true);
            publish_pending_wake(&self.multimedia_wake, &pending.wake_status)?;
            let status = pending.wake_status
                .lock().unwrap_or_else(PoisonError::into_inner);
            if status.completion_publication
                != runtime::Win16HostNetbiosCompletionPublication::SharedWake
            {
                return Ok(None);
            }
            drop(status);
            pending.completion_delivered = true;
            return Ok(pending.completion_result.take());
        }
        if let Some(error) = pending.completion_error.as_ref() {
            request_wake(&pending.wake_status, false);
            let wake_result = publish_pending_wake(&self.multimedia_wake, &pending.wake_status);
            let diagnostic = retained_runtime_error(
                Arc::clone(error),
                "Windows NetBIOS worker retained a wait or projection diagnostic",
            );
            return Err(match wake_result {
                Ok(()) => {
                    diagnostic
                }
                Err(wake_error) => diagnostic.with_cleanup(
                    "NetBIOS diagnostic publication and its USER/modal wake both failed",
                    wake_error,
                ),
            });
        }
        Ok(None)
    }

    pub(in crate::windows) fn cancel(
        &mut self,
        id: runtime::Win16HostNetbiosId,
    ) -> Result<runtime::Win16HostNetbiosResult, RuntimeError> {
        let Some(pending) = self.active.iter_mut().find(|pending| pending.id == id) else {
            return Ok(runtime::Win16HostNetbiosResult::status(NRC_CANCEL));
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        pending.commands.send(WorkerCommand::Cancel(reply_tx)).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                format!("Windows NetBIOS worker {} cannot receive exact cancellation", id.0),
            )
        })?;
        pending.cancel_requested = true;
        reply_rx.recv_timeout(WORKER_REPLY_TIMEOUT).map_err(|_| RuntimeError::new(
            Kind::HostFailure,
            format!("Windows NetBIOS worker {} did not return a cancellation result; source remains retained", id.0),
        ))?
    }

    pub(in crate::windows) fn ack(
        &mut self,
        id: runtime::Win16HostNetbiosId,
    ) -> Result<bool, RuntimeError> {
        if id.0 == 0 {
            return Ok(true);
        }
        let Some(index) = self.active.iter().position(|pending| pending.id == id) else {
            return Err(unknown_request(id));
        };
        if self.active[index].wake_status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .teardown_requested
        {
            return Ok(false);
        }
        let publication = self.active[index].wake_status
            .lock().unwrap_or_else(PoisonError::into_inner)
            .completion_publication;
        let allow_release = self.active[index].completion_delivered
            && matches!(
                publication,
                runtime::Win16HostNetbiosCompletionPublication::InlineReturn
                    | runtime::Win16HostNetbiosCompletionPublication::SharedWake
            );
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.active[index].commands.send(WorkerCommand::Ack {
            allow_release,
            reply: reply_tx,
        }).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                format!("Windows NetBIOS worker {} cannot receive exact ACK", id.0),
            )
        })?;
        if !reply_rx.recv_timeout(WORKER_REPLY_TIMEOUT).map_err(|_| RuntimeError::new(
            Kind::HostFailure,
            format!("Windows NetBIOS worker {} did not return its exact ACK result; source remains retained", id.0),
        ))?? {
            return Ok(false);
        }
        if let Err(error) = join_worker(&mut self.active[index]) {
            let mut status = self.active[index].wake_status
                .lock().unwrap_or_else(PoisonError::into_inner);
            status.worker_joined = true;
            remember_worker_join_error(
                &mut status,
                Arc::new(error),
                "join exact completed Windows NetBIOS worker",
            );
            let retained = Arc::clone(status.teardown_error.as_ref().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "NetBIOS worker join failure was not retained",
                )
            })?);
            return Err(retained_runtime_error(
                retained,
                "join exact completed Windows NetBIOS worker",
            ));
        }
        self.active.remove(index);
        Ok(true)
    }

    pub(in crate::windows) fn teardown(
        &mut self,
        id: runtime::Win16HostNetbiosId,
        reason: runtime::Win16HostNetbiosTeardownReason,
    ) -> Result<runtime::Win16HostNetbiosTeardownReceipt, RuntimeError> {
        if id.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "zero Windows NetBIOS identity cannot name a teardown source",
            ));
        }
        let Some(index) = self.active.iter().position(|pending| pending.id == id) else {
            return Err(unknown_request(id));
        };
        if let Some(receipt) = self.active[index].teardown_receipt.as_ref() {
            if receipt.reason != reason {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("Windows NetBIOS request {} already has a different cached teardown reason", id.0),
                ));
            }
            if receipt.native_owner_retired() {
                return Ok(receipt.clone());
            }
        }
        let lane_terminal = self.multimedia_wake.terminal_requested();
        let pending = &mut self.active[index];
        let mut status = pending.wake_status
            .lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(previous) = status.teardown_reason
            && previous != reason
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                format!("Windows NetBIOS request {} already has a different teardown owner", id.0),
            ));
        }
        if reason == runtime::Win16HostNetbiosTeardownReason::TerminalWakeUnavailable
            && !lane_terminal
        {
            return Ok(teardown_receipt(pending, &status, reason));
        }
        let retry_close = status.teardown_requested
            && status.native_terminal
            && !status.event_closed
            && status.teardown_error.is_some();
        let retry_wait_probe = status.teardown_requested
            && status.native_wait_failed
            && !status.native_terminal
            && !status.native_probe_pending;
        if status.no_consumer {
            // A worker in its explicit Drop quarantine cannot consume another
            // command. Record this exact handoff on the retained host row,
            // then only observe terminal/close/join facts on later retries.
            status.teardown_reason = Some(reason);
            status.teardown_requested = true;
            drop(status);
        } else if !status.teardown_requested && status.native_terminal && status.event_closed {
            drop(status);
            let mut status = pending.wake_status
                .lock().unwrap_or_else(PoisonError::into_inner);
            status.teardown_reason = Some(reason);
            status.teardown_requested = true;
            drop(status);
        } else if !status.teardown_requested || retry_close || retry_wait_probe {
            let issue_cancel = !pending.cancel_requested && !status.native_terminal;
            let wait_probe = status.native_wait_failed && !status.native_terminal;
            if wait_probe {
                status.native_probe_pending = true;
            }
            if pending.commands.send(WorkerCommand::Teardown { reason, issue_cancel }).is_err() {
                if wait_probe {
                    status.native_probe_pending = false;
                }
                status.teardown_reason = Some(reason);
                mark_no_consumer(
                    &mut status,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!("Windows NetBIOS worker {} has no teardown consumer; exact native source remains retained", id.0),
                    ),
                );
                remember_teardown_handoff_error(
                    &mut status,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!("Windows NetBIOS worker {} did not receive its typed teardown request", id.0),
                    ),
                );
                let receipt = teardown_receipt(pending, &status, reason);
                pending.teardown_receipt = Some(receipt.clone());
                return Ok(receipt);
            }
            pending.cancel_requested |= issue_cancel;
            drop(status);
            let mut status = pending.wake_status
                .lock().unwrap_or_else(PoisonError::into_inner);
            status.teardown_reason = Some(reason);
            status.teardown_requested = true;
            drop(status);
        } else {
            drop(status);
        }

        collect_teardown_completion(pending);
        let status = pending.wake_status
            .lock().unwrap_or_else(PoisonError::into_inner);
        if status.native_terminal && status.event_closed {
            let worker_finished = pending.thread.as_ref().is_some_and(JoinHandle::is_finished);
            if worker_finished {
                drop(status);
                let join = join_worker(pending);
                // Join closes the producer's completion channel. Drain once
                // more before freezing the final receipt so a late queued
                // projection error cannot be hidden by an older cleanup Arc.
                collect_teardown_completion(pending);
                let mut status = pending.wake_status
                    .lock().unwrap_or_else(PoisonError::into_inner);
                status.worker_joined = true;
                if let Err(error) = join {
                    remember_worker_join_error(
                        &mut status,
                        Arc::new(error),
                        "join exact torn-down Windows NetBIOS worker",
                    );
                }
                let receipt = teardown_receipt(pending, &status, reason);
                pending.teardown_receipt = Some(receipt.clone());
                return Ok(receipt);
            }
        }
        let receipt = teardown_receipt(pending, &status, reason);
        if status.teardown_requested {
            pending.teardown_receipt = Some(receipt.clone());
        }
        Ok(receipt)
    }

    pub(in crate::windows) fn teardown_ack(
        &mut self,
        receipt: &runtime::Win16HostNetbiosTeardownReceipt,
    ) -> Result<bool, RuntimeError> {
        if !receipt.native_owner_retired() {
            return Ok(false);
        }
        let Some(index) = self.active.iter().position(|pending| pending.id == receipt.id) else {
            return Err(unknown_request(receipt.id));
        };
        let Some(cached) = self.active[index].teardown_receipt.as_ref() else {
            return Ok(false);
        };
        if !cached.same_cached_receipt(receipt) {
            return Ok(false);
        }
        self.active.remove(index);
        Ok(true)
    }
}

fn collect_teardown_completion(pending: &mut PendingRequest) {
    loop {
        match pending.completions.try_recv() {
            Ok(WorkerCompletion::Completed(result)) if pending.completion_result.is_none() => {
                pending.completion_result = Some(result);
            }
            Ok(WorkerCompletion::ProjectionFailure(error)) => {
                retain_projection_error(pending, error);
            }
            Ok(WorkerCompletion::NativeWaitFailure(cause)) => {
                remember_native_wait_forwarding(pending, cause);
            }
            Ok(_) => {}
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
}

fn retain_completion_error(pending: &mut PendingRequest, error: Arc<RuntimeError>) {
    if pending.completion_error.is_none() {
        pending.completion_error = Some(error);
    }
}

pub(super) fn record_projection_failure(
    wake_status: &SharedWakeStatus,
    cause: Arc<RuntimeError>,
) {
    wake_status.lock().unwrap_or_else(PoisonError::into_inner)
        .failure_diagnostics.completion_projection.record(cause);
}

fn retain_projection_error(pending: &mut PendingRequest, error: Arc<RuntimeError>) {
    // The worker recorded this exact Arc before transport; consumers must not
    // increment the same completion_projection phase a second time.
    retain_completion_error(pending, error);
}

fn remember_native_wait_forwarding(pending: &mut PendingRequest, cause: Arc<RuntimeError>) {
    // report_wait_failure already recorded this exact Arc in native_wait;
    // forwarding it must not claim a second projection failure.
    let forwarded = Arc::new(retained_runtime_error(
        cause,
        "accepted asynchronous NetBIOS event wait failed",
    ));
    retain_completion_error(pending, forwarded);
}

fn join_worker(pending: &mut PendingRequest) -> Result<(), RuntimeError> {
    let Some(worker) = pending.thread.take() else {
        return Ok(());
    };
    worker.join().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant,
        format!("Windows NetBIOS worker {} panicked", pending.id.0),
    ))
}

fn unknown_request(id: runtime::Win16HostNetbiosId) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("Windows NetBIOS request {} is no longer retained", id.0),
    )
}
