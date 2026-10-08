//! Fallible worker shutdown with native storage retained through OS thread exit.

use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::super::win16_common_dialog_worker::ShutdownStorageGuard;
use super::WindowWorker;

struct RetainedWorker {
    thread: JoinHandle<()>,
    shutdown_storage: Arc<Mutex<Vec<ShutdownStorageGuard>>>,
    toolbar_bitmap_retention: Arc<Mutex<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>>,
    worker_retirement_id: u64,
    bitmap_retention_slot_reserved: bool,
    terminal_response_slots: Arc<Mutex<Vec<super::PendingTerminalResponse>>>,
}

enum RetentionCommand {
    Waiting,
    Retain(RetainedWorker),
    Stop,
}

struct RetentionShared {
    command: Mutex<RetentionCommand>,
    ready: Condvar,
}

pub(super) struct WorkerRetention {
    shared: Arc<RetentionShared>,
    supervisor: Option<JoinHandle<()>>,
    transferred: bool,
}

impl WorkerRetention {
    pub(super) fn start() -> Result<Self, RuntimeError> {
        let shared = Arc::new(RetentionShared {
            command: Mutex::new(RetentionCommand::Waiting),
            ready: Condvar::new(),
        });
        let reaper_state = Arc::clone(&shared);
        let supervisor = thread::Builder::new()
            .name("Win16 USER worker reaper".to_owned())
            .spawn(move || reap_one_worker(reaper_state))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "start the Win16 USER worker lifetime supervisor",
                    error,
                )
            })?;
        Ok(Self {
            shared,
            supervisor: Some(supervisor),
            transferred: false,
        })
    }

    /// Consume the one-shot supervisor while transferring the worker to its
    /// prestarted join owner. A live worker can reach this path only before
    /// this supervisor has been stopped or used.
    pub(super) fn retain_after_failed_shutdown(
        mut self,
        thread: JoinHandle<()>,
        shutdown_storage: Arc<Mutex<Vec<ShutdownStorageGuard>>>,
        toolbar_bitmap_retention: Arc<Mutex<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>>,
        worker_retirement_id: u64,
        bitmap_retention_slot_reserved: bool,
        terminal_response_slots: Arc<Mutex<Vec<super::PendingTerminalResponse>>>,
    ) {
        let mut command = self
            .shared
            .command
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(matches!(&*command, RetentionCommand::Waiting));
        *command = RetentionCommand::Retain(RetainedWorker {
            thread,
            shutdown_storage,
            toolbar_bitmap_retention,
            worker_retirement_id,
            bitmap_retention_slot_reserved,
            terminal_response_slots,
        });
        self.transferred = true;
        drop(command);
        self.shared.ready.notify_one();
    }

    fn stop_and_join(&mut self) -> Result<(), RuntimeError> {
        if self.transferred {
            return Ok(());
        }
        let mut command = self
            .shared
            .command
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = match &*command {
            RetentionCommand::Waiting => 0,
            RetentionCommand::Retain(_) => 1,
            RetentionCommand::Stop => 2,
        };
        match current {
            0 => *command = RetentionCommand::Stop,
            1 => {
                self.transferred = true;
                return Ok(());
            }
            _ => {}
        }
        drop(command);
        self.shared.ready.notify_one();
        match self.supervisor.take().map(JoinHandle::join) {
            Some(Ok(())) | None => Ok(()),
            Some(Err(_)) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER worker lifetime supervisor panicked",
            )),
        }
    }
}

fn reap_one_worker(shared: Arc<RetentionShared>) {
    let mut command = shared
        .command
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while matches!(&*command, RetentionCommand::Waiting) {
        command = shared
            .ready
            .wait(command)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    let pending = std::mem::replace(&mut *command, RetentionCommand::Stop);
    drop(command);
    if let RetentionCommand::Retain(worker) = pending {
        let join_failure = worker.thread.join().err().map(super::worker_join_failure);
        let mut reservation = worker.bitmap_retention_slot_reserved;
        let bitmap_failure = super::super::win16_common_controls_bitmap_pins::retire_worker_after_join(
            worker.worker_retirement_id, &worker.toolbar_bitmap_retention, &mut reservation)
            .err().map(Arc::new);
        if let Some(error) = &bitmap_failure {
            eprintln!("runtime: {error}");
        }
        worker
            .shutdown_storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        super::finish_terminal_response_slots(
            take_terminal_response_slots(&worker.terminal_response_slots),
            join_failure,
            bitmap_failure,
        );
    }
}

impl Drop for WorkerRetention {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            eprintln!("runtime: {error}");
        }
    }
}

impl WindowWorker {
    fn request_shutdown(&self) -> Result<Receiver<super::ShutdownResult>, RuntimeError> {
        self.request_terminal(|request_id, response| super::WorkerCommand::Shutdown {
            request_id,
            response,
        })
    }

    fn request_terminal(
        &self,
        command: impl FnOnce(u64, Sender<super::ShutdownResult>) -> super::WorkerCommand,
    ) -> Result<Receiver<super::ShutdownResult>, RuntimeError> {
        let (response, receive) = mpsc::channel();
        // Reserve response ownership before publishing a terminal request. A
        // failed thread-message wake can otherwise drop a later BeforeEntry
        // cancellation result while this worker still owns the native modal.
        let mut terminal_response_slots = self
            .terminal_response_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminal_response_slots.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a Win16 terminal response slot before enqueue",
                error,
            )
        })?;
        let pending_state = Arc::new(Mutex::new(super::PendingTerminalResponseState::default()));
        let request_id = self.modal_control.enqueue_terminal(|request_id| {
            self.send(command(request_id, response)).map_err(|_| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "enqueue terminal request for the Win16 USER worker",
                )
            })
        })?;
        if let Err(cause) = self.modal_control.post_terminal_wake(request_id) {
            let (error, pending) = super::retain_pending_terminal_response(
                cause, request_id, receive, pending_state,
            );
            terminal_response_slots.push(pending);
            return Err(error);
        }
        if self.send(super::WorkerCommand::TerminalWakePosted { request_id }).is_err() {
            let cause = RuntimeError::new(
                Kind::HostFailure,
                "publish the posted terminal wake to the Win16 USER worker",
            );
            let (error, pending) = super::retain_pending_terminal_response(
                cause, request_id, receive, pending_state,
            );
            terminal_response_slots.push(pending);
            return Err(error);
        }
        // Keep the reserved response slot until both wake publications finish.
        drop(terminal_response_slots);
        Ok(receive)
    }

    fn take_terminal_response_slots(&self) -> Vec<super::PendingTerminalResponse> {
        std::mem::take(
            &mut *self
                .terminal_response_slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(in crate::windows::win16_windows) fn shutdown(
        &mut self,
    ) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
        self.modal_wake_dispatcher.close_abort_submission_for_shutdown()?;
        if let Some(receipt) = &self.terminal_receipt {
            return Ok(receipt.clone());
        }
        if self.thread.is_none() {
            let own = super::super::win16_common_controls_bitmap_pins::retire_worker_after_join(
                self.worker_retirement_id,
                &self.toolbar_bitmap_retention,
                &mut self.bitmap_retention_slot_reserved,
            );
            let retry = super::super::win16_common_controls_bitmap_pins::retry_retained_after_join();
            return match (own, retry) {
                (Ok(()), Ok(())) => Err(RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 USER worker stopped without a retained terminal receipt",
                )),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(primary), Err(cleanup)) => Err(combine_shutdown_failures(
                    primary,
                    cleanup,
                    "worker-owned and process-retained toolbar bitmap retries both failed",
                )),
            };
        }
        let receive = match self.request_shutdown() {
            Ok(receive) => receive,
            Err(error) => {
                return match self.join_if_finished() {
                    Ok(()) => Err(error),
                    Err(additional) => Err(combine_shutdown_failures(
                        error,
                        additional,
                        "requesting shutdown and retiring the finished worker both failed",
                    )),
                };
            }
        };
        let response = receive.recv();
        let mut result = match response {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(error)) => Err(RuntimeError::with_source(
                error.kind(),
                "native window worker shutdown",
                error,
            )),
            Err(error) => Err(RuntimeError::with_source(
                Kind::HostFailure,
                "receive native window worker shutdown result",
                error,
            )),
        };
        let worker_finished = self
            .thread
            .as_ref()
            .is_some_and(|(thread, _)| thread.is_finished());
        if result.is_err() && !worker_finished {
            // A negative receipt does not prove the modal API returned or the
            // owner thread stopped. Keep the JoinHandle and all native backing.
            return result;
        }
        let Some((thread, mut retention)) = self.thread.take() else {
            return result;
        };
        let join_failure = if let Err(payload) = thread.join() {
            let failure = super::worker_join_failure(payload);
            let join_error = shared_runtime_error(&failure, "native window worker join panicked");
            result = match result {
                Ok(receipt) => Err(preserve_shutdown_receipt(
                    receipt,
                    join_error,
                    "native window worker join failed after preserving its modal receipt",
                )),
                Err(primary) => Err(combine_shutdown_failures(
                    primary,
                    join_error,
                    "native window worker shutdown and thread join both failed",
                )),
            };
            Some(failure)
        } else {
            None
        };
        let bitmap_failure = super::super::win16_common_controls_bitmap_pins::retire_worker_after_join(
            self.worker_retirement_id, &self.toolbar_bitmap_retention,
            &mut self.bitmap_retention_slot_reserved).err().map(Arc::new);
        if let Some(failure) = &bitmap_failure {
            let additional = shared_runtime_error(failure,
                "retire toolbar bitmap owners after USER worker join");
            result = match result {
                Ok(receipt) => Err(preserve_shutdown_receipt(receipt, additional,
                    "toolbar bitmap retirement failed after preserving the modal receipt")),
                Err(primary) => Err(combine_shutdown_failures(primary, additional,
                    "worker shutdown and toolbar bitmap retirement both failed")),
            };
        }
        // join includes thread termination and USER's window cleanup. These
        // opaque guards expose no native-writable memory to the joining thread.
        self.shutdown_storage
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        let supervisor_failure = combine_shared_failures(
            retention.stop_and_join().err().map(Arc::new), bitmap_failure.clone(),
            "worker retention and toolbar bitmap retirement both failed");
        if let Some(failure) = &supervisor_failure {
            let additional = shared_runtime_error(failure, "join the Win16 USER worker reaper");
            result = match result {
                Ok(receipt) => Err(preserve_shutdown_receipt(
                    receipt,
                    additional,
                    "native worker lifetime supervisor failed after preserving its modal receipt",
                )),
                Err(primary) => Err(combine_shutdown_failures(
                    primary,
                    additional,
                    "native worker shutdown and lifetime supervision both failed",
                )),
            };
        }
        super::finish_terminal_response_slots(
            self.take_terminal_response_slots(),
            join_failure,
            supervisor_failure,
        );
        if let Ok(receipt) = &mut result {
            receipt.resource_retirement = runtime::Win16NativeResourceRetirement::Retired;
            self.terminal_receipt = Some(receipt.clone());
        }
        result
    }

    fn join_if_finished(&mut self) -> Result<(), RuntimeError> {
        let finished = self
            .thread
            .as_ref()
            .is_some_and(|(thread, _)| thread.is_finished());
        if !finished {
            return Ok(());
        }
        if let Some((thread, mut retention)) = self.thread.take() {
            let join_failure = if let Err(payload) = thread.join() {
                Some(super::worker_join_failure(payload))
            } else {
                None
            };
            self.shutdown_storage
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
            let mut bitmap_reservation = self.bitmap_retention_slot_reserved;
            let bitmap_failure = super::super::win16_common_controls_bitmap_pins::retire_worker_after_join(
                self.worker_retirement_id, &self.toolbar_bitmap_retention,
                &mut bitmap_reservation).err().map(Arc::new);
            self.bitmap_retention_slot_reserved = bitmap_reservation;
            let supervisor_failure = combine_shared_failures(
                retention.stop_and_join().err().map(Arc::new), bitmap_failure,
                "worker retention and toolbar bitmap retirement both failed");
            super::finish_terminal_response_slots(
                self.take_terminal_response_slots(),
                join_failure.clone(),
                supervisor_failure.clone(),
            );
            let join_error = join_failure
                .as_ref()
                .map(|error| shared_runtime_error(error, "native window worker join panicked"));
            let supervisor_error = supervisor_failure
                .as_ref()
                .map(|error| shared_runtime_error(error, "join the Win16 USER worker reaper"));
            return match (join_error, supervisor_error) {
                (None, None) => Ok(()),
                (Some(error), None) | (None, Some(error)) => Err(error),
                (Some(primary), Some(additional)) => Err(combine_shutdown_failures(
                    primary,
                    additional,
                    "native worker join and lifetime supervision both failed",
                )),
            };
        }
        Ok(())
    }
}

fn preserve_shutdown_receipt(
    receipt: runtime::Win16WindowAbortReceipt,
    error: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    RuntimeError::with_source(
        error.kind(),
        context,
        WorkerShutdownReceiptFailure { error, receipt },
    )
}

#[derive(Debug)]
struct WorkerShutdownReceiptFailure {
    error: RuntimeError,
    receipt: runtime::Win16WindowAbortReceipt,
}

impl std::fmt::Display for WorkerShutdownReceiptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; {} native modal cancellation receipt(s) retained",
            self.error,
            self.receipt.cancelled_modals.len()
        )
    }
}

impl std::error::Error for WorkerShutdownReceiptFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
struct WorkerShutdownFailures {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl std::fmt::Display for WorkerShutdownFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; another shutdown stage also failed: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for WorkerShutdownFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn combine_shutdown_failures(
    primary: RuntimeError,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(additional.kind());
    RuntimeError::with_source(
        kind,
        context,
        WorkerShutdownFailures {
            primary,
            additional,
        },
    )
}

fn shared_runtime_error(error: &Arc<RuntimeError>, context: &'static str) -> RuntimeError {
    RuntimeError::with_source(error.kind(), context, Arc::clone(error))
}

fn combine_shared_failures(
    first: Option<Arc<RuntimeError>>,
    second: Option<Arc<RuntimeError>>,
    context: &'static str,
) -> Option<Arc<RuntimeError>> {
    match (first, second) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(primary), Some(additional)) => Some(Arc::new(combine_shutdown_failures(
            shared_runtime_error(&primary, context),
            shared_runtime_error(&additional, context),
            context,
        ))),
    }
}

fn take_terminal_response_slots(
    slots: &Arc<Mutex<Vec<super::PendingTerminalResponse>>>,
) -> Vec<super::PendingTerminalResponse> {
    std::mem::take(&mut *slots.lock().unwrap_or_else(
        std::sync::PoisonError::into_inner,
    ))
}

pub(super) type ShutdownResult = Result<runtime::Win16WindowAbortReceipt, Arc<RuntimeError>>;
