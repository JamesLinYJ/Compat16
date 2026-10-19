//! Owner-thread modal ingress continuation and terminal wake dispatch.

use std::cell::RefCell;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::rc::Rc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindowOperationId, Win16WindowStep};

use super::{
    CanonicalAbortResponse, PendingTerminalResponse, PendingTerminalResponseState, WorkerCommand,
    WorkerState, combine_worker_failures, retain_canonical_abort_pending_response,
    retain_canonical_abort_response_slot, retain_pending_terminal_response,
};

/// Shared terminal owner used by producer-side modal wake failures. It submits
/// the existing Abort command and retains its response slot without waiting;
/// native API arguments and source events remain with their existing owners.
pub(in crate::windows) struct ModalWakeDispatcher {
    pub(super) sender: Sender<WorkerCommand>,
    pub(super) wake_event: Arc<OwnedHandle>,
    pub(super) modal_control: Arc<super::super::super::win16_modal::ModalWorkerControl>,
    pub(super) terminal_response_slots: Arc<Mutex<Vec<PendingTerminalResponse>>>,
    pub(super) canonical_abort_response: Arc<CanonicalAbortResponse>,
    pub(super) abort_submission: AtomicU8,
    pub(super) abort_submission_lock: Mutex<()>,
    pub(super) abort_submission_ready: Condvar,
    pub(super) abort_publication_failure: Mutex<Option<Arc<RuntimeError>>>,
}

impl ModalWakeDispatcher {
    pub(in crate::windows) fn request_abort_for_modal_failure(&self) -> Result<(), RuntimeError> {
        let mut guard = self
            .abort_submission_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match self.abort_submission.load(Ordering::Acquire) {
                0 => {
                    self.abort_submission.store(1, Ordering::Release);
                    break;
                }
                1 => {
                    guard = self
                        .abort_submission_ready
                        .wait(guard)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                2 => {
                    drop(guard);
                    return self.retained_publication_result();
                }
                3 if self.canonical_abort_response.request_id().is_some() => {
                    drop(guard);
                    return self.retained_publication_result();
                }
                3 => {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "Win16 USER Abort publication was closed by worker shutdown",
                    ));
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "modal-ingress Abort publication entered an unknown state",
                    ));
                }
            }
        }
        drop(guard);
        let mut slots = self
            .terminal_response_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = slots.try_reserve(1) {
            self.publish_abort_submission_state(0);
            return Err(RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the modal-ingress Abort response slot before enqueue",
                error,
            ));
        }
        let (response, receive) = mpsc::channel();
        let request_id = match self.modal_control.enqueue_terminal(|request_id| {
            self.sender
                .send(WorkerCommand::Abort {
                    request_id,
                    response,
                })
                .map_err(|_| {
                    RuntimeError::new(
                        Kind::HostFailure,
                        "enqueue the modal-ingress Abort command for the Win16 USER worker",
                    )
                })
        }) {
            Ok(request_id) => request_id,
            Err(error) => {
                self.publish_abort_submission_state(0);
                return Err(error);
            }
        };
        if let Err((error, receive)) = self.canonical_abort_response.publish(request_id, receive) {
            let state = Arc::new(Mutex::new(PendingTerminalResponseState::default()));
            // Publication already reached the worker. Keep this original
            // receiver alive even if the canonical owner itself is damaged.
            let (retained, slot) =
                retain_pending_terminal_response(error, request_id, receive, state);
            let shared = Arc::new(retained);
            *self
                .abort_publication_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&shared));
            slots.push(slot);
            self.publish_abort_submission_state(2);
            return Err(super::shared_terminal_response_failure(
                &shared,
                "canonical modal-ingress Abort response publication failed",
            ));
        }

        let terminal_post = self.modal_control.post_terminal_wake(request_id);
        let wake_publish = if self
            .sender
            .send(WorkerCommand::TerminalWakePosted { request_id })
            .is_err()
        {
            Err(RuntimeError::new(
                Kind::HostFailure,
                "publish the modal-ingress terminal wake to the Win16 USER worker",
            ))
        } else if (crate::windows::win32_safe::set_event(self.wake_event.as_raw_handle() as _)) == 0
        {
            let code = crate::windows::win32_safe::last_error();
            Err(RuntimeError::with_source(
                Kind::HostFailure,
                format!(
                    "wake the Win16 USER worker for modal-ingress Abort (Windows error {code})"
                ),
                std::io::Error::from_raw_os_error(code as i32),
            ))
        } else {
            Ok(())
        };

        let mut failure = terminal_post.err();
        if let Err(error) = wake_publish {
            match failure.take() {
                Some(primary) => {
                    failure = Some(combine_worker_failures(
                        primary,
                        error,
                        "modal-ingress terminal publication failures combined",
                    ))
                }
                None => failure = Some(error),
            }
        }
        if let Some(cause) = failure {
            let (error, slot) = retain_canonical_abort_pending_response(
                cause,
                Arc::clone(&self.canonical_abort_response),
            );
            let shared = Arc::new(error);
            *self
                .abort_publication_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&shared));
            slots.push(slot);
            self.publish_abort_submission_state(2);
            return Err(super::shared_terminal_response_failure(
                &shared,
                "modal-ingress terminal Abort publication failed",
            ));
        }
        slots.push(retain_canonical_abort_response_slot(Arc::clone(
            &self.canonical_abort_response,
        )));
        self.publish_abort_submission_state(2);
        Ok(())
    }

    pub(super) fn close_abort_submission_for_shutdown(
        &self,
    ) -> Result<Option<(u64, Option<Arc<RuntimeError>>)>, RuntimeError> {
        let mut guard = self
            .abort_submission_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match self.abort_submission.load(Ordering::Acquire) {
                1 => {
                    guard = self
                        .abort_submission_ready
                        .wait(guard)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                0 => {
                    self.abort_submission.store(3, Ordering::Release);
                    self.abort_submission_ready.notify_all();
                    return Ok(None);
                }
                2 => {
                    let request_id =
                        self.canonical_abort_response.request_id().ok_or_else(|| {
                            self.abort_publication_failure.lock().unwrap_or_else(
                            std::sync::PoisonError::into_inner,
                        ).as_ref().map_or_else(
                            || RuntimeError::new(Kind::InternalInvariant,
                                "published Win16 USER Abort has no canonical request identity"),
                            |error| super::shared_terminal_response_failure(
                                error,
                                "close Abort publication after canonical response ownership failed",
                            ),
                        )
                        })?;
                    self.abort_submission.store(3, Ordering::Release);
                    self.abort_submission_ready.notify_all();
                    let failure = self
                        .abort_publication_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .as_ref()
                        .map(Arc::clone);
                    return Ok(Some((request_id, failure)));
                }
                3 => {
                    let Some(request_id) = self.canonical_abort_response.request_id() else {
                        return Ok(None);
                    };
                    let failure = self
                        .abort_publication_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .as_ref()
                        .map(Arc::clone);
                    return Ok(Some((request_id, failure)));
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "modal-ingress Abort publication entered an unknown state",
                    ));
                }
            }
        }
    }

    fn publish_abort_submission_state(&self, state: u8) {
        let _guard = self
            .abort_submission_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.abort_submission.store(state, Ordering::Release);
        self.abort_submission_ready.notify_all();
    }

    fn retained_publication_result(&self) -> Result<(), RuntimeError> {
        if let Some(error) = self
            .abort_publication_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone)
        {
            return Err(super::shared_terminal_response_failure(
                &error,
                "reuse the canonical modal-ingress Abort after its wake publication failed",
            ));
        }
        Ok(())
    }
}

pub(in crate::windows) fn yield_pending_modal_guest_work(
    state: &Rc<RefCell<WorkerState>>,
    work: super::super::super::win16_modal::ModalGuestWorkIdentity,
    failure: Option<Arc<RuntimeError>>,
) -> Result<(), RuntimeError> {
    let response = {
        let state = state.borrow();
        let Some(active) = state
            .active_operations
            .last()
            .filter(|active| active.id == work.operation_id)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work marker does not match the active USER operation",
            ));
        };
        if state.modal_control.active_modal_work_scope() != Some((work.operation_id, work.scope_id))
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work marker does not match the active modal scope",
            ));
        }
        active.response.clone()
    };
    let work_fields = work.runtime_fields()?;
    let failure = failure.map(|cause| RuntimeError::with_source(
        cause.kind(),
        "Win16 modal marker publication failed; terminal teardown must still obtain native return",
        cause,
    ));
    let failed_publication = failure.is_some();
    response
        .send(Ok(Win16WindowStep::PendingModalGuestWork {
            operation_id: Win16HostWindowOperationId(work_fields.0),
            scope_id: work_fields.1,
            generation: work_fields.2,
            marker_id: work_fields.3,
            wake_generation: work_fields.4,
            failure,
        }))
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a suspended Win16 modal guest-work continuation",
            )
        })?;

    if failed_publication {
        return Ok(());
    }
    loop {
        // Terminal intent is published only after the exact Abort command is
        // enqueued under the same gate used by Resume publication. Keep
        // consuming this FIFO until that command is observed, so an accepted
        // matching Resume ahead of it cannot escape to the outer worker loop.
        if state.borrow().aborted {
            if let Some((failed_work, cause)) = state
                .borrow()
                .modal_control
                .pending_modal_failure(work.operation_id, work.scope_id)
            {
                let failed_fields = failed_work.runtime_fields()?;
                let failure = RuntimeError::with_source(
                    cause.kind(),
                    "Win16 modal marker publication failed; terminal teardown must still obtain native return",
                    cause,
                );
                response
                    .send(Ok(Win16WindowStep::PendingModalGuestWork {
                        operation_id: Win16HostWindowOperationId(failed_fields.0),
                        scope_id: failed_fields.1,
                        generation: failed_fields.2,
                        marker_id: failed_fields.3,
                        wake_generation: failed_fields.4,
                        failure: Some(failure),
                    }))
                    .map_err(|_| {
                        RuntimeError::new(
                            Kind::HostFailure,
                            "runtime dropped the retained Win16 modal ingress failure",
                        )
                    })?;
            }
            return Ok(());
        }
        let command = super::super::win16_message_loop::wait_for_worker_command(state)?;
        match command {
            WorkerCommand::ResumeModalGuestWork {
                operation_id: resume_operation_id,
                scope_id: resume_scope_id,
                generation: resume_generation,
                marker_id: resume_marker_id,
                wake_generation: resume_wake_generation,
            } if (
                resume_operation_id,
                resume_scope_id,
                resume_generation,
                resume_marker_id,
                resume_wake_generation,
            ) == work_fields =>
            {
                let wake_generation = state
                    .borrow()
                    .modal_control
                    .complete_modal_guest_work(work)?;
                let mut state = state.borrow_mut();
                state.multimedia_generation_seen =
                    state.multimedia_generation_seen.max(wake_generation);
                return Ok(());
            }
            WorkerCommand::ResumeModalGuestWork {
                operation_id: resume_operation_id,
                scope_id: resume_scope_id,
                generation: resume_generation,
                marker_id: resume_marker_id,
                wake_generation: resume_wake_generation,
            } => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!(
                        "modal resume tuple ({resume_operation_id}, {resume_scope_id}, {resume_generation}, {resume_marker_id:?}, {resume_wake_generation:?}) does not match pending ({}, {}, {}, {:?}, {:?})",
                        work_fields.0, work_fields.1, work_fields.2, work_fields.3, work_fields.4,
                    ),
                ));
            }
            command => super::process_command(state, command),
        }
    }
}
