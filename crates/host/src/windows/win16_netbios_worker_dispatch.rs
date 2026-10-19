//! Startup classification and diagnostics for one owned NetBIOS worker.

use super::*;

pub(super) fn publish_inline_terminal(
    owner: &mut NativeNcbOwner,
    function_return: u8,
    commands: &Receiver<WorkerCommand>,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &SharedWakeStatus,
) {
    let raw = super::raw_snapshot(owner, function_return);
    match super::snapshot(owner, function_return) {
        Ok(projected) => {
            if !super::send_worker_start(
                owner,
                Ok(WorkerStart::InlineTerminal {
                    raw,
                    projected: Some(projected),
                }),
            ) {
                super::close_after_terminal(owner);
                return;
            }
            super::await_exact_ack(owner, commands, None, wake_status);
        }
        Err(error) => {
            if !super::send_worker_start(
                owner,
                Ok(WorkerStart::InlineTerminal {
                    raw,
                    projected: None,
                }),
            ) {
                super::close_after_terminal(owner);
                return;
            }
            super::publish_terminal_projection(
                owner,
                commands,
                completions,
                multimedia_wake,
                wake_status,
                Some(error),
            );
        }
    }
}

pub(super) fn finish_accepted_async_request(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &SharedWakeStatus,
) {
    if !super::wait_for_terminal(owner, commands, completions, multimedia_wake, wake_status) {
        if owner.terminal {
            if owner.teardown_reason.is_some() {
                super::finish_native_teardown(owner, commands, wake_status);
            } else {
                super::publish_terminal_projection(
                    owner,
                    commands,
                    completions,
                    multimedia_wake,
                    wake_status,
                    None,
                );
            }
        } else {
            service_native_owner_after_wait_failure(
                owner,
                commands,
                completions,
                multimedia_wake,
                wake_status,
            );
        }
        return;
    }
    if owner.teardown_reason.is_some() {
        super::finish_native_teardown(owner, commands, wake_status);
    } else {
        super::publish_terminal_projection(
            owner,
            commands,
            completions,
            multimedia_wake,
            wake_status,
            None,
        );
    }
}

pub(super) fn report_wait_failure(
    error: RuntimeError,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &SharedWakeStatus,
    publish_wake: bool,
) -> bool {
    let cause = std::sync::Arc::new(error);
    super::mark_native_wait_failed(wake_status, Some(std::sync::Arc::clone(&cause)));
    if completions
        .send(WorkerCompletion::NativeWaitFailure(std::sync::Arc::clone(
            &cause,
        )))
        .is_err()
    {
        return false;
    }
    if publish_wake {
        super::request_wake(wake_status, false);
        let _ = super::publish_pending_wake(multimedia_wake, wake_status);
    }
    true
}

pub(super) fn service_native_owner_after_wait_failure(
    owner: &mut NativeNcbOwner,
    commands: &Receiver<WorkerCommand>,
    completions: &Sender<WorkerCompletion>,
    multimedia_wake: &MultimediaWakeSender,
    wake_status: &SharedWakeStatus,
) {
    loop {
        match commands.recv() {
            Ok(WorkerCommand::Cancel(reply)) => {
                let _ = reply.send(Ok(super::cancel_native(owner)));
            }
            Ok(WorkerCommand::Ack { reply, .. }) => {
                let _ = reply.send(Ok(false));
            }
            Ok(WorkerCommand::ProbeTerminal) => {
                if poll_native_terminal(owner, wake_status) {
                    if owner.teardown_reason.is_some() {
                        super::finish_native_teardown(owner, commands, wake_status);
                    } else {
                        super::publish_terminal_projection(
                            owner,
                            commands,
                            completions,
                            multimedia_wake,
                            wake_status,
                            None,
                        );
                    }
                    return;
                }
                super::clear_native_probe_pending(wake_status);
            }
            Ok(WorkerCommand::Teardown {
                reason,
                issue_cancel,
            }) => {
                if owner
                    .teardown_reason
                    .is_some_and(|previous| previous != reason)
                {
                    super::clear_native_probe_pending(wake_status);
                    continue;
                }
                owner.teardown_reason = Some(reason);
                super::mark_teardown_requested(wake_status, reason);
                if issue_cancel && !owner.cancel_requested {
                    let _ = super::cancel_native(owner);
                }
                if poll_native_terminal(owner, wake_status) {
                    super::finish_native_teardown(owner, commands, wake_status);
                    return;
                }
                super::clear_native_probe_pending(wake_status);
            }
            Err(_) => {
                super::abandon_until_terminal(owner);
                return;
            }
        }
    }
}

fn poll_native_terminal(owner: &mut NativeNcbOwner, wake_status: &SharedWakeStatus) -> bool {
    // SAFETY: WaitForSingleObject waits on a handle this process owns.
    match unsafe { WaitForSingleObject(owner.event, 0) } {
        WAIT_OBJECT_0 => {
            owner.terminal = true;
            owner.in_flight = false;
            super::mark_native_terminal(wake_status);
            true
        }
        WAIT_TIMEOUT => false,
        result => {
            let cause = if result == WAIT_FAILED {
                last_error("probe asynchronous Windows NetBIOS event after wait failure")
            } else {
                RuntimeError::new(
                    Kind::HostFailure,
                    format!("terminal NetBIOS probe returned unexpected wait status {result}"),
                )
            };
            super::mark_native_wait_failed(wake_status, Some(std::sync::Arc::new(cause)));
            false
        }
    }
}
