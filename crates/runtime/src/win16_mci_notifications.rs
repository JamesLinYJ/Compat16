//! Exact MCI event -> USER POST -> USER source consume -> MCI source ACK.

use super::{Win16MciNotificationPost, Win16MciPendingNotification, Win16State};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16GuestNotification, Win16GuestNotificationTarget, Win16WindowOperation,
    Win16WindowResult, Win16WindowStep,
};

fn notification_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, message)
}

impl Win16State {
    /// Poll one retained native event at a guest safe point. The MCI ledger
    /// remains the source owner until its exact source tuple is acknowledged.
    pub(in crate::win16_runtime) fn poll_mci_notification(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.mci.pending_notification.is_none() {
            let Some(event) = host.win16_mci_peek_notification()? else {
                return Ok(());
            };
            self.mci.pending_notification = Some(Win16MciPendingNotification {
                event,
                post: Win16MciNotificationPost::ResolveTarget,
            });
        }

        macro_rules! set_post {
            ($post:expr) => {
                self.mci
                    .pending_notification
                    .as_mut()
                    .expect("MCI notification remains owned until exact source ACK")
                    .post = $post
            };
        }

        loop {
            let event = self.mci.pending_notification.as_ref().map(|pending| pending.event).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI notification owner disappeared before its exact source ACK",
                )
            })?;
            if event.source.id == 0
                || event.source.id == u64::MAX
                || event.source.generation == 0
                || event.source.generation != event.device.generation
                || event.device.token == 0
                || event.source.sequence == 0
                || event.source.sequence != event.id.0
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI notification source does not match its exact device generation and event ID",
                ));
            }

            let post = std::mem::replace(
                &mut self.mci.pending_notification.as_mut().expect("MCI notification exists").post,
                Win16MciNotificationPost::ResolveTarget,
            );
            match post {
                Win16MciNotificationPost::ResolveTarget => {
                    let device_alias = self
                        .mci
                        .devices
                        .iter()
                        .find_map(|(guest, entry)| (entry.host == event.device).then_some(*guest));
                    let window_alias = self
                        .window_handles
                        .iter()
                        .find_map(|(guest, window)| (*window == event.target).then_some(*guest));
                    if let (Some(guest_device), Some(guest_hwnd)) = (device_alias, window_alias) {
                        set_post!(Win16MciNotificationPost::Ready(Win16GuestNotification {
                            target: Win16GuestNotificationTarget::Window {
                                window: event.target,
                                guest_hwnd,
                            },
                            source: event.source,
                            message: 0x03b9,
                            w_param: event.status,
                            l_param: u32::from(guest_device),
                        }));
                        continue;
                    }
                    match host.win16_host_window_liveness(event.target)? {
                        crate::Win16HostWindowLiveness::Live => {
                            set_post!(Win16MciNotificationPost::ResolveTarget);
                            return Ok(());
                        }
                        crate::Win16HostWindowLiveness::Retired => {
                            host.report_diagnostic(&Diagnostic::warning(
                                Kind::CompatibilityGap,
                                "retired MCI notification target has no guest alias; consuming only its exact MCI source",
                            ));
                            set_post!(Win16MciNotificationPost::RetiredTarget);
                            continue;
                        }
                    }
                }
                Win16MciNotificationPost::Ready(notification) => {
                    if self.window_abort_receipt.is_some() {
                        match host.win16_host_window_liveness(event.target)? {
                            crate::Win16HostWindowLiveness::Retired => {
                                // Task teardown has already sealed USER source
                                // admission. Retire only this accepted MCI row.
                                set_post!(Win16MciNotificationPost::RetiredTarget);
                                continue;
                            }
                            crate::Win16HostWindowLiveness::Live => {
                                set_post!(Win16MciNotificationPost::Ready(notification));
                                return Err(notification_error(
                                    "MCI notification remains owned while its target is live after USER abort; no new POST is submitted",
                                ));
                            }
                        }
                    }
                    match host.win16_window_begin(Win16WindowOperation::PostGuestNotification(
                        notification,
                    )) {
                        Ok(Win16WindowStep::SourceRetired { proof, result }) => {
                            let operation = crate::Win16NativeWindowOperationProof {
                                operation_id: proof.operation.operation_id,
                                kind: proof.operation.kind,
                            };
                            if operation.operation_id.0 == 0
                                || operation.kind
                                    != crate::Win16NativeWindowOperationKind::PostGuestNotification
                                || proof.worker_generation == 0
                                || proof.state
                                    != crate::Win16NativeWindowOperationState::Returned
                            {
                                set_post!(Win16MciNotificationPost::Unexpected {
                                    proof: Some(proof),
                                    step: result,
                                });
                                return Err(notification_error(
                                    "USER POST source proof has an invalid operation identity or returned state",
                                ));
                            }
                            let posted = match result.as_ref() {
                                Win16WindowStep::Complete(
                                    Win16WindowResult::NotificationPosted(posted),
                                ) => Some(*posted),
                                _ => None,
                            };
                            let Some(posted) = posted else {
                                set_post!(Win16MciNotificationPost::Unexpected {
                                    proof: Some(proof),
                                    step: result,
                                });
                                return Err(notification_error(
                                    "USER POST source proof wrapped a non-POST completion",
                                ));
                            };
                            set_post!(Win16MciNotificationPost::NormalProof {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            continue;
                        }
                        Ok(Win16WindowStep::StartedFailure(failure)) => {
                            if failure.operation.operation_id.0 == 0
                                || failure.operation.kind
                                    != crate::Win16NativeWindowOperationKind::PostGuestNotification
                                || failure.worker_generation == 0
                            {
                                set_post!(Win16MciNotificationPost::Unexpected {
                                    proof: None,
                                    step: Box::new(Win16WindowStep::StartedFailure(failure)),
                                });
                                return Err(notification_error(
                                    "USER POST StartedFailure changed the real operation identity or kind",
                                ));
                            }
                            set_post!(Win16MciNotificationPost::TerminalFailure(failure));
                            continue;
                        }
                        Ok(unexpected) => {
                            set_post!(Win16MciNotificationPost::Unexpected {
                                proof: None,
                                step: Box::new(unexpected),
                            });
                            return Err(notification_error(
                                "USER POST returned an unexpected continuation; its MCI event remains owned",
                            ));
                        }
                        Err(error) => {
                            // No USER identity was reported, so retain the
                            // original event and exact notification for retry.
                            set_post!(Win16MciNotificationPost::Ready(notification));
                            return Err(error);
                        }
                    }
                }
                Win16MciNotificationPost::NormalProof {
                    notification,
                    proof,
                    result,
                    posted,
                } => {
                    let operation = proof.operation;
                    let readback = match host.win16_window_source_retirement(
                        operation,
                        proof.worker_generation,
                    ) {
                        Ok(readback) => readback,
                        Err(error) => {
                            set_post!(Win16MciNotificationPost::NormalProof {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            return Err(error);
                        }
                    };
                    if !readback
                        .as_ref()
                        .is_some_and(|recorded| std::sync::Arc::ptr_eq(recorded, &proof))
                    {
                        set_post!(Win16MciNotificationPost::NormalProof {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        return Err(notification_error(
                            "USER POST carrier lacks the same exact retained source-retirement proof",
                        ));
                    }
                    if let Err(error) = host.win16_window_source_retirement_consumed(&proof) {
                        set_post!(Win16MciNotificationPost::NormalProof {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        return Err(error);
                    }
                    set_post!(Win16MciNotificationPost::NormalConsumed {
                        notification,
                        proof,
                        result,
                        posted,
                    });
                    continue;
                }
                Win16MciNotificationPost::NormalConsumed {
                    notification,
                    proof,
                    result,
                    posted,
                } => {
                    if posted {
                        if let Err(error) = host.win16_mci_ack_notification(event.source) {
                            set_post!(Win16MciNotificationPost::NormalConsumed {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            return Err(error);
                        }
                        self.mci.pending_notification = None;
                        return Ok(());
                    }
                    match host.win16_host_window_liveness(event.target) {
                        Ok(crate::Win16HostWindowLiveness::Live) => {
                            // Keep the same MCI event and source sequence. A
                            // false USER post is retried at the next safe point.
                            set_post!(Win16MciNotificationPost::Ready(notification));
                            return Ok(());
                        }
                        Ok(crate::Win16HostWindowLiveness::Retired) => {
                            host.report_diagnostic(&Diagnostic::warning(
                                Kind::CompatibilityGap,
                                "MCI USER POST returned false after its USER proof was consumed; the exact target retired",
                            ));
                            set_post!(Win16MciNotificationPost::RetiredTarget);
                            continue;
                        }
                        Err(error) => {
                            set_post!(Win16MciNotificationPost::NormalConsumed {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            return Err(error);
                        }
                    }
                }
                Win16MciNotificationPost::TerminalFailure(failure) => {
                    if let Err(error) =
                        self.acknowledge_started_post_failure(&failure, host)
                    {
                        set_post!(Win16MciNotificationPost::TerminalFailure(failure));
                        return Err(error);
                    }
                    set_post!(Win16MciNotificationPost::TerminalAcknowledged(failure));
                    continue;
                }
                Win16MciNotificationPost::TerminalAcknowledged(failure) => {
                    if let Err(error) = host.win16_mci_ack_notification(event.source) {
                        set_post!(Win16MciNotificationPost::TerminalAcknowledged(failure));
                        return Err(error);
                    }
                    self.mci.pending_notification = None;
                    return Ok(());
                }
                Win16MciNotificationPost::RetiredTarget => {
                    if let Err(error) = host.win16_mci_ack_notification(event.source) {
                        set_post!(Win16MciNotificationPost::RetiredTarget);
                        return Err(error);
                    }
                    self.mci.pending_notification = None;
                    return Ok(());
                }
                Win16MciNotificationPost::Unexpected { proof, step } => {
                    let error = super::unexpected_mci_post_error(proof.as_ref(), step.as_ref());
                    set_post!(Win16MciNotificationPost::Unexpected { proof, step });
                    return Err(error);
                }
            }
        }
    }
}
