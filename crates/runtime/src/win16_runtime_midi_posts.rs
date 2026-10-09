//! Runtime consumers for normal USER POST proof and MIDI source ACK.

use guest_core::memory::Memory;

use crate::{
    RuntimeError, RuntimeHost, Win16GuestNotificationTarget,
    Win16HostMidiNotificationId, Win16WindowOperation,
};
use super::{MidiCallbackRoute, Win16MidiNotificationTarget, Win16State};
use super::super::window_post::{
    resolve_window_post_step, started_failure_error, WindowPostAttempt, WindowPostOutcome,
};
use crate::Win16HostMidiCancellationReason as CancellationReason;

impl Win16State {
    /// Distinguish exact source ACK progress from an idle/blocked POST, while
    /// keeping the existing message-loop callback-entry contract unchanged.
    pub(in crate::win16_runtime) fn dispatch_midi_notification_with_progress(
        &mut self, cpu: &mut x86_cpu::Cpu, memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<super::MidiDispatch, RuntimeError> {
        let before = self.midi.notification_progress;
        let no_callback = self.dispatch_pending_midi_notification(cpu, memory, host)?;
        Ok(if !no_callback { super::MidiDispatch::CallbackEntered }
            else if self.midi.notification_progress != before { super::MidiDispatch::Progress }
            else { super::MidiDispatch::Idle })
    }

    /// Route one exact MIDI notification. USER results are first retained on
    /// the existing dispatch owner; source ACK follows proof consumption.
    pub(in crate::win16_runtime) fn dispatch_pending_midi_notification(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.retry_midi_callback_start_cleanup()? {
            return Ok(true);
        }
        if let Some(pending) = self.midi.dispatching.clone() {
            if pending.post_accepted {
                self.finish_midi_notification_target(host, pending.identity)?;
            } else if pending.post_attempt.is_some() {
                self.resume_midi_user_post(host, pending.identity)?;
            }
            return Ok(true);
        }
        let Some(target) = self.poll_midi_notification_target(memory, host)? else {
            return Ok(true);
        };
        match target {
            Win16MidiNotificationTarget::Function { identity, event } => {
                Ok(!self.begin_midi_asynchronous_guest_callback(
                    cpu, memory, host, identity, event,
                )?)
            }
            Win16MidiNotificationTarget::Post { identity, notification } => {
                if !self.validate_guest_notification_target(notification.target) {
                    self.retry_or_retire_midi_post_target(host, identity, notification.target)?;
                    return Ok(true);
                }
                let step = match host.win16_window_begin(
                    Win16WindowOperation::PostGuestNotification(notification),
                ) {
                    Ok(step) => step,
                    Err(error) => {
                        // The boundary guarantees this error means no enqueue;
                        // release the exact runtime reservation for safe retry.
                        self.cancel_midi_notification_target(identity)?;
                        return Err(error.with_context(format!(
                            "MIDI USER source {}:{}:{} Begin failed before enqueue",
                            identity.device.token,
                            identity.device.generation,
                            identity.sequence,
                        )));
                    }
                };
                match resolve_window_post_step(step)? {
                    WindowPostOutcome::StartedFailure(failure) => {
                        self.retain_midi_post_failure(identity, failure.clone())?;
                        return Err(started_failure_error(
                            &failure,
                            "MIDI USER notification Begin failed after enqueue",
                        ));
                    }
                    WindowPostOutcome::SourceRetired(receipt) => {
                        self.retain_midi_post_attempt(
                            identity,
                            WindowPostAttempt::SourceRetired(receipt),
                        )?;
                    }
                    WindowPostOutcome::Retained(attempt) => {
                        self.retain_midi_post_attempt(identity, attempt)?;
                    }
                    WindowPostOutcome::Completed(_) => {
                        return Err(midi_invariant(
                            "MIDI USER Begin resolver returned a local target result",
                        ));
                    }
                }
                self.resume_midi_user_post(host, identity)?;
                Ok(true)
            }
        }
    }

    fn retry_or_retire_midi_post_target(
        &mut self,
        host: &mut impl RuntimeHost,
        identity: Win16HostMidiNotificationId,
        target: Win16GuestNotificationTarget,
    ) -> Result<(), RuntimeError> {
        let Some(dispatch) = self.midi.dispatching.clone() else {
            return Err(midi_invariant("MIDI target eligibility lost its dispatch owner"));
        };
        if dispatch.identity != identity {
            return Err(midi_invariant("MIDI target eligibility changed source identity"));
        }
        match (dispatch.callback_route, target) {
            (
                MidiCallbackRoute::Window { host: expected, guest },
                Win16GuestNotificationTarget::Window { window, guest_hwnd },
            ) if expected == window && guest == guest_hwnd => {
                if self.window_handles.get(&guest) != Some(&expected) {
                    self.cancel_midi_notification_source(
                        host, identity, CancellationReason::WindowTargetRetired,
                    )?;
                } else {
                    self.cancel_midi_notification_target(identity)?;
                }
            }
            (
                MidiCallbackRoute::Task(task),
                Win16GuestNotificationTarget::Task {
                    owner, guest_htask, task_selector_generation, queue,
                },
            ) if (owner, guest_htask, task_selector_generation)
                == (task.owner, task.handle, task.selector_generation) =>
            {
                if self.midi_task_identity_for(task.owner, task.handle) != Some(task) {
                    self.cancel_midi_notification_source(
                        host, identity, CancellationReason::TaskTargetRetired,
                    )?;
                } else if self.tasks.current() != Some(task.owner)
                    || self.user_task_queue != Some((
                        task.owner, task.handle, task.selector_generation, queue,
                    ))
                {
                    self.cancel_midi_notification_target(identity)?;
                } else {
                    return Err(midi_invariant(
                        "eligible MIDI CALLBACK_TASK failed exact notification validation",
                    ));
                }
            }
            _ => return Err(midi_invariant(
                "MIDI POST target changed the captured window or task identity",
            )),
        }
        Ok(())
    }

    fn retain_midi_post_attempt(
        &mut self,
        identity: Win16HostMidiNotificationId,
        attempt: WindowPostAttempt,
    ) -> Result<(), RuntimeError> {
        let dispatch = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI normal USER POST lost its dispatch owner"))?;
        if dispatch.identity != identity
            || dispatch.post_accepted
            || dispatch.post_failure.is_some()
            || dispatch.post_attempt.is_some()
            || dispatch.terminal_ack.is_some()
            || dispatch.terminal_acknowledged
            || !matches!(dispatch.callback_route,
                MidiCallbackRoute::Window { .. } | MidiCallbackRoute::Task(_))
        {
            return Err(midi_invariant(
                "MIDI normal POST changed its exact dispatch owner or retry phase",
            ));
        }
        dispatch.post_attempt = Some(attempt);
        Ok(())
    }

    pub(super) fn resume_midi_user_post(
        &mut self,
        host: &mut impl RuntimeHost,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let posted = {
            let dispatch = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
                "MIDI USER POST proof retry lost its dispatch owner"))?;
            if dispatch.identity != identity || dispatch.post_failure.is_some() {
                return Err(midi_invariant(
                    "MIDI USER POST proof retry changed its exact source identity",
                ));
            }
            let attempt = dispatch.post_attempt.as_mut().ok_or_else(|| midi_invariant(
                "MIDI USER POST proof retry has no cached result"))?;
            super::super::window_post::consume_window_post_attempt(host, attempt)?
        };
        if posted {
            self.mark_midi_notification_posted(identity)?;
            self.finish_midi_notification_target(host, identity)
        } else {
            let reason = match self.midi.dispatching.as_ref().map(|dispatch| dispatch.callback_route) {
                Some(MidiCallbackRoute::Window { .. } | MidiCallbackRoute::Task(_)) => {
                    CancellationReason::UserPostRejected
                }
                _ => return Err(midi_invariant(
                    "MIDI rejected USER POST lost its exact window/task route",
                )),
            };
            self.cancel_midi_notification_source(host, identity, reason)
        }
    }

    fn mark_midi_notification_posted(
        &mut self,
        identity: Win16HostMidiNotificationId,
    ) -> Result<(), RuntimeError> {
        let pending = self.midi.dispatching.as_mut().ok_or_else(|| midi_invariant(
            "MIDI USER post acceptance lost its runtime source frame"))?;
        if pending.identity != identity || pending.post_accepted || pending.post_failure.is_some()
            || pending.post_attempt.as_ref().is_none_or(|attempt| {
                !super::super::window_post::window_post_attempt_consumed(attempt)
                    || super::super::window_post::window_post_attempt_result(attempt) != Some(true)
            })
            || !matches!(pending.callback_route,
                MidiCallbackRoute::Window { .. } | MidiCallbackRoute::Task(_))
        {
            return Err(midi_invariant(
                "MIDI USER post acceptance changed its exact source or route",
            ));
        }
        pending.post_accepted = true;
        Ok(())
    }
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(crate::DiagnosticKind::InternalInvariant, message)
}
