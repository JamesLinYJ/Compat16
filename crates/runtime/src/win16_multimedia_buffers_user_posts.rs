//! Normal USER POST completion proofs remain owned by exact WAVE source rows.

use super::*;
use super::super::window_post::{
    consume_window_post_attempt, started_failure_error, WindowPostAttempt, WindowPostOutcome,
};
use crate::Win16HostTaskQueue;

impl Win16State {
    pub(super) fn dispatch_pending_wave_user_notification(
        &mut self,
        host: &mut impl RuntimeHost,
        pending: &PendingWaveCallback,
        task: WaveTaskIdentity,
        queue: Win16HostTaskQueue,
    ) -> Result<(), RuntimeError> {
        let notification_id = pending.notification_id;
        let has_cached_attempt = self.wave_audio.pending_callbacks.iter().any(|source| {
            source.notification_id == notification_id
                && source.source == pending.source
                && source.post_attempt.is_some()
        });
        if !has_cached_attempt {
            let Some(current_queue) = self.ensure_user_queue(host)? else {
                self.defer_or_retire_wave_post_target(pending)?;
                return Ok(());
            };
            if current_queue != queue || !self.wave_task_queue_is_current(task, queue) {
                self.defer_or_retire_wave_post_target(pending)?;
                return Ok(());
            }
            let attempt = match self.post_wave_guest_notification(host, pending)? {
                WindowPostOutcome::Completed(false) => {
                    self.defer_or_retire_wave_post_target(pending)?;
                    return Ok(());
                }
                WindowPostOutcome::Completed(true) => {
                    return Err(wave_invariant(
                        "WAVE local USER route check cannot report an accepted post",
                    ));
                }
                WindowPostOutcome::StartedFailure(failure) => {
                    self.retain_wave_post_failure(
                        notification_id,
                        pending.source,
                        failure.clone(),
                    )?;
                    return Err(started_failure_error(
                        &failure,
                        "WAVE guest notification Begin failed after enqueue",
                    ));
                }
                WindowPostOutcome::SourceRetired(receipt) => {
                    WindowPostAttempt::SourceRetired(receipt)
                }
                WindowPostOutcome::Retained(attempt) => attempt,
            };
            self.retain_wave_post_attempt(notification_id, pending.source, attempt)?;
        }

        let posted_to_user = {
            let exact = self.wave_audio.pending_callbacks.iter().filter(|source| {
                source.notification_id == notification_id && source.source == pending.source
            }).count();
            if exact != 1 {
                return Err(wave_invariant("WAVE source identity is not unique"));
            }
            let source = self.wave_audio.pending_callbacks.iter_mut().find(|source| {
                source.notification_id == notification_id && source.source == pending.source
            }).ok_or_else(|| {
                wave_invariant("WAVE source disappeared before USER proof consumption")
            })?;
            let attempt = source.post_attempt.as_mut().ok_or_else(|| {
                wave_invariant("WAVE source lost its cached USER POST result")
            })?;
            consume_window_post_attempt(host, attempt)?
        };
        if !posted_to_user {
            self.cancel_pending_wave_notification(
                notification_id,
                WaveCallbackCancellationReason::UserPostRejected,
            )?;
            return Ok(());
        }
        let posted = self.wave_audio.pending_callbacks.pop_front().ok_or_else(|| {
            wave_invariant("WAVE notification disappeared after USER accepted it")
        })?;
        if posted.notification_id != notification_id || posted.source != pending.source {
            self.wave_audio.pending_callbacks.push_front(posted);
            return Err(wave_invariant("WAVE notification source changed after USER post"));
        }
        retire_posted_close(self, posted);
        Ok(())
    }

    fn defer_or_retire_wave_post_target(
        &mut self,
        pending: &PendingWaveCallback,
    ) -> Result<(), RuntimeError> {
        let retired = match pending.route {
            WaveCallbackRoute::Window { window, guest_hwnd, task, .. } => {
                !self.wave_task_identity_is_live(task)
                    || self.window_handles.get(&guest_hwnd) != Some(&window)
            }
            WaveCallbackRoute::Task { task, .. } => !self.wave_task_identity_is_live(task),
            WaveCallbackRoute::Function { .. } => {
                return Err(wave_invariant("WAVE function source entered USER post retry"));
            }
        };
        if retired {
            return self.cancel_pending_wave_notification(
                pending.notification_id,
                WaveCallbackCancellationReason::TargetRetired,
            );
        }
        let front = self.wave_audio.pending_callbacks.pop_front().ok_or_else(|| {
            wave_invariant("pending WAVE USER target disappeared during eligibility retry")
        })?;
        if front.notification_id != pending.notification_id || front.source != pending.source {
            self.wave_audio.pending_callbacks.push_front(front);
            return Err(wave_invariant(
                "WAVE USER eligibility retry changed its exact source row",
            ));
        }
        self.wave_audio.pending_callbacks.push_back(front);
        Ok(())
    }

    fn retain_wave_post_attempt(
        &mut self,
        notification_id: u64,
        source: crate::Win16GuestNotificationSource,
        attempt: WindowPostAttempt,
    ) -> Result<(), RuntimeError> {
        let mut matches = self.wave_audio.pending_callbacks.iter_mut().filter(|pending| {
            pending.notification_id == notification_id && pending.source == source
        });
        let pending = matches.next().ok_or_else(|| {
            wave_invariant("WAVE normal POST attempt lost its exact source row")
        })?;
        if matches.next().is_some()
            || !matches!(pending.route,
                WaveCallbackRoute::Window { .. } | WaveCallbackRoute::Task { .. })
            || pending.dispatch != WaveCallbackDispatchState::Available
            || pending.post_failure.is_some()
            || pending.post_attempt.is_some()
            || pending.terminal_ack.is_some()
            || pending.terminal_acknowledged
        {
            return Err(wave_invariant(
                "WAVE normal POST changed its exact source owner or retry phase",
            ));
        }
        pending.post_attempt = Some(attempt);
        Ok(())
    }

    fn retain_wave_post_failure(
        &mut self,
        notification_id: u64,
        source: crate::Win16GuestNotificationSource,
        failure: std::sync::Arc<crate::Win16WindowOperationStartedFailure>,
    ) -> Result<(), RuntimeError> {
        let mut matches = self.wave_audio.pending_callbacks.iter_mut().filter(|pending| {
            pending.notification_id == notification_id && pending.source == source
        });
        let pending = matches.next().ok_or_else(|| {
            wave_invariant("WAVE failed POST lost its exact pending source row")
        })?;
        if matches.next().is_some()
            || !matches!(pending.route,
                WaveCallbackRoute::Window { .. } | WaveCallbackRoute::Task { .. })
            || pending.dispatch != WaveCallbackDispatchState::Available
            || pending.post_failure.is_some()
            || pending.post_attempt.is_some()
            || pending.terminal_ack.is_some()
            || pending.terminal_acknowledged
        {
            return Err(wave_invariant(
                "WAVE failed POST changed its unique source owner or retry phase",
            ));
        }
        if failure.operation.operation_id.0 == 0
            || failure.worker_generation == 0
            || failure.operation.kind
                != crate::Win16NativeWindowOperationKind::PostGuestNotification
        {
            return Err(wave_invariant(
                "WAVE failed POST lacks a real typed USER operation identity",
            ));
        }
        pending.post_failure = Some(failure);
        Ok(())
    }
}

pub(super) fn retire_posted_close(state: &mut Win16State, pending: PendingWaveCallback) {
    if let Some(device) = state.wave_audio.devices.iter().find(|device| {
        device.host.0 == pending.source.id
            && device.generation == pending.source.generation
    }).map(|device| device.host) {
        state.retire_unprepared_wave_header_if_idle(
            device,
            pending.source.generation,
            pending.guest_handle,
            pending.header_far,
        );
    }
    if let Some(device) = pending.closed_device {
        state.retire_quiescent_wave_device_if_idle(device);
    }
}
