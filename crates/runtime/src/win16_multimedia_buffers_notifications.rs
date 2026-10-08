//! Project WAVE completion records into exact USER sidecar notifications.

use super::*;
use super::super::window_post::{resolve_window_post_step, WindowPostOutcome};
use crate::{
    Win16GuestNotification, Win16GuestNotificationTarget, Win16WindowOperation,
};

impl Win16WaveState {
    pub(super) fn allocate_notification_id(&mut self) -> Result<u64, RuntimeError> {
        let identity = self.next_notification_id;
        self.next_notification_id = identity.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 WAVE notification identities are exhausted",
            )
        })?;
        if identity == 0 {
            return Err(wave_invariant("Win16 WAVE notification identity is zero"));
        }
        Ok(identity)
    }
}

fn wave_guest_notification(
    pending: &PendingWaveCallback,
) -> Result<Win16GuestNotification, RuntimeError> {
    let target = match pending.route {
        WaveCallbackRoute::Window { window, guest_hwnd, .. } => {
            Win16GuestNotificationTarget::Window { window, guest_hwnd }
        }
        WaveCallbackRoute::Task { task, queue } => Win16GuestNotificationTarget::Task {
            owner: task.owner,
            guest_htask: task.guest_htask,
            task_selector_generation: task.task_selector_generation,
            queue,
        },
        WaveCallbackRoute::Function { .. } => {
            return Err(wave_invariant(
                "Win16 FUNCTION callback was projected as a USER notification",
            ));
        }
    };
    Ok(Win16GuestNotification {
        target,
        source: pending.source,
        message: pending.message,
        w_param: pending.guest_handle,
        l_param: pending.header_far,
    })
}

impl Win16State {
    pub(super) fn post_wave_guest_notification(
        &self,
        host: &mut impl RuntimeHost,
        pending: &PendingWaveCallback,
    ) -> Result<WindowPostOutcome, RuntimeError> {
        if pending.post_failure.is_some() {
            return Err(wave_invariant(
                "WAVE notification retained a failed USER POST and cannot begin another",
            ));
        }
        if pending.post_attempt.is_some() {
            return Err(wave_invariant(
                "WAVE normal POST already has an exact retained attempt",
            ));
        }
        let notification = wave_guest_notification(pending)?;
        let route_is_current = match pending.route {
            WaveCallbackRoute::Window {
                window,
                guest_hwnd,
                task,
                queue,
            } => {
                self.wave_task_queue_is_current(task, queue)
                    && self.window_handles.get(&guest_hwnd) == Some(&window)
            }
            WaveCallbackRoute::Task { task, queue } => {
                self.wave_task_queue_is_current(task, queue)
            }
            WaveCallbackRoute::Function { .. } => false,
        };
        if !route_is_current {
            return Ok(WindowPostOutcome::Completed(false));
        }
        if !self.validate_guest_notification_target(notification.target) {
            return Ok(WindowPostOutcome::Completed(false));
        }
        let receipt_context = format!(
            "WAVE notification {} source {}:{}:{}",
            pending.notification_id,
            pending.source.id,
            pending.source.generation,
            pending.source.sequence,
        );
        let step = host
            .win16_window_begin(Win16WindowOperation::PostGuestNotification(notification))
            .map_err(|error| error.with_context(receipt_context.clone()))?;
        resolve_window_post_step(step).map_err(|error| error.with_context(receipt_context))
    }
}
