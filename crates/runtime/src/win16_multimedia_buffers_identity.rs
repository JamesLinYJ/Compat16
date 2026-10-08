//! Exact task and source receipt identities for WAVE callback dispatch.

use guest_core::OwnerId;

use super::Win16State;
use crate::{
    Win16GuestCallbackToken, Win16GuestNotificationSource, Win16HostTaskQueue, Win16HostWindow,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct WaveTaskIdentity {
    pub(in crate::win16_runtime) owner: OwnerId,
    pub(in crate::win16_runtime) guest_htask: u16,
    pub(in crate::win16_runtime) task_selector_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct WaveCallbackReceipt {
    pub(in crate::win16_runtime) notification_id: u64,
    pub(in crate::win16_runtime) source: Win16GuestNotificationSource,
    pub(in crate::win16_runtime) callback: Win16GuestCallbackToken,
    pub(in crate::win16_runtime) task: WaveTaskIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaveCallbackRoute {
    Function {
        callback: Win16GuestCallbackToken,
        task: WaveTaskIdentity,
    },
    Window {
        window: Win16HostWindow,
        guest_hwnd: u16,
        task: WaveTaskIdentity,
        queue: Win16HostTaskQueue,
    },
    Task {
        task: WaveTaskIdentity,
        queue: Win16HostTaskQueue,
    },
}

impl Win16State {
    pub(super) fn wave_task_identity_is_live(&self, task: WaveTaskIdentity) -> bool {
        self.tasks.info(task.owner).is_ok_and(|info| {
            !matches!(info.state,
                win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited)
        })
            && self.task_handles.get(&task.owner) == Some(&task.guest_htask)
            && self
                .selectors
                .reference(guest_core::Selector(task.guest_htask))
                .is_ok_and(|selector| {
                    selector.generation() == task.task_selector_generation
                })
    }

    pub(super) fn wave_task_queue_is_current(
        &self,
        task: WaveTaskIdentity,
        queue: Win16HostTaskQueue,
    ) -> bool {
        self.tasks.current() == Some(task.owner)
            && self.wave_task_identity_is_live(task)
            && self.user_task_queue
                == Some((
                    task.owner,
                    task.guest_htask,
                    task.task_selector_generation,
                    queue,
                ))
    }

    pub(super) fn unregister_wave_callback(&mut self, route: Option<WaveCallbackRoute>) {
        if let Some(WaveCallbackRoute::Function { callback, .. }) = route {
            // An active frame may defer removal. The scheduler records that
            // request in the retained registration and completes it after
            // the exact frame and any source-release receipt are gone.
            self.unregister_guest_callback(callback);
        }
    }
}
