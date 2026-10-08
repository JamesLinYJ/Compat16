//! Exact guest-task identity captured for MIDI CALLBACK_TASK routing.

use guest_core::Selector;

use super::{Win16GuestTaskIdentity, Win16State};

impl Win16State {
    pub(super) fn midi_task_identity(&self, handle: u16) -> Option<Win16GuestTaskIdentity> {
        let (&owner, &registered_handle) = self.task_handles.iter()
            .find(|(_, registered)| **registered == handle)?;
        self.midi_task_identity_for(owner, registered_handle)
    }

    pub(super) fn current_midi_task_identity(&self) -> Option<Win16GuestTaskIdentity> {
        let owner = self.tasks.current()?;
        let handle = *self.task_handles.get(&owner)?;
        self.midi_task_identity_for(owner, handle)
    }

    pub(super) fn midi_task_identity_for(
        &self,
        owner: guest_core::OwnerId,
        handle: u16,
    ) -> Option<Win16GuestTaskIdentity> {
        let task = self.tasks.info(owner).ok()?;
        if matches!(task.state, win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited)
            || self.task_handles.get(&owner).copied() != Some(handle)
        {
            return None;
        }
        let selector = self.selectors.reference(Selector(handle)).ok()?;
        Some(Win16GuestTaskIdentity {
            owner,
            handle,
            selector_generation: selector.generation(),
        })
    }
}
