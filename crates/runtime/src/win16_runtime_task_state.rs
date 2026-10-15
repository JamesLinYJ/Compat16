//! Checked task-event routing and the guest-visible task event counter.

use guest_core::{memory::Memory, GuestMemory, OwnerId};
#[cfg(test)]
use guest_core::Selector;
use win16_abi::{Access, SegmentedPointer, TaskState, TASK_EVENT_COUNT_OFFSET};

use super::{Win16State, runtime_arena_backing::{RuntimeArenaChunkKind, RuntimeArenaBackingIdentity}};
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone, Copy)]
pub(super) struct TaskEventTarget {
    pub owner: OwnerId,
    handle: u16,
    backing: RuntimeArenaBackingIdentity,
}

impl Win16State {
    pub(super) fn post_task_event(
        &mut self,
        requested: u16,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let target = self.task_event_target(requested, memory)?;
        let owner = target.owner;
        let identity = target.backing;
        let pointer = SegmentedPointer::new(identity.primary, TASK_EVENT_COUNT_OFFSET as u16);
        let address = self.selectors.translate(pointer, Access::Write, 2, memory)
            .map_err(crate::runtime_error)?;
        // This routing change preserves the existing saturated counter and
        // Void-return policies; it does not establish exact legacy parity.
        let next = self.tasks.pending_events(owner).map_err(crate::runtime_error)?
            .saturating_add(1);
        // Native storage can fail even after preflight. Publish no registry
        // increment on failure, and never attempt to roll back a partial write.
        memory.write(address, &next.to_le_bytes()).map_err(crate::runtime_error)?;
        // The validated task cannot change during this exclusive, non-yielding
        // operation. After the successful write, this commit is infallible.
        self.tasks.post_event(owner).map_err(crate::runtime_error)
    }

    pub(super) fn task_event_target(
        &self, requested: u16, memory: &Memory,
    ) -> Result<TaskEventTarget, RuntimeError> {
        let handle = if requested == 0 { self.current_task_handle()? } else { requested };
        let invalid = || RuntimeError::new(Kind::GuestFault,
            format!("Win16 event task handle 0x{handle:04X} has no live task database"));
        let owner = self.task_handles.iter().find_map(|(&owner, &registered)|
            (registered == handle).then_some(owner)).ok_or_else(invalid)?;
        let info = self.tasks.info(owner).map_err(|_| invalid())?;
        if matches!(info.state, TaskState::Terminating | TaskState::Exited) { return Err(invalid()); }
        let backing = self.runtime_arena_backing.identities().find(|identity|
            identity.kind == RuntimeArenaChunkKind::TaskDatabase
                && identity.primary.raw().0 == handle).ok_or_else(invalid)?;
        if !self.runtime_arena_backing.identity_is_live(backing, &self.selectors, memory)? {
            return Err(invalid());
        }
        Ok(TaskEventTarget { owner, handle, backing })
    }

    /// Publication precedes registry mutation, including while returning from
    /// a suspended WaitEvent. A failed native write never consumes the token.
    pub(super) fn take_task_event(
        &mut self, target: TaskEventTarget, memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let actual = self.task_event_target(target.handle, memory)?;
        if actual.owner != target.owner || actual.backing != target.backing {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 event wait target changed its owner or task database incarnation"));
        }
        let count = self.tasks.pending_events(target.owner).map_err(crate::runtime_error)?;
        let Some(next) = count.checked_sub(1) else { return Ok(false); };
        let pointer = SegmentedPointer::new(target.backing.primary, TASK_EVENT_COUNT_OFFSET as u16);
        let address = self.selectors.translate(pointer, Access::Write, 2, memory)
            .map_err(crate::runtime_error)?;
        memory.write(address, &next.to_le_bytes()).map_err(crate::runtime_error)?;
        if !self.tasks.take_event(target.owner).map_err(crate::runtime_error)? {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 event count changed during an exclusive counter publication"));
        }
        Ok(true)
    }

    pub(super) fn current_task_handle(&self) -> Result<u16, RuntimeError> {
        let owner = self.tasks.current().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "Win16 has no current task")
        })?;
        self.task_handles.get(&owner).copied().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 current task has no guest handle",
            )
        })
    }

    #[cfg(test)]
    pub(super) fn sync_task_event_count(&self, memory: &mut Memory) -> Result<(), RuntimeError> {
        let handle = self.current_task_handle()?;
        let pointer = self
            .selectors
            .pointer_from_raw(Selector(handle), TASK_EVENT_COUNT_OFFSET as u16)
            .map_err(crate::runtime_error)?;
        let count = self
            .tasks
            .current_pending_events()
            .map_err(crate::runtime_error)?;
        self.selectors
            .write(memory, pointer, &count.to_le_bytes())
            .map_err(crate::runtime_error)
    }
}

#[cfg(test)]
#[path = "win16_runtime_task_state_tests.rs"]
mod tests;
