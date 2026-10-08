//! Current-task handle resolution and the guest-visible task event counter.

use guest_core::{memory::Memory, Selector};
use win16_abi::TASK_EVENT_COUNT_OFFSET;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
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
