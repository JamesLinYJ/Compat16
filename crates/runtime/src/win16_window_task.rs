//! USER.224 GetWindowTask, Windows 3.1 SDK Reference Vol. 2, p. 483.
//! Success returns HTASK; an unresolved window/task returns NULL.

use guest_core::memory::Memory;
use win16_abi::TaskState;

use super::{Win16State, runtime_arena_backing::RuntimeArenaChunkKind};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16WindowEnumerationQuery as Query, Win16WindowEnumerationReply as Reply};

impl Win16State {
    pub(super) fn get_window_task(
        &self,
        window: u16,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if window == 0 { return Ok(0); }
        let Some(&native) = self.window_handles.get(&window) else { return Ok(0); };
        let Some((owner, task, generation, queue)) = self.user_task_queue else { return Ok(0); };
        if task == 0 || self.task_handles.get(&owner) != Some(&task) {
            return Ok(0);
        }
        let Ok(info) = self.tasks.info(owner) else { return Ok(0); };
        if matches!(info.state, TaskState::Terminating | TaskState::Exited) {
            return Ok(0);
        }
        // Retain the original TDB generation; resolving only its raw selector
        // could mistake a later allocation for the original window's task.
        let Some(identity) = self.runtime_arena_backing.identities().find(|identity|
            identity.kind == RuntimeArenaChunkKind::TaskDatabase
                && identity.primary.raw().0 == task
                && identity.primary.generation() == generation)
        else { return Ok(0); };
        if !self.runtime_arena_backing.identity_is_live(identity, &self.selectors, memory)? {
            return Ok(0);
        }
        // This runtime models one immutable task binding per native USER
        // worker. The host proves the exact live same-worker HWND cookie and
        // active queue, including borrowed aliases for our dialog controls.
        // A foreign window has no guest queue. Never create/rebind a queue or
        // substitute the currently scheduled task during this read-only call.
        match host.win16_window_enumeration(Query::TaskQueue(native))? {
            Reply::TaskQueue(Some(actual)) if actual == queue => Ok(task),
            Reply::TaskQueue(_) => Ok(0),
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "GetWindowTask host query returned an unrelated window reply")),
        }
    }
}

#[cfg(test)]
#[path = "win16_window_task_tests.rs"]
mod tests;
