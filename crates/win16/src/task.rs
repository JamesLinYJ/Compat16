use std::collections::BTreeMap;

use crate::{GlobalHeap, SelectorTable, Win16Error};
use guest_core::OwnerId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TaskState { Ready, Running, Suspended, Terminating, Exited }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskInfo {
    pub owner: OwnerId,
    pub parent: Option<OwnerId>,
    pub state: TaskState,
    pub exit_code: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Task {
    parent: Option<OwnerId>,
    state: TaskState,
    exit_code: Option<u16>,
    pending_events: u16,
}

/// Tracks task lifecycle and keeps at most one task in the Running state.
/// OwnerId values are not recycled by this registry.
#[derive(Debug, Default)]
pub struct TaskRegistry {
    tasks: BTreeMap<OwnerId, Task>,
    current: Option<OwnerId>,
}

impl TaskRegistry {
    pub fn new() -> Self { Self::default() }

    pub fn create(&mut self, owner: OwnerId, parent: Option<OwnerId>) -> Result<(), Win16Error> {
        if self.tasks.contains_key(&owner) { return Err(Win16Error::TaskAlreadyExists); }
        if let Some(parent) = parent {
            let parent_task = self.tasks.get(&parent).ok_or(Win16Error::UnknownTask)?;
            if matches!(parent_task.state, TaskState::Terminating | TaskState::Exited) {
                return Err(Win16Error::InvalidTaskState);
            }
        }
        self.tasks.insert(owner, Task {
            parent,
            state: TaskState::Ready,
            exit_code: None,
            pending_events: 0,
        });
        Ok(())
    }

    /// Switches to a ready task and returns the previous task to Ready.
    pub fn dispatch(&mut self, owner: OwnerId) -> Result<(), Win16Error> {
        let target = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        if self.current == Some(owner) {
            return if target.state == TaskState::Running { Ok(()) } else { Err(Win16Error::InvalidTaskState) };
        }
        if target.state != TaskState::Ready { return Err(Win16Error::InvalidTaskState); }
        if let Some(current) = self.current {
            let current_task = self.tasks.get(&current).ok_or(Win16Error::InvalidTaskState)?;
            if current_task.state != TaskState::Running { return Err(Win16Error::InvalidTaskState); }
        }
        if let Some(current) = self.current {
            self.tasks.get_mut(&current).ok_or(Win16Error::InvalidTaskState)?.state = TaskState::Ready;
        }
        self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?.state = TaskState::Running;
        self.current = Some(owner);
        Ok(())
    }

    pub fn suspend(&mut self, owner: OwnerId) -> Result<(), Win16Error> {
        let task = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        if task.state != TaskState::Running || self.current != Some(owner) {
            return Err(Win16Error::InvalidTaskState);
        }
        self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?.state = TaskState::Suspended;
        self.current = None;
        Ok(())
    }

    pub fn resume(&mut self, owner: OwnerId) -> Result<(), Win16Error> {
        let task = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        if task.state != TaskState::Suspended { return Err(Win16Error::InvalidTaskState); }
        self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?.state = TaskState::Ready;
        Ok(())
    }

    /// Marks a task terminating before reclaiming all of its global blocks. If
    /// cleanup detects an invariant error, the task remains non-dispatchable.
    pub fn terminate(
        &mut self,
        owner: OwnerId,
        exit_code: u16,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
    ) -> Result<usize, Win16Error> {
        let task = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        if task.state == TaskState::Exited { return Err(Win16Error::InvalidTaskState); }
        let task = self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?;
        task.state = TaskState::Terminating;
        task.pending_events = 0;
        if self.current == Some(owner) { self.current = None; }
        let freed = heap.free_owner(owner, selectors)?;
        let task = self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?;
        task.state = TaskState::Exited;
        task.exit_code = Some(exit_code);
        Ok(freed)
    }

    pub fn info(&self, owner: OwnerId) -> Result<TaskInfo, Win16Error> {
        let task = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        Ok(TaskInfo { owner, parent: task.parent, state: task.state, exit_code: task.exit_code })
    }

    pub fn current(&self) -> Option<OwnerId> { self.current }

    /// Returns the task's pending Win16 event count for syncing its task
    /// database representation.
    pub fn pending_events(&self, owner: OwnerId) -> Result<u16, Win16Error> {
        let task = self.tasks.get(&owner).ok_or(Win16Error::UnknownTask)?;
        Ok(task.pending_events)
    }

    /// Returns the current task's pending Win16 event count.
    pub fn current_pending_events(&self) -> Result<u16, Win16Error> {
        let owner = self.current.ok_or(Win16Error::InvalidTaskState)?;
        self.pending_events(owner)
    }

    /// Posts one Win16 task event. The target may be ready, running, or
    /// suspended; a terminated task cannot receive a new event.
    ///
    /// The Win16 task database represents its event count as a WORD. Saturate
    /// at that field's maximum rather than wrapping a pending event count back
    /// to zero and losing the wakeup condition.
    pub fn post_event(&mut self, owner: OwnerId) -> Result<(), Win16Error> {
        let task = self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?;
        if matches!(task.state, TaskState::Terminating | TaskState::Exited) {
            return Err(Win16Error::InvalidTaskState);
        }
        task.pending_events = task.pending_events.saturating_add(1);
        Ok(())
    }

    /// Posts one event to the currently running task, corresponding to a
    /// Win16 `PostEvent(0)` call.
    pub fn post_current_event(&mut self) -> Result<(), Win16Error> {
        let owner = self.current.ok_or(Win16Error::InvalidTaskState)?;
        self.post_event(owner)
    }

    /// Consumes one pending event from a live task without waiting. Returns
    /// `true` when an event was consumed and `false` when none was pending;
    /// the runtime is responsible for scheduling or blocking in the latter
    /// case.
    pub fn take_event(&mut self, owner: OwnerId) -> Result<bool, Win16Error> {
        let task = self.tasks.get_mut(&owner).ok_or(Win16Error::UnknownTask)?;
        if matches!(task.state, TaskState::Terminating | TaskState::Exited) {
            return Err(Win16Error::InvalidTaskState);
        }
        if task.pending_events == 0 {
            return Ok(false);
        }
        task.pending_events -= 1;
        Ok(true)
    }

    /// Consumes one event for the current task without blocking.
    pub fn take_current_event(&mut self) -> Result<bool, Win16Error> {
        let owner = self.current.ok_or(Win16Error::InvalidTaskState)?;
        self.take_event(owner)
    }

    pub fn live_count(&self) -> usize {
        self.tasks.values().filter(|task| task.state != TaskState::Exited).count()
    }
}
