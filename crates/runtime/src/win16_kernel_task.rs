//! KERNEL task queries over the live guest task registry.

use std::collections::BTreeMap;

use guest_core::{memory::Memory, OwnerId};
use win16_abi::{Access, WINDOWS_COMPATIBILITY_PROFILE};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// Guest task priority, queue word, lock, and last-error.
///
/// Every value is a guest word or owner identity. None of these fields is a
/// host pointer, and the stored priority does not select another task.
#[derive(Default)]
pub(super) struct TaskControls {
    priority: BTreeMap<OwnerId, i16>,
    queue: BTreeMap<OwnerId, u16>,
    locked_task: u16,
    last_error: BTreeMap<OwnerId, u32>,
}

/// Windows 3.1 scheduler priority range. Stored only; this runtime has one task.
const PRIORITY_MIN: i16 = -32;
const PRIORITY_MAX: i16 = 15;
/// `OSVERSIONINFO` byte count: five DWORDs plus a 128-byte CSD string.
const OSVERSIONINFO_BYTES: usize = 148;

impl Win16State {
    /// `GetCurrentPDB` returns the task's PDB handle in the low word and zero
    /// in the high word. The TDB installed by this runtime stores exactly the
    /// checked protected PDB selector there. The canonical DOS PSP keeps its
    /// real-mode address fields independently.
    pub(super) fn kernel_get_current_pdb(&self) -> u32 {
        u32::from(self.psp_selector.raw().0)
    }

    pub(super) fn kernel_get_num_tasks(&self) -> Result<u16, RuntimeError> {
        let mut count = 0_u16;
        for owner in self.task_handles.keys() {
            let Ok(info) = self.tasks.info(*owner) else { continue; };
            if !matches!(info.state, win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// There is one modeled Win16 task and its current instance data selector
    /// is the task's DS target (not its movable HINSTANCE handle).
    pub(super) fn kernel_get_task_ds(&self) -> u16 {
        self.instance_selector.raw().0
    }

    pub(super) fn kernel_is_task(&self, task_handle: u16) -> u16 {
        if task_handle == 0 { return 0; }
        let owner = self.task_handles.iter().find_map(|(owner, handle)| {
            (*handle == task_handle).then_some(*owner)
        });
        let Some(owner) = owner else { return 0; };
        match self.tasks.info(owner) {
            Ok(info) if !matches!(info.state,
                win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited) => 1,
            _ => 0,
        }
    }

    /// `SetPriority` adjusts a live task by a signed delta and clamps the
    /// result to -32..=15. An unknown handle is left unchanged. The value is
    /// recorded only; this runtime does not reorder tasks.
    pub(super) fn kernel_set_priority(
        &mut self, task: u16, delta: i16,
    ) -> Result<(), RuntimeError> {
        let Some(owner) = self.task_owner(task)? else { return Ok(()); };
        let current = i32::from(self.task_controls.priority.get(&owner).copied().unwrap_or(0));
        let adjusted = current.saturating_add(i32::from(delta))
            .clamp(i32::from(PRIORITY_MIN), i32::from(PRIORITY_MAX));
        self.task_controls.priority.insert(owner, adjusted as i16);
        Ok(())
    }

    /// Nonzero records the current HTASK and returns it. Zero clears the lock
    /// and returns zero. The lock is one handle, not a nested count.
    pub(super) fn kernel_lock_current_task(&mut self, lock: u16) -> Result<u16, RuntimeError> {
        if lock == 0 {
            self.task_controls.locked_task = 0;
            return Ok(0);
        }
        let current = self.current_task_handle()?;
        self.task_controls.locked_task = current;
        Ok(current)
    }

    /// Returns the locked HTASK while that task is still live, otherwise zero.
    pub(super) fn kernel_is_task_locked(&self) -> u16 {
        let locked = self.task_controls.locked_task;
        if self.kernel_is_task(locked) == 0 { 0 } else { locked }
    }

    /// Stores a guest HQUEUE word and returns the previous word. A zero task
    /// handle names the current task. An unknown handle returns zero.
    pub(super) fn kernel_set_task_queue(
        &mut self, task: u16, queue: u16,
    ) -> Result<u16, RuntimeError> {
        let Some(owner) = self.task_owner(task)? else { return Ok(0); };
        Ok(self.task_controls.queue.insert(owner, queue).unwrap_or(0))
    }

    pub(super) fn kernel_get_task_queue(&self, task: u16) -> Result<u16, RuntimeError> {
        let Some(owner) = self.task_owner(task)? else { return Ok(0); };
        Ok(self.task_controls.queue.get(&owner).copied().unwrap_or(0))
    }

    /// Queue word of the task that owns `segment`. The segment may be the
    /// task handle or the current instance DS. DS and ES themselves are not
    /// changed; the word is returned in AX.
    pub(super) fn kernel_task_queue_for_segment(
        &self, segment: u16,
    ) -> Result<u16, RuntimeError> {
        if segment == 0 { return Ok(0); }
        if self.kernel_is_task(segment) != 0 {
            return self.kernel_get_task_queue(segment);
        }
        if segment == self.instance_selector.raw().0 {
            return self.kernel_get_task_queue(0);
        }
        Ok(0)
    }

    /// `OldYield` asks the host to yield this thread. It does not switch to
    /// another guest task, because this runtime has only one.
    pub(super) fn kernel_old_yield(
        &mut self, host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        host.win16_yield_thread()
    }

    pub(super) fn kernel_set_last_error(&mut self, error: u32) -> Result<(), RuntimeError> {
        let owner = self.current_owner()?;
        self.task_controls.last_error.insert(owner, error);
        Ok(())
    }

    pub(super) fn kernel_get_last_error(&self) -> Result<u32, RuntimeError> {
        let owner = self.current_owner()?;
        Ok(self.task_controls.last_error.get(&owner).copied().unwrap_or(0))
    }

    /// `GetVersionEx` writes the same 3.10 identity `GetVersion` already
    /// reports. A null pointer or a size other than 148 returns FALSE and
    /// writes nothing. Build, platform id, and the CSD string stay zero.
    pub(super) fn kernel_get_version_ex(
        &self, version_info: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        if version_info == 0 { return Ok(0); }
        let pointer = self.selectors.pointer_from_far(version_info).map_err(|error| {
            crate::runtime_error(error).with_context("reading Win16 GetVersionEx version info")
        })?;
        let mut size_bytes = [0_u8; 4];
        self.selectors.read(memory, pointer, &mut size_bytes).map_err(|error| {
            crate::runtime_error(error).with_context("reading Win16 GetVersionEx structure size")
        })?;
        if u32::from_le_bytes(size_bytes) != OSVERSIONINFO_BYTES as u32 { return Ok(0); }
        let mut info = [0_u8; OSVERSIONINFO_BYTES];
        let profile = WINDOWS_COMPATIBILITY_PROFILE;
        info[0..4].copy_from_slice(&(OSVERSIONINFO_BYTES as u32).to_le_bytes());
        info[4..8].copy_from_slice(&u32::from(profile.major).to_le_bytes());
        info[8..12].copy_from_slice(&u32::from(profile.minor).to_le_bytes());
        self.selectors.translate(pointer, Access::Write, info.len(), memory).map_err(|error| {
            crate::runtime_error(error).with_context("writing Win16 GetVersionEx version info")
        })?;
        self.selectors.write(memory, pointer, &info).map_err(|error| {
            crate::runtime_error(error).with_context("writing Win16 GetVersionEx version info")
        })?;
        Ok(1)
    }

    /// Same honest limit as ToolHelp `TaskSwitch`: there is no second runnable
    /// task. Every handle, including null and the current task, returns 0.
    /// This does not call `Yield` or `OldYield`.
    pub(super) fn kernel_directed_yield(&self, _task: u16) -> u16 {
        0
    }

    fn current_owner(&self) -> Result<OwnerId, RuntimeError> {
        self.tasks.current().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 has no current task",
        ))
    }

    fn task_owner(&self, task: u16) -> Result<Option<OwnerId>, RuntimeError> {
        let handle = if task == 0 { self.current_task_handle()? } else { task };
        let owner = self.task_handles.iter().find_map(|(owner, candidate)| {
            (*candidate == handle).then_some(*owner)
        });
        Ok(owner.filter(|owner| self.live_owner(*owner)))
    }

    fn live_owner(&self, owner: OwnerId) -> bool {
        self.tasks.info(owner).is_ok_and(|info| !matches!(
            info.state,
            win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited,
        ))
    }
}

#[cfg(test)]
#[path = "win16_kernel_task_tests.rs"]
mod tests;
