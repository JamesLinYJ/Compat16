//! KERNEL task queries over the live guest task registry.

use super::Win16State;
use crate::RuntimeError;

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
}
