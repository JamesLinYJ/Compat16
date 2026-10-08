//! Checked guest task/PDB ownership projection for ToolHelp global entries.

use guest_core::{memory::Memory, OwnerId, Selector};
use win16_abi::{
    SegmentedPointer, TaskState, TASK_DATABASE_HSELF_OFFSET, TASK_DATABASE_HPDB_OFFSET,
    TASK_DATABASE_MAGIC, TASK_DATABASE_MAGIC_OFFSET,
};

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(super) fn pdb_owner(
        &self,
        owner: OwnerId,
        memory: &Memory,
    ) -> Result<(u16, bool), RuntimeError> {
        let Some(&task_handle) = self.task_handles.get(&owner) else { return Ok((0, false)); };
        let Ok(task_info) = self.tasks.info(owner) else { return Ok((0, false)); };
        if matches!(task_info.state, TaskState::Terminating | TaskState::Exited) {
            return Ok((0, false));
        }
        let task = self.selectors.reference(Selector(task_handle)).map_err(crate::runtime_error)?;
        let read_word = |offset: usize| -> Result<u16, RuntimeError> {
            let pointer = SegmentedPointer::new(task, offset as u16);
            let mut bytes = [0_u8; 2];
            self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
            Ok(u16::from_le_bytes(bytes))
        };
        if read_word(TASK_DATABASE_HSELF_OFFSET)? != task_handle
            || read_word(TASK_DATABASE_MAGIC_OFFSET)? != TASK_DATABASE_MAGIC
        {
            return Ok((0, false));
        }
        let pdb = read_word(TASK_DATABASE_HPDB_OFFSET)?;
        if pdb != self.psp_selector.raw().0
            || self.selectors.describe(self.psp_selector).is_err()
        {
            return Ok((0, false));
        }
        Ok((pdb, true))
    }

    /// Validate GF_PDB_OWNER from guest PDB identity, not allocator owner words.
    pub(super) fn guest_owner_is_pdb(&self, raw: u16, memory: &Memory) -> Result<bool, RuntimeError> {
        if raw == 0 { return Ok(false); }
        for &owner in self.task_handles.keys() {
            let (pdb, valid) = self.pdb_owner(owner, memory)?;
            if valid && pdb == raw { return Ok(true); }
        }
        Ok(false)
    }
}
