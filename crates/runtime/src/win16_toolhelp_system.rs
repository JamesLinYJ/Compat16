//! ToolHelp system-heap output requires real guest USER and GDI DGROUP heaps.
//! This runtime currently implements neither heap model.

use guest_core::memory::Memory;

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    /// `SYSHEAPINFO` exposes USER/GDI segment handles and free-resource
    /// percentages. Until those guest heaps exist, report the documented
    /// failure result and leave every byte of caller memory untouched.
    pub(super) fn toolhelp_system_heap_info(
        &self,
        _output: u32,
        _memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        Ok(0)
    }
}
