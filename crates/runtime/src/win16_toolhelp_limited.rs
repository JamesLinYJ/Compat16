//! Explicit failure for ToolHelp services whose guest model is not present.

use super::Win16State;

impl Win16State {
    /// TaskSetCSIP returns the previous packed CS:IP. Microsoft's XP NTVDM
    /// implementation explicitly returns DWORD zero for the current task;
    /// this single-task runtime has no suspended TDB context for other tasks.
    pub(super) fn toolhelp_task_set_csip_unavailable(&self) -> u32 {
        0
    }

    /// TaskSwitch reports BOOL failure because there is no second runnable
    /// Win16 task or saved architectural context to dispatch.
    pub(super) fn toolhelp_task_switch_unavailable(&self) -> u16 {
        0
    }
}
