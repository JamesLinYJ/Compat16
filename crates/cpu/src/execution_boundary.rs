//! Decoder-independent progress at the CPU's existing execution seam.
//!
//! This is not a retirement counter, a runtime budget, or permission to enter
//! a callback. Checked continuations and opaque event tokens remain the only
//! authorities for those transitions.

use crate::CpuError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionProgress {
    /// No instruction attempt: for example a halted poll, a pending NMI, or
    /// a task-debug event handled before fetch. Event delivery may have effects.
    NoInstruction,
    /// Fetch, decode, or execution did not produce a successful body boundary.
    /// This does not imply rollback: REP iterations or a task switch may have
    /// committed effects before a fault, including one returned as an event.
    InstructionIncomplete,
    /// A successful REP boundary with further iterations pending. One boundary
    /// can execute multiple iterations; this is not an iteration count.
    RepeatPartial,
    /// The executor completed the instruction body, including a zero-count REP.
    /// Subsequent event delivery can still fail or restart a software INT, so
    /// this is not a guarantee of architectural retirement or boundary success.
    InstructionBodyCompleted,
}

impl ExecutionProgress {
    pub(crate) const fn after_repeat(unfinished: bool) -> Self {
        if unfinished { Self::RepeatPartial } else { Self::InstructionBodyCompleted }
    }
}

/// Keep progress even when post-execution event delivery returns an error.
/// The observed form carries the original opaque event without rebuilding it.
#[derive(Debug)]
pub(crate) struct ExecutionBoundaryReport<T> {
    pub(crate) progress: ExecutionProgress,
    pub(crate) outcome: Result<T, CpuError>,
}
