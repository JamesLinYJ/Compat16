//! Independent compiled integer blocks with checked state and cache ownership.
//!
//! Generated code touches only owned integer state, checkpoints and bounded RAM windows. CPU
//! decoding, guest memory, exception delivery and retirement remain outside.

mod artifact;
mod compiler;
mod float_block_lowering;
#[cfg(test)]
mod float_block_tests;
mod float_blocks;
mod float_lowering;
#[cfg(test)]
mod float_tests;
mod floating;
pub use float_blocks::{
    FloatBlock, FloatBlockCache, FloatInstruction, FloatMemoryFormat, FloatRegisters,
    MAX_FLOAT_BLOCK_INSTRUCTIONS,
};
pub use floating::{Float80, FloatCache, FloatOperation, FloatResult};
mod ir;
mod loops;
mod memory;
mod memory_lowering;
mod region_lowering;
#[cfg(test)]
mod region_tests;
mod regions;
pub use memory::{
    Address, BlockInstruction, MemoryInstruction, MemoryLoop, MemoryLoopCache, MemoryOutcome,
    MemoryWindow, ValueOperand,
};
pub use regions::{
    MAX_REGION_BLOCKS, MAX_REGION_INSTRUCTIONS, Region, RegionBlock, RegionBranch, RegionCache,
    RegionOutcome, RegionPosition, RegionTarget,
};
mod lowering;
pub use loops::{IntegerLoop, LoopCache, LoopOutcome};
#[cfg(test)]
mod memory_tests;
#[cfg(test)]
mod tests;
mod trace;

pub use artifact::{Artifact, ArtifactStore, MAX_ARTIFACT_BYTES};
use compiler::{Compiler, Function};
pub use ir::{Condition, Instruction, IntegerState, Operand, Operation, Register};
use std::{collections::HashMap, sync::Arc};
pub use trace::{TraceEngine, TraceSite};

pub const MAX_BLOCK_INSTRUCTIONS: usize = 16;
const HOT_THRESHOLD: u8 = 32;
const MAX_ENTRIES: usize = 1024;

#[derive(Default, Clone, Copy, Debug)]
pub struct Statistics {
    pub float_blocks_compiled: u64,
    pub float_blocks_executed: u64,
    pub float_block_instructions: u64,
    pub float_compiled: u64,
    pub float_executed: u64,
    pub float_fallbacks: u64,
    pub regions_compiled: u64,
    pub regions_executed: u64,
    pub region_instructions: u64,
    pub direct_links: u64,
    pub branches_taken: u64,
    pub branches_fallthrough: u64,
    pub budget_exits: u64,
    pub memory_window_exits: u64,
    pub loop_dispatch_hits: u64,

    pub memory_loops_compiled: u64,
    pub memory_loops_executed: u64,
    pub memory_instructions: u64,
    pub loops_compiled: u64,
    pub loops_executed: u64,
    pub loop_iterations: u64,
    pub compiled: u64,
    pub executed: u64,
    pub failures: u64,
    pub cache_resets: u64,
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub checkpoint_hits: u64,
    pub block_invalidations: u64,
    pub persistent_hits: u64,
    pub persistent_writes: u64,
}
impl Statistics {
    pub fn combined(self, other: Self) -> Self {
        Self {
            float_blocks_compiled: self
                .float_blocks_compiled
                .saturating_add(other.float_blocks_compiled),
            float_blocks_executed: self
                .float_blocks_executed
                .saturating_add(other.float_blocks_executed),
            float_block_instructions: self
                .float_block_instructions
                .saturating_add(other.float_block_instructions),
            float_compiled: self.float_compiled.saturating_add(other.float_compiled),
            float_executed: self.float_executed.saturating_add(other.float_executed),
            float_fallbacks: self.float_fallbacks.saturating_add(other.float_fallbacks),
            regions_compiled: self.regions_compiled.saturating_add(other.regions_compiled),
            regions_executed: self.regions_executed.saturating_add(other.regions_executed),
            region_instructions: self
                .region_instructions
                .saturating_add(other.region_instructions),
            direct_links: self.direct_links.saturating_add(other.direct_links),
            branches_taken: self.branches_taken.saturating_add(other.branches_taken),
            branches_fallthrough: self
                .branches_fallthrough
                .saturating_add(other.branches_fallthrough),
            budget_exits: self.budget_exits.saturating_add(other.budget_exits),
            memory_window_exits: self
                .memory_window_exits
                .saturating_add(other.memory_window_exits),
            loop_dispatch_hits: self
                .loop_dispatch_hits
                .saturating_add(other.loop_dispatch_hits),

            memory_loops_compiled: self
                .memory_loops_compiled
                .saturating_add(other.memory_loops_compiled),
            memory_loops_executed: self
                .memory_loops_executed
                .saturating_add(other.memory_loops_executed),
            memory_instructions: self
                .memory_instructions
                .saturating_add(other.memory_instructions),
            loops_compiled: self.loops_compiled.saturating_add(other.loops_compiled),
            loops_executed: self.loops_executed.saturating_add(other.loops_executed),
            loop_iterations: self.loop_iterations.saturating_add(other.loop_iterations),
            compiled: self.compiled.saturating_add(other.compiled),
            executed: self.executed.saturating_add(other.executed),
            failures: self.failures.saturating_add(other.failures),
            cache_resets: self.cache_resets.saturating_add(other.cache_resets),
            blocks_compiled: self.blocks_compiled.saturating_add(other.blocks_compiled),
            blocks_executed: self.blocks_executed.saturating_add(other.blocks_executed),
            checkpoint_hits: self.checkpoint_hits.saturating_add(other.checkpoint_hits),
            block_invalidations: self
                .block_invalidations
                .saturating_add(other.block_invalidations),
            persistent_hits: self.persistent_hits.saturating_add(other.persistent_hits),
            persistent_writes: self
                .persistent_writes
                .saturating_add(other.persistent_writes),
        }
    }
}
enum Entry {
    Cold(u8),
    Compiled(Function),
    Rejected,
}

/// Function pointers cannot escape. Exclusive calls prevent eviction/free
/// from racing execution. Cache providers return authenticated artifacts.
pub struct CodeCache {
    compiler: Compiler,
    entries: HashMap<Vec<Instruction>, Entry>,
    statistics: Statistics,
    enabled: bool,
}
impl Default for CodeCache {
    fn default() -> Self {
        Self {
            compiler: Compiler::default(),
            entries: HashMap::new(),
            statistics: Statistics::default(),
            enabled: true,
        }
    }
}
impl CodeCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    pub fn artifact_store(&self) -> Option<Arc<dyn ArtifactStore>> {
        self.compiler.store.clone()
    }
    pub fn execute(&mut self, instruction: Instruction, state: &mut IntegerState) -> bool {
        self.execute_block(&[instruction], state, &mut [IntegerState::default()])
    }
    /// Computes a complete pure-integer block and every intermediate state.
    /// Cold/disabled/failing paths leave state and checkpoints unchanged.
    /// Checkpoints grant no authority over guest instruction retirement.
    pub fn execute_block(
        &mut self,
        instructions: &[Instruction],
        state: &mut IntegerState,
        checkpoints: &mut [IntegerState],
    ) -> bool {
        if instructions.is_empty()
            || instructions.len() > MAX_BLOCK_INSTRUCTIONS
            || checkpoints.len() < instructions.len()
        {
            return false;
        }
        let Some(function) = self.ready(instructions) else {
            return false;
        };
        self.invoke(function, state, checkpoints);
        if instructions.len() > 1 {
            self.statistics.blocks_executed = self.statistics.blocks_executed.saturating_add(1);
        }
        true
    }
    /// Compilation/hotness precedes operand reads, preserving single device
    /// reads on interpreter fallback. Provider errors precede execution.
    pub fn execute_with<E>(
        &mut self,
        instruction: Instruction,
        input: impl FnOnce() -> Result<IntegerState, E>,
    ) -> Result<Option<IntegerState>, E> {
        let Some(function) = self.ready(&[instruction]) else {
            return Ok(None);
        };
        let mut state = input()?;
        self.invoke(function, &mut state, &mut [IntegerState::default()]);
        Ok(Some(state))
    }
    fn ready(&mut self, instructions: &[Instruction]) -> Option<Function> {
        if !self.enabled {
            return None;
        }
        if let Some(entry) = self.entries.get_mut(instructions) {
            match entry {
                Entry::Compiled(function) => return Some(*function),
                Entry::Rejected => return None,
                Entry::Cold(count) => {
                    *count = count.saturating_add(1);
                    let threshold = if instructions.len() > 1 {
                        2
                    } else {
                        HOT_THRESHOLD
                    };
                    if *count < threshold {
                        return None;
                    }
                }
            }
        } else {
            if self.entries.len() == MAX_ENTRIES {
                self.clear();
                self.statistics.cache_resets = self.statistics.cache_resets.saturating_add(1);
            }
            self.entries.try_reserve(1).ok()?;
            let mut key = Vec::new();
            key.try_reserve_exact(instructions.len()).ok()?;
            key.extend_from_slice(instructions);
            self.entries.insert(key, Entry::Cold(1));
            return None;
        }
        match self.compiler.compile(instructions) {
            Ok(compiled) => {
                *self.entries.get_mut(instructions)? = Entry::Compiled(compiled.function);
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.blocks_compiled = self
                    .statistics
                    .blocks_compiled
                    .saturating_add(u64::from(instructions.len() > 1));
                self.statistics.persistent_hits = self
                    .statistics
                    .persistent_hits
                    .saturating_add(u64::from(compiled.cache_hit));
                self.statistics.persistent_writes = self
                    .statistics
                    .persistent_writes
                    .saturating_add(compiled.cache_writes);
                Some(compiled.function)
            }
            Err(_) => {
                *self.entries.get_mut(instructions)? = Entry::Rejected;
                self.statistics.failures = self.statistics.failures.saturating_add(1);
                self.enabled = false;
                None
            }
        }
    }
    fn invoke(
        &mut self,
        function: Function,
        state: &mut IntegerState,
        checkpoints: &mut [IntegerState],
    ) {
        // SAFETY: The bounded block's exact C signature accesses only these
        // exclusive live buffers. Their lengths were checked before dispatch.
        // Generated arithmetic is nontrapping and has no guest side effects.
        // The owning module remains live and cannot be cleared during this call.
        unsafe {
            function(state, checkpoints.as_mut_ptr());
        }
        self.statistics.executed = self.statistics.executed.saturating_add(1);
    }
    fn clear(&mut self) {
        self.entries.clear();
        // SAFETY: No executable pointer escapes; all entries are gone, and &mut
        // self excludes an executing function, including during destruction.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for CodeCache {
    fn drop(&mut self) {
        self.clear();
    }
}
