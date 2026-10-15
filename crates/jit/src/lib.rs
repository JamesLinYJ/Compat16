//! Independent native integer blocks with checked state and cache ownership.
//!
//! Generated code touches only owned IntegerState and checkpoint arrays. CPU
//! decoding, guest memory, exception delivery and retirement remain outside.

mod artifact;
mod compiler;
mod ir;
mod lowering;
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
        // SAFETY: No native pointer escapes; all entries are gone, and &mut
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
