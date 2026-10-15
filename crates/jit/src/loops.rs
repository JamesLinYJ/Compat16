//! Budgeted compiled loops over pure integer IR; no guest or host services.

use crate::compiler::{Compiler, LoopFunction};
use crate::{
    ArtifactStore, Condition, Instruction, IntegerState, MAX_BLOCK_INSTRUCTIONS, Statistics,
};
use std::{collections::HashMap, sync::Arc};

/// A loop iteration ends with a conditional backedge, or an unconditional
/// backedge when `condition` is None. Locations and instruction retirement
/// belong to the caller, not this independent compiler module.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IntegerLoop {
    instructions: Vec<Instruction>,
    condition: Option<Condition>,
}
impl IntegerLoop {
    pub fn new(instructions: Vec<Instruction>, condition: Option<Condition>) -> Option<Self> {
        (!instructions.is_empty() && instructions.len() <= MAX_BLOCK_INSTRUCTIONS).then_some(Self {
            instructions,
            condition,
        })
    }
    pub fn body_len(&self) -> usize {
        self.instructions.len()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopOutcome {
    pub iterations: u32,
    pub backedge_taken: bool,
}
enum Entry {
    Cold(u8),
    Compiled(LoopFunction),
    Rejected,
}
#[derive(Default)]
pub struct LoopCache {
    compiler: Compiler,
    entries: HashMap<IntegerLoop, Entry>,
    statistics: Statistics,
}
impl LoopCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    /// The owner must guard the complete code span and exclude events for this
    /// quantum. Cold/invalid requests leave state unchanged. Every generated-code call
    /// has a finite cap even when a guest backedge is unconditional.
    pub fn execute(
        &mut self,
        plan: &IntegerLoop,
        state: &mut IntegerState,
        max_iterations: u32,
    ) -> Option<LoopOutcome> {
        if max_iterations == 0 {
            return None;
        }
        let function = self.ready(plan)?;
        let budget = max_iterations.min(4096);
        // SAFETY: Signature and IntegerState layout match loop emission. The
        // function accesses only this exclusive state and terminates within
        // budget; the private owning module stays live throughout this call.
        let result = unsafe { function(state, budget) };
        let outcome = LoopOutcome {
            iterations: (result >> 1) as u32,
            backedge_taken: result & 1 != 0,
        };
        self.statistics.executed = self.statistics.executed.saturating_add(1);
        self.statistics.loops_executed = self.statistics.loops_executed.saturating_add(1);
        self.statistics.loop_iterations = self
            .statistics
            .loop_iterations
            .saturating_add(u64::from(outcome.iterations));
        Some(outcome)
    }
    fn ready(&mut self, plan: &IntegerLoop) -> Option<LoopFunction> {
        if let Some(entry) = self.entries.get_mut(plan) {
            match entry {
                Entry::Compiled(function) => return Some(*function),
                Entry::Rejected => return None,
                Entry::Cold(count) => {
                    *count = count.saturating_add(1);
                    if *count < 8 {
                        return None;
                    }
                }
            }
        } else {
            if self.entries.len() == 1024 {
                self.clear();
                self.statistics.cache_resets = self.statistics.cache_resets.saturating_add(1);
            }
            self.entries.try_reserve(1).ok()?;
            self.entries.insert(plan.clone(), Entry::Cold(1));
            return None;
        }
        match self
            .compiler
            .compile_loop(&plan.instructions, plan.condition)
        {
            Ok(compiled) => {
                *self.entries.get_mut(plan)? = Entry::Compiled(compiled.function);
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.loops_compiled = self.statistics.loops_compiled.saturating_add(1);
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
                *self.entries.get_mut(plan)? = Entry::Rejected;
                self.statistics.failures = self.statistics.failures.saturating_add(1);
                None
            }
        }
    }
    fn clear(&mut self) {
        self.entries.clear();
        // SAFETY: Exclusive ownership and cleared entries exclude live calls.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for LoopCache {
    fn drop(&mut self) {
        self.clear();
    }
}
