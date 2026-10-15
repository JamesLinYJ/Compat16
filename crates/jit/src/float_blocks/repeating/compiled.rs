//! Private ownership and bounded specialization of combined floating loops.
use super::{FloatLoop, FloatLoopOutcome, FloatLoopPosition, FloatRegisters};
use crate::{
    ArtifactStore, FloatOperation, IntegerState, Statistics,
    compiler::{Compiler, FloatLoopFunction},
    floating::FloatPlan,
};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Copy)]
enum Entry {
    Cold(u8),
    Compiled(FloatLoopFunction),
    Rejected,
}
#[derive(Default)]
pub(in crate::float_blocks) struct Cache {
    compiler: Compiler,
    entries: HashMap<FloatLoop, [Entry; 12]>,
    last: Option<(FloatLoop, usize, FloatLoopFunction)>,
    statistics: Statistics,
}
impl Cache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    pub fn execute(
        &mut self,
        plan: &FloatLoop,
        floats: &mut FloatRegisters,
        integers: &mut IntegerState,
        memory: Option<&mut [u8; 256]>,
        budget: u32,
    ) -> Option<FloatLoopOutcome> {
        if budget == 0 || floats.status & !floats.control & 0x3f != 0 || floats.control & 0x20 == 0
        {
            return None;
        }
        let memory = match memory {
            Some(bytes) => bytes.as_mut_ptr(),
            None if !plan.body.memory => std::ptr::null_mut(),
            None => return None,
        };
        let (precision, pc) = match (floats.control >> 8) & 3 {
            0 => (24, 0),
            2 => (53, 1),
            _ => (64, 2),
        };
        let rounding = ((floats.control >> 10) & 3) as u8;
        let index = pc * 4 + usize::from(rounding);
        let function = self.ready(
            plan,
            index,
            FloatPlan {
                operation: FloatOperation::Add,
                precision,
                rounding,
            },
        )?;
        // SAFETY: The private function uses the repr(C) state layouts and
        // validated constant RAM offsets. The optional null window is allowed
        // only for memory-free IR. Every cycle spends a positive instruction
        // budget; masks and pending exceptions were checked above. All three
        // buffers are exclusive and this cache owns the live executable code.
        let result = unsafe { function(floats, integers, memory, budget.min(4096)) };
        let retired = result as u32;
        let prefix = (result >> 32) as usize;
        let finished = prefix == plan.body.len() + 1;
        let position = if finished {
            FloatLoopPosition::Finished
        } else if prefix == plan.body.len() {
            FloatLoopPosition::IntegerTail
        } else {
            FloatLoopPosition::Floating(prefix as u8)
        };
        let iterations = retired / plan.instructions_per_iteration();
        let partial = if finished { 0 } else { prefix };
        let float_count = u64::from(iterations) * plan.body.len() as u64 + partial as u64;
        self.statistics.executed = self
            .statistics
            .executed
            .saturating_add(float_count + u64::from(iterations));
        self.statistics.float_executed = self.statistics.float_executed.saturating_add(float_count);
        self.statistics.float_blocks_executed =
            self.statistics.float_blocks_executed.saturating_add(1);
        self.statistics.float_block_instructions = self
            .statistics
            .float_block_instructions
            .saturating_add(float_count);
        self.statistics.loops_executed = self.statistics.loops_executed.saturating_add(1);
        self.statistics.loop_iterations = self
            .statistics
            .loop_iterations
            .saturating_add(u64::from(iterations));
        self.statistics.branches_taken = self
            .statistics
            .branches_taken
            .saturating_add(u64::from(iterations) - u64::from(finished));
        self.statistics.branches_fallthrough = self
            .statistics
            .branches_fallthrough
            .saturating_add(u64::from(finished));
        self.statistics.budget_exits = self
            .statistics
            .budget_exits
            .saturating_add(u64::from(!finished && retired == budget.min(4096)));
        self.statistics.float_fallbacks = self.statistics.float_fallbacks.saturating_add(
            u64::from(!finished && prefix < plan.body.len() && retired < budget.min(4096)),
        );
        let last_float = if partial != 0 {
            partial - 1
        } else {
            plan.body.len() - 1
        };
        let last_memory = partial
            .checked_sub(1)
            .and_then(|i| plan.memory_prefix[i])
            .or_else(|| {
                (iterations != 0)
                    .then_some(plan.memory_prefix[plan.body.len() - 1])
                    .flatten()
            });
        Some(FloatLoopOutcome {
            retired,
            position,
            last_float: last_float as u8,
            last_memory,
        })
    }
    fn ready(
        &mut self,
        plan: &FloatLoop,
        index: usize,
        mode: FloatPlan,
    ) -> Option<FloatLoopFunction> {
        if let Some((key, pc, function)) = &self.last
            && *pc == index
            && key == plan
        {
            self.statistics.loop_dispatch_hits =
                self.statistics.loop_dispatch_hits.saturating_add(1);
            return Some(*function);
        }
        if let Some(entries) = self.entries.get_mut(plan) {
            match entries[index] {
                Entry::Compiled(function) => {
                    self.last = Some((plan.clone(), index, function));
                    return Some(function);
                }
                Entry::Rejected => return None,
                Entry::Cold(count) => {
                    entries[index] = Entry::Cold(count + 1);
                    if count < 7 {
                        return None;
                    }
                }
            }
        } else {
            if self.entries.len() == 256 {
                self.clear();
                self.statistics.cache_resets = self.statistics.cache_resets.saturating_add(1);
            }
            self.entries.try_reserve(1).ok()?;
            let mut entries = [Entry::Cold(0); 12];
            entries[index] = Entry::Cold(1);
            self.entries.insert(plan.clone(), entries);
            return None;
        }
        match self.compiler.compile_float_loop(plan, mode) {
            Ok(code) => {
                self.entries.get_mut(plan)?[index] = Entry::Compiled(code.function);
                self.last = Some((plan.clone(), index, code.function));
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.float_blocks_compiled =
                    self.statistics.float_blocks_compiled.saturating_add(1);
                self.statistics.loops_compiled = self.statistics.loops_compiled.saturating_add(1);
                self.statistics.persistent_hits = self
                    .statistics
                    .persistent_hits
                    .saturating_add(u64::from(code.cache_hit));
                self.statistics.persistent_writes = self
                    .statistics
                    .persistent_writes
                    .saturating_add(code.cache_writes);
                Some(code.function)
            }
            Err(_) => {
                self.entries.get_mut(plan)?[index] = Entry::Rejected;
                self.statistics.failures = self.statistics.failures.saturating_add(1);
                None
            }
        }
    }
    fn clear(&mut self) {
        self.last = None;
        self.entries.clear();
        // SAFETY: No function pointer escapes this exclusive cache owner.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for Cache {
    fn drop(&mut self) {
        self.clear();
    }
}
