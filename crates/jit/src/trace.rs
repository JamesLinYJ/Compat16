//! Multi-instruction prediction with a separately checked commit per step.

use crate::{
    ArtifactStore, CodeCache, Instruction, IntegerState, MAX_BLOCK_INSTRUCTIONS, Statistics,
};
use std::{collections::HashMap, sync::Arc};

/// Opaque caller locations, never host pointers. The caller validates its
/// current instruction before offering a location and semantic operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TraceSite {
    pub current: u64,
    pub next: u64,
}

#[derive(Clone)]
struct Plan {
    sites: Vec<TraceSite>,
    instructions: Vec<Instruction>,
}
struct Pending {
    plan: Arc<Plan>,
    index: usize,
}
#[derive(Default)]
pub struct TraceEngine {
    cache: CodeCache,
    plans: HashMap<u64, Arc<Plan>>,
    recording: Vec<(TraceSite, Instruction)>,
    pending: Option<Pending>,
    checkpoints: [IntegerState; MAX_BLOCK_INSTRUCTIONS],
}
impl TraceEngine {
    pub fn statistics(&self) -> Statistics {
        self.cache.statistics()
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.cache.set_artifact_store(store);
    }
    pub fn artifact_store(&self) -> Option<Arc<dyn ArtifactStore>> {
        self.cache.artifact_store()
    }
    pub fn set_enabled(&mut self, enabled: bool) {
        self.barrier();
        self.cache.set_enabled(enabled);
    }
    /// An unsupported instruction, callback, transfer or other caller boundary
    /// must not join two observations into a straight-line trace.
    pub fn barrier(&mut self) {
        self.finish_recording();
        self.invalidate_pending();
    }
    fn invalidate_pending(&mut self) {
        if self.pending.take().is_some() {
            self.cache.statistics.block_invalidations =
                self.cache.statistics.block_invalidations.saturating_add(1);
        }
    }
    fn finish_recording(&mut self) {
        if self.recording.len() >= 2 {
            let first = self.recording[0].0.current;
            if self.plans.len() == 1024 && !self.plans.contains_key(&first) {
                self.plans.clear();
            }
            if self.plans.try_reserve(1).is_ok() {
                self.plans.insert(
                    first,
                    Arc::new(Plan {
                        sites: self.recording.iter().map(|item| item.0).collect(),
                        instructions: self.recording.iter().map(|item| item.1).collect(),
                    }),
                );
            }
        }
        self.recording.clear();
    }
    fn record(&mut self, site: TraceSite, instruction: Instruction) {
        if self
            .recording
            .last()
            .is_some_and(|(previous, _)| previous.next != site.current)
        {
            self.finish_recording();
        }
        if self.recording.try_reserve(1).is_ok() {
            self.recording.push((site, instruction));
        }
        if self.recording.len() == MAX_BLOCK_INSTRUCTIONS {
            self.finish_recording();
        }
    }
    /// Compute several register-only operations once, then expose exactly one
    /// checked checkpoint. Future computations have no guest side effects.
    /// Rewritten code, changed input state or control flow discards the tail.
    #[inline]
    pub fn execute(
        &mut self,
        site: TraceSite,
        instruction: Instruction,
        state: &mut IntegerState,
    ) -> bool {
        if !self.cache.enabled {
            return false;
        }
        if let Some(pending) = self.pending.as_mut() {
            let index = pending.index;
            if pending.plan.sites[index] == site
                && pending.plan.instructions[index] == instruction
                && self.checkpoints[index - 1] == *state
            {
                *state = self.checkpoints[index];
                pending.index += 1;
                if pending.index == pending.plan.instructions.len() {
                    self.pending = None;
                }
                self.cache.statistics.checkpoint_hits =
                    self.cache.statistics.checkpoint_hits.saturating_add(1);
                return true;
            }
            self.invalidate_pending();
        }
        self.execute_head(site, instruction, state)
    }

    // Keep compilation, map lookups and recording out of the checkpoint hit
    // path so cross-crate inlining need not pull the cold compiler machinery
    // into every CPU boundary.
    fn execute_head(
        &mut self,
        site: TraceSite,
        instruction: Instruction,
        state: &mut IntegerState,
    ) -> bool {
        if let Some(plan) = self
            .plans
            .get(&site.current)
            .filter(|plan| plan.sites[0] == site && plan.instructions[0] == instruction)
            .cloned()
        {
            let mut scratch = *state;
            if self
                .cache
                .execute_block(&plan.instructions, &mut scratch, &mut self.checkpoints)
            {
                self.recording.clear();
                *state = self.checkpoints[0];
                self.pending = Some(Pending { plan, index: 1 });
                return true;
            }
        }
        self.record(site, instruction);
        self.cache.execute(instruction, state)
    }
    pub fn execute_with<E>(
        &mut self,
        instruction: Instruction,
        input: impl FnOnce() -> Result<IntegerState, E>,
    ) -> Result<Option<IntegerState>, E> {
        self.barrier();
        self.cache.execute_with(instruction, input)
    }
}
