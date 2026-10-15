//! Bounded integer control-flow graphs. Links are private compiled branches;
//! guest addresses, fetching, permissions and retirement belong to the owner.

use crate::compiler::{Compiler, RegionFunction};
use crate::{
    ArtifactStore, Condition, Instruction, IntegerState, MAX_BLOCK_INSTRUCTIONS, Statistics,
};
use std::{collections::HashMap, sync::Arc};

pub const MAX_REGION_BLOCKS: usize = 16;
pub const MAX_REGION_INSTRUCTIONS: usize = 64;
const EXIT: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegionTarget {
    Block(u8),
    Exit(u8),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegionBranch {
    /// A sequential edge does not retire a guest branch instruction.
    Continue(RegionTarget),
    Jump(RegionTarget),
    Conditional {
        condition: Condition,
        taken: RegionTarget,
        fallthrough: RegionTarget,
        prefer_taken: bool,
    },
}
impl RegionBranch {
    pub(crate) fn retires(self) -> u32 {
        u32::from(!matches!(self, Self::Continue(_)))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RegionBlock {
    pub instructions: Vec<Instruction>,
    pub branch: RegionBranch,
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Region {
    pub(crate) blocks: Vec<RegionBlock>,
    exits: u8,
}
impl Region {
    pub fn new(blocks: Vec<RegionBlock>, exits: u8) -> Option<Self> {
        if blocks.is_empty() || blocks.len() > MAX_REGION_BLOCKS {
            return None;
        }
        let valid = |target: RegionTarget| match target {
            RegionTarget::Block(i) => usize::from(i) < blocks.len(),
            RegionTarget::Exit(i) => i < exits,
        };
        let mut count = 0;
        for block in &blocks {
            let cost = block.instructions.len() + block.branch.retires() as usize;
            // Every cycle consumes budget, including branch-only blocks.
            if cost == 0 || block.instructions.len() > MAX_BLOCK_INSTRUCTIONS {
                return None;
            }
            count += cost;
            if count > MAX_REGION_INSTRUCTIONS {
                return None;
            }
            match block.branch {
                RegionBranch::Continue(t) | RegionBranch::Jump(t) if valid(t) => {}
                RegionBranch::Conditional {
                    taken, fallthrough, ..
                } if valid(taken) && valid(fallthrough) => {}
                _ => return None,
            }
        }
        Some(Self { blocks, exits })
    }
    fn accepts(&self, position: RegionPosition) -> bool {
        match position {
            RegionPosition::Block { block, instruction } => self
                .blocks
                .get(usize::from(block))
                .is_some_and(|b| usize::from(instruction) <= b.instructions.len()),
            RegionPosition::Exit(_) => false,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionPosition {
    Block { block: u8, instruction: u8 },
    Exit(u8),
}
impl RegionPosition {
    pub(crate) fn encode(self) -> u32 {
        match self {
            Self::Block { block, instruction } => u32::from(block) * 32 + u32::from(instruction),
            Self::Exit(i) => EXIT | u32::from(i),
        }
    }
    fn decode(value: u32) -> Self {
        if value & EXIT != 0 {
            Self::Exit(value as u8)
        } else {
            Self::Block {
                block: (value / 32) as u8,
                instruction: (value % 32) as u8,
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionOutcome {
    pub retired: u32,
    pub next: RegionPosition,
}
enum Entry {
    Cold(u8),
    Compiled(RegionFunction),
    Rejected,
}
#[derive(Default)]
pub struct RegionCache {
    compiler: Compiler,
    entries: HashMap<Region, Entry>,
    last: Option<(Region, RegionFunction)>,
    statistics: Statistics,
}
impl RegionCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    /// The caller validates all linked code and excludes observable events for
    /// this quantum. Entry can resume any instruction, with exact prefix state.
    /// Cold, invalid and compilation-failure paths leave state unchanged.
    pub fn execute(
        &mut self,
        plan: &Region,
        state: &mut IntegerState,
        position: RegionPosition,
        max_instructions: u32,
    ) -> Option<RegionOutcome> {
        if max_instructions == 0 || !plan.accepts(position) {
            return None;
        }
        let function = self.ready(plan)?;
        let budget = max_instructions.min(256);
        let mut profile = 0u32;
        // SAFETY: Constructor-checked IR emits this exact C signature, touches
        // only the two exclusive owned outputs, and every cycle spends budget.
        // No executable pointer escapes; &mut self keeps its module live.
        let result = unsafe { function(state, budget, position.encode(), &mut profile) };
        let outcome = RegionOutcome {
            retired: (result >> 32) as u32,
            next: RegionPosition::decode(result as u32),
        };
        self.statistics.executed = self.statistics.executed.saturating_add(1);
        self.statistics.regions_executed = self.statistics.regions_executed.saturating_add(1);
        self.statistics.region_instructions = self
            .statistics
            .region_instructions
            .saturating_add(u64::from(outcome.retired));
        // Each counter fits ten bits: a call retires at most 256 instructions.
        self.statistics.direct_links = self
            .statistics
            .direct_links
            .saturating_add(u64::from(profile & 1023));
        self.statistics.branches_taken = self
            .statistics
            .branches_taken
            .saturating_add(u64::from((profile >> 10) & 1023));
        self.statistics.branches_fallthrough = self
            .statistics
            .branches_fallthrough
            .saturating_add(u64::from(profile >> 20));
        self.statistics.budget_exits =
            self.statistics
                .budget_exits
                .saturating_add(u64::from(matches!(
                    outcome.next,
                    RegionPosition::Block { .. }
                )));
        Some(outcome)
    }
    fn ready(&mut self, plan: &Region) -> Option<RegionFunction> {
        if let Some((key, function)) = &self.last
            && key == plan
        {
            return Some(*function);
        }
        if let Some(entry) = self.entries.get_mut(plan) {
            match entry {
                Entry::Compiled(function) => {
                    self.last = Some((plan.clone(), *function));
                    return Some(*function);
                }
                Entry::Rejected => return None,
                Entry::Cold(count) => {
                    *count += 1;
                    if *count < 8 {
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
            self.entries.insert(plan.clone(), Entry::Cold(1));
            return None;
        }
        match self.compiler.compile_region(plan) {
            Ok(compiled) => {
                *self.entries.get_mut(plan)? = Entry::Compiled(compiled.function);
                self.last = Some((plan.clone(), compiled.function));
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.regions_compiled =
                    self.statistics.regions_compiled.saturating_add(1);
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
        self.last = None;
        self.entries.clear();
        // SAFETY: All private entry pointers are gone; exclusive ownership
        // excludes an executing function, including during destruction.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for RegionCache {
    fn drop(&mut self) {
        self.clear();
    }
}
