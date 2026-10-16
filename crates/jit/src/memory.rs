//! Pointer-free memory IR and bounded, caller-owned RAM execution windows.

use crate::compiler::{Compiler, MemoryFunction};
use crate::{
    ArtifactStore, Condition, Instruction, IntegerState, MAX_BLOCK_INSTRUCTIONS, Operand,
    Operation, Register, Statistics,
};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Address {
    pub(crate) base: Option<Register>,
    pub(crate) index: Option<Register>,
    pub(crate) shift: u8,
    pub(crate) displacement: u32,
    pub(crate) bits: u8,
}
impl Address {
    pub fn new(
        base: Option<Register>,
        index: Option<Register>,
        scale: u8,
        displacement: u32,
        bits: u8,
    ) -> Option<Self> {
        if !matches!(bits, 16 | 32)
            || !matches!(scale, 1 | 2 | 4 | 8)
            || [base, index]
                .into_iter()
                .flatten()
                .any(|r| r.high8 || r.bytes != bits / 8)
        {
            return None;
        }
        Some(Self {
            base,
            index,
            shift: scale.trailing_zeros() as u8,
            displacement,
            bits,
        })
    }
    pub fn offset(self, state: &IntegerState) -> u32 {
        let value = |r: Register| state.registers[r.index as usize] & r.mask();
        let offset = self
            .base
            .map_or(0, value)
            .wrapping_add(
                self.index
                    .map_or(0, value)
                    .wrapping_shl(u32::from(self.shift)),
            )
            .wrapping_add(self.displacement);
        if self.bits == 16 {
            offset & 0xffff
        } else {
            offset
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ValueOperand {
    Register(Register),
    Immediate(u32),
    Memory { address: Address, bytes: u8 },
}
impl ValueOperand {
    pub(crate) fn width(self) -> Option<u8> {
        match self {
            Self::Register(r) => Some(r.bytes),
            Self::Memory { bytes, .. } if matches!(bytes, 1 | 2 | 4) => Some(bytes),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MemoryInstruction {
    pub(crate) operation: Operation,
    pub(crate) destination: ValueOperand,
    pub(crate) source: ValueOperand,
    pub(crate) arithmetic: Instruction,
}
impl MemoryInstruction {
    pub fn new(
        operation: Operation,
        destination: ValueOperand,
        source: ValueOperand,
    ) -> Option<Self> {
        let memory_count = u8::from(matches!(destination, ValueOperand::Memory { .. }))
            + u8::from(matches!(source, ValueOperand::Memory { .. }));
        if memory_count != 1
            || matches!(operation, Operation::Exchange | Operation::ByteSwap)
            || matches!(destination, ValueOperand::Memory { .. })
                && matches!(
                    operation,
                    Operation::ZeroExtend | Operation::SignExtend | Operation::ConditionalMove(_)
                )
        {
            return None;
        }
        let dest_width = destination.width()?;
        let source_width = match source {
            ValueOperand::Immediate(_) => dest_width,
            _ => source.width()?,
        };
        let arithmetic = Instruction::new(
            operation,
            Register::new(0, dest_width, false)?,
            Operand::Register(Register::new(1, source_width, false)?),
        )?;
        Some(Self {
            operation,
            destination,
            source,
            arithmetic,
        })
    }
    pub fn address(self) -> Address {
        match (self.destination, self.source) {
            (ValueOperand::Memory { address, .. }, _)
            | (_, ValueOperand::Memory { address, .. }) => address,
            _ => unreachable!("constructor requires one memory operand"),
        }
    }
    pub fn writes(self) -> bool {
        matches!(self.destination, ValueOperand::Memory { .. })
            && !matches!(self.operation, Operation::Compare | Operation::Test)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BlockInstruction {
    Integer(Instruction),
    Memory(MemoryInstruction),
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MemoryLoop {
    pub(crate) instructions: Vec<BlockInstruction>,
    pub(crate) condition: Option<Condition>,
}
impl MemoryLoop {
    pub fn new(instructions: Vec<BlockInstruction>, condition: Option<Condition>) -> Option<Self> {
        (!instructions.is_empty()
            && instructions.len() <= MAX_BLOCK_INSTRUCTIONS
            && instructions
                .iter()
                .any(|i| matches!(i, BlockInstruction::Memory(_))))
        .then_some(Self {
            instructions,
            condition,
        })
    }
    pub fn first_memory(&self) -> MemoryInstruction {
        self.instructions
            .iter()
            .find_map(|i| match i {
                BlockInstruction::Memory(m) => Some(*m),
                _ => None,
            })
            .expect("constructor requires memory")
    }
    pub fn writes(&self) -> bool {
        self.instructions
            .iter()
            .any(|i| matches!(i,BlockInstruction::Memory(m) if m.writes()))
    }
    pub fn body_len(&self) -> usize {
        self.instructions.len()
    }
}
/// Offsets are guest logical offsets. Bytes belong to an exclusive Rust
/// buffer, never an unchecked mapping or a pointer supplied by guest code.
pub struct MemoryWindow<'a> {
    pub start: u32,
    pub bytes: &'a mut [u8],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryOutcome {
    pub retired: u32,
    pub next_instruction: u32,
}
enum Entry {
    Cold(u8),
    Compiled(MemoryFunction),
    Rejected,
}
#[derive(Default)]
pub struct MemoryLoopCache {
    compiler: Compiler,
    entries: HashMap<MemoryLoop, Entry>,
    last: Option<(MemoryLoop, MemoryFunction)>,
    statistics: Statistics,
}
impl MemoryLoopCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    /// Executes only in the owned window. A window miss or instruction budget
    /// returns before the next instruction, preserving every completed effect.
    /// The CPU owns permissions, publication and exact guest fault delivery.
    pub fn execute(
        &mut self,
        plan: &MemoryLoop,
        state: &mut IntegerState,
        window: MemoryWindow<'_>,
        budget: u32,
    ) -> Option<MemoryOutcome> {
        if budget == 0
            || window.bytes.is_empty()
            || window.bytes.len() > 4096
            || u64::from(window.start) + window.bytes.len() as u64 > u64::from(u32::MAX) + 1
        {
            return None;
        }
        let function = self.ready(plan)?;
        // SAFETY: Private code has exactly this signature. Every generated
        // access checks the offset and complete width before addressing this
        // exclusive live byte slice. Code/state owners cannot be freed during
        // the call, and instruction count is bounded independently of data.
        let packed = unsafe {
            function(
                state,
                window.bytes.as_mut_ptr(),
                window.start,
                window.bytes.len() as u32,
                budget.min(256),
            )
        };
        let result = MemoryOutcome {
            retired: (packed >> 32) as u32,
            next_instruction: packed as u32,
        };
        self.statistics.executed = self.statistics.executed.saturating_add(1);
        self.statistics.memory_loops_executed =
            self.statistics.memory_loops_executed.saturating_add(1);
        self.statistics.memory_instructions = self
            .statistics
            .memory_instructions
            .saturating_add(u64::from(result.retired));
        // Reconstruct guest branch outcomes from exact retirement; no
        // counters or host calls are inserted inside the generated loop.
        let per = plan.body_len() as u32 + 1;
        let fallthrough = u64::from(plan.condition.is_some() && result.next_instruction == per);
        self.statistics.branches_taken = self
            .statistics
            .branches_taken
            .saturating_add(u64::from(result.retired / per) - fallthrough);
        self.statistics.branches_fallthrough = self
            .statistics
            .branches_fallthrough
            .saturating_add(fallthrough);
        if result.next_instruction != per {
            if result.retired == budget.min(256) {
                self.statistics.budget_exits = self.statistics.budget_exits.saturating_add(1);
            } else {
                self.statistics.memory_window_exits =
                    self.statistics.memory_window_exits.saturating_add(1);
            }
        }
        Some(result)
    }
    fn ready(&mut self, plan: &MemoryLoop) -> Option<MemoryFunction> {
        // Repeated execution of one hot loop avoids hash-table probes and
        // reaches the same indirect target. Keys remain owned, and callers
        // still validate current guest code and permissions independently.
        if let Some((key, function)) = &self.last {
            if key == plan {
                self.statistics.loop_dispatch_hits =
                    self.statistics.loop_dispatch_hits.saturating_add(1);
                return Some(*function);
            }
        }
        if let Some(entry) = self.entries.get_mut(plan) {
            match entry {
                Entry::Compiled(f) => {
                    self.last = Some((plan.clone(), *f));
                    return Some(*f);
                }
                Entry::Rejected => return None,
                Entry::Cold(n) => {
                    *n = n.saturating_add(1);
                    if *n < 8 {
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
        match self.compiler.compile_memory_loop(plan) {
            Ok(code) => {
                *self.entries.get_mut(plan)? = Entry::Compiled(code.function);
                self.last = Some((plan.clone(), code.function));
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.memory_loops_compiled =
                    self.statistics.memory_loops_compiled.saturating_add(1);
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
                *self.entries.get_mut(plan)? = Entry::Rejected;
                self.statistics.failures = self.statistics.failures.saturating_add(1);
                None
            }
        }
    }
    fn clear(&mut self) {
        // Invalidate the direct dispatch before freeing any executable code.
        self.last = None;
        self.entries.clear();
        // SAFETY: Both dispatch paths are empty, and exclusive ownership excludes calls.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for MemoryLoopCache {
    fn drop(&mut self) {
        self.clear();
    }
}
