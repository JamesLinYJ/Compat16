//! Bounded linear x87 blocks. The owner certifies code, supplies an exclusive
//! RAM window, and retires the returned prefix. No guest pointers or callbacks
//! enter generated code. Register indices are relative to the entry TOP.
use crate::{
    ArtifactStore, Float80, FloatOperation, Statistics,
    compiler::{Compiler, FloatBlockFunction},
    floating::FloatPlan,
};
use std::{collections::HashMap, sync::Arc};
pub const MAX_FLOAT_BLOCK_INSTRUCTIONS: usize = 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FloatMemoryFormat {
    Binary32,
    Binary64,
}
impl FloatMemoryFormat {
    pub fn bytes(self) -> u8 {
        match self {
            Self::Binary32 => 4,
            Self::Binary64 => 8,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FloatInstruction {
    Binary {
        operation: FloatOperation,
        destination: u8,
        source: u8,
        reverse: bool,
        pop: bool,
    },
    Load80 {
        offset: u8,
    },
    LoadMemory {
        format: FloatMemoryFormat,
        offset: u8,
    },
    BinaryMemory {
        operation: FloatOperation,
        format: FloatMemoryFormat,
        offset: u8,
        reverse: bool,
    },
    Store80 {
        offset: u8,
        pop: bool,
    },
    LoadRegister(u8),
    StoreRegister {
        destination: u8,
        pop: bool,
    },
    Exchange(u8),
    One,
    Zero,
    Negate,
    Absolute,
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FloatBlock {
    // Immutable shared IR makes a dispatch-key clone allocation-free. An
    // unrelated equal block still uses structural equality, never identity alone.
    instructions: Arc<[FloatInstruction]>,
}
impl FloatBlock {
    pub fn new(instructions: Vec<FloatInstruction>) -> Option<Self> {
        if !(2..=MAX_FLOAT_BLOCK_INSTRUCTIONS).contains(&instructions.len())
            || instructions.iter().any(|i| match *i {
                FloatInstruction::Binary {
                    destination,
                    source,
                    ..
                } => destination >= 8 || source >= 8,
                FloatInstruction::LoadRegister(i) | FloatInstruction::Exchange(i) => i >= 8,
                FloatInstruction::StoreRegister { destination, .. } => destination >= 8,
                FloatInstruction::Load80 { offset } | FloatInstruction::Store80 { offset, .. } => {
                    offset > 246
                }
                FloatInstruction::LoadMemory { format, offset }
                | FloatInstruction::BinaryMemory { format, offset, .. } => {
                    u16::from(offset) + u16::from(format.bytes()) > 256
                }
                _ => false,
            })
        {
            return None;
        }
        Some(Self {
            instructions: instructions.into(),
        })
    }
    pub fn len(&self) -> usize {
        self.instructions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
    pub(crate) fn instructions(&self) -> &[FloatInstruction] {
        &self.instructions
    }
}
/// Values and tag pairs are indexed relative to the TOP at block entry.
/// Status retains its architectural TOP; returned values use the same entry
/// indexing, including payloads in slots that became empty after a pop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FloatRegisters {
    pub values: [Float80; 8],
    pub status: u16,
    pub tags: u16,
    pub control: u16,
}
#[repr(C)]
pub(crate) struct BlockState {
    pub words: [u64; 19],
}
#[derive(Clone, Copy)]
enum Entry {
    Cold(u8),
    Compiled(FloatBlockFunction),
    Rejected,
}
#[derive(Default)]
pub struct FloatBlockCache {
    compiler: Compiler,
    entries: HashMap<FloatBlock, [Entry; 12]>,
    last: Option<(FloatBlock, usize, FloatBlockFunction)>,
    statistics: Statistics,
}
impl FloatBlockCache {
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    pub fn set_artifact_store(&mut self, store: Option<Arc<dyn ArtifactStore>>) {
        self.compiler.store = store;
    }
    pub fn execute(
        &mut self,
        block: &FloatBlock,
        state: &mut FloatRegisters,
        memory: &mut [u8; 256],
        budget: u32,
    ) -> Option<u32> {
        if budget == 0 || state.status & !state.control & 0x3f != 0 {
            return None;
        }
        let (precision, pc) = match (state.control >> 8) & 3 {
            0 => (24, 0),
            2 => (53, 1),
            _ => (64, 2),
        };
        let rounding = ((state.control >> 10) & 3) as u8;
        let index = pc * 4 + usize::from(rounding);
        let function = self.ready(
            block,
            index,
            FloatPlan {
                operation: FloatOperation::Add,
                precision,
                rounding,
            },
        )?;
        let mut raw = BlockState { words: [0; 19] };
        for (i, value) in state.values.iter().enumerate() {
            raw.words[i * 2] = value.significand;
            raw.words[i * 2 + 1] = u64::from(value.sign_exponent);
        }
        raw.words[16] = u64::from(state.status);
        raw.words[17] = u64::from(state.tags);
        raw.words[18] = u64::from(state.control);
        // SAFETY: This signature accesses only these exclusive fixed-size
        // buffers. All RAM offsets are compile-time validated constants;
        // arithmetic is nontrapping and every exit publishes a bounded prefix.
        let retired = unsafe {
            function(
                &mut raw,
                memory.as_mut_ptr(),
                budget.min(block.len() as u32),
            )
        };
        for (i, value) in state.values.iter_mut().enumerate() {
            *value = Float80 {
                significand: raw.words[i * 2],
                sign_exponent: raw.words[i * 2 + 1] as u16,
            };
        }
        state.status = raw.words[16] as u16;
        state.tags = raw.words[17] as u16;
        self.statistics.float_blocks_executed =
            self.statistics.float_blocks_executed.saturating_add(1);
        self.statistics.float_block_instructions = self
            .statistics
            .float_block_instructions
            .saturating_add(u64::from(retired));
        self.statistics.float_executed = self
            .statistics
            .float_executed
            .saturating_add(u64::from(retired));
        self.statistics.executed = self.statistics.executed.saturating_add(u64::from(retired));
        if retired < budget.min(block.len() as u32) {
            self.statistics.float_fallbacks = self.statistics.float_fallbacks.saturating_add(1);
        }
        Some(retired)
    }
    fn ready(
        &mut self,
        block: &FloatBlock,
        index: usize,
        plan: FloatPlan,
    ) -> Option<FloatBlockFunction> {
        // The owned key and precision/rounding index identify this compiler's
        // private entry. Guest code/permissions remain the CPU owner's checks.
        if let Some((key, mode, function)) = &self.last
            && *mode == index
            && (Arc::ptr_eq(&key.instructions, &block.instructions) || key == block)
        {
            return Some(*function);
        }
        if let Some(entries) = self.entries.get_mut(block) {
            match entries[index] {
                Entry::Compiled(function) => {
                    self.last = Some((block.clone(), index, function));
                    return Some(function);
                }
                Entry::Rejected => return None,
                Entry::Cold(count) => {
                    let count = count + 1;
                    entries[index] = Entry::Cold(count);
                    if count < 8 {
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
            self.entries.insert(block.clone(), entries);
            return None;
        }
        match self.compiler.compile_float_block(block, plan) {
            Ok(code) => {
                self.entries.get_mut(block)?[index] = Entry::Compiled(code.function);
                self.last = Some((block.clone(), index, code.function));
                self.statistics.compiled = self.statistics.compiled.saturating_add(1);
                self.statistics.float_blocks_compiled =
                    self.statistics.float_blocks_compiled.saturating_add(1);
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
                self.entries.get_mut(block)?[index] = Entry::Rejected;
                self.statistics.failures = self.statistics.failures.saturating_add(1);
                None
            }
        }
    }
    fn clear(&mut self) {
        // Invalidate every dispatch path before releasing executable memory.
        self.last = None;
        self.entries.clear();
        // SAFETY: No pointer escapes; exclusive ownership excludes live calls.
        unsafe {
            self.compiler.clear();
        }
    }
}
impl Drop for FloatBlockCache {
    fn drop(&mut self) {
        self.clear();
    }
}
