//! Continue between compiled floating bodies and pure integer backedges
//! within one owner-certified quantum. No guest decoding or services enter
//! this module; a cold tail or short budget publishes the completed prefix.
use super::{FloatBlock, FloatBlockCache, FloatInstruction as I, FloatRegisters};
use crate::{IntegerLoop, IntegerState, LoopCache};

#[derive(Clone, Debug)]
pub struct FloatLoop {
    body: FloatBlock,
    tail: IntegerLoop,
    memory_prefix: [Option<u8>; crate::MAX_FLOAT_BLOCK_INSTRUCTIONS],
}
impl FloatLoop {
    pub fn instructions_per_iteration(&self) -> u32 {
        (self.body.len() + self.tail.body_len() + 1) as u32
    }
    pub fn new(body: FloatBlock, tail: IntegerLoop) -> Option<Self> {
        // Each body call uses the same entry-relative slot indexing. A net
        // TOP rotation would require rebasing values/tags between iterations.
        if body.access.rotation != 0 {
            return None;
        }
        let mut last = None;
        let memory_prefix = std::array::from_fn(|index| {
            if body.instructions().get(index).is_some_and(|i| {
                matches!(
                    i,
                    I::Load80 { .. }
                        | I::Store80 { .. }
                        | I::LoadMemory { .. }
                        | I::BinaryMemory { .. }
                )
            }) {
                last = Some(index as u8);
            }
            last
        });
        Some(Self {
            body,
            tail,
            memory_prefix,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatLoopPosition {
    Floating(u8),
    IntegerTail,
    Finished,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FloatLoopOutcome {
    pub retired: u32,
    pub position: FloatLoopPosition,
    pub last_float: u8,
    pub last_memory: Option<u8>,
}
impl FloatBlockCache {
    pub fn execute_loop(
        &mut self,
        plan: &FloatLoop,
        state: &mut FloatRegisters,
        integers: &mut IntegerState,
        tail_cache: &mut LoopCache,
        mut memory: Option<&mut [u8; 256]>,
        budget: u32,
    ) -> Option<FloatLoopOutcome> {
        let budget = budget.min(4096);
        let mut output = FloatLoopOutcome {
            retired: 0,
            position: FloatLoopPosition::Floating(0),
            last_float: 0,
            last_memory: None,
        };
        let tail_cost = plan.tail.body_len() as u32 + 1;
        while output.retired < budget {
            let remaining = budget - output.retired;
            let retired = match memory.as_deref_mut() {
                Some(bytes) => self.execute(&plan.body, state, bytes, remaining),
                None => self.execute_registers(&plan.body, state, remaining),
            }
            .unwrap_or(0);
            if retired != 0 {
                output.last_float = (retired - 1) as u8;
                if let Some(index) = plan.memory_prefix[retired as usize - 1] {
                    output.last_memory = Some(index);
                }
                output.retired += retired;
            }
            if retired < plan.body.len() as u32 {
                output.position = FloatLoopPosition::Floating(retired as u8);
                break;
            }
            output.position = FloatLoopPosition::IntegerTail;
            // Publish an unmasked x87 exception before any integer tail so
            // the CPU owner can deliver legacy IRQ13 at its normal boundary.
            if state.status & !state.control & 0x3f != 0 || budget - output.retired < tail_cost {
                break;
            }
            let Some(tail) = tail_cache.execute(&plan.tail, integers, 1) else {
                break;
            };
            debug_assert_eq!(tail.iterations, 1);
            output.retired += tail_cost;
            output.position = if tail.backedge_taken {
                FloatLoopPosition::Floating(0)
            } else {
                FloatLoopPosition::Finished
            };
            if !tail.backedge_taken {
                break;
            }
        }
        (output.retired != 0).then_some(output)
    }
}
