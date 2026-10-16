//! Decode/certify linear floating blocks. All x87 architectural and guest
//! memory authority stays here; compat16-jit receives only raw owned state.
mod repeating;
use super::mapping;
use crate::{
    Cpu, CpuError, CpuModel, SegmentAccess, SegmentResolver,
    registers::{SegmentRegister, read_segment},
    x86_decode::{self, NormalizedInstruction, Operand},
    x87_state::Ext80,
};
use compat16_jit::{
    FloatBlock, FloatBlockCache, FloatInstruction as I, FloatMemoryFormat, FloatOperation as O,
    FloatRegisters,
};
use guest_core::{GuestMemory, PhysAddr};
use x86_decoder::{Mnemonic as M, Register};
#[derive(Clone, Copy)]
struct Site {
    ip: u32,
    opcode: u16,
    data: Option<u32>,
}
pub(super) struct Block {
    pub ir: FloatBlock,
    sites: Vec<Site>,
    next: u32,
    window: Option<(SegmentRegister, u32, bool)>,
    tail: Option<repeating::Tail>,
}
impl Block {
    pub fn decode(
        bytes: &[u8],
        ip: u32,
        bits: u32,
        protected: bool,
        model: CpuModel,
    ) -> Option<(Self, usize)> {
        let mut cursor = 0;
        let mut instructions = Vec::new();
        let mut sites = Vec::new();
        let mut window = None;
        while instructions.len() < compat16_jit::MAX_FLOAT_BLOCK_INSTRUCTIONS
            && cursor < bytes.len()
        {
            let Some(decoded) =
                x86_decode::decode_plain(&bytes[cursor..], ip + cursor as u32, bits, protected)
            else {
                break;
            };
            if !decoded.is_x87()
                || !model.supports_instruction_features(decoded.required_cpu_features())
                || decoded.instruction.has_lock_prefix()
                || decoded.next_ip <= decoded.start_ip
            {
                break;
            }
            let n = NormalizedInstruction::new(decoded);
            let memory = n.operands[..usize::from(n.operand_count)]
                .iter()
                .find_map(|o| {
                    if let Operand::Memory(mem) = o {
                        Some(*mem)
                    } else {
                        None
                    }
                });
            let mut data = None;
            let instruction = if let Some(mem) = memory {
                if mem.base != Register::None || mem.index != Register::None {
                    break;
                }
                let format = match n.memory_width {
                    4 => Some(FloatMemoryFormat::Binary32),
                    8 => Some(FloatMemoryFormat::Binary64),
                    10 => None,
                    _ => break,
                };
                let binary = match n.mnemonic {
                    M::Fadd => Some((O::Add, false)),
                    M::Fsub => Some((O::Subtract, false)),
                    M::Fsubr => Some((O::Subtract, true)),
                    M::Fmul => Some((O::Multiply, false)),
                    M::Fdiv => Some((O::Divide, false)),
                    M::Fdivr => Some((O::Divide, true)),
                    M::Fld => None,
                    M::Fstp if format.is_none() => None,
                    _ => break,
                };
                if binary.is_some() && format.is_none() {
                    break;
                }
                let offset = if mem.address32 {
                    mem.displacement as u32
                } else {
                    u32::from(mem.displacement as u16)
                };
                let start = offset & !255;
                if (offset - start) as usize + n.memory_width > 256 {
                    break;
                }
                let writes = n.mnemonic == M::Fstp;
                match window {
                    Some((segment, previous, write))
                        if segment == mem.segment && previous == start =>
                    {
                        window = Some((segment, start, write || writes))
                    }
                    None => window = Some((mem.segment, start, writes)),
                    _ => break,
                }
                data = Some(offset);
                if let Some((operation, reverse)) = binary {
                    I::BinaryMemory {
                        operation,
                        reverse,
                        format: format?,
                        offset: (offset - start) as u8,
                    }
                } else if let Some(format) = format {
                    I::LoadMemory {
                        format,
                        offset: (offset - start) as u8,
                    }
                } else if writes {
                    I::Store80 {
                        offset: (offset - start) as u8,
                        pop: true,
                    }
                } else {
                    I::Load80 {
                        offset: (offset - start) as u8,
                    }
                }
            } else {
                let dst = n.float_register(0).unwrap_or(0);
                let src = n.float_register(1).unwrap_or(if dst == 0 { 1 } else { 0 });
                let binary = |operation, reverse, pop| I::Binary {
                    operation,
                    destination: dst,
                    source: src,
                    reverse,
                    pop,
                };
                match n.mnemonic {
                    M::Fadd => binary(O::Add, false, false),
                    M::Faddp => binary(O::Add, false, true),
                    M::Fsub => binary(O::Subtract, false, false),
                    M::Fsubp => binary(O::Subtract, false, true),
                    M::Fsubr => binary(O::Subtract, true, false),
                    M::Fsubrp => binary(O::Subtract, true, true),
                    M::Fmul => binary(O::Multiply, false, false),
                    M::Fmulp => binary(O::Multiply, false, true),
                    M::Fdiv => binary(O::Divide, false, false),
                    M::Fdivp => binary(O::Divide, false, true),
                    M::Fdivr => binary(O::Divide, true, false),
                    M::Fdivrp => binary(O::Divide, true, true),
                    M::Fld => I::LoadRegister(dst),
                    M::Fst => I::StoreRegister {
                        destination: dst,
                        pop: false,
                    },
                    M::Fstp => I::StoreRegister {
                        destination: dst,
                        pop: true,
                    },
                    M::Fxch => I::Exchange(
                        n.float_register(1)
                            .filter(|i| *i != 0)
                            .or_else(|| n.float_register(0).filter(|i| *i != 0))
                            .unwrap_or(1),
                    ),
                    M::Fld1 => I::One,
                    M::Fldz => I::Zero,
                    M::Fchs => I::Negate,
                    M::Fabs => I::Absolute,
                    _ => break,
                }
            };
            instructions.push(instruction);
            sites.push(Site {
                ip: decoded.start_ip,
                opcode: decoded.x87_opcode?,
                data,
            });
            cursor += decoded.instruction.len();
        }
        let ir = FloatBlock::new(instructions)?;
        let next = ip + cursor as u32;
        let tail = repeating::Tail::decode(bytes, ip, cursor, bits, protected, model, &ir).map(
            |(tail, used)| {
                cursor = used;
                tail
            },
        );
        if ir.len() == 1 && tail.is_none() {
            return None;
        }
        Some((
            Self {
                ir,
                sites,
                next,
                window,
                tail,
            },
            cursor,
        ))
    }
}
impl Cpu {
    pub(super) fn execute_float_block(
        &mut self,
        memory: &mut impl GuestMemory,
        resolver: &impl SegmentResolver,
        block: &Block,
        code: PhysAddr,
        code_length: usize,
        budget: u32,
    ) -> Result<Option<u32>, CpuError> {
        if self.system.x87_instruction_unavailable() || self.x87.pending_unmasked_exceptions() != 0
        {
            return Ok(None);
        }
        let mut bytes = None;
        let mut target = None;
        if let Some((segment, start, writes)) = block.window {
            let mut window = [0u8; 256];
            if self.system.architectural_context_initialized
                && self.system.cpl == 3
                && self.system.cr0 & crate::system::CR0_AM != 0
                && self.regs.eflags & (1 << 18) != 0
            {
                return Ok(None);
            }
            let Some(address) =
                mapping::range(self, resolver, segment, start, 256, SegmentAccess::Read)
            else {
                return Ok(None);
            };
            if writes
                && mapping::range(self, resolver, segment, start, 256, SegmentAccess::Write)
                    != Some(address)
            {
                return Ok(None);
            }
            let Some(code_identity) = memory.plain_ram_identity(code, code_length) else {
                return Ok(None);
            };
            let Some(data_identity) = memory.plain_ram_identity(address, 256) else {
                return Ok(None);
            };
            if u64::from(data_identity.0) < u64::from(code_identity.0) + code_length as u64
                && u64::from(code_identity.0) < u64::from(data_identity.0) + 256
            {
                return Ok(None);
            }
            if !memory.read_plain_data(address, &mut window, writes)? {
                return Ok(None);
            }
            target = Some((address, writes));
            bytes = Some(window);
        }
        let original = if target.is_some_and(|(_, writes)| writes) {
            bytes
        } else {
            None
        };
        let top = self.x87.top();
        let mut values = [compat16_jit::Float80 {
            significand: 0,
            sign_exponent: 0,
        }; 8];
        let mut inputs = block.ir.input_register_mask();
        while inputs != 0 {
            let i = inputs.trailing_zeros() as usize;
            inputs &= inputs - 1;
            let v = self.x87.registers[(usize::from(top) + i) & 7];
            values[i] = compat16_jit::Float80 {
                significand: v.significand,
                sign_exponent: v.sign_exponent,
            };
        }
        let rotation = u32::from(top) * 2;
        let tags = self.x87.tag_word.rotate_right(rotation);
        let mut state = FloatRegisters {
            values,
            status: self.x87.status_word,
            tags,
            control: self.x87.control_word,
        };
        let mut integers = super::loops::state(self);
        let loops = &mut self.jit.loops;
        let (retired, last_float, last_memory, ip) = if let Some(tail) = &block.tail {
            let per = tail.plan.instructions_per_iteration();
            let budget = if budget == 256 {
                budget / per * per
            } else {
                budget
            };
            let Some(output) = loops.float_blocks.execute_loop(
                &tail.plan,
                &mut state,
                &mut integers,
                &mut loops.cache,
                bytes.as_mut(),
                budget,
            ) else {
                return Ok(None);
            };
            let ip = match output.position {
                compat16_jit::FloatLoopPosition::Floating(index) => {
                    block.sites[usize::from(index)].ip
                }
                compat16_jit::FloatLoopPosition::IntegerTail => tail.start,
                compat16_jit::FloatLoopPosition::Finished => tail.next,
            };
            (
                output.retired,
                usize::from(output.last_float),
                output.last_memory.map(usize::from),
                ip,
            )
        } else {
            let retired = match bytes.as_mut() {
                Some(bytes) => loops
                    .float_blocks
                    .execute(&block.ir, &mut state, bytes, budget),
                None => loops
                    .float_blocks
                    .execute_registers(&block.ir, &mut state, budget),
            };
            let Some(retired) = retired else {
                return Ok(None);
            };
            if retired == 0 {
                return Ok(None);
            }
            let last_memory = block.sites[..retired as usize]
                .iter()
                .rposition(|s| s.data.is_some());
            let ip = block
                .sites
                .get(retired as usize)
                .map_or(block.next, |s| s.ip);
            (retired, retired as usize - 1, last_memory, ip)
        };
        if retired == 0 {
            return Ok(None);
        }
        if let (Some((address, true)), Some(bytes)) = (target, bytes.as_ref())
            && original.as_ref() != Some(bytes)
        {
            memory.write(address, bytes)?;
        }
        let mut outputs = block.ir.output_register_mask();
        while outputs != 0 {
            let i = outputs.trailing_zeros() as usize;
            outputs &= outputs - 1;
            let physical = (usize::from(top) + i) & 7;
            let v = state.values[i];
            self.x87.registers[physical] = Ext80 {
                significand: v.significand,
                sign_exponent: v.sign_exponent,
            };
        }
        self.x87.tag_word = state.tags.rotate_left(rotation);
        self.x87.status_word = state.status;
        let last = block.sites[last_float];
        self.x87.instruction_pointer = last.ip;
        self.x87.instruction_segment = self.regs.cs;
        self.x87.opcode = last.opcode;
        if let Some(offset) = last_memory.and_then(|index| block.sites[index].data) {
            let (segment, _, _) = block.window.expect("data site has window");
            self.x87.data_pointer = offset;
            self.x87.data_segment = read_segment(&self.regs, segment);
        }
        if self.system.architectural_context_initialized
            && self.system.cr0 & crate::system::CR0_NE == 0
            && self.x87.pending_unmasked_exceptions() != 0
        {
            self.pending_x87_irq13 = true;
        }
        self.apply_loop(integers, retired, ip);
        Ok(Some(retired))
    }
}
// Keep the cache type near the CPU adapter's ownership, rather than making
// the independent JIT depend on Cpu or its memory/selector abstractions.
pub(super) type Cache = FloatBlockCache;
