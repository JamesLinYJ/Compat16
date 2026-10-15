//! Decode/certify linear floating blocks. All x87 architectural and guest
//! memory authority stays here; compat16-jit receives only raw owned state.
use super::mapping;
use crate::{
    Cpu, CpuError, CpuModel, SegmentAccess, SegmentResolver,
    registers::{SegmentRegister, read_segment},
    x86_decode::{self, NormalizedInstruction, Operand},
    x87_state::{Ext80, X87Tag},
};
use compat16_jit::{
    FloatBlock, FloatBlockCache, FloatInstruction as I, FloatOperation as O, FloatRegisters,
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
                if mem.base != Register::None
                    || mem.index != Register::None
                    || n.memory_width != 10
                    || !matches!(n.mnemonic, M::Fld | M::Fstp)
                {
                    break;
                }
                let offset = if mem.address32 {
                    mem.displacement as u32
                } else {
                    u32::from(mem.displacement as u16)
                };
                let start = offset & !255;
                if offset - start > 246 {
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
                if writes {
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
        Some((
            Self {
                ir,
                sites,
                next: ip + cursor as u32,
                window,
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
        let mut bytes = [0u8; 256];
        let mut target = None;
        if let Some((segment, start, writes)) = block.window {
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
            if !memory.read_plain_data(address, &mut bytes, writes)? {
                return Ok(None);
            }
            target = Some((address, writes));
        }
        let original = bytes;
        let top = self.x87.top();
        let values = std::array::from_fn(|i| {
            let v = self.x87.registers[(usize::from(top) + i) & 7];
            compat16_jit::Float80 {
                significand: v.significand,
                sign_exponent: v.sign_exponent,
            }
        });
        let tags = (0..8).fold(0u16, |word, i| {
            word | ((self.x87.tag((usize::from(top) + i) & 7) as u16) << (i * 2))
        });
        let mut state = FloatRegisters {
            values,
            status: self.x87.status_word,
            tags,
            control: self.x87.control_word,
        };
        let Some(retired) = self
            .jit
            .loops
            .float_blocks
            .execute(&block.ir, &mut state, &mut bytes, budget)
        else {
            return Ok(None);
        };
        if retired == 0 {
            return Ok(None);
        }
        if let Some((address, true)) = target
            && original != bytes
        {
            memory.write(address, &bytes)?;
        }
        for i in 0..8 {
            let physical = (usize::from(top) + i) & 7;
            let v = state.values[i];
            self.x87.registers[physical] = Ext80 {
                significand: v.significand,
                sign_exponent: v.sign_exponent,
            };
            self.x87
                .set_tag(physical, X87Tag::from_bits(state.tags >> (i * 2)));
        }
        self.x87.status_word = state.status;
        let last = block.sites[retired as usize - 1];
        self.x87.instruction_pointer = last.ip;
        self.x87.instruction_segment = self.regs.cs;
        self.x87.opcode = last.opcode;
        if let Some(offset) = block.sites[..retired as usize]
            .iter()
            .rev()
            .find_map(|s| s.data)
        {
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
        let ip = block
            .sites
            .get(retired as usize)
            .map_or(block.next, |s| s.ip);
        let integers = super::loops::state(self);
        self.apply_loop(integers, retired, ip);
        Ok(Some(retired))
    }
}
// Keep the cache type near the CPU adapter's ownership, rather than making
// the independent JIT depend on Cpu or its memory/selector abstractions.
pub(super) type Cache = FloatBlockCache;
