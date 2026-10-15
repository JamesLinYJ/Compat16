//! Checked 16/32-bit register and RAM loops. Cpu::step remains one instruction.
use super::{ExecutionEngine, mapping, translation};
use crate::{
    Cpu, CpuError, CpuExecutionMode, CpuModel, RealModeSegments, SegmentAccess, SegmentResolver,
    registers::SegmentRegister, x86_decode,
};
use compat16_jit::{
    Address, BlockInstruction, Condition, IntegerLoop, IntegerState, LoopCache, MemoryInstruction,
    MemoryLoop, MemoryLoopCache, MemoryWindow, Register, ValueOperand,
};
use guest_core::{GuestMemory, PhysAddr};
use std::{collections::HashMap, sync::Arc};
use x86_decoder::{Mnemonic, OpKind};

#[derive(Default)]
pub(super) struct Loops {
    pub cache: LoopCache,
    pub memory: MemoryLoopCache,
    probes: HashMap<u64, Probe>,
}
#[derive(Default)]
struct Probe {
    seen: u8,
    plan: Option<Arc<Plan>>,
}
enum Body {
    Registers(IntegerLoop),
    Memory {
        ir: MemoryLoop,
        segment: SegmentRegister,
    },
}
struct Plan {
    bytes: Vec<u8>,
    body: Body,
    sites: Vec<u32>,
    model: CpuModel,
    bits: u32,
    protected_ip: bool,
}
struct Ready {
    plan: Arc<Plan>,
    address: PhysAddr,
    budget: u32,
    ip: u32,
}
impl Loops {
    fn plan(
        &mut self,
        key: u64,
        ip: u32,
        address: PhysAddr,
        length: usize,
        bits: u32,
        protected_ip: bool,
        memory: &impl GuestMemory,
        model: CpuModel,
    ) -> Result<Option<Arc<Plan>>, CpuError> {
        if self.probes.len() == 1024 && !self.probes.contains_key(&key) {
            self.probes.clear();
        }
        if !self.probes.contains_key(&key) {
            if self.probes.try_reserve(1).is_err() {
                return Ok(None);
            }
            self.probes.insert(key, Probe::default());
        }
        let probe = self.probes.get_mut(&key).expect("inserted probe");
        if let Some(plan) = probe.plan.as_ref() {
            // A temporary segment limit can prevent validation without
            // changing code. Retain the plan, but never execute it until the
            // entire span is permitted and its current bytes match again.
            if length < plan.bytes.len()
                && plan.model == model
                && plan.bits == bits
                && plan.protected_ip == protected_ip
            {
                return Ok(None);
            }
            let mut actual = [0u8; 255];
            if plan.model == model
                && plan.bits == bits
                && plan.protected_ip == protected_ip
                && length >= plan.bytes.len()
                && memory.read_plain_code(address, &mut actual[..plan.bytes.len()])?
                && actual[..plan.bytes.len()] == plan.bytes
            {
                return Ok(Some(plan.clone()));
            }
            probe.plan = None;
            probe.seen = 0;
            return Ok(None);
        }
        probe.seen += 1;
        if probe.seen < 8 {
            return Ok(None);
        }
        probe.seen = 0;
        let mut bytes = [0u8; 255];
        if length == 0 || !memory.read_plain_code(address, &mut bytes[..length])? {
            return Ok(None);
        }
        let mut cursor = 0;
        let mut instructions = Vec::new();
        let mut sites = Vec::new();
        let mut memory_segment = None;
        for _ in 0..=compat16_jit::MAX_BLOCK_INSTRUCTIONS {
            let Some(decoded) = x86_decode::decode_plain(
                &bytes[cursor..length],
                ip + cursor as u32,
                bits,
                protected_ip,
            ) else {
                return Ok(None);
            };
            if !model.supports_instruction_features(decoded.required_cpu_features())
                || decoded.next_ip <= decoded.start_ip
                || decoded.instruction.has_lock_prefix()
            {
                return Ok(None);
            }
            sites.push(decoded.start_ip);
            cursor += decoded.instruction.len();
            let branch = decoded.instruction;
            let condition = branch_condition(branch.mnemonic());
            if branch.mnemonic() == Mnemonic::Jmp || condition.is_some() {
                if !matches!(
                    branch.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32
                ) || branch.near_branch_target() != u64::from(ip)
                {
                    return Ok(None);
                }
                let body = if let Some(segment) = memory_segment {
                    let Some(ir) = MemoryLoop::new(instructions, condition) else {
                        return Ok(None);
                    };
                    Body::Memory { ir, segment }
                } else {
                    let integers = instructions
                        .into_iter()
                        .map(|i| match i {
                            BlockInstruction::Integer(i) => i,
                            _ => unreachable!(),
                        })
                        .collect();
                    let Some(ir) = IntegerLoop::new(integers, condition) else {
                        return Ok(None);
                    };
                    Body::Registers(ir)
                };
                sites.push(decoded.next_ip);
                let plan = Arc::new(Plan {
                    bytes: bytes[..cursor].to_vec(),
                    body,
                    sites,
                    model,
                    bits,
                    protected_ip,
                });
                probe.plan = Some(plan.clone());
                return Ok(Some(plan));
            }
            if let Some(ir) = translation::translate(decoded) {
                instructions.push(BlockInstruction::Integer(ir));
            } else if let Some((ir, segment)) = translate_memory(decoded) {
                if memory_segment.is_some_and(|previous| previous != segment) {
                    return Ok(None);
                }
                memory_segment = Some(segment);
                instructions.push(BlockInstruction::Memory(ir));
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }
}
fn address_register(register: x86_decoder::Register, bits: u8) -> Option<Register> {
    use x86_decoder::Register::*;
    let index = match register {
        AX | EAX => 0,
        CX | ECX => 1,
        DX | EDX => 2,
        BX | EBX => 3,
        SP | ESP => 4,
        BP | EBP => 5,
        SI | ESI => 6,
        DI | EDI => 7,
        _ => return Option::None,
    };
    Register::new(index, bits / 8, false)
}
fn translate_memory(
    decoded: x86_decode::DecodedInstruction,
) -> Option<(MemoryInstruction, SegmentRegister)> {
    use x86_decode::{NormalizedInstruction, Operand};
    let normalized = NormalizedInstruction::new(decoded);
    let operation = translation::operation(normalized.mnemonic)?;
    let mut segment = None;
    let mut convert = |operand: Operand| -> Option<ValueOperand> {
        Some(match operand {
            Operand::Gpr(r) => ValueOperand::Register(Register::new(r.index, r.width, r.high8)?),
            Operand::Immediate(v) => ValueOperand::Immediate(v as u32),
            Operand::Memory(m) => {
                let bits = if m.address32 { 32 } else { 16 };
                let base = if m.base == x86_decoder::Register::None {
                    None
                } else {
                    Some(address_register(m.base, bits)?)
                };
                let index = if m.index == x86_decoder::Register::None {
                    None
                } else {
                    Some(address_register(m.index, bits)?)
                };
                segment = Some(m.segment);
                ValueOperand::Memory {
                    address: Address::new(base, index, m.scale as u8, m.displacement as u32, bits)?,
                    bytes: u8::try_from(decoded.instruction.memory_size().size()).ok()?,
                }
            }
            _ => return None,
        })
    };
    let destination = convert(normalized.operand(0))?;
    let source = if normalized.operand_count == 1 {
        ValueOperand::Immediate(0)
    } else {
        convert(normalized.operand(1))?
    };
    Some((
        MemoryInstruction::new(operation, destination, source)?,
        segment?,
    ))
}
fn branch_condition(mnemonic: Mnemonic) -> Option<Condition> {
    use Condition::*;
    Some(match mnemonic {
        Mnemonic::Jo => Overflow,
        Mnemonic::Jno => NotOverflow,
        Mnemonic::Jb => Below,
        Mnemonic::Jae => AboveEqual,
        Mnemonic::Je => Equal,
        Mnemonic::Jne => NotEqual,
        Mnemonic::Jbe => BelowEqual,
        Mnemonic::Ja => Above,
        Mnemonic::Js => Sign,
        Mnemonic::Jns => NotSign,
        Mnemonic::Jp => Parity,
        Mnemonic::Jnp => NotParity,
        Mnemonic::Jl => Less,
        Mnemonic::Jge => GreaterEqual,
        Mnemonic::Jle => LessEqual,
        Mnemonic::Jg => Greater,
        _ => return None,
    })
}
fn state(cpu: &Cpu) -> IntegerState {
    IntegerState {
        registers: [
            cpu.regs.eax,
            cpu.regs.ecx,
            cpu.regs.edx,
            cpu.regs.ebx,
            cpu.regs.esp,
            cpu.regs.ebp,
            cpu.regs.esi,
            cpu.regs.edi,
        ],
        flags: cpu.model.normalize_eflags(cpu.regs.eflags),
    }
}
impl Cpu {
    fn ready_loop(
        &mut self,
        memory: &impl GuestMemory,
        resolver: &impl SegmentResolver,
        max: u32,
    ) -> Result<Option<Ready>, CpuError> {
        if self.jit.engine != ExecutionEngine::Jit
            || max < 2
            || self.system.cr0 & crate::system::CR0_PG != 0
            || self.regs.eflags & ((1 << 8) | (1 << 16) | (1 << 17)) != 0
            || self.system.debug.control & 0xff != 0
            || self.deferred_data_breakpoint_hits.matching != 0
            || self.deferred_data_breakpoint_hits.enabled != 0
            || self.maskable_interrupt_shadow
            || self.debug_exception_shadow
            || self.pending_non_maskable_interrupt
            || self.pending_task_debug_trap
            || self.pending_x87_irq13
            || self.halted
            || self.shutdown_reason.is_some()
            || self.intermediate_rep_boundary
            || self.defer_cpu_events
            || self.deferred_cpu_event.is_some()
            || self.call_boundary_sequence_exhausted
        {
            return Ok(None);
        }
        let budget = u64::from(max.min(256)).min(u64::MAX - self.call_boundary_sequence) as u32;
        if budget < 2 {
            return Ok(None);
        }
        let architectural = self.system.architectural_context_initialized;
        let bits = if architectural {
            self.system.code_bits()
        } else {
            resolver.code_bits()
        };
        if !matches!(bits, 16 | 32) {
            return Ok(None);
        }
        let protected_ip = architectural
            && self.architectural_execution_mode() == Some(CpuExecutionMode::Protected);
        let ip = if bits == 16 && !protected_ip {
            u32::from(self.regs.ip())
        } else {
            self.regs.eip
        };
        let remaining = if bits == 16 && !protected_ip {
            0x10000 - u64::from(ip)
        } else {
            u64::from(u32::MAX) + 1 - u64::from(ip)
        };
        let Some((address, length)) =
            mapping::code(self, resolver, ip, remaining.min(255) as usize)
        else {
            return Ok(None);
        };
        let key = (u64::from(self.regs.cs) << 32) | u64::from(ip);
        let Some(plan) = self.jit.loops.plan(
            key,
            ip,
            address,
            length,
            bits,
            protected_ip,
            memory,
            self.model,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(Ready {
            plan,
            address,
            budget,
            ip,
        }))
    }
    fn apply_loop(&mut self, state: IntegerState, retired: u32, ip: u32) {
        self.jit.cache.barrier();
        self.jit.current = None;
        [
            self.regs.eax,
            self.regs.ecx,
            self.regs.edx,
            self.regs.ebx,
            self.regs.esp,
            self.regs.ebp,
            self.regs.esi,
            self.regs.edi,
        ] = state.registers;
        self.regs.eflags = self.model.normalize_eflags(state.flags);
        self.regs.eip = ip;
        self.call_boundary_sequence += u64::from(retired);
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
    }
    fn execute_register_loop(&mut self, ready: &Ready) -> Option<u32> {
        let Body::Registers(ir) = &ready.plan.body else {
            return None;
        };
        let per = ir.body_len() as u32 + 1;
        let mut output = state(self);
        let result = self
            .jit
            .loops
            .cache
            .execute(ir, &mut output, ready.budget / per)?;
        let retired = result.iterations * per;
        self.apply_loop(
            output,
            retired,
            if result.backedge_taken {
                ready.ip
            } else {
                *ready.plan.sites.last()?
            },
        );
        Some(retired)
    }
    pub(super) fn try_integer_loop_compiled(
        &mut self,
        memory: &impl GuestMemory,
        max: u32,
    ) -> Result<Option<u32>, CpuError> {
        let Some(ready) = self.ready_loop(memory, &RealModeSegments, max)? else {
            return Ok(None);
        };
        Ok(self.execute_register_loop(&ready))
    }
    pub(super) fn try_loop_with_context(
        &mut self,
        memory: &mut impl GuestMemory,
        resolver: &impl SegmentResolver,
        max: u32,
    ) -> Result<Option<u32>, CpuError> {
        let Some(ready) = self.ready_loop(memory, resolver, max)? else {
            return Ok(None);
        };
        let Body::Memory { ir, segment } = &ready.plan.body else {
            return Ok(self.execute_register_loop(&ready));
        };
        // No alignment fault may be hidden by the RAM snapshot. Legacy
        // selector projections retain their existing unknown-CPL contract.
        if self.system.architectural_context_initialized
            && self.system.cpl == 3
            && self.system.cr0 & crate::system::CR0_AM != 0
            && self.regs.eflags & (1 << 18) != 0
        {
            return Ok(None);
        }
        let mut output = state(self);
        let first = ir.first_memory().address().offset(&output);
        let start = first & !255;
        let Some(address) =
            mapping::range(self, resolver, *segment, start, 256, SegmentAccess::Read)
        else {
            return Ok(None);
        };
        if ir.writes()
            && mapping::range(self, resolver, *segment, start, 256, SegmentAccess::Write)
                != Some(address)
        {
            return Ok(None);
        }
        let Some(code_identity) = memory.plain_ram_identity(ready.address, ready.plan.bytes.len())
        else {
            return Ok(None);
        };
        let Some(data_identity) = memory.plain_ram_identity(address, 256) else {
            return Ok(None);
        };
        if u64::from(data_identity.0) < u64::from(code_identity.0) + ready.plan.bytes.len() as u64
            && u64::from(code_identity.0) < u64::from(data_identity.0) + 256
        {
            return Ok(None);
        }
        let mut bytes = [0u8; 256];
        if !memory.read_plain_data(address, &mut bytes, ir.writes())? {
            return Ok(None);
        }
        let original = bytes;
        let Some(result) = self.jit.loops.memory.execute(
            ir,
            &mut output,
            MemoryWindow {
                start,
                bytes: &mut bytes,
            },
            ready.budget,
        ) else {
            return Ok(None);
        };
        if result.retired == 0 {
            return Ok(None);
        }
        if ir.writes() && bytes != original {
            memory.write(address, &bytes)?;
        }
        let ip = ready.plan.sites[result.next_instruction as usize];
        self.apply_loop(output, result.retired, ip);
        Ok(Some(result.retired))
    }
}
