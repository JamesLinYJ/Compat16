//! Guarded real-address register loops. Ordinary Cpu::step remains one step.

use super::{ExecutionEngine, native};
use crate::{
    Cpu, CpuError, CpuExecutionMode, CpuModel, registers::SegmentRegister, system::SegmentCache,
    x86_decode,
};
use guest_core::{GuestMemory, PhysAddr};
use native_jit::{Condition, IntegerLoop, IntegerState, LoopCache};
use std::{collections::HashMap, sync::Arc};
use x86_decoder::{Mnemonic, OpKind};

#[derive(Default)]
pub(super) struct Loops {
    pub cache: LoopCache,
    probes: HashMap<u64, Probe>,
}
#[derive(Default)]
struct Probe {
    seen: u8,
    plan: Option<Arc<Plan>>,
}
struct Plan {
    bytes: Vec<u8>,
    ir: IntegerLoop,
    next_ip: u32,
    model: CpuModel,
}

impl Loops {
    fn plan(
        &mut self,
        key: u64,
        ip: u32,
        address: PhysAddr,
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
            let mut actual = [0u8; 255];
            if plan.model == model
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
        // This opt-in RAM read cannot perform device reads or guest-visible
        // permission checks. Failed lookahead eligibility is just a miss;
        // ordered instruction fetch will establish the actual guest fault.
        let length = 255usize
            .min((0x10000 - ip) as usize)
            .min(memory.len().saturating_sub(address.0) as usize);
        if length == 0 {
            return Ok(None);
        }
        let mut bytes = [0u8; 255];
        if !memory.read_plain_code(address, &mut bytes[..length])? {
            return Ok(None);
        }
        let mut cursor = 0;
        let mut instructions = Vec::new();
        for _ in 0..=native_jit::MAX_BLOCK_INSTRUCTIONS {
            let Some(decoded) =
                x86_decode::decode_plain16(&bytes[cursor..length], ip + cursor as u32)
            else {
                return Ok(None);
            };
            if !model.supports_instruction_features(decoded.required_cpu_features())
                || decoded.next_ip <= decoded.start_ip
                || decoded.instruction.has_lock_prefix()
            {
                return Ok(None);
            }
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
                let Some(ir) = IntegerLoop::new(instructions, condition) else {
                    return Ok(None);
                };
                let plan = Arc::new(Plan {
                    bytes: bytes[..cursor].to_vec(),
                    ir,
                    next_ip: decoded.next_ip,
                    model,
                });
                probe.plan = Some(plan.clone());
                return Ok(Some(plan));
            }
            let Some(operation) = native::translate(decoded) else {
                return Ok(None);
            };
            instructions.push(operation);
        }
        Ok(None)
    }
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
impl Cpu {
    pub(super) fn try_integer_loop_native(
        &mut self,
        memory: &impl GuestMemory,
        max_instructions: u32,
    ) -> Result<Option<u32>, CpuError> {
        // Imported/unreal/protected/paged contexts need their complete fetch
        // contracts. A caller-owned selector resolver never grants this path.
        if self.jit.engine != ExecutionEngine::NativeJit
            || max_instructions < 2
            || !self.system.architectural_context_initialized
            || self.architectural_execution_mode() != Some(CpuExecutionMode::RealAddress)
            || self.system.cr0 & (crate::system::CR0_PE | crate::system::CR0_PG) != 0
            || *self.system.segment_cache(SegmentRegister::Cs)
                != SegmentCache::real_mode(self.regs.cs, true)
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
        let budget =
            u64::from(max_instructions.min(256)).min(u64::MAX - self.call_boundary_sequence) as u32;
        if budget < 2 {
            return Ok(None);
        }
        let ip = u32::from(self.regs.ip());
        let address = PhysAddr((u32::from(self.regs.cs) << 4) + ip);
        let key = (u64::from(self.regs.cs) << 32) | u64::from(ip);
        let Some(plan) = self.jit.loops.plan(key, ip, address, memory, self.model)? else {
            return Ok(None);
        };
        let per_iteration = plan.ir.body_len() as u32 + 1;
        let mut state = IntegerState {
            registers: [
                self.regs.eax,
                self.regs.ecx,
                self.regs.edx,
                self.regs.ebx,
                self.regs.esp,
                self.regs.ebp,
                self.regs.esi,
                self.regs.edi,
            ],
            flags: self.model.normalize_eflags(self.regs.eflags),
        };
        let Some(result) =
            self.jit
                .loops
                .cache
                .execute(&plan.ir, &mut state, budget / per_iteration)
        else {
            return Ok(None);
        };
        let retired = result.iterations * per_iteration;
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
        self.regs.eip = if result.backedge_taken {
            ip
        } else {
            plan.next_ip
        };
        self.call_boundary_sequence += u64::from(retired);
        self.control_transfer = None;
        self.invalidate_control_transfer_provenance();
        Ok(Some(retired))
    }
}
