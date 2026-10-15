//! JIT execution adapter for decoded integer instructions. Instruction fetch,
//! model checks, exception delivery, continuation stamps and retirement stay
//! in step.rs. IR keys include immediates and register widths, so re-decoding
//! self-modifying/remapped code cannot reuse a different instruction's body.

#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod loops;
#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod mapping;

use crate::x86_decode::DecodedInstruction;
use guest_core::Registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionEngine {
    Interpreter,
    Jit,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct JitStatistics {
    pub memory_loops_compiled: u64,
    pub memory_loops_executed: u64,
    pub memory_instructions: u64,
    pub loops_compiled: u64,
    pub loops_executed: u64,
    pub loop_iterations: u64,
    pub compiled: u64,
    pub executed: u64,
    pub failures: u64,
    pub cache_resets: u64,
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    pub checkpoint_hits: u64,
    pub block_invalidations: u64,
    pub persistent_hits: u64,
    pub persistent_writes: u64,
}

pub(super) struct IntegerTranslator {
    engine: ExecutionEngine,
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    cache: compat16_jit::TraceEngine,
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    current: Option<compat16_jit::Instruction>,
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    loops: loops::Loops,
}
impl Default for IntegerTranslator {
    fn default() -> Self {
        Self {
            engine: if cfg!(all(
                windows,
                any(target_arch = "aarch64", target_arch = "x86_64")
            )) {
                ExecutionEngine::Jit
            } else {
                ExecutionEngine::Interpreter
            },
            #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
            cache: compat16_jit::TraceEngine::default(),
            #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
            current: None,
            #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
            loops: loops::Loops::default(),
        }
    }
}
impl IntegerTranslator {
    pub(super) fn observe(
        &mut self,
        decoded: DecodedInstruction,
        cs: u16,
        decode_cache: &mut crate::x86_decode::DecodeCache,
    ) {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            if self.engine != ExecutionEngine::Jit {
                self.current = None;
                return;
            }
            self.current = match decode_cache.integer_ir(cs, decoded.start_ip) {
                Some(ir) => ir,
                None => {
                    let ir = translation::translate(decoded);
                    decode_cache.set_integer_ir(cs, decoded.start_ip, ir);
                    ir
                }
            };
            if self.current.is_none() {
                self.cache.barrier();
            }
        }
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let _ = (decoded, cs, decode_cache);
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn set_artifact_store(
        &mut self,
        store: Option<std::sync::Arc<dyn compat16_jit::ArtifactStore>>,
    ) {
        self.loops.cache.set_artifact_store(store.clone());
        self.loops.memory.set_artifact_store(store.clone());
        self.cache.set_artifact_store(store);
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn artifact_store(&self) -> Option<std::sync::Arc<dyn compat16_jit::ArtifactStore>> {
        self.cache.artifact_store()
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn operation(
        &self,
        mnemonic: x86_decoder::Mnemonic,
    ) -> Option<compat16_jit::Operation> {
        translation::operation(mnemonic)
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn execute_with<E>(
        &mut self,
        instruction: compat16_jit::Instruction,
        input: impl FnOnce() -> Result<compat16_jit::IntegerState, E>,
    ) -> Result<Option<compat16_jit::IntegerState>, E> {
        self.cache.execute_with(instruction, input)
    }
    pub(super) fn engine(&self) -> ExecutionEngine {
        self.engine
    }
    pub(super) fn set_engine(&mut self, engine: ExecutionEngine) {
        self.engine = engine;
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        self.cache.set_enabled(engine == ExecutionEngine::Jit);
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let _ = engine;
    }
    pub(super) fn statistics(&self) -> JitStatistics {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let stats = self
                .cache
                .statistics()
                .combined(self.loops.cache.statistics()).combined(self.loops.memory.statistics());
            JitStatistics {
                memory_loops_compiled: stats.memory_loops_compiled,
                memory_loops_executed: stats.memory_loops_executed,
                memory_instructions: stats.memory_instructions,
                loops_compiled: stats.loops_compiled,
                loops_executed: stats.loops_executed,
                loop_iterations: stats.loop_iterations,
                compiled: stats.compiled,
                executed: stats.executed,
                failures: stats.failures,
                cache_resets: stats.cache_resets,
                blocks_compiled: stats.blocks_compiled,
                blocks_executed: stats.blocks_executed,
                checkpoint_hits: stats.checkpoint_hits,
                block_invalidations: stats.block_invalidations,
                persistent_hits: stats.persistent_hits,
                persistent_writes: stats.persistent_writes,
            }
        }
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        {
            JitStatistics::default()
        }
    }
    #[inline]
    pub(super) fn execute(&mut self, regs: &mut Registers, decoded: DecodedInstruction) -> bool {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let Some(instruction) = self.current.take() else {
                return false;
            };
            let mut state = compat16_jit::IntegerState {
                registers: [
                    regs.eax, regs.ecx, regs.edx, regs.ebx, regs.esp, regs.ebp, regs.esi, regs.edi,
                ],
                flags: regs.eflags,
            };
            let domain = u64::from(regs.cs) << 32;
            let site = compat16_jit::TraceSite {
                current: domain | u64::from(decoded.start_ip),
                next: domain | u64::from(decoded.next_ip),
            };
            if !self.cache.execute(site, instruction, &mut state) {
                return false;
            }
            [
                regs.eax, regs.ecx, regs.edx, regs.ebx, regs.esp, regs.ebp, regs.esi, regs.edi,
            ] = state.registers;
            regs.eflags = state.flags;
            true
        }
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        {
            let _ = (regs, decoded);
            false
        }
    }
}

#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod translation {
    use crate::x86_decode::{DecodedInstruction, NormalizedInstruction, Operand};
    use compat16_jit::{Condition, Instruction, Operand as IrOperand, Operation, Register};
    use x86_decoder::Mnemonic;

    pub(super) fn translate(decoded: DecodedInstruction) -> Option<Instruction> {
        if decoded.instruction.has_lock_prefix() {
            return None;
        }
        let instruction = NormalizedInstruction::new(decoded);
        let operation = operation(instruction.mnemonic)?;
        let Operand::Gpr(destination) = instruction.operand(0) else {
            return None;
        };
        let destination = Register::new(destination.index, destination.width, destination.high8)?;
        let source = if instruction.operand_count == 1 {
            IrOperand::Immediate(0)
        } else {
            match instruction.operand(1) {
                Operand::Gpr(source) => {
                    IrOperand::Register(Register::new(source.index, source.width, source.high8)?)
                }
                Operand::Immediate(value) => IrOperand::Immediate(value as u32),
                _ => return None,
            }
        };
        Instruction::new(operation, destination, source)
    }

    pub(super) fn operation(mnemonic: Mnemonic) -> Option<Operation> {
        Some(match mnemonic {
            Mnemonic::Mov => Operation::Move,
            Mnemonic::Add => Operation::Add,
            Mnemonic::Adc => Operation::AddCarry,
            Mnemonic::Sub => Operation::Subtract,
            Mnemonic::Sbb => Operation::SubtractBorrow,
            Mnemonic::And => Operation::And,
            Mnemonic::Or => Operation::Or,
            Mnemonic::Xor => Operation::Xor,
            Mnemonic::Cmp => Operation::Compare,
            Mnemonic::Test => Operation::Test,
            Mnemonic::Inc => Operation::Increment,
            Mnemonic::Dec => Operation::Decrement,
            Mnemonic::Neg => Operation::Negate,
            Mnemonic::Not => Operation::Not,
            Mnemonic::Xchg => Operation::Exchange,
            Mnemonic::Movzx => Operation::ZeroExtend,
            Mnemonic::Movsx => Operation::SignExtend,
            Mnemonic::Bswap => Operation::ByteSwap,
            mnemonic => condition_operation(mnemonic)?,
        })
    }

    fn condition_operation(mnemonic: Mnemonic) -> Option<Operation> {
        use Condition::*;
        let condition = match mnemonic {
            Mnemonic::Seto | Mnemonic::Cmovo => Overflow,
            Mnemonic::Setno | Mnemonic::Cmovno => NotOverflow,
            Mnemonic::Setb | Mnemonic::Cmovb => Below,
            Mnemonic::Setae | Mnemonic::Cmovae => AboveEqual,
            Mnemonic::Sete | Mnemonic::Cmove => Equal,
            Mnemonic::Setne | Mnemonic::Cmovne => NotEqual,
            Mnemonic::Setbe | Mnemonic::Cmovbe => BelowEqual,
            Mnemonic::Seta | Mnemonic::Cmova => Above,
            Mnemonic::Sets | Mnemonic::Cmovs => Sign,
            Mnemonic::Setns | Mnemonic::Cmovns => NotSign,
            Mnemonic::Setp | Mnemonic::Cmovp => Parity,
            Mnemonic::Setnp | Mnemonic::Cmovnp => NotParity,
            Mnemonic::Setl | Mnemonic::Cmovl => Less,
            Mnemonic::Setge | Mnemonic::Cmovge => GreaterEqual,
            Mnemonic::Setle | Mnemonic::Cmovle => LessEqual,
            Mnemonic::Setg | Mnemonic::Cmovg => Greater,
            _ => return None,
        };
        Some(
            if matches!(
                mnemonic,
                Mnemonic::Seto
                    | Mnemonic::Setno
                    | Mnemonic::Setb
                    | Mnemonic::Setae
                    | Mnemonic::Sete
                    | Mnemonic::Setne
                    | Mnemonic::Setbe
                    | Mnemonic::Seta
                    | Mnemonic::Sets
                    | Mnemonic::Setns
                    | Mnemonic::Setp
                    | Mnemonic::Setnp
                    | Mnemonic::Setl
                    | Mnemonic::Setge
                    | Mnemonic::Setle
                    | Mnemonic::Setg
            ) {
                Operation::SetCondition(condition)
            } else {
                Operation::ConditionalMove(condition)
            },
        )
    }
}

impl crate::Cpu {
    /// Try a bounded pure register loop over opted-in stable real-address RAM.
    /// Returns the exact instruction count, including backedges, or None with
    /// no architectural effects. The machine must service pending external
    /// interrupts first and poll devices/host events again after the quantum.
    /// Callers requiring per-instruction observation must keep using step.
    pub fn try_run_integer_loop(
        &mut self,
        memory: &impl guest_core::GuestMemory,
        max_instructions: u32,
    ) -> Result<Option<u32>, crate::CpuError> {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            self.try_integer_loop_compiled(memory, max_instructions)
        }
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        {
            let _ = (memory, max_instructions);
            Ok(None)
        }
    }
}

impl crate::Cpu {
    /// Opt-in 16/32-bit checked segment execution, including RAM windows.
    /// The machine owner excludes per-instruction observers and services
    /// pending events first. No paging or MMIO access is coalesced.
    pub fn try_run_jit_loop(&mut self, memory:&mut impl guest_core::GuestMemory, segments:&impl crate::SegmentResolver, budget:u32)->Result<Option<u32>,crate::CpuError>{
        #[cfg(all(windows,any(target_arch="aarch64",target_arch="x86_64")))]
        {self.try_loop_with_context(memory,segments,budget)}
        #[cfg(not(all(windows,any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=(memory,segments,budget);Ok(None)}
    }
}
