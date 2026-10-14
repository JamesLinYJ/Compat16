//! Native execution adapter for decoded integer instructions. Instruction fetch,
//! model checks, exception delivery, continuation stamps and retirement stay
//! in step.rs. IR keys include immediates and register widths, so re-decoding
//! self-modifying/remapped code cannot reuse a different instruction's body.

use crate::x86_decode::DecodedInstruction;
use guest_core::Registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionEngine {
    Interpreter,
    NativeJit,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct JitStatistics {
    pub compiled: u64,
    pub executed: u64,
    pub failures: u64,
    pub cache_resets: u64,
}

pub(super) struct IntegerTranslator {
    engine: ExecutionEngine,
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    cache: native_jit::CodeCache,
}
impl Default for IntegerTranslator {
    fn default() -> Self {
        Self {
            engine: if cfg!(all(
                windows,
                any(target_arch = "aarch64", target_arch = "x86_64")
            )) {
                ExecutionEngine::NativeJit
            } else {
                ExecutionEngine::Interpreter
            },
            #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
            cache: native_jit::CodeCache::default(),
        }
    }
}
impl IntegerTranslator {
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn operation(
        &self,
        mnemonic: x86_decoder::Mnemonic,
    ) -> Option<native_jit::Operation> {
        native::operation(mnemonic)
    }
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) fn execute_with<E>(
        &mut self,
        instruction: native_jit::Instruction,
        input: impl FnOnce() -> Result<native_jit::IntegerState, E>,
    ) -> Result<Option<native_jit::IntegerState>, E> {
        self.cache.execute_with(instruction, input)
    }
    pub(super) fn engine(&self) -> ExecutionEngine {
        self.engine
    }
    pub(super) fn set_engine(&mut self, engine: ExecutionEngine) {
        self.engine = engine;
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        self.cache.set_enabled(engine == ExecutionEngine::NativeJit);
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let _ = engine;
    }
    pub(super) fn statistics(&self) -> JitStatistics {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let stats = self.cache.statistics();
            JitStatistics {
                compiled: stats.compiled,
                executed: stats.executed,
                failures: stats.failures,
                cache_resets: stats.cache_resets,
            }
        }
        #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
        {
            JitStatistics::default()
        }
    }
    pub(super) fn execute(&mut self, regs: &mut Registers, decoded: DecodedInstruction) -> bool {
        #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let Some(instruction) = native::translate(decoded) else {
                return false;
            };
            let mut state = native_jit::IntegerState {
                registers: [
                    regs.eax, regs.ecx, regs.edx, regs.ebx, regs.esp, regs.ebp, regs.esi, regs.edi,
                ],
                flags: regs.eflags,
            };
            if !self.cache.execute(instruction, &mut state) {
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
mod native {
    use crate::x86_decode::{DecodedInstruction, NormalizedInstruction, Operand};
    use native_jit::{Condition, Instruction, Operand as IrOperand, Operation, Register};
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
