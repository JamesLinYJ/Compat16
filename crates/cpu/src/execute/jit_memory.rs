//! Checked operand ingress/writeback for independent compiled integer bodies.

use crate::{
    CpuError, jit::IntegerTranslator, memory_access::CpuBus, x86_decode::DecodedInstruction,
};
use guest_core::Registers;

pub(crate) fn execute(
    translator: &mut IntegerTranslator,
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    decoded: DecodedInstruction,
) -> Result<bool, CpuError> {
    #[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        translation::execute(translator, regs, bus, decoded)
    }
    #[cfg(not(all(windows, any(target_arch = "aarch64", target_arch = "x86_64"))))]
    {
        let _ = (translator, regs, bus, decoded);
        Ok(false)
    }
}

#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod translation {
    use super::super::operand::{
        operand_width, prepare_operand, read_operand, read_prepared_operand, write_operand,
        write_prepared_operand,
    };
    use super::*;
    use crate::{
        memory_access::AccessKind,
        x86_decode::{NormalizedInstruction, Operand},
    };
    use compat16_jit::{Instruction, IntegerState, Operand as IrOperand, Operation as Op, Register};

    pub(super) fn execute(
        translator: &mut IntegerTranslator,
        regs: &mut Registers,
        bus: &mut impl CpuBus,
        decoded: DecodedInstruction,
    ) -> Result<bool, CpuError> {
        if decoded.instruction.has_lock_prefix() {
            return Ok(false);
        }
        let instruction = NormalizedInstruction::new(decoded);
        let destination = instruction.operand(0);
        let source = instruction.operand(1);
        if !matches!(destination, Operand::Memory(_)) && !matches!(source, Operand::Memory(_)) {
            return Ok(false);
        }
        let Some(operation) = translator.operation(instruction.mnemonic) else {
            return Ok(false);
        };
        // Memory XCHG is always atomic, even without LOCK. Its existing atomic
        // executor remains the owner of that contract.
        if matches!(operation, Op::Exchange | Op::ByteSwap)
            || !matches!(destination, Operand::Gpr(_) | Operand::Memory(_))
            || instruction.operand_count > 1
                && !matches!(
                    source,
                    Operand::Gpr(_) | Operand::Memory(_) | Operand::Immediate(_)
                )
            || matches!(operation, Op::ConditionalMove(_))
                && !matches!(destination, Operand::Gpr(_))
        {
            return Ok(false);
        }
        let width = operand_width(&instruction, 0);
        let source_width = if matches!(operation, Op::ZeroExtend | Op::SignExtend) {
            operand_width(&instruction, 1)
        } else {
            width
        };
        let (Some(left), Some(right)) = (
            Register::new(0, width, false),
            Register::new(1, source_width, false),
        ) else {
            return Ok(false);
        };
        let Some(ir) = Instruction::new(operation, left, IrOperand::Register(right)) else {
            return Ok(false);
        };
        let move_source = matches!(
            operation,
            Op::Move | Op::ZeroExtend | Op::SignExtend | Op::ConditionalMove(_)
        );
        let write_only = matches!(operation, Op::SetCondition(_));
        let writes = !matches!(operation, Op::Compare | Op::Test);
        let mut prepared = None;
        let result = translator.execute_with(ir, || -> Result<IntegerState, CpuError> {
            let (left, right) = if write_only {
                (0, 0)
            } else if move_source {
                // MOV/CMOV read the source first; CMOV reads it even when the
                // condition is false. Neither path reads a memory destination.
                let right = read_operand(regs, bus, source, source_width)?;
                let left = if matches!(operation, Op::ConditionalMove(_)) {
                    read_operand(regs, bus, destination, width)?
                } else {
                    0
                };
                (left, right)
            } else {
                let access = if writes {
                    AccessKind::DataReadWrite
                } else {
                    AccessKind::DataRead
                };
                let target = prepare_operand(regs, bus, destination, width, access)?;
                let left = read_prepared_operand(regs, bus, &target)?;
                let right = if instruction.operand_count > 1 {
                    read_operand(regs, bus, source, width)?
                } else {
                    0
                };
                prepared = Some(target);
                (left, right)
            };
            Ok(IntegerState {
                registers: [left, right, 0, 0, 0, 0, 0, 0],
                flags: regs.eflags,
            })
        })?;
        let Some(result) = result else {
            return Ok(false);
        };
        if writes {
            if let Some(target) = prepared {
                write_prepared_operand(regs, bus, target, result.registers[0])?;
            } else {
                write_operand(regs, bus, destination, width, result.registers[0])?;
            }
        }
        // A failed write must not publish computed flags. Bus/page/device
        // effects retain the same ownership as the ordinary interpreter.
        regs.eflags = result.flags;
        Ok(true)
    }
}
