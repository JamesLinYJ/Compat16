//! Instruction-level privilege checks that do not mutate architectural state.

use super::super::{CpuError, CpuExecutionMode};
use super::{
    super::memory_access::CpuBus,
    flags_transfer::{FlagContext, flag_context},
};
use crate::x86_decode::NormalizedInstruction;
use guest_core::Registers;

const IOPL_MASK: u32 = 0x0000_3000;

pub(super) fn require_cli_sti(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    match flag_context(registers, bus, instruction)? {
        FlagContext::LegacyProjection => Ok(()),
        FlagContext::Architectural {
            mode: CpuExecutionMode::RealAddress,
            ..
        } => Ok(()),
        FlagContext::Architectural { cpl, .. } => {
            let iopl = ((registers.eflags & IOPL_MASK) >> 12) as u8;
            if cpl <= iopl {
                Ok(())
            } else {
                Err(general_protection(instruction))
            }
        }
    }
}

pub(super) fn require_hlt(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    match flag_context(registers, bus, instruction)? {
        FlagContext::LegacyProjection
        | FlagContext::Architectural {
            mode: CpuExecutionMode::RealAddress,
            ..
        }
        | FlagContext::Architectural {
            mode: CpuExecutionMode::Protected,
            cpl: 0,
        } => Ok(()),
        FlagContext::Architectural { .. } => Err(general_protection(instruction)),
    }
}

fn general_protection(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}
