//! i486 cache and TLB maintenance instructions.

use guest_core::Registers;

use crate::{
    CpuError, CpuExecutionMode,
    memory_access::CpuBus,
    x86_decode::{NormalizedSystemInstruction, SystemOperand, SystemOperation},
};

pub(crate) fn execute(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<(), CpuError> {
    if matches!(instruction.operation, SystemOperation::InvalidEncoding) {
        return Err(invalid_opcode(instruction));
    }
    if matches!(
        instruction.operation,
        SystemOperation::Invlpg(SystemOperand::Invalid)
    ) {
        // INVLPG with a non-memory operand is #UD at decode priority. Report
        // this even if the machine has not supplied its hidden segment/CPL
        // state; an unknown privilege provider cannot make the encoding valid.
        return Err(CpuError::InvalidOpcode {
            opcode: instruction.opcode,
            ip: instruction.ip,
        });
    }
    if matches!(
        instruction.operation,
        SystemOperation::Lmsw(SystemOperand::Invalid)
            | SystemOperation::Smsw(SystemOperand::Invalid)
    ) {
        return Err(invalid_opcode(instruction));
    }
    if matches!(
        instruction.operation,
        SystemOperation::Lmsw(SystemOperand::Gpr(gpr))
            | SystemOperation::Smsw(SystemOperand::Gpr(gpr))
            if !matches!(gpr.width, 2 | 4)
    ) {
        return Err(invalid_opcode(instruction));
    }
    validate_family_a_encoding(instruction)?;
    validate_register_encoding(instruction)?;
    if matches!(instruction.operation, SystemOperation::Bound { .. }) {
        return super::family_a::execute(registers, bus, instruction);
    }
    let mode = execution_mode(registers, bus, instruction)?;
    match instruction.operation {
        SystemOperation::Invd | SystemOperation::Wbinvd => {
            let cpl = current_privilege_level(mode, bus, instruction)?;
            require_privilege(mode, cpl, instruction)?;
            // This interpreter has no guest cache state. Guest writes already
            // reach process-owned memory, so neither cache instruction has an
            // additional observable effect in this software cache model.
        }
        SystemOperation::Invlpg(operand) => {
            if mode == CpuExecutionMode::Virtual8086 {
                return Err(general_protection_fault(instruction));
            }
            match operand {
                SystemOperand::Invalid => {
                    // Handled before consulting mode/privilege providers so
                    // the invalid encoding cannot be hidden by missing state.
                    return Err(CpuError::InvalidOpcode {
                        opcode: instruction.opcode,
                        ip: instruction.ip,
                    });
                }
                SystemOperand::Gpr(_) => return Err(invalid_opcode(instruction)),
                SystemOperand::Memory(address) => {
                    let cpl = current_privilege_level(mode, bus, instruction)?;
                    require_privilege(mode, cpl, instruction)?;
                    // Resolve and validate the segmented operand without
                    // probing its page tables or backing memory. The software
                    // CPU has no TLB entries; every later access walks the
                    // current tables, so there is no cached translation to
                    // invalidate or stale-entry behavior to model.
                    let _linear = bus.invlpg_linear_address(address.logical_span(registers, 1))?;
                }
                SystemOperand::UnsupportedAddressing => {
                    let cpl = current_privilege_level(mode, bus, instruction)?;
                    require_privilege(mode, cpl, instruction)?;
                    return Err(CpuError::UnsupportedSystemAddressing {
                        opcode: instruction.opcode,
                        ip: instruction.ip,
                    });
                }
            }
        }
        SystemOperation::MoveRegister { .. }
        | SystemOperation::Clts
        | SystemOperation::Lmsw(_)
        | SystemOperation::Smsw(_)
        | SystemOperation::UnsupportedTestRegister => {
            super::system_registers::execute(registers, bus, instruction)?;
        }
        SystemOperation::StoreTable { .. }
        | SystemOperation::LoadTable { .. }
        | SystemOperation::StoreSystemSelector { .. }
        | SystemOperation::LoadSystemSelector { .. }
        | SystemOperation::QuerySelector { .. }
        | SystemOperation::VerifySelector { .. }
        | SystemOperation::AdjustRpl { .. }
        | SystemOperation::Bound { .. } => {
            super::family_a::execute(registers, bus, instruction)?;
        }
        SystemOperation::InvalidEncoding => return Err(invalid_opcode(instruction)),
    }
    Ok(())
}

fn validate_family_a_encoding(instruction: &NormalizedSystemInstruction) -> Result<(), CpuError> {
    let valid_rm16 = |operand: SystemOperand| match operand {
        SystemOperand::Gpr(gpr) => gpr.width == 2,
        SystemOperand::Memory(_) => true,
        SystemOperand::Invalid | SystemOperand::UnsupportedAddressing => false,
    };
    let valid_selector_register = |operand: SystemOperand| match operand {
        // SLDT/STR/LLDT/LTR encode r32m16 in 32-bit operand mode, but
        // selector data is still transferred through the low 16 bits.
        SystemOperand::Gpr(gpr) => matches!(gpr.width, 2 | 4),
        SystemOperand::Memory(_) => true,
        SystemOperand::Invalid | SystemOperand::UnsupportedAddressing => false,
    };
    let valid_memory = |operand: SystemOperand| matches!(operand, SystemOperand::Memory(_));
    let valid_selector_query_source = |operand: SystemOperand| match operand {
        // LAR/LSL r32,r/m16 uses a 32-bit register encoding while consuming
        // only the selector in its low word.
        SystemOperand::Gpr(gpr) => matches!(gpr.width, 2 | 4),
        SystemOperand::Memory(_) => true,
        SystemOperand::Invalid | SystemOperand::UnsupportedAddressing => false,
    };
    let valid_selector_verify_source = |operand: SystemOperand| match operand {
        // VERR/VERW remain strictly r/m16 on the i486 target.
        SystemOperand::Gpr(gpr) => gpr.width == 2,
        SystemOperand::Memory(_) => true,
        SystemOperand::Invalid | SystemOperand::UnsupportedAddressing => false,
    };
    let valid = match instruction.operation {
        SystemOperation::StoreTable { operand, .. }
        | SystemOperation::LoadTable { operand, .. } => valid_memory(operand),
        SystemOperation::StoreSystemSelector { operand, .. }
        | SystemOperation::LoadSystemSelector { operand, .. } => valid_selector_register(operand),
        SystemOperation::QuerySelector {
            destination,
            source,
            ..
        } => matches!(destination.width, 2 | 4) && valid_selector_query_source(source),
        SystemOperation::VerifySelector { source, .. } => valid_selector_verify_source(source),
        SystemOperation::AdjustRpl {
            destination,
            source,
        } => source.width == 2 && valid_rm16(destination),
        SystemOperation::Bound { index, bounds } => {
            matches!(index.width, 2 | 4) && valid_memory(bounds)
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_opcode(instruction))
    }
}

fn validate_register_encoding(instruction: &NormalizedSystemInstruction) -> Result<(), CpuError> {
    let SystemOperation::MoveRegister {
        register, operand, ..
    } = instruction.operation
    else {
        return Ok(());
    };
    let valid_register = match register.kind {
        crate::x86_decode::SystemRegisterKind::Control => {
            matches!(register.index, 0 | 2 | 3)
        }
        crate::x86_decode::SystemRegisterKind::Debug => register.index <= 7,
        crate::x86_decode::SystemRegisterKind::Test => (3..=7).contains(&register.index),
    };
    if !valid_register || !matches!(operand, SystemOperand::Gpr(_)) {
        return Err(invalid_opcode(instruction));
    }
    Ok(())
}

fn invalid_opcode(instruction: &NormalizedSystemInstruction) -> CpuError {
    CpuError::InvalidOpcode {
        opcode: instruction.opcode,
        ip: instruction.ip,
    }
}

pub(super) fn execution_mode(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<CpuExecutionMode, CpuError> {
    let unsupported = || CpuError::UnsupportedSystemMode {
        opcode: instruction.opcode,
        ip: instruction.ip,
    };
    let mode = bus.execution_mode().ok_or_else(unsupported)?;
    if bus.system().execution_mode(registers.eflags) != Some(mode) {
        return Err(unsupported());
    }
    Ok(mode)
}

pub(super) fn current_privilege_level(
    mode: CpuExecutionMode,
    bus: &impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<u8, CpuError> {
    let unsupported = || CpuError::UnsupportedSystemMode {
        opcode: instruction.opcode,
        ip: instruction.ip,
    };
    let cpl = bus.current_privilege_level().ok_or_else(unsupported)?;
    if cpl > 3
        || (mode == CpuExecutionMode::RealAddress && cpl != 0)
        || (mode == CpuExecutionMode::Virtual8086 && cpl != 3)
    {
        return Err(unsupported());
    }
    Ok(cpl)
}

pub(super) fn require_privilege(
    mode: CpuExecutionMode,
    cpl: u8,
    instruction: &NormalizedSystemInstruction,
) -> Result<(), CpuError> {
    match mode {
        CpuExecutionMode::RealAddress => Ok(()),
        CpuExecutionMode::Protected if cpl == 0 => Ok(()),
        CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086 => {
            Err(general_protection_fault(instruction))
        }
    }
}

pub(super) fn general_protection_fault(instruction: &NormalizedSystemInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: 0,
        ip: instruction.ip,
    }
}
