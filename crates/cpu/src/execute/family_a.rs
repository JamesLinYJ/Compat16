//! Intel486 descriptor, selector-query, and bounds instructions.
//!
//! This module uses CPU-owned hidden state and the prepared guest-memory bus.
//! A legacy selector resolver is never used to satisfy a protected descriptor
//! access; callers without an imported architectural context get an explicit
//! unsupported-state error instead.

use guest_core::{LinearAddr, Registers};

use crate::{
    CpuError, CpuExecutionMode, ZF,
    memory_access::{AccessKind, AccessRequest, CpuBus, DataAlignment},
    memory_values::{read_prepared_width, read_width, write_prepared_width, write_width},
    read_register,
    system::{
        DescriptorType, SegmentTableRegister, SystemSegmentCache, read_descriptor,
        read_gdt_descriptor, set_system_descriptor_type,
    },
    write_register,
    x86_decode::{
        Gpr, NormalizedSystemInstruction, SelectorQuery, SystemMemoryAddress, SystemOperand,
        SystemOperation, SystemSegmentRegister, SystemTableKind,
    },
};

use super::system::{current_privilege_level, execution_mode, general_protection_fault};

pub(super) fn execute(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<(), CpuError> {
    match instruction.operation {
        SystemOperation::StoreTable { table, operand } => {
            store_table(registers, bus, instruction, table, operand)
        }
        SystemOperation::LoadTable { table, operand } => {
            load_table(registers, bus, instruction, table, operand)
        }
        SystemOperation::StoreSystemSelector { register, operand } => {
            store_system_selector(registers, bus, instruction, register, operand)
        }
        SystemOperation::LoadSystemSelector { register, operand } => {
            load_system_selector(registers, bus, instruction, register, operand)
        }
        SystemOperation::QuerySelector {
            query,
            destination,
            source,
        } => query_selector(registers, bus, instruction, query, destination, source),
        SystemOperation::VerifySelector { writable, source } => {
            verify_selector(registers, bus, instruction, writable, source)
        }
        SystemOperation::AdjustRpl {
            destination,
            source,
        } => adjust_rpl(registers, bus, instruction, destination, source),
        SystemOperation::Bound { index, bounds } => {
            check_bounds(registers, bus, instruction, index, bounds)
        }
        _ => Err(invalid_opcode(instruction)),
    }
}

fn store_table(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    table: SystemTableKind,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    let SystemOperand::Memory(address) = operand else {
        return Err(invalid_opcode(instruction));
    };
    require_architectural_state(bus, instruction)?;
    let register = table_register(bus, table);
    // Intel describes this pseudo-descriptor as separate word and dword
    // references. Keep two checked transfers for per-reference #AC/page faults
    // and a committed limit if the later base reference faults.
    let limit_span = address.logical_span(registers, 2);
    let base_span = address
        .logical_subspan(registers, 2, 4)
        .ok_or_else(|| general_protection_fault(instruction))?;
    write_width(bus, limit_span, AccessKind::DataWrite, register.limit)?;
    let base = if instruction.operand32 {
        register.base.0
    } else {
        register.base.0 & 0x00ff_ffff
    };
    write_width(bus, base_span, AccessKind::DataWrite, base)
}

fn load_table(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    table: SystemTableKind,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    let SystemOperand::Memory(address) = operand else {
        return Err(invalid_opcode(instruction));
    };
    let mode = execution_mode(registers, bus, instruction)?;
    match mode {
        CpuExecutionMode::RealAddress => {}
        CpuExecutionMode::Protected => {
            require_architectural_state(bus, instruction)?;
            let cpl = current_privilege_level(mode, bus, instruction)?;
            if cpl != 0 {
                return Err(general_protection_fault(instruction));
            }
        }
        CpuExecutionMode::Virtual8086 => return Err(general_protection_fault(instruction)),
    }
    // Read the two Intel-defined references independently. The 16-bit form
    // ignores the high base byte but still performs the dword-sized access.
    let limit = read_width(
        bus,
        address.logical_span(registers, 2),
        AccessKind::DataRead,
    )? as u16;
    let base_bytes = read_width(
        bus,
        address
            .logical_subspan(registers, 2, 4)
            .ok_or_else(|| general_protection_fault(instruction))?,
        AccessKind::DataRead,
    )?;
    let base = if instruction.operand32 {
        base_bytes
    } else {
        base_bytes & 0x00ff_ffff
    };
    let value = SegmentTableRegister {
        base: LinearAddr(base),
        limit: u32::from(limit),
    };
    let system = bus.system_mut();
    match table {
        SystemTableKind::Global => system.gdtr = value,
        SystemTableKind::Interrupt => system.idtr = value,
    }
    Ok(())
}

fn store_system_selector(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    register: SystemSegmentRegister,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    require_protected_instruction(registers, bus, instruction)?;
    require_architectural_state(bus, instruction)?;
    let selector = match register {
        SystemSegmentRegister::LocalDescriptorTable => bus.system().ldtr.selector,
        SystemSegmentRegister::Task => bus.system().task.selector,
    };
    match operand {
        // The r/m16 contract stores only the selector low word; the high
        // half of a 32-bit destination is undefined on this i486 target.
        SystemOperand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => {
            write_register(registers, gpr.index, 2, u32::from(selector));
            Ok(())
        }
        SystemOperand::Memory(address) => write_width(
            bus,
            address.logical_span(registers, 2),
            AccessKind::DataWrite,
            u32::from(selector),
        ),
        _ => Err(invalid_opcode(instruction)),
    }
}

fn load_system_selector(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    register: SystemSegmentRegister,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    let mode = require_protected_instruction(registers, bus, instruction)?;
    let cpl = current_privilege_level(mode, bus, instruction)?;
    if cpl != 0 {
        return Err(general_protection_fault(instruction));
    }
    require_architectural_state(bus, instruction)?;
    let selector = read_selector(registers, bus, instruction, operand)?;
    if selector & 0xfffc == 0 {
        if register == SystemSegmentRegister::Task {
            return Err(general_protection(
                selector_error_code(selector),
                instruction,
            ));
        }
        // Null LDTR selectors make the hidden table unusable but retain the
        // visible low RPL bits so SLDT reports the selector value actually
        // loaded.
        bus.system_mut().ldtr = SystemSegmentCache {
            selector,
            ..SystemSegmentCache::default()
        };
        return Ok(());
    }
    let record = read_gdt_descriptor(bus, selector)?;
    let descriptor = record.descriptor;
    let required_type = match (register, descriptor.descriptor_type) {
        (
            SystemSegmentRegister::LocalDescriptorTable,
            DescriptorType::System { system_type: 2 },
        ) => 2,
        (SystemSegmentRegister::Task, DescriptorType::System { system_type: 1 }) => 1,
        (SystemSegmentRegister::Task, DescriptorType::System { system_type: 9 }) => 9,
        (SystemSegmentRegister::Task, _) => {
            return Err(general_protection(
                selector_error_code(selector),
                instruction,
            ));
        }
        (SystemSegmentRegister::LocalDescriptorTable, _) => {
            return Err(general_protection(
                selector_error_code(selector),
                instruction,
            ));
        }
    };
    if !descriptor.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: selector_error_code(selector),
            ip: instruction.ip,
        });
    }
    if register == SystemSegmentRegister::Task {
        set_system_descriptor_type(bus, record, if required_type == 1 { 3 } else { 0x0b })?;
    }
    let (base, limit, system_type) = (descriptor.base, descriptor.limit, required_type);
    let state = SystemSegmentCache {
        selector,
        base,
        limit,
        system_type: if register == SystemSegmentRegister::Task {
            if required_type == 1 { 3 } else { 0x0b }
        } else {
            system_type
        },
        present: true,
        valid: true,
    };
    let system = bus.system_mut();
    match register {
        SystemSegmentRegister::LocalDescriptorTable => system.ldtr = state,
        SystemSegmentRegister::Task => system.task = state,
    }
    Ok(())
}

fn query_selector(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    query: SelectorQuery,
    destination: Gpr,
    source: SystemOperand,
) -> Result<(), CpuError> {
    let mode = require_protected_instruction(registers, bus, instruction)?;
    let cpl = current_privilege_level(mode, bus, instruction)?;
    require_architectural_state(bus, instruction)?;
    let selector = read_selector(registers, bus, instruction, source)?;
    let record = if selector & 0xfffc == 0 {
        None
    } else {
        match read_descriptor(bus, selector) {
            Ok(record) => Some(record),
            Err(CpuError::GeneralProtectionFault { .. }) => None,
            Err(error) => return Err(error),
        }
    };
    let result = record.and_then(|record| {
        let descriptor = record.descriptor;
        if !descriptor.permits_selector_query(selector, cpl)
            || !query_descriptor_type_allowed(query, descriptor.descriptor_type)
        {
            return None;
        }
        Some(match query {
            SelectorQuery::AccessRights => {
                let access = ((record.raw >> 40) & 0xff) as u32;
                let flags = ((record.raw >> 52) & 0x0f) as u32;
                let rights = access << 8;
                if destination.width == 4 {
                    rights | (flags << 20)
                } else {
                    rights
                }
            }
            SelectorQuery::Limit => descriptor.limit,
        })
    });
    if let Some(value) = result {
        write_register(registers, destination.index, destination.width, value);
        registers.eflags |= ZF;
    } else {
        registers.eflags &= !ZF;
    }
    Ok(())
}

fn verify_selector(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    writable: bool,
    source: SystemOperand,
) -> Result<(), CpuError> {
    let mode = require_protected_instruction(registers, bus, instruction)?;
    let cpl = current_privilege_level(mode, bus, instruction)?;
    require_architectural_state(bus, instruction)?;
    let selector = read_selector(registers, bus, instruction, source)?;
    let record = if selector & 0xfffc == 0 {
        None
    } else {
        match read_descriptor(bus, selector) {
            Ok(record) => Some(record),
            Err(CpuError::GeneralProtectionFault { .. }) => None,
            Err(error) => return Err(error),
        }
    };
    let valid = record.is_some_and(|record| {
        let descriptor = record.descriptor;
        descriptor.permits_selector_query(selector, cpl)
            && if writable {
                descriptor.is_writable_data()
            } else {
                descriptor.is_readable_segment()
            }
    });
    if valid {
        registers.eflags |= ZF;
    } else {
        registers.eflags &= !ZF;
    }
    Ok(())
}

fn adjust_rpl(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    destination: SystemOperand,
    source: Gpr,
) -> Result<(), CpuError> {
    let mode = require_protected_instruction(registers, bus, instruction)?;
    let _cpl = current_privilege_level(mode, bus, instruction)?;
    require_architectural_state(bus, instruction)?;
    let source_rpl = read_register(registers, source.index, 2) as u16 & 3;
    let updated = match destination {
        SystemOperand::Gpr(destination) if destination.width == 2 => {
            let selector = read_register(registers, destination.index, 2) as u16;
            let current_rpl = selector & 3;
            let update = current_rpl < source_rpl;
            if update {
                write_register(
                    registers,
                    destination.index,
                    2,
                    u32::from((selector & !3) | source_rpl),
                );
            }
            update
        }
        SystemOperand::Memory(address) => {
            let access = bus.prepare(AccessRequest::instruction(
                address.logical_span(registers, 2),
                AccessKind::DataReadWrite,
                DataAlignment::Natural(2),
            ))?;
            let selector = read_prepared_width(bus, &access, 2)? as u16;
            let current_rpl = selector & 3;
            if current_rpl < source_rpl {
                write_prepared_width(bus, access, 2, u32::from((selector & !3) | source_rpl))?;
                true
            } else {
                false
            }
        }
        _ => return Err(invalid_opcode(instruction)),
    };
    if updated {
        registers.eflags |= ZF;
    } else {
        registers.eflags &= !ZF;
    }
    Ok(())
}

fn check_bounds(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    index: Gpr,
    bounds: SystemOperand,
) -> Result<(), CpuError> {
    let SystemOperand::Memory(address) = bounds else {
        return Err(invalid_opcode(instruction));
    };
    let width = index.width;
    if !matches!(width, 2 | 4) {
        return Err(invalid_opcode(instruction));
    }
    let byte_width = usize::from(width);
    // BOUND pairs are width-selected ISA fields rather than a generic host
    // struct; keep the complete range on the checked guest-memory bus.
    let mut bytes = [0_u8; 8];
    read_width_bytes(registers, bus, address, width, &mut bytes[..byte_width * 2])?;
    let index_value = read_register(registers, index.index, width);
    let within = if width == 2 {
        let lower = i16::from_le_bytes([bytes[0], bytes[1]]) as i32;
        let upper = i16::from_le_bytes([bytes[2], bytes[3]]) as i32;
        let index = index_value as u16 as i16 as i32;
        index >= lower && index <= upper
    } else {
        let lower = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let upper = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        (index_value as i32) >= lower && (index_value as i32) <= upper
    };
    if within {
        Ok(())
    } else {
        Err(CpuError::BoundRangeFault { ip: instruction.ip })
    }
}

fn read_selector(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    operand: SystemOperand,
) -> Result<u16, CpuError> {
    match operand {
        SystemOperand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => {
            Ok(read_register(registers, gpr.index, 2) as u16)
        }
        SystemOperand::Memory(address) => {
            let value = read_width(
                bus,
                address.logical_span(registers, 2),
                AccessKind::DataRead,
            )?;
            Ok(value as u16)
        }
        _ => Err(invalid_opcode(instruction)),
    }
}

fn query_descriptor_type_allowed(query: SelectorQuery, descriptor: DescriptorType) -> bool {
    match (query, descriptor) {
        (
            SelectorQuery::AccessRights,
            DescriptorType::Data { .. } | DescriptorType::Code { .. },
        ) => true,
        (SelectorQuery::AccessRights, DescriptorType::System { system_type }) => {
            matches!(system_type, 1 | 2 | 3 | 4 | 5 | 9 | 0x0b | 0x0c)
        }
        (SelectorQuery::Limit, DescriptorType::Data { .. } | DescriptorType::Code { .. }) => true,
        (SelectorQuery::Limit, DescriptorType::System { system_type }) => {
            matches!(system_type, 1 | 2 | 3 | 9 | 0x0b)
        }
    }
}

fn table_register(bus: &impl CpuBus, table: SystemTableKind) -> SegmentTableRegister {
    match table {
        SystemTableKind::Global => bus.system().gdtr,
        SystemTableKind::Interrupt => bus.system().idtr,
    }
}

fn read_width_bytes(
    registers: &Registers,
    bus: &mut impl CpuBus,
    address: SystemMemoryAddress,
    element_width: u8,
    bytes: &mut [u8],
) -> Result<(), CpuError> {
    let access = bus.prepare(AccessRequest::instruction(
        address.logical_span(registers, bytes.len()),
        AccessKind::DataRead,
        DataAlignment::Natural(element_width),
    ))?;
    bus.read_prepared(&access, bytes)
}

fn require_protected_instruction(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<CpuExecutionMode, CpuError> {
    let mode = execution_mode(registers, bus, instruction)?;
    match mode {
        CpuExecutionMode::Protected => {
            require_architectural_state(bus, instruction)?;
            Ok(mode)
        }
        CpuExecutionMode::Virtual8086 => Err(invalid_opcode(instruction)),
        CpuExecutionMode::RealAddress => Err(invalid_opcode(instruction)),
    }
}

fn require_architectural_state(
    bus: &impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<(), CpuError> {
    if bus.architectural_mode_active() {
        Ok(())
    } else {
        Err(CpuError::UnsupportedSystemMode {
            opcode: instruction.opcode,
            ip: instruction.ip,
        })
    }
}

fn invalid_opcode(instruction: &NormalizedSystemInstruction) -> CpuError {
    CpuError::InvalidOpcode {
        opcode: instruction.opcode,
        ip: instruction.ip,
    }
}

fn general_protection(error_code: u32, instruction: &NormalizedSystemInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code,
        ip: instruction.ip,
    }
}

fn selector_error_code(selector: u16) -> u32 {
    if selector & 0xfffc == 0 {
        0
    } else {
        u32::from(selector & 0xfffc)
    }
}
