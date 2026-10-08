//! Validated far control transfers against the CPU's hidden segment state.
//!
//! Direct transfers, call gates, and task-switch routing use checked CPU state.

mod call_gate;
mod far_return;

use guest_core::Registers;
use x86_decoder::Mnemonic;

use crate::{
    CpuError, CpuExecutionMode, CpuModel,
    memory_access::{AccessKind, CpuBus, DataAlignment, LogicalSpan},
    memory_values::{read_bytes, write_bytes},
    system::{
        DescriptorRecord, DescriptorType, SegmentCache, mark_segment_accessed,
        read_descriptor,
    },
    x86_decode::{NormalizedInstruction, Operand},
};

use super::{
    control::{far_pointer_width, is_far_indirect},
    operand::logical_span,
    segment_load::{commit_code_transfer, validate_code_transfer},
    stack::{push_slots, set_stack_pointer, stack_pointer},
};

#[derive(Clone, Copy)]
struct FarPointer {
    offset: u32,
    selector: u16,
    width: u8,
}

#[derive(Clone, Copy)]
struct CallGate {
    selector: u16,
    offset: u32,
    width: u8,
    parameter_count: u8,
}

pub(super) fn handles(bus: &impl CpuBus, instruction: &NormalizedInstruction) -> bool {
    if !bus.architectural_mode_active() {
        return false;
    }
    match instruction.mnemonic {
        Mnemonic::Retf => true,
        Mnemonic::Call | Mnemonic::Jmp => {
            matches!(instruction.operand(0), Operand::FarBranch { .. })
                || is_far_indirect(instruction)
        }
        _ => false,
    }
}

pub(super) fn execute(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    match instruction.mnemonic {
        Mnemonic::Call => {
            execute_far_call(registers, bus, instruction, next_ip, pending_task_debug, model)
        }
        Mnemonic::Jmp => {
            execute_far_jump(registers, bus, instruction, next_ip, pending_task_debug, model)
        }
        Mnemonic::Retf => far_return::execute(registers, bus, instruction, next_ip),
        _ => Err(invalid_opcode(instruction)),
    }
}

fn execute_far_call(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let pointer = far_pointer(registers, bus, instruction)?;
    match bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))?
    {
        CpuExecutionMode::RealAddress | CpuExecutionMode::Virtual8086 => {
            let (cache, cpl) =
                validate_code_transfer(bus, pointer.selector, pointer.offset, instruction, false)?;
            let mut next = registers.clone();
            if bus.architectural_mode_active() {
                next = push_checked_far_frame(
                    registers,
                    bus,
                    [u32::from(registers.cs), *next_ip],
                    pointer.width,
                    instruction,
                )?;
            } else {
                push_slots(
                    &mut next,
                    bus,
                    &[u32::from(registers.cs), *next_ip],
                    pointer.width,
                )?;
            }
            commit_code_transfer(&mut next, bus, pointer.selector, cache, cpl);
            *registers = next;
            *next_ip = pointer.offset;
            Ok(())
        }
        CpuExecutionMode::Protected => {
            require_architectural_mode(bus, instruction)?;
            let cpl = bus
                .current_privilege_level()
                .ok_or_else(|| unsupported_mode(instruction))?;
            let record = read_descriptor(bus, pointer.selector)?;
            match record.descriptor.descriptor_type {
                DescriptorType::Code { .. } => {
                    let (cache, resulting_cpl) = validate_code_transfer(
                        bus,
                        pointer.selector,
                        pointer.offset,
                        instruction,
                        false,
                    )?;
                    if resulting_cpl != cpl {
                        return Err(general_protection(pointer.selector, instruction));
                    }
                    let mut next = push_checked_far_frame(
                        registers,
                        bus,
                        [u32::from(registers.cs), *next_ip],
                        pointer.width,
                        instruction,
                    )?;
                    commit_code_transfer(&mut next, bus, pointer.selector, cache, resulting_cpl);
                    *registers = next;
                    *next_ip = pointer.offset;
                    Ok(())
                }
                DescriptorType::System {
                    system_type: 4 | 0x0c,
                } => execute_call_gate(registers, bus, instruction, next_ip, record, cpl, false),
                DescriptorType::System { system_type: 5 } => {
                    super::super::task_switch::execute_task_gate(
                        registers,
                        bus,
                        instruction,
                        next_ip,
                        record,
                        cpl,
                        false,
                        pending_task_debug,
                        model,
                    )
                }
                DescriptorType::System {
                    system_type: 1 | 3 | 9 | 0x0b,
                } => super::super::task_switch::execute_direct_tss(
                    registers,
                    bus,
                    instruction,
                    next_ip,
                    record,
                    false,
                    pending_task_debug,
                    model,
                ),
                _ => Err(general_protection(pointer.selector, instruction)),
            }
        }
    }
}

fn execute_far_jump(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let pointer = far_pointer(registers, bus, instruction)?;
    match bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))?
    {
        CpuExecutionMode::RealAddress | CpuExecutionMode::Virtual8086 => {
            let (cache, cpl) =
                validate_code_transfer(bus, pointer.selector, pointer.offset, instruction, false)?;
            commit_code_transfer(registers, bus, pointer.selector, cache, cpl);
            *next_ip = pointer.offset;
            Ok(())
        }
        CpuExecutionMode::Protected => {
            require_architectural_mode(bus, instruction)?;
            let cpl = bus
                .current_privilege_level()
                .ok_or_else(|| unsupported_mode(instruction))?;
            let record = read_descriptor(bus, pointer.selector)?;
            match record.descriptor.descriptor_type {
                DescriptorType::Code { .. } => {
                    let (cache, resulting_cpl) = validate_code_transfer(
                        bus,
                        pointer.selector,
                        pointer.offset,
                        instruction,
                        false,
                    )?;
                    if resulting_cpl != cpl {
                        return Err(general_protection(pointer.selector, instruction));
                    }
                    commit_code_transfer(registers, bus, pointer.selector, cache, resulting_cpl);
                    *next_ip = pointer.offset;
                    Ok(())
                }
                DescriptorType::System {
                    system_type: 4 | 0x0c,
                } => execute_call_gate(registers, bus, instruction, next_ip, record, cpl, true),
                DescriptorType::System { system_type: 5 } => {
                    super::super::task_switch::execute_task_gate(
                        registers,
                        bus,
                        instruction,
                        next_ip,
                        record,
                        cpl,
                        true,
                        pending_task_debug,
                        model,
                    )
                }
                DescriptorType::System {
                    system_type: 1 | 3 | 9 | 0x0b,
                } => super::super::task_switch::execute_direct_tss(
                    registers,
                    bus,
                    instruction,
                    next_ip,
                    record,
                    true,
                    pending_task_debug,
                    model,
                ),
                _ => Err(general_protection(pointer.selector, instruction)),
            }
        }
    }
}

fn execute_call_gate(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    gate_record: DescriptorRecord,
    cpl: u8,
    jump: bool,
) -> Result<(), CpuError> {
    let gate_selector = gate_record.selector;
    let return_ip = *next_ip;
    let gate_rpl = (gate_selector & 3) as u8;
    if cpl.max(gate_rpl) > gate_record.descriptor.dpl {
        return Err(general_protection(gate_selector, instruction));
    }
    if !gate_record.descriptor.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: selector_error_code(gate_selector),
            ip: instruction.decoded.start_ip,
        });
    }
    let gate = parse_call_gate(gate_record);
    if (gate_record.raw & (0x7_u64 << 37) != 0) || (gate.width == 2 && gate_record.raw >> 48 != 0) {
        return Err(general_protection(gate_record.selector, instruction));
    }
    let target_record = read_descriptor(bus, gate.selector)?;
    let DescriptorType::Code { conforming, .. } = target_record.descriptor.descriptor_type else {
        return Err(general_protection(gate.selector, instruction));
    };
    let target_dpl = target_record.descriptor.dpl;
    let new_cpl = if conforming { cpl } else { target_dpl };
    if target_dpl > cpl {
        return Err(general_protection(gate.selector, instruction));
    }
    if !target_record.descriptor.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: selector_error_code(gate.selector),
            ip: instruction.decoded.start_ip,
        });
    }
    if gate.offset > target_record.descriptor.limit {
        return Err(general_protection(0, instruction));
    }
    let selector = (gate.selector & !3) | u16::from(cpl);
    if new_cpl < cpl {
        if jump {
            return Err(general_protection(gate.selector, instruction));
        }
        return call_gate::execute_call_gate_stack_switch(
            registers,
            bus,
            instruction,
            next_ip,
            gate,
            target_record,
            new_cpl,
        );
    }
    let descriptor = mark_segment_accessed(bus, target_record)?;
    let cache =
        SegmentCache::from_descriptor((gate.selector & !3) | u16::from(new_cpl), descriptor);
    if jump {
        commit_code_transfer(registers, bus, selector, cache, cpl);
        *next_ip = gate.offset;
    } else {
        let mut next = push_checked_far_frame(
            registers,
            bus,
            [u32::from(registers.cs), return_ip],
            gate.width,
            instruction,
        )?;
        commit_code_transfer(&mut next, bus, selector, cache, cpl);
        *registers = next;
        *next_ip = gate.offset;
    }
    Ok(())
}

fn far_pointer(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<FarPointer, CpuError> {
    match instruction.operand(0) {
        Operand::FarBranch {
            offset,
            segment,
            width,
        } => Ok(FarPointer {
            offset,
            selector: segment,
            width,
        }),
        operand if is_far_indirect(instruction) => {
            let width = far_pointer_width(instruction);
            let Operand::Memory(reference) = operand else {
                return Err(invalid_opcode(instruction));
            };
            let len = usize::from(width) + 2;
            let mut bytes = [0_u8; 6];
            read_bytes(
                bus,
                logical_span(registers, reference, len)?,
                AccessKind::DataRead,
                DataAlignment::Natural(width),
                &mut bytes[..len],
            )?;
            let mut offset_bytes = [0_u8; 4];
            offset_bytes[..usize::from(width)].copy_from_slice(&bytes[..usize::from(width)]);
            let selector_start = usize::from(width);
            Ok(FarPointer {
                offset: u32::from_le_bytes(offset_bytes),
                selector: u16::from_le_bytes([bytes[selector_start], bytes[selector_start + 1]]),
                width,
            })
        }
        _ => Err(invalid_opcode(instruction)),
    }
}

fn parse_call_gate(record: DescriptorRecord) -> CallGate {
    // Intel's gate descriptor has a fixed bit layout that differs by 16/32-bit
    // gate type. Decode it here because a generic wire codec cannot express
    // the descriptor-type-dependent reserved and offset fields.
    let kind = match record.descriptor.descriptor_type {
        DescriptorType::System { system_type } => system_type,
        _ => 0,
    };
    let width = if kind == 4 { 2 } else { 4 };
    let selector = ((record.raw >> 16) & 0xffff) as u16;
    let low_offset = (record.raw & 0xffff) as u32;
    let parameter_count = ((record.raw >> 32) & 0x1f) as u8;
    let offset = if width == 2 {
        low_offset
    } else {
        low_offset | (((record.raw >> 48) as u32 & 0xffff) << 16)
    };
    CallGate {
        selector,
        offset,
        width,
        parameter_count,
    }
}

fn push_checked_far_frame(
    registers: &Registers,
    bus: &mut impl CpuBus,
    values: [u32; 2],
    width: u8,
    instruction: &NormalizedInstruction,
) -> Result<Registers, CpuError> {
    if !matches!(width, 2 | 4) {
        return Err(invalid_opcode(instruction));
    }
    let byte_len = usize::from(width) * values.len();
    let (offset, span) = checked_far_stack_span(registers, bus, byte_len, true, instruction)?;
    let mut bytes = [0_u8; 8];
    // Pushes proceed downward, so the last pushed slot is at the lowest
    // address and must be encoded first in this contiguous frame.
    for (index, value) in values.into_iter().rev().enumerate() {
        let start = index * usize::from(width);
        bytes[start..start + usize::from(width)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
    }
    write_bytes(
        bus,
        span,
        AccessKind::StackWrite,
        DataAlignment::Natural(width),
        &bytes[..byte_len],
    )?;
    let mut next = registers.clone();
    set_stack_pointer(&mut next, bus, offset);
    Ok(next)
}

fn pop_checked_far_frame(
    registers: &Registers,
    bus: &mut impl CpuBus,
    width: u8,
    instruction: &NormalizedInstruction,
) -> Result<(Registers, [u32; 2]), CpuError> {
    if !matches!(width, 2 | 4) {
        return Err(invalid_opcode(instruction));
    }
    let byte_len = usize::from(width) * 2;
    let (next_pointer, span) =
        checked_far_stack_span(registers, bus, byte_len, false, instruction)?;
    let mut bytes = [0_u8; 8];
    read_bytes(
        bus,
        span,
        AccessKind::StackRead,
        DataAlignment::Natural(width),
        &mut bytes[..byte_len],
    )?;
    let mut values = [0_u32; 2];
    for (index, value) in values.iter_mut().enumerate() {
        let start = index * usize::from(width);
        let mut slot = [0_u8; 4];
        slot[..usize::from(width)].copy_from_slice(&bytes[start..start + usize::from(width)]);
        *value = u32::from_le_bytes(slot);
    }
    let mut next = registers.clone();
    set_stack_pointer(&mut next, bus, next_pointer);
    Ok((next, values))
}

fn checked_far_stack_span(
    registers: &Registers,
    bus: &impl CpuBus,
    byte_len: usize,
    pushing: bool,
    instruction: &NormalizedInstruction,
) -> Result<(u32, LogicalSpan), CpuError> {
    let stack32 = bus.stack32();
    let current = stack_pointer(registers, bus);
    let address_limit = if stack32 {
        u64::from(u32::MAX)
    } else {
        u64::from(u16::MAX)
    };
    let byte_len = u64::try_from(byte_len).map_err(|_| stack_wrap_fault(instruction))?;
    let offset = if pushing {
        let amount = u32::try_from(byte_len).map_err(|_| stack_wrap_fault(instruction))?;
        if stack32 {
            u64::from(current.wrapping_sub(amount))
        } else {
            let amount = u16::try_from(byte_len).map_err(|_| stack_wrap_fault(instruction))?;
            u64::from((current as u16).wrapping_sub(amount))
        }
    } else {
        u64::from(current)
    };
    let end = offset
        .checked_add(byte_len)
        .ok_or_else(|| stack_wrap_fault(instruction))?;
    if end > address_limit + 1 {
        return Err(stack_wrap_fault(instruction));
    }
    let offset = u32::try_from(offset).map_err(|_| stack_wrap_fault(instruction))?;
    Ok((
        if pushing { offset } else { end as u32 },
        LogicalSpan {
            register: crate::registers::SegmentRegister::Ss,
            selector: registers.ss,
            offset,
            len: usize::try_from(byte_len).map_err(|_| stack_wrap_fault(instruction))?,
            address32: stack32,
        },
    ))
}

fn stack_wrap_fault(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::StackSegmentFault {
        // Current-stack limit/wrap failures use #SS(0).
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}

fn require_architectural_mode(
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if bus.architectural_mode_active() {
        Ok(())
    } else {
        Err(unsupported_mode(instruction))
    }
}

fn general_protection(selector: u16, instruction: &NormalizedInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: selector_error_code(selector),
        ip: instruction.decoded.start_ip,
    }
}

fn selector_error_code(selector: u16) -> u32 {
    if selector & 0xfffc == 0 {
        0
    } else {
        u32::from(selector & 0xfffc)
    }
}

fn invalid_opcode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::InvalidOpcode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}

fn unsupported_mode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedSystemMode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}
