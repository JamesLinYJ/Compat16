//! Far return frame validation and privilege-stack restoration.

use guest_core::Registers;

use crate::{
    CpuError, CpuExecutionMode,
    memory_access::{AccessKind, CpuBus, DataAlignment, LogicalSpan},
    memory_values::read_bytes,
    registers::SegmentRegister,
    system::{
        DescriptorType, SegmentAccess, SegmentCache, map_fault, mark_segment_accessed,
        read_descriptor,
    },
    x86_decode::NormalizedInstruction,
};

use super::super::stack::{pop_slots, set_stack_pointer, stack_pointer, stack_width};
use super::{pop_checked_far_frame, selector_error_code, unsupported_mode};

pub(super) fn execute(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(), CpuError> {
    let width = stack_width(instruction);
    let mode = bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))?;
    if mode == CpuExecutionMode::Protected {
        execute_protected(registers, bus, instruction, next_ip, width)
    } else {
        execute_real_or_v86(registers, bus, instruction, next_ip, width)
    }
}

fn execute_real_or_v86(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    width: u8,
) -> Result<(), CpuError> {
    let (mut next, values) = if bus.architectural_mode_active() {
        pop_checked_far_frame(registers, bus, width, instruction)?
    } else {
        let mut next = registers.clone();
        let slots = pop_slots(&mut next, bus, 2, width)?;
        if slots.len() != 2 {
            return Err(CpuError::InvalidMemoryAccessPlan {
                ip: instruction.decoded.start_ip,
            });
        }
        (next, [slots[0], slots[1]])
    };
    let selector = values[1] as u16;
    let (cache, cpl) = super::super::segment_load::validate_code_transfer(
        bus,
        selector,
        values[0],
        instruction,
        true,
    )?;
    apply_return_cleanup(&mut next, bus, instruction);
    super::super::segment_load::commit_code_transfer(&mut next, bus, selector, cache, cpl);
    *registers = next;
    *next_ip = values[0];
    Ok(())
}

fn execute_protected(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    width: u8,
) -> Result<(), CpuError> {
    if !bus.architectural_mode_active() || !matches!(width, 2 | 4) {
        return Err(unsupported_mode(instruction));
    }
    let current_cpl = bus
        .current_privilege_level()
        .filter(|value| *value <= 3)
        .ok_or_else(|| unsupported_mode(instruction))?;
    let (mut next, values) = pop_checked_far_frame(registers, bus, width, instruction)?;
    let selector = values[1] as u16;
    let record = read_descriptor(bus, selector)?;
    let return_cpl = record
        .descriptor
        .validate_code_return(selector, current_cpl)
        .map_err(|fault| map_fault(fault, bus))?;
    if values[0] > record.descriptor.limit {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: instruction.decoded.start_ip,
        });
    }

    if return_cpl > current_cpl {
        return execute_outer_return(
            registers,
            bus,
            instruction,
            next_ip,
            width,
            current_cpl,
            return_cpl,
            values[0],
            record,
        );
    }

    let descriptor = mark_segment_accessed(bus, record)?;
    let cache = SegmentCache::from_descriptor((selector & !3) | u16::from(return_cpl), descriptor);
    apply_return_cleanup(&mut next, bus, instruction);
    super::super::segment_load::commit_code_transfer(&mut next, bus, selector, cache, return_cpl);
    *registers = next;
    *next_ip = values[0];
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_outer_return(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    width: u8,
    current_cpl: u8,
    return_cpl: u8,
    return_ip: u32,
    code_record: crate::system::DescriptorRecord,
) -> Result<(), CpuError> {
    let cleanup = if instruction.operand_count == 0 {
        0
    } else {
        u32::from(instruction.decoded.instruction.immediate16())
    };
    let old_pointer = stack_pointer(registers, bus);
    let word = u32::from(width);
    let frame_bytes = usize::try_from(word * 4 + cleanup).map_err(|_| stack_fault(instruction))?;
    validate_old_stack_extent(
        registers,
        bus,
        old_pointer,
        frame_bytes,
        current_cpl,
        instruction,
    )?;
    let new_stack_slot = old_pointer
        .checked_add(word * 2)
        .and_then(|value| value.checked_add(cleanup))
        .ok_or_else(|| stack_fault(instruction))?;
    let slot_bytes = usize::try_from(word * 2).map_err(|_| stack_fault(instruction))?;
    let mut saved_stack = [0_u8; 8];
    let address32 = bus.stack32();
    read_bytes(
        bus,
        LogicalSpan {
            register: SegmentRegister::Ss,
            selector: registers.ss,
            offset: new_stack_slot,
            len: slot_bytes,
            address32,
        },
        AccessKind::StackRead,
        DataAlignment::Natural(width),
        &mut saved_stack[..slot_bytes],
    )?;
    let outer_sp = read_slot(&saved_stack, 0, width);
    let outer_ss = read_slot(&saved_stack, usize::from(width), width) as u16;
    let stack_record = validate_return_stack(bus, outer_ss, return_cpl, instruction)?;

    let code_accessed = mark_segment_accessed(bus, code_record)?;
    let stack_accessed = mark_segment_accessed(bus, stack_record)?;
    let code_selector = (code_record.selector & !3) | u16::from(return_cpl);
    let stack_selector = (outer_ss & !3) | u16::from(return_cpl);
    let code_cache = SegmentCache::from_descriptor(code_selector, code_accessed);
    let stack_cache = SegmentCache::from_descriptor(stack_selector, stack_accessed);

    let mut segments = bus.system().segments;
    let mut next = registers.clone();
    next.cs = code_selector;
    next.ss = stack_selector;
    // RET's immediate cleanup follows the restored SS.B stack-address size,
    // which can differ from the return operand size used to pop ESP:SS.
    let adjusted_sp =
        adjust_outer_stack_pointer(outer_sp, cleanup, stack_cache.descriptor.default_big);
    set_outer_stack_register(&mut next, adjusted_sp, width);
    clear_inaccessible_segments(&mut next, &mut segments, return_cpl);
    segments[0] = code_cache;
    segments[1] = stack_cache;
    let system = bus.system_mut();
    system.segments = segments;
    system.cpl = return_cpl;
    *registers = next;
    *next_ip = return_ip;
    Ok(())
}

fn validate_old_stack_extent(
    registers: &Registers,
    bus: &impl CpuBus,
    pointer: u32,
    length: usize,
    cpl: u8,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let address32 = bus.stack32();
    let max = if address32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    let start = if address32 {
        u64::from(pointer)
    } else {
        u64::from(pointer as u16)
    };
    start
        .checked_add(u64::try_from(length).map_err(|_| stack_fault(instruction))?)
        .filter(|end| *end <= max)
        .ok_or_else(|| stack_fault(instruction))?;
    bus.system().segments[1]
        .descriptor
        .check_access(
            registers.ss,
            SegmentAccess::StackRead,
            cpl,
            (registers.ss & 3) as u8,
            if address32 {
                pointer
            } else {
                pointer as u16 as u32
            },
            length,
        )
        .map_err(|fault| map_fault(fault, bus))
}

fn validate_return_stack(
    bus: &mut impl CpuBus,
    selector: u16,
    cpl: u8,
    instruction: &NormalizedInstruction,
) -> Result<crate::system::DescriptorRecord, CpuError> {
    let error_code = selector_error_code(selector);
    if selector & 0xfffc == 0 {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: instruction.decoded.start_ip,
        });
    }
    let record = read_descriptor(bus, selector)?;
    if selector & 3 != u16::from(cpl)
        || record.descriptor.dpl != cpl
        || !matches!(
            record.descriptor.descriptor_type,
            DescriptorType::Data { writable: true, .. }
        )
    {
        return Err(CpuError::GeneralProtectionFault {
            error_code,
            ip: instruction.decoded.start_ip,
        });
    }
    if !record.descriptor.present {
        return Err(CpuError::StackSegmentFault {
            // The far-return exception table assigns #SS(0) when the
            // restored outer stack segment is not present.
            error_code: 0,
            ip: instruction.decoded.start_ip,
        });
    }
    Ok(record)
}

fn clear_inaccessible_segments(
    registers: &mut Registers,
    segments: &mut [SegmentCache; 6],
    cpl: u8,
) {
    for (index, visible) in [registers.ds, registers.es, registers.fs, registers.gs]
        .into_iter()
        .enumerate()
    {
        let index = index + 2;
        let cache = segments[index];
        if !cache.unusable && !is_accessible(cache.descriptor, visible, cpl) {
            match index {
                2 => registers.ds = 0,
                3 => registers.es = 0,
                4 => registers.fs = 0,
                5 => registers.gs = 0,
                _ => {}
            }
            segments[index] = SegmentCache::unusable(0);
        }
    }
}

fn is_accessible(descriptor: crate::system::SegmentDescriptor, selector: u16, cpl: u8) -> bool {
    match descriptor.descriptor_type {
        DescriptorType::Data { .. }
        | DescriptorType::Code {
            readable: true,
            conforming: false,
            ..
        } => cpl.max((selector & 3) as u8) <= descriptor.dpl,
        DescriptorType::Code {
            readable: true,
            conforming: true,
            ..
        } => true,
        _ => false,
    }
}

fn apply_return_cleanup(
    registers: &mut Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) {
    if instruction.operand_count == 0 {
        return;
    }
    let cleanup = u32::from(instruction.decoded.instruction.immediate16());
    let pointer = stack_pointer(registers, bus).wrapping_add(cleanup);
    set_stack_pointer(registers, bus, pointer);
}

fn adjust_outer_stack_pointer(value: u32, cleanup: u32, stack32: bool) -> u32 {
    if !stack32 {
        // RET's 16-bit stack-address-size cleanup writes SP, preserving the
        // high half of the ESP value loaded by a 32-bit outer return.
        (value & 0xffff_0000) | u32::from((value as u16).wrapping_add(cleanup as u16))
    } else {
        value.wrapping_add(cleanup)
    }
}

fn set_outer_stack_register(registers: &mut Registers, value: u32, width: u8) {
    if width == 2 {
        registers.set_sp(value as u16);
    } else {
        registers.esp = value;
    }
}

fn read_slot(bytes: &[u8], offset: usize, width: u8) -> u32 {
    if width == 2 {
        u32::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
    } else {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
}

fn stack_fault(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::StackSegmentFault {
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}
