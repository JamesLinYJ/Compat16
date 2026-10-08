//! Stack, frame, and stack-width instruction semantics.

use guest_core::{MemoryError, Registers};
use x86_decoder::Code;

use super::super::{CpuError, CpuExecutionMode, read_register, write_register};
use super::super::memory_access::{
    AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan,
};
use super::super::memory_values::{read_prepared_width, read_width, write_prepared_width, write_width};
use super::super::registers::SegmentRegister;
use super::super::x86_decode::{NormalizedInstruction, Operand};
use super::operand::{read_immediate, read_operand, write_operand};

pub(super) fn stack_pointer(regs: &Registers, bus: &impl CpuBus) -> u32 {
    if bus.stack32() { regs.esp } else { u32::from(regs.sp()) }
}

pub(super) fn set_stack_pointer(regs: &mut Registers, bus: &impl CpuBus, value: u32) {
    if bus.stack32() { regs.esp = value; } else { regs.set_sp(value as u16); }
}

fn stack_span(regs: &Registers, bus: &impl CpuBus, offset: u32, len: usize) -> LogicalSpan {
    LogicalSpan {
        register: SegmentRegister::Ss,
        selector: regs.ss,
        offset,
        len,
        address32: bus.stack32(),
    }
}

fn advance_stack(value: u32, amount: u32, bus: &impl CpuBus) -> u32 {
    if bus.stack32() {
        value.wrapping_add(amount)
    } else {
        u32::from((value as u16).wrapping_add(amount as u16))
    }
}

fn retreat_stack(value: u32, amount: u32, bus: &impl CpuBus) -> u32 {
    if bus.stack32() {
        value.wrapping_sub(amount)
    } else {
        u32::from((value as u16).wrapping_sub(amount as u16))
    }
}

pub(super) fn push_stack(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    value: u32,
    width: u8,
) -> Result<(), CpuError> {
    push_stack_sized(regs, bus, value, width, width)
}

fn push_stack_sized(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    value: u32,
    stride: u8,
    byte_len: u8,
) -> Result<(), CpuError> {
    let next = retreat_stack(stack_pointer(regs, bus), u32::from(stride), bus);
    write_width(
        bus,
        stack_span(regs, bus, next, usize::from(byte_len)),
        AccessKind::StackWrite,
        value,
    )?;
    set_stack_pointer(regs, bus, next);
    Ok(())
}

pub(super) fn pop_stack(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    width: u8,
) -> Result<u32, CpuError> {
    pop_stack_sized(regs, bus, width, width)
}

fn pop_stack_sized(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    stride: u8,
    byte_len: u8,
) -> Result<u32, CpuError> {
    let current = stack_pointer(regs, bus);
    let value = read_width(
        bus,
        stack_span(regs, bus, current, usize::from(byte_len)),
        AccessKind::StackRead,
    )?;
    set_stack_pointer(regs, bus, advance_stack(current, u32::from(stride), bus));
    Ok(value)
}

pub(super) fn execute_push(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let stride = stack_operand_width(instruction);
    let operand = instruction.operand(0);
    let byte_len = if matches!(operand, Operand::Segment(_)) { 2 } else { stride };
    let value = read_operand(regs, bus, operand, byte_len)?;
    push_stack_sized(regs, bus, value, stride, byte_len)
}

pub(super) fn execute_pop(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let stride = stack_operand_width(instruction);
    let operand = instruction.operand(0);
    let byte_len = if matches!(operand, Operand::Segment(_)) { 2 } else { stride };
    let mut next = regs.clone();
    let value = pop_stack_sized(&mut next, bus, stride, byte_len)?;
    // POP [ESP] forms its destination with the incremented stack pointer.
    write_operand(&mut next, bus, operand, byte_len, value)?;
    *regs = next;
    Ok(())
}

pub(super) fn execute_pusha(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = stack_operand_width(instruction);
    let initial_sp = stack_pointer(regs, bus);
    if bus.execution_mode() == Some(CpuExecutionMode::RealAddress)
        && matches!(initial_sp, 7 | 9 | 11 | 13 | 15)
    {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: bus.instruction_site().ip,
        });
    }
    let original_sp = if width == 2 { u32::from(regs.sp()) } else { regs.esp };
    let values = [
        read_register(regs, 0, width),
        read_register(regs, 1, width),
        read_register(regs, 2, width),
        read_register(regs, 3, width),
        original_sp,
        read_register(regs, 5, width),
        read_register(regs, 6, width),
        read_register(regs, 7, width),
    ];
    push_slots(regs, bus, &values, width)
}

pub(super) fn push_slots(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    values: &[u32],
    width: u8,
) -> Result<(), CpuError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(values.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    let mut offset = stack_pointer(regs, bus);
    for _ in values {
        offset = retreat_stack(offset, u32::from(width), bus);
        requests.push(AccessRequest::instruction(
            stack_span(regs, bus, offset, usize::from(width)),
            AccessKind::StackWrite,
            DataAlignment::Natural(width),
        ));
    }
    let accesses = bus.prepare_group(&requests)?.into_accesses();
    for (access, value) in accesses.into_iter().zip(values) {
        write_prepared_width(bus, access, width, *value)?;
    }
    set_stack_pointer(regs, bus, offset);
    Ok(())
}

pub(super) fn execute_popa(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = stack_operand_width(instruction);
    let current = stack_pointer(regs, bus);
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(7)
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    let mut offset = current;
    for slot in 0..8 {
        if slot != 3 {
            requests.push(AccessRequest::instruction(
                stack_span(regs, bus, offset, usize::from(width)),
                AccessKind::StackRead,
                DataAlignment::Natural(width),
            ));
        }
        offset = advance_stack(offset, u32::from(width), bus);
    }
    let accesses = bus.prepare_group(&requests)?.into_accesses();
    let mut values = [0_u32; 8];
    let mut access_index = 0;
    for slot in 0..8 {
        if slot != 3 {
            values[slot] = read_prepared_width(bus, &accesses[access_index], width)?;
            access_index += 1;
        }
    }
    let mut next = regs.clone();
    for (slot, index) in [7_u8, 6, 5, 4, 3, 2, 1, 0].into_iter().enumerate() {
        if index != 4 {
            write_register(&mut next, index, width, values[slot]);
        }
    }
    set_stack_pointer(&mut next, bus, offset);
    *regs = next;
    Ok(())
}

pub(super) fn pop_slots(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    count: usize,
    width: u8,
) -> Result<Vec<u32>, CpuError> {
    let current = stack_pointer(regs, bus);
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(count)
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    let mut offset = current;
    for _ in 0..count {
        requests.push(AccessRequest::instruction(
            stack_span(regs, bus, offset, usize::from(width)),
            AccessKind::StackRead,
            DataAlignment::Natural(width),
        ));
        offset = advance_stack(offset, u32::from(width), bus);
    }
    let accesses = bus.prepare_group(&requests)?.into_accesses();
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    for access in &accesses {
        values.push(read_prepared_width(bus, access, width)?);
    }
    set_stack_pointer(regs, bus, offset);
    Ok(values)
}

pub(super) fn execute_enter(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = frame_width(instruction);
    let allocation = read_immediate(instruction, 0)? as u16;
    let nesting = read_immediate(instruction, 1)? as u8 & 0x1f;
    let frame_source = read_register(regs, 5, width);
    let frame_address = if bus.stack32() {
        regs.ebp
    } else {
        u32::from(regs.bp())
    };
    let source_count = usize::from(nesting.saturating_sub(1));
    let push_count = if nesting == 0 { 1 } else { usize::from(nesting) + 1 };
    let old_sp = stack_pointer(regs, bus);
    let first_frame_stack_pointer = retreat_stack(old_sp, u32::from(width), bus);
    // ENTER uses SS.B for push addresses but OperandSize for FrameTemp.
    let first_frame = if width == 4 {
        if bus.stack32() {
            first_frame_stack_pointer
        } else {
            (regs.esp & 0xffff_0000) | u32::from(first_frame_stack_pointer as u16)
        }
    } else {
        u32::from(first_frame_stack_pointer as u16)
    };

    let request_count = source_count
        .checked_add(push_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(CpuError::Memory(MemoryError::AddressOverflow))?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(request_count)
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    let mut stack_offset = old_sp;
    stack_offset = retreat_stack(stack_offset, u32::from(width), bus);
    requests.push(AccessRequest::instruction(
        stack_span(regs, bus, stack_offset, usize::from(width)),
        AccessKind::StackWrite,
        DataAlignment::Natural(width),
    ));
    for level in 1..nesting {
        let offset = retreat_stack(
            frame_address,
            u32::from(level) * u32::from(width),
            bus,
        );
        requests.push(AccessRequest::instruction(
            stack_span(regs, bus, offset, usize::from(width)),
            AccessKind::StackRead,
            DataAlignment::Natural(width),
        ));
        stack_offset = retreat_stack(stack_offset, u32::from(width), bus);
        requests.push(AccessRequest::instruction(
            stack_span(regs, bus, stack_offset, usize::from(width)),
            AccessKind::StackWrite,
            DataAlignment::Natural(width),
        ));
    }
    if nesting != 0 {
        stack_offset = retreat_stack(stack_offset, u32::from(width), bus);
        requests.push(AccessRequest::instruction(
            stack_span(regs, bus, stack_offset, usize::from(width)),
            AccessKind::StackWrite,
            DataAlignment::Natural(width),
        ));
    }
    let post_push_esp = if bus.stack32() {
        stack_offset
    } else {
        (regs.esp & 0xffff_0000) | u32::from(stack_offset as u16)
    };
    // Allocation uses OperandSize; SS.B selects the address form of the probe.
    let allocated_stack_pointer = if width == 4 {
        post_push_esp.wrapping_sub(u32::from(allocation))
    } else {
        (post_push_esp & 0xffff_0000)
            | u32::from((post_push_esp as u16).wrapping_sub(allocation))
    };
    let final_stack_address = if bus.stack32() {
        allocated_stack_pointer
    } else {
        u32::from(allocated_stack_pointer as u16)
    };
    requests.push(AccessRequest::instruction(
        stack_span(regs, bus, final_stack_address, 1),
        AccessKind::StackWrite,
        DataAlignment::Natural(1),
    ));
    let mut accesses = bus.prepare_group(&requests)?.into_accesses();
    // The final allocation pointer is validated but receives no store.
    let _final_stack_probe = accesses.pop().ok_or_else(|| CpuError::InvalidMemoryAccessPlan {
        ip: bus.instruction_site().ip,
    })?;

    // Keep the architected Push/Read sequence after whole-operation preflight:
    // an ancestor can alias the first saved-frame slot that Push(BP) changes.
    let mut accesses = accesses.into_iter();
    let first_push = accesses.next().ok_or_else(|| CpuError::InvalidMemoryAccessPlan {
        ip: bus.instruction_site().ip,
    })?;
    write_prepared_width(bus, first_push, width, frame_source)?;
    for _ in 1..nesting {
        let read_access = accesses.next().ok_or_else(|| CpuError::InvalidMemoryAccessPlan {
            ip: bus.instruction_site().ip,
        })?;
        let value = read_prepared_width(bus, &read_access, width)?;
        let write_access = accesses.next().ok_or_else(|| CpuError::InvalidMemoryAccessPlan {
            ip: bus.instruction_site().ip,
        })?;
        write_prepared_width(bus, write_access, width, value)?;
    }
    if nesting != 0 {
        let frame_push = accesses.next().ok_or_else(|| CpuError::InvalidMemoryAccessPlan {
            ip: bus.instruction_site().ip,
        })?;
        write_prepared_width(bus, frame_push, width, first_frame)?;
    }

    let mut next = regs.clone();
    write_register(&mut next, 5, width, first_frame);
    next.esp = allocated_stack_pointer;
    *regs = next;
    Ok(())
}

pub(super) fn execute_leave(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = if instruction.decoded.instruction.code() == Code::Leaved { 4 } else { 2 };
    let mut next = regs.clone();
    if bus.stack32() {
        next.esp = next.ebp;
    } else {
        next.set_sp(next.bp());
    }
    let value = pop_stack(&mut next, bus, width)?;
    write_register(&mut next, 5, width, value);
    *regs = next;
    Ok(())
}

pub(super) fn stack_width(instruction: &NormalizedInstruction) -> u8 {
    match instruction.decoded.instruction.code() {
        Code::Pushfd | Code::Popfd | Code::Retnd_imm16 | Code::Retnd |
        Code::Retfd_imm16 | Code::Retfd | Code::Iretd => 4,
        _ => 2,
    }
}

pub(super) fn stack_operand_width(instruction: &NormalizedInstruction) -> u8 {
    use Code as C;
    match instruction.decoded.instruction.code() {
        C::Pushad | C::Popad => return 4,
        C::Pushaw | C::Popaw => return 2,
        _ => {}
    }
    if instruction.decoded.instruction.stack_pointer_increment().abs() == 4 { 4 } else { 2 }
}

pub(super) fn frame_width(instruction: &NormalizedInstruction) -> u8 {
    if instruction.decoded.instruction.code() == Code::Enterd_imm16_imm8 { 4 } else { 2 }
}
