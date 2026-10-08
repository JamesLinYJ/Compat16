//! Privilege-changing call-gate stack selection and frame construction.

use guest_core::{LinearAddr, Registers};

use crate::{
    CpuError,
    memory_access::{AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan},
    memory_values::{read_prepared_width, write_prepared_width},
    registers::SegmentRegister,
    system::{DescriptorRecord, SegmentCache, map_fault, mark_segment_accessed, read_descriptor},
    x86_decode::NormalizedInstruction,
};

use super::{CallGate, selector_error_code};

pub(super) fn execute_call_gate_stack_switch(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    gate: CallGate,
    target_record: DescriptorRecord,
    target_cpl: u8,
) -> Result<(), CpuError> {
    let stack = call_gate_stack(bus, target_cpl, instruction)?;
    let parameters = read_call_gate_parameters(
        registers,
        bus,
        gate.parameter_count,
        gate.width,
        instruction,
    )?;
    let mut pushes = Vec::new();
    pushes
        .try_reserve_exact(parameters.len() + 4)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    pushes.push(u32::from(registers.ss));
    pushes.push(if gate.width == 2 {
        u32::from(registers.sp())
    } else {
        registers.esp
    });
    pushes.extend(parameters.iter().rev().copied());
    pushes.push(u32::from(registers.cs));
    pushes.push(*next_ip);

    let address32 = stack.cache.descriptor.default_big;
    let pushed_bytes = pushes
        .len()
        .checked_mul(usize::from(gate.width))
        .ok_or_else(|| new_stack_wrap_fault(stack.selector, instruction))?;
    let stack_limit = if address32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    let frame_start = if address32 {
        let decrement = u32::try_from(pushed_bytes)
            .map_err(|_| new_stack_wrap_fault(stack.selector, instruction))?;
        stack.pointer.wrapping_sub(decrement)
    } else {
        let decrement = u16::try_from(pushed_bytes)
            .map_err(|_| new_stack_wrap_fault(stack.selector, instruction))?;
        u32::from((stack.pointer as u16).wrapping_sub(decrement))
    };
    if u64::from(frame_start) + pushed_bytes as u64 > stack_limit {
        return Err(new_stack_wrap_fault(stack.selector, instruction));
    }
    let mut pointer = stack.pointer;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(pushes.len())
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    for _ in &pushes {
        pointer = if address32 {
            pointer.wrapping_sub(u32::from(gate.width))
        } else {
            (pointer & 0xffff_0000)
                | u32::from((pointer as u16).wrapping_sub(u16::from(gate.width)))
        };
        requests.push(AccessRequest::instruction(
            LogicalSpan {
                register: SegmentRegister::Ss,
                selector: stack.selector,
                offset: if address32 { pointer } else { u32::from(pointer as u16) },
                len: usize::from(gate.width),
                address32,
            },
            AccessKind::StackWrite,
            DataAlignment::Natural(gate.width),
        ));
    }
    let mut prepared = bus
        .prepare_group_for_stack(&requests, stack.cache, target_cpl)
        .map_err(|error| map_call_gate_stack_access_error(error, stack.selector))?
        .into_accesses();
    if prepared.len() != pushes.len() {
        return Err(CpuError::InvalidMemoryAccessPlan {
            ip: instruction.decoded.start_ip,
        });
    }

    let code_descriptor = mark_segment_accessed(bus, target_record)?;
    let stack_descriptor = mark_segment_accessed(bus, stack.record)?;
    let code_selector = (gate.selector & !3) | u16::from(target_cpl);
    let code_cache = SegmentCache::from_descriptor(code_selector, code_descriptor);
    let stack_cache = SegmentCache::from_descriptor(stack.selector, stack_descriptor);
    for (access, value) in prepared.drain(..).zip(pushes) {
        write_prepared_width(bus, access, gate.width, value)?;
    }

    let mut next = registers.clone();
    next.cs = code_selector;
    next.eip = gate.offset;
    next.ss = stack.selector;
    if address32 {
        next.esp = pointer;
    } else {
        // Preserve the full ESP image loaded from a 32-bit TSS even though
        // this destination stack uses 16-bit SP addressing.
        next.esp = (stack.pointer & 0xffff_0000) | u32::from(pointer as u16);
    }
    let system = bus.system_mut();
    system.segments[0] = code_cache;
    system.segments[1] = stack_cache;
    system.cpl = target_cpl;
    *registers = next;
    *next_ip = gate.offset;
    Ok(())
}

#[derive(Clone, Copy)]
struct CallStack {
    cache: SegmentCache,
    selector: u16,
    pointer: u32,
    record: DescriptorRecord,
}

fn call_gate_stack(
    bus: &mut impl CpuBus,
    target_cpl: u8,
    instruction: &NormalizedInstruction,
) -> Result<CallStack, CpuError> {
    let task = bus.system().task;
    let task_error = selector_error_code(task.selector);
    if !task.valid || !task.present || !matches!(task.system_type, 0x03 | 0x0b) {
        return Err(CpuError::InvalidTssFault {
            error_code: task_error,
            ip: instruction.decoded.start_ip,
        });
    }
    let is_32 = task.system_type == 0x0b;
    let pointer_offset = if is_32 {
        4_u32 + u32::from(target_cpl) * 8
    } else {
        2_u32 + u32::from(target_cpl) * 4
    };
    let selector_offset = pointer_offset + if is_32 { 4 } else { 2 };
    if selector_offset + 1 > task.limit {
        return Err(CpuError::InvalidTssFault {
            error_code: task_error,
            ip: instruction.decoded.start_ip,
        });
    }
    let address = task
        .base
        .checked_add(pointer_offset)
        .ok_or(CpuError::InvalidTssFault {
            error_code: task_error,
            ip: instruction.decoded.start_ip,
        })?;
    let len = if is_32 { 6 } else { 4 };
    let access = bus.prepare(AccessRequest::SystemLinear {
        address: LinearAddr(address),
        len,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut bytes = [0_u8; 6];
    bus.read_prepared(&access, &mut bytes[..len])?;
    let pointer = if is_32 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let index = if is_32 { 4 } else { 2 };
    let selector = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
    let selector_error = selector_error_code(selector);
    if selector & 0xfffc == 0 {
        return Err(CpuError::InvalidTssFault {
            error_code: selector_error,
            ip: instruction.decoded.start_ip,
        });
    }
    let record = read_descriptor(bus, selector).map_err(|error| match error {
        CpuError::GeneralProtectionFault { .. } => CpuError::InvalidTssFault {
            error_code: selector_error,
            ip: instruction.decoded.start_ip,
        },
        other => other,
    })?;
    record
        .descriptor
        .validate_stack_load(selector, target_cpl)
        .map_err(|fault| match map_fault(fault, bus) {
            CpuError::GeneralProtectionFault { .. } => CpuError::InvalidTssFault {
                error_code: selector_error,
                ip: instruction.decoded.start_ip,
            },
            CpuError::StackSegmentFault { .. } => CpuError::StackSegmentFault {
                error_code: selector_error,
                ip: instruction.decoded.start_ip,
            },
            other => other,
        })?;
    let selector = (selector & !3) | u16::from(target_cpl);
    Ok(CallStack {
        cache: SegmentCache::from_descriptor(selector, record.descriptor),
        selector,
        pointer,
        record,
    })
}

fn read_call_gate_parameters(
    registers: &Registers,
    bus: &mut impl CpuBus,
    count: u8,
    width: u8,
    instruction: &NormalizedInstruction,
) -> Result<Vec<u32>, CpuError> {
    let count = usize::from(count);
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(count)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    let stack32 = bus.stack32();
    let start = if stack32 {
        registers.esp
    } else {
        u32::from(registers.sp())
    };
    let source_bytes = count
        .checked_mul(usize::from(width))
        .ok_or_else(|| stack_wrap_fault(instruction))?;
    if !stack32 && u64::from(start) + u64::try_from(source_bytes).unwrap_or(u64::MAX) > 0x1_0000 {
        return Err(stack_wrap_fault(instruction));
    }
    for index in 0..count {
        let delta = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(u32::from(width)))
            .ok_or_else(|| stack_wrap_fault(instruction))?;
        let offset = if stack32 {
            start
                .checked_add(delta)
                .ok_or_else(|| stack_wrap_fault(instruction))?
        } else {
            u32::from((start as u16).wrapping_add(delta as u16))
        };
        requests.push(AccessRequest::instruction(
            LogicalSpan {
                register: SegmentRegister::Ss,
                selector: registers.ss,
                offset,
                len: usize::from(width),
                address32: stack32,
            },
            AccessKind::StackRead,
            DataAlignment::Natural(width),
        ));
    }
    let mut accesses = bus.prepare_group(&requests)?.into_accesses();
    if accesses.len() != count {
        return Err(CpuError::InvalidMemoryAccessPlan {
            ip: instruction.decoded.start_ip,
        });
    }
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(count)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    for access in accesses.drain(..) {
        parameters.push(read_prepared_width(bus, &access, width)?);
    }
    Ok(parameters)
}

fn stack_wrap_fault(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::StackSegmentFault {
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}

fn new_stack_wrap_fault(selector: u16, instruction: &NormalizedInstruction) -> CpuError {
    CpuError::StackSegmentFault {
        error_code: selector_error_code(selector),
        ip: instruction.decoded.start_ip,
    }
}

fn map_call_gate_stack_access_error(error: CpuError, selector: u16) -> CpuError {
    match error {
        CpuError::GeneralProtectionFault { ip, .. } | CpuError::StackSegmentFault { ip, .. } => {
            CpuError::StackSegmentFault {
                error_code: selector_error_code(selector),
                ip,
            }
        }
        other => other,
    }
}
