//! Protected-mode IRET with staged same/outer-level frames.

use guest_core::Registers;

use crate::{
    CpuError, CpuExecutionMode, CpuModel,
    memory_access::{AccessKind, CpuBus, DataAlignment, LogicalSpan},
    memory_values::read_bytes,
    registers::SegmentRegister,
    system::{DescriptorType, SegmentCache, map_fault, mark_segment_accessed, read_descriptor},
    x86_decode::NormalizedInstruction,
};

use super::{
    flags_transfer::{FlagContext, merge_iret_flag_image},
    segment_load::{commit_code_transfer, validate_code_transfer},
    stack::{set_stack_pointer, stack_pointer},
};

const EFLAGS_NT: u32 = 1 << 14;
const EFLAGS_RF: u32 = 1 << 16;
const EFLAGS_VM: u32 = 1 << 17;

pub(super) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    width: u8,
    context: FlagContext,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let FlagContext::Architectural {
        mode: CpuExecutionMode::Protected,
        cpl,
    } = context
    else {
        return Err(unsupported_mode(instruction));
    };
    if regs.eflags & EFLAGS_NT != 0 {
        return super::super::task_switch::return_from_nested_task(
            regs,
            bus,
            instruction,
            next_ip,
            pending_task_debug,
            model,
        );
    }
    if !matches!(width, 2 | 4) || cpl > 3 {
        return Err(unsupported_mode(instruction));
    }
    let address32 = bus.stack32();
    let pointer = stack_pointer(regs, bus);
    check_nonwrapping_stack_read(pointer, usize::from(width) * 3, address32, instruction)?;
    let mut first = [0_u8; 12];
    let first_len = usize::from(width) * 3;
    read_bytes(
        bus,
        LogicalSpan {
            register: SegmentRegister::Ss,
            selector: regs.ss,
            offset: pointer,
            len: first_len,
            address32,
        },
        AccessKind::StackRead,
        DataAlignment::Natural(width),
        &mut first[..first_len],
    )?;
    let target_ip = read_slot(&first, 0, width);
    let selector = read_slot(&first, usize::from(width), width) as u16;
    let image = read_slot(&first, usize::from(width) * 2, width);
    if width == 4 && cpl == 0 && image & EFLAGS_VM != 0 {
        execute_vm86_entry(regs, bus, instruction, next_ip, context, model)?;
        return Ok(());
    }
    let (code_cache, return_cpl) =
        validate_code_transfer(bus, selector, target_ip, instruction, true)?;
    let mut returned_stack = None;
    let mut total_slots = 3_usize;
    if return_cpl > cpl {
        total_slots = 5;
        let tail_offset = pointer
            .checked_add(first_len as u32)
            .ok_or_else(|| stack_fault(instruction))?;
        check_nonwrapping_stack_read(
            pointer,
            usize::from(width) * total_slots,
            address32,
            instruction,
        )?;
        let mut tail = [0_u8; 8];
        let tail_len = usize::from(width) * 2;
        read_bytes(
            bus,
            LogicalSpan {
                register: SegmentRegister::Ss,
                selector: regs.ss,
                offset: tail_offset,
                len: tail_len,
                address32,
            },
            AccessKind::StackRead,
            DataAlignment::Natural(width),
            &mut tail[..tail_len],
        )?;
        let new_pointer = read_slot(&tail, 0, width);
        let new_selector = read_slot(&tail, usize::from(width), width) as u16;
        if new_selector & 0xfffc == 0 {
            return Err(CpuError::GeneralProtectionFault {
                error_code: 0,
                ip: instruction.decoded.start_ip,
            });
        }
        let record = read_descriptor(bus, new_selector)?;
        record
            .descriptor
            .validate_stack_load(new_selector, return_cpl)
            .map_err(|fault| {
                let error = map_fault(fault, bus);
                match error {
                    // IRET's protected-mode exception table assigns a null
                    // error code to an absent return stack segment.
                    CpuError::StackSegmentFault { ip, .. } => {
                        CpuError::StackSegmentFault { error_code: 0, ip }
                    }
                    other => other,
                }
            })?;
        let descriptor = mark_segment_accessed(bus, record)?;
        let cache_selector = (new_selector & !3) | u16::from(return_cpl);
        returned_stack = Some((
            SegmentCache::from_descriptor(cache_selector, descriptor),
            cache_selector,
            new_pointer,
        ));
    }
    let total_bytes = usize::from(width) * total_slots;
    let old_pointer_after = if address32 {
        // The complete read span was checked without wrapping above. The
        // architectural ESP update itself is still 32-bit arithmetic.
        pointer.wrapping_add(total_bytes as u32)
    } else {
        pointer
            .checked_add(total_bytes as u32)
            .ok_or_else(|| stack_fault(instruction))?
    };
    let mut next = regs.clone();
    next.eflags = merge_protected_iret_flags(regs.eflags, image, width, context, model);
    *next_ip = target_ip;
    if let Some((stack_cache, stack_selector, stack_pointer)) = returned_stack {
        next.ss = stack_selector;
        if width == 4 {
            next.esp = stack_pointer;
        } else {
            next.set_sp(stack_pointer as u16);
        }
        clear_inaccessible_data_segments(&mut next, bus, return_cpl);
        commit_architectural_return(&mut next, bus, code_cache, return_cpl, Some(stack_cache));
    } else {
        set_stack_pointer(&mut next, bus, old_pointer_after);
        commit_code_transfer(&mut next, bus, selector, code_cache, return_cpl);
    }
    *regs = next;
    Ok(())
}

fn execute_vm86_entry(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    context: FlagContext,
    model: CpuModel,
) -> Result<(), CpuError> {
    let pointer = stack_pointer(regs, bus);
    let address32 = bus.stack32();
    let first_len = 3 * 4;
    check_nonwrapping_stack_read(pointer, first_len, address32, instruction)?;
    let mut first = [0_u8; 12];
    read_bytes(
        bus,
        LogicalSpan {
            register: SegmentRegister::Ss,
            selector: regs.ss,
            offset: pointer,
            len: first_len,
            address32,
        },
        AccessKind::StackRead,
        DataAlignment::Natural(4),
        &mut first,
    )?;
    let target_ip = read_slot(&first, 0, 4);
    let selector = read_slot(&first, 4, 4) as u16;
    let flags = read_slot(&first, 8, 4);
    let code_cache = SegmentCache::real_mode(selector, true);
    if target_ip > code_cache.descriptor.limit {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: instruction.decoded.start_ip,
        });
    }
    let total_len = 9 * 4;
    check_nonwrapping_stack_read(pointer, total_len, address32, instruction)?;
    let tail_offset = pointer
        .checked_add(first_len as u32)
        .ok_or_else(|| stack_fault(instruction))?;
    let tail_len = total_len - first_len;
    let mut tail = [0_u8; 24];
    read_bytes(
        bus,
        LogicalSpan {
            register: SegmentRegister::Ss,
            selector: regs.ss,
            offset: tail_offset,
            len: tail_len,
            address32,
        },
        AccessKind::StackRead,
        DataAlignment::Natural(4),
        &mut tail,
    )?;
    let new_sp = read_slot(&tail, 0, 4);
    let new_ss = read_slot(&tail, 4, 4) as u16;
    let new_es = read_slot(&tail, 8, 4) as u16;
    let new_ds = read_slot(&tail, 12, 4) as u16;
    let new_fs = read_slot(&tail, 16, 4) as u16;
    let new_gs = read_slot(&tail, 20, 4) as u16;
    let mut next = regs.clone();
    next.cs = code_cache.selector;
    next.ss = new_ss;
    next.es = new_es;
    next.ds = new_ds;
    next.fs = new_fs;
    next.gs = new_gs;
    next.eip = target_ip;
    next.esp = new_sp;
    next.eflags = merge_protected_iret_flags(regs.eflags, flags, 4, context, model) | EFLAGS_VM;
    let system = bus.system_mut();
    system.segments[0] = SegmentCache::real_mode(next.cs, true);
    system.segments[1] = SegmentCache::real_mode(next.ss, false);
    system.segments[2] = SegmentCache::real_mode(next.ds, false);
    system.segments[3] = SegmentCache::real_mode(next.es, false);
    system.segments[4] = SegmentCache::real_mode(next.fs, false);
    system.segments[5] = SegmentCache::real_mode(next.gs, false);
    system.cpl = 3;
    *next_ip = target_ip;
    *regs = next;
    Ok(())
}

pub(super) fn merge_protected_iret_flags(
    old: u32,
    image: u32,
    width: u8,
    context: FlagContext,
    model: CpuModel,
) -> u32 {
    let merged = merge_iret_flag_image(old, image, width, context, model);
    if width == 4 {
        // IA-32 protected returns restore RF from the 32-bit frame after
        // privilege and segment validation; the shared flag helper leaves
        // this mode-specific field to the protected-return transaction.
        (merged & !EFLAGS_RF) | (image & EFLAGS_RF)
    } else {
        merged
    }
}

fn clear_inaccessible_data_segments(regs: &mut Registers, bus: &impl CpuBus, cpl: u8) {
    for (index, register, visible) in [
        (2, SegmentRegister::Ds, regs.ds),
        (3, SegmentRegister::Es, regs.es),
        (4, SegmentRegister::Fs, regs.fs),
        (5, SegmentRegister::Gs, regs.gs),
    ] {
        let cache = bus.system().segments[index];
        if !cache.unusable && !segment_is_accessible(cache.descriptor, visible, cpl) {
            match register {
                SegmentRegister::Ds => regs.ds = 0,
                SegmentRegister::Es => regs.es = 0,
                SegmentRegister::Fs => regs.fs = 0,
                SegmentRegister::Gs => regs.gs = 0,
                _ => {}
            }
        }
    }
}

fn segment_is_accessible(
    descriptor: crate::system::SegmentDescriptor,
    selector: u16,
    cpl: u8,
) -> bool {
    match descriptor.descriptor_type {
        DescriptorType::Data { .. } => cpl.max((selector & 3) as u8) <= descriptor.dpl,
        DescriptorType::Code {
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

fn commit_architectural_return(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    code: SegmentCache,
    cpl: u8,
    stack: Option<SegmentCache>,
) {
    regs.cs = code.selector;
    let system = bus.system_mut();
    system.segments[0] = code;
    if let Some(stack) = stack {
        system.segments[1] = stack;
    }
    system.cpl = cpl;
    if stack.is_some() {
        for index in 2..6 {
            let cache = system.segments[index];
            let selector = cache.selector;
            if !cache.unusable && !segment_is_accessible(cache.descriptor, selector, cpl) {
                system.segments[index] = SegmentCache::unusable(0);
            }
        }
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

fn check_nonwrapping_stack_read(
    pointer: u32,
    len: usize,
    address32: bool,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let start = if address32 {
        u64::from(pointer)
    } else {
        u64::from(pointer as u16)
    };
    let limit = if address32 {
        u64::from(u32::MAX) + 1
    } else {
        u64::from(u16::MAX) + 1
    };
    let end = u64::try_from(len)
        .ok()
        .and_then(|length| start.checked_add(length));
    if end.is_none_or(|end| end > limit) {
        return Err(stack_fault(instruction));
    }
    Ok(())
}

fn stack_fault(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::StackSegmentFault {
        // A limit/wrap failure on the current IRET stack uses #SS(0).
        error_code: 0,
        ip: instruction.decoded.start_ip,
    }
}

fn unsupported_mode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedSystemMode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}
