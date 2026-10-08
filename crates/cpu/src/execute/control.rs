//! Branch, call, return, interrupt-return, and loop semantics.

use x86_decoder::{Code, InstructionInfoFactory, Mnemonic, Register};
use guest_core::Registers;

use super::super::{CpuError, CpuExecutionMode, CpuModel, ZF};
use super::super::memory_access::{
    AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan,
};
use super::super::memory_values::{read_bytes, read_prepared_width};
use super::super::registers::SegmentRegister;
use super::super::x86_decode::{NormalizedInstruction, Operand};
use super::flags_transfer::{
    check_v86_iopl, check_v86_stack_span, flag_context, merge_iret_flag_image, FlagContext,
};
use super::operand::{branch_target, error_at, logical_span, read_immediate, read_operand};
use super::segment_load::{commit_code_transfer, validate_code_transfer};
use super::stack::{pop_slots, push_slots, set_stack_pointer, stack_pointer, stack_width};

pub(super) fn execute_call(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(), CpuError> {
    let mut next = regs.clone();
    let target_ip;
    match instruction.operand(0) {
        Operand::NearBranch { target, width } => {
            target_ip = target as u32;
            bus.validate_near_code_target(regs.cs, target_ip)?;
            push_slots(&mut next, bus, &[u32::from(*next_ip)], width)?;
        }
        Operand::FarBranch { offset, segment, width } => {
            push_slots(
                &mut next,
                bus,
                &[u32::from(regs.cs), *next_ip],
                width,
            )?;
            next.cs = segment;
            target_ip = offset;
        }
        operand if is_far_indirect(instruction) => {
            let width = far_pointer_width(instruction);
            let (target, selector) = read_far_pointer(regs, bus, operand, width, instruction)?;
            push_slots(
                &mut next,
                bus,
                &[u32::from(regs.cs), *next_ip],
                width,
            )?;
            next.cs = selector;
            target_ip = target;
        }
        operand => {
            let width = instruction.data_width();
            target_ip = read_operand(regs, bus, operand, width)?;
            bus.validate_near_code_target(regs.cs, target_ip)?;
            push_slots(&mut next, bus, &[u32::from(*next_ip)], width)?;
        }
    }
    *regs = next;
    *next_ip = target_ip;
    Ok(())
}

pub(super) fn execute_jump(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(), CpuError> {
    let mut next = regs.clone();
    let target_ip = match instruction.operand(0) {
        Operand::NearBranch { target, .. } => {
            let target = target as u32;
            bus.validate_near_code_target(regs.cs, target)?;
            target
        }
        Operand::FarBranch { offset, segment, .. } => {
            next.cs = segment;
            offset
        }
        operand if is_far_indirect(instruction) => {
            let (target, selector) =
                read_far_pointer(regs, bus, operand, far_pointer_width(instruction), instruction)?;
            next.cs = selector;
            target
        }
        operand => {
            let target = read_operand(regs, bus, operand, instruction.data_width())?;
            bus.validate_near_code_target(regs.cs, target)?;
            target
        }
    };
    *regs = next;
    *next_ip = target_ip;
    Ok(())
}

fn read_far_pointer(
    regs: &Registers,
    bus: &mut impl CpuBus,
    operand: Operand,
    width: u8,
    instruction: &NormalizedInstruction,
) -> Result<(u32, u16), CpuError> {
    let reference = match operand {
        Operand::Memory(reference) => reference,
        _ => return Err(error_at(instruction)),
    };
    if !matches!(width, 2 | 4) {
        return Err(error_at(instruction));
    }
    let len = usize::from(width) + 2;
    let span = logical_span(regs, reference, len).map_err(|_| error_at(instruction))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
    bytes.resize(len, 0);
    read_bytes(
        bus,
        span,
        AccessKind::DataRead,
        DataAlignment::Natural(width),
        &mut bytes,
    )?;
    let mut target_bytes = [0; 4];
    target_bytes[..usize::from(width)].copy_from_slice(&bytes[..usize::from(width)]);
    let selector_offset = usize::from(width);
    let selector = u16::from_le_bytes([bytes[selector_offset], bytes[selector_offset + 1]]);
    Ok((u32::from_le_bytes(target_bytes), selector))
}

pub(super) fn is_far_indirect(instruction: &NormalizedInstruction) -> bool {
    matches!(
        instruction.decoded.instruction.code(),
        Code::Call_m1616 | Code::Call_m1632 | Code::Call_m1664 |
        Code::Jmp_m1616 | Code::Jmp_m1632 | Code::Jmp_m1664
    )
}

pub(super) fn far_pointer_width(instruction: &NormalizedInstruction) -> u8 {
    match instruction.decoded.instruction.code() {
        Code::Call_m1616 | Code::Jmp_m1616 => 2,
        Code::Call_m1632 | Code::Jmp_m1632 => 4,
        _ => instruction.data_width(),
    }
}

pub(super) fn execute_return(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(), CpuError> {
    let width = stack_width(instruction);
    let far = instruction.mnemonic == Mnemonic::Retf;
    let mut next = regs.clone();
    let values = pop_slots(&mut next, bus, if far { 2 } else { 1 }, width)?;
    if far {
        next.cs = values[1] as u16;
    } else {
        bus.validate_near_code_target(regs.cs, values[0])?;
    }
    if instruction.operand_count != 0 {
        let cleanup = read_immediate(instruction, 0)? as u16;
        let pointer = stack_pointer(&next, bus).wrapping_add(u32::from(cleanup));
        set_stack_pointer(&mut next, bus, pointer);
    }
    *regs = next;
    *next_ip = values[0];
    Ok(())
}

pub(super) fn execute_iret(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
    pending_task_debug: &mut bool,
    model: CpuModel,
) -> Result<(), CpuError> {
    let width = stack_width(instruction);
    let context = flag_context(regs, bus, instruction)?;
    if matches!(
        context,
        FlagContext::Architectural {
            mode: CpuExecutionMode::Protected,
            ..
        }
    ) {
        return super::protected_iret::execute(
            regs,
            bus,
            instruction,
            next_ip,
            width,
            context,
            pending_task_debug,
            model,
        );
    }
    if let FlagContext::Architectural { mode, .. } = context {
        check_v86_iopl(regs, mode, instruction)?;
    }
    let code_bits = bus.code_bits();
    if !matches!(code_bits, 16 | 32) {
        return Err(CpuError::InvalidCodeSize(code_bits));
    }
    if matches!(
        context,
        FlagContext::Architectural {
            mode: CpuExecutionMode::Virtual8086,
            ..
        }
    ) && code_bits != 16
    {
        return Err(CpuError::UnsupportedSystemMode {
            opcode: instruction.decoded.opcode,
            ip: instruction.decoded.start_ip,
        });
    }

    let mut next = regs.clone();
    let current = stack_pointer(&next, bus);
    let address32 = bus.stack32();
    check_v86_stack_span(regs, bus, width, 3, false, context, instruction)?;
    let frame_len = usize::from(width) * 3;
    let next_stack_pointer = if address32 {
        current.wrapping_add(frame_len as u32)
    } else {
        u32::from((current as u16).wrapping_add(frame_len as u16))
    };
    let mut values = [0_u32; 3];
    match context {
        FlagContext::LegacyProjection => {
            // The selector-only Win16 projection has no imported hidden SS
            // cache or stack-size state. Keep its checked per-slot resolver
            // plan while preparing every slot before reading.
            let mut requests = Vec::new();
            requests
                .try_reserve_exact(3)
                .map_err(|_| CpuError::Memory(guest_core::MemoryError::AllocationFailed))?;
            let mut offset = current;
            for _ in 0..3 {
                requests.push(AccessRequest::instruction(
                    LogicalSpan {
                        register: SegmentRegister::Ss,
                        selector: next.ss,
                        offset,
                        len: usize::from(width),
                        address32,
                    },
                    AccessKind::StackRead,
                    DataAlignment::Natural(width),
                ));
                offset = if address32 {
                    offset.wrapping_add(u32::from(width))
                } else {
                    u32::from((offset as u16).wrapping_add(u16::from(width)))
                };
            }
            let accesses = bus.prepare_group(&requests)?.into_accesses();
            if accesses.len() != 3 {
                return Err(CpuError::InvalidMemoryAccessPlan {
                    ip: bus.instruction_site().ip,
                });
            }
            for index in 0..3 {
                values[index] = read_prepared_width(bus, &accesses[index], width)?;
            }
        }
        FlagContext::Architectural { .. } => {
            // One contiguous checked span prevents a 16-bit SP frame from
            // wrapping between slots. A frame ending at 0x10000 remains valid.
            let mut frame = [0_u8; 12];
            read_bytes(
                bus,
                LogicalSpan {
                    register: SegmentRegister::Ss,
                    selector: next.ss,
                    offset: current,
                    len: frame_len,
                    address32,
                },
                AccessKind::StackRead,
                DataAlignment::Natural(width),
                &mut frame[..frame_len],
            )?;
            for (index, value) in values.iter_mut().enumerate() {
                let start = index * usize::from(width);
                *value = if width == 2 {
                    u32::from(u16::from_le_bytes([frame[start], frame[start + 1]]))
                } else {
                    u32::from_le_bytes([
                        frame[start],
                        frame[start + 1],
                        frame[start + 2],
                        frame[start + 3],
                    ])
                };
            }
        }
    }

    let target_ip = if width == 2 {
        values[0] & 0xffff
    } else {
        values[0]
    };
    if (matches!(
        context,
        FlagContext::Architectural {
            mode: CpuExecutionMode::Virtual8086,
            ..
        }
    ) || code_bits == 16)
        && target_ip > u16::MAX as u32
    {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: instruction.decoded.start_ip,
        });
    }
    let code_transfer = match context {
        FlagContext::Architectural { .. } => {
            let (cache, target_cpl) =
                validate_code_transfer(bus, values[1] as u16, target_ip, instruction, true)?;
            if target_ip > cache.descriptor.limit {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: instruction.decoded.start_ip,
                });
            }
            Some((cache, target_cpl))
        }
        FlagContext::LegacyProjection => {
            // Validate the far target through the checked selector resolver;
            // do not synthesize a real-mode hidden CS cache for this path.
            bus.prepare(AccessRequest::instruction(
                LogicalSpan {
                    register: SegmentRegister::Cs,
                    selector: values[1] as u16,
                    offset: target_ip,
                    len: 1,
                    address32: code_bits == 32,
                },
                AccessKind::Fetch,
                DataAlignment::Unaligned,
            ))?;
            None
        }
    };

    set_stack_pointer(&mut next, bus, next_stack_pointer);
    next.eflags = merge_iret_flag_image(regs.eflags, values[2], width, context, model);
    if let Some((cache, target_cpl)) = code_transfer {
        commit_code_transfer(&mut next, bus, values[1] as u16, cache, target_cpl);
    } else {
        next.cs = values[1] as u16;
    }
    *regs = next;
    *next_ip = target_ip;
    Ok(())
}

pub(super) fn execute_loop(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(), CpuError> {
    let is_32 = instruction.mnemonic == Mnemonic::Jecxz || instruction_uses_ecx(instruction);
    let count = if is_32 { regs.ecx } else { u32::from(regs.cx()) };
    let count_result = if instruction.mnemonic == Mnemonic::Jcxz || instruction.mnemonic == Mnemonic::Jecxz {
        None
    } else {
        let next_count = count.wrapping_sub(1);
        Some(next_count)
    };
    let should_jump = match count_result {
        None => count == 0,
        Some(next_count) => next_count != 0 && match instruction.mnemonic {
            Mnemonic::Loope => regs.eflags & ZF != 0,
            Mnemonic::Loopne => regs.eflags & ZF == 0,
            _ => true,
        },
    };
    let target = if should_jump {
        let target = branch_target(instruction, 0)?;
        bus.validate_near_code_target(regs.cs, target)?;
        Some(target)
    } else {
        None
    };
    if let Some(next_count) = count_result {
        if is_32 {
            regs.ecx = next_count;
        } else {
            regs.set_cx(next_count as u16);
        }
    }
    if let Some(target) = target {
        *next_ip = target;
    }
    Ok(())
}

pub(super) fn instruction_uses_ecx(instruction: &NormalizedInstruction) -> bool {
    let mut factory = InstructionInfoFactory::new();
    factory
        .info(&instruction.decoded.instruction)
        .used_registers()
        .iter()
        .any(|register| register.register() == Register::ECX)
}

pub(super) fn jump_condition_code(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Jo => 0,
        Mnemonic::Jno => 1,
        Mnemonic::Jb => 2,
        Mnemonic::Jae => 3,
        Mnemonic::Je => 4,
        Mnemonic::Jne => 5,
        Mnemonic::Jbe => 6,
        Mnemonic::Ja => 7,
        Mnemonic::Js => 8,
        Mnemonic::Jns => 9,
        Mnemonic::Jp => 10,
        Mnemonic::Jnp => 11,
        Mnemonic::Jl => 12,
        Mnemonic::Jge => 13,
        Mnemonic::Jle => 14,
        Mnemonic::Jg => 15,
        _ => return None,
    })
}
