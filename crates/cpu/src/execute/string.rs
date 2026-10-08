//! Implicit string and repeat-prefix instruction semantics.

use x86_decoder::{Mnemonic, OpKind, Register};
use guest_core::Registers;

use super::super::{
    alu_compute, apply_flags, read_register, read_segment, write_register, AluOp, CpuError, DF, TF,
    ZF,
};
use super::super::memory_access::{
    AccessKind, AccessRequest, CpuBus, DataAlignment, DataBreakpointHits, LogicalSpan,
};
use super::super::memory_values::{read_prepared_width, write_prepared_width};
use super::super::x86_decode::{NormalizedInstruction, Operand};
use super::super::registers::SegmentRegister;
use super::operand::error_at;

pub(super) fn execute_string(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
    next_ip: &mut u32,
) -> Result<(bool, DataBreakpointHits), CpuError> {
    let mnemonic = instruction.mnemonic;
    let (operation, width) = match mnemonic {
        Mnemonic::Movsb => (0xa4, 1),
        Mnemonic::Movsw => (0xa4, 2),
        Mnemonic::Movsd => (0xa4, 4),
        Mnemonic::Cmpsb => (0xa6, 1),
        Mnemonic::Cmpsw => (0xa6, 2),
        Mnemonic::Cmpsd => (0xa6, 4),
        Mnemonic::Stosb => (0xaa, 1),
        Mnemonic::Stosw => (0xaa, 2),
        Mnemonic::Stosd => (0xaa, 4),
        Mnemonic::Lodsb => (0xac, 1),
        Mnemonic::Lodsw => (0xac, 2),
        Mnemonic::Lodsd => (0xac, 4),
        Mnemonic::Scasb => (0xae, 1),
        Mnemonic::Scasw => (0xae, 2),
        Mnemonic::Scasd => (0xae, 4),
        _ => return Err(error_at(instruction)),
    };
    let address32 = instruction
        .operands
        .iter()
        .take(usize::from(instruction.operand_count))
        .find_map(|operand| match operand {
            Operand::Memory(reference) => Some(reference.address32),
            _ => None,
        })
        .unwrap_or(false);
    let source_segment = instruction
        .operands
        .iter()
        .take(usize::from(instruction.operand_count))
        .find_map(|operand| match operand {
            Operand::Memory(reference) if reference.base == Register::SI || reference.base == Register::ESI => {
                Some(reference.segment)
            }
            _ => None,
        })
        .unwrap_or(SegmentRegister::Ds);
    let repeated = instruction.repeated.is_some();
    let mut remaining = if address32 { regs.ecx } else { u32::from(regs.cx()) };
    if repeated && remaining == 0 {
        return Ok((false, DataBreakpointHits::default()));
    }

    let mut iterations = 0_u32;
    let mut data_breakpoint_hits = DataBreakpointHits::default();
    let mut continue_by_flags = true;
    let budget = if repeated { 4096 } else { 1 };
    let delta = if regs.eflags & DF != 0 {
        0_u32.wrapping_sub(u32::from(width))
    } else {
        u32::from(width)
    };

    while iterations < budget && (!repeated || remaining != 0) && continue_by_flags {
        let source_index = if address32 { regs.esi } else { u32::from(regs.si()) };
        let destination_index = if address32 { regs.edi } else { u32::from(regs.di()) };
        let accumulator = read_register(regs, 0, width);
        let source_span = LogicalSpan {
            register: source_segment,
            selector: read_segment(regs, source_segment),
            offset: source_index,
            len: usize::from(width),
            address32,
        };
        let destination_span = LogicalSpan {
            register: SegmentRegister::Es,
            selector: regs.es,
            offset: destination_index,
            len: usize::from(width),
            address32,
        };
        let alignment = DataAlignment::Natural(width);
        let source_read = AccessRequest::instruction(source_span, AccessKind::DataRead, alignment);
        let destination_read =
            AccessRequest::instruction(destination_span, AccessKind::DataRead, alignment);
        let destination_write =
            AccessRequest::instruction(destination_span, AccessKind::DataWrite, alignment);
        let (requests, request_count) = match operation {
            0xa4 => ([source_read, destination_write], 2),
            0xa6 => ([source_read, destination_read], 2),
            0xaa => ([destination_write, destination_write], 1),
            0xac => ([source_read, source_read], 1),
            0xae => ([destination_read, destination_read], 1),
            _ => return Err(error_at(instruction)),
        };
        let mut accesses = bus.prepare_group(&requests[..request_count])?.into_accesses();
        if accesses.len() != request_count {
            return Err(CpuError::InvalidMemoryAccessPlan { ip: bus.instruction_site().ip });
        }
        match operation {
            0xa4 => {
                let value = read_prepared_width(bus, &accesses[0], width)?;
                write_prepared_width(bus, accesses.remove(1), width, value)?;
                update_index(regs, 6, address32, source_index.wrapping_add(delta));
                update_index(regs, 7, address32, destination_index.wrapping_add(delta));
            }
            0xa6 => {
                let left = read_prepared_width(bus, &accesses[0], width)?;
                let right = read_prepared_width(bus, &accesses[1], width)?;
                let (_, mask, flags) = alu_compute(regs, AluOp::Cmp, left, right, width);
                apply_flags(regs, mask, flags);
                update_index(regs, 6, address32, source_index.wrapping_add(delta));
                update_index(regs, 7, address32, destination_index.wrapping_add(delta));
            }
            0xaa => {
                write_prepared_width(bus, accesses.remove(0), width, accumulator)?;
                update_index(regs, 7, address32, destination_index.wrapping_add(delta));
            }
            0xac => {
                let value = read_prepared_width(bus, &accesses[0], width)?;
                write_register(regs, 0, width, value);
                update_index(regs, 6, address32, source_index.wrapping_add(delta));
            }
            0xae => {
                let right = read_prepared_width(bus, &accesses[0], width)?;
                let (_, mask, flags) = alu_compute(regs, AluOp::Cmp, accumulator, right, width);
                apply_flags(regs, mask, flags);
                update_index(regs, 7, address32, destination_index.wrapping_add(delta));
            }
            _ => return Err(error_at(instruction)),
        }
        iterations += 1;
        // Drain per-iteration hits so a REP string instruction can trap after
        // the matching transfer without leaking them into its continuation.
        let iteration_hits = bus.take_data_breakpoint_hits();
        data_breakpoint_hits = if iteration_hits.enabled != 0 {
            // Report the breakpoint conditions sampled on the trapping REP
            // iteration, not disabled matches from earlier iterations.
            iteration_hits
        } else {
            data_breakpoint_hits.union(iteration_hits)
        };
        if repeated {
            remaining = remaining.wrapping_sub(1);
            if address32 {
                regs.ecx = remaining;
            } else {
                regs.set_cx(remaining as u16);
            }
            if matches!(operation, 0xa6 | 0xae) {
                let equal = regs.eflags & ZF != 0;
                continue_by_flags = match instruction.repeated {
                    Some(true) => equal,
                    Some(false) => !equal,
                    None => true,
                };
            }
        }
        if (iteration_hits.enabled != 0 || regs.eflags & TF != 0)
            && repeated
            && remaining != 0
        {
            break;
        }
    }
    let unfinished_repeat = repeated && remaining != 0 && continue_by_flags;
    if unfinished_repeat {
        *next_ip = instruction.decoded.start_ip;
    }
    Ok((unfinished_repeat, data_breakpoint_hits))
}

pub(super) fn is_implicit_string(instruction: &NormalizedInstruction) -> bool {
    (0..instruction.decoded.instruction.op_count()).any(|index| {
        matches!(
            instruction.decoded.instruction.op_kind(index),
            OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
        )
    })
}

pub(super) fn update_index(regs: &mut Registers, index: u8, address32: bool, value: u32) {
    write_register(regs, index, if address32 { 4 } else { 2 }, value);
}
