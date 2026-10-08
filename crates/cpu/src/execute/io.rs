//! Scalar and string I/O instructions on the emulated device bus.

use guest_core::Registers;
use guest_core::io::{PortIo, PortWidth};
use x86_decoder::Mnemonic;

use super::io_permission::require_port_access;
use super::operand::{error_at, logical_span, operand_width, read_operand, write_operand};
use crate::memory_access::{AccessKind, AccessRequest, CpuBus, DataAlignment, DataBreakpointHits};
use crate::memory_values::{read_prepared_width, write_prepared_width};
use crate::x86_decode::{DecodedInstruction, NormalizedInstruction, Operand};
use crate::{CpuError, DF, TF};

/// Returns None for non-I/O instructions. String operations yield after a
/// bounded number of transfers, retaining IP and the remaining CX/ECX count;
/// the boolean explicitly reports an unfinished REP boundary.
pub(crate) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    ports: &mut impl PortIo,
    decoded: DecodedInstruction,
) -> Result<Option<(u32, bool, DataBreakpointHits)>, CpuError> {
    use Mnemonic as M;
    let instruction = NormalizedInstruction::new(decoded);
    let mnemonic = instruction.mnemonic;
    if matches!(mnemonic, M::In | M::Out) {
        let input = mnemonic == M::In;
        let data_operand = usize::from(!input);
        let port_operand = usize::from(input);
        let port = read_operand(regs, bus, instruction.operand(port_operand), 2)? as u16;
        let width = bus_width(operand_width(&instruction, data_operand), &instruction)?;
        require_port_access(bus, port, width, &instruction)?;
        if input {
            let value = ports.read(port, width).map_err(CpuError::Io)? & width.mask();
            write_operand(
                regs,
                bus,
                instruction.operand(data_operand),
                width.bytes(),
                value,
            )?;
        } else {
            let value = read_operand(regs, bus, instruction.operand(data_operand), width.bytes())?;
            ports
                .write(port, width, value & width.mask())
                .map_err(CpuError::Io)?;
        }
        return Ok(Some((
            decoded.next_ip,
            false,
            bus.take_data_breakpoint_hits(),
        )));
    }

    let (input, width) = match mnemonic {
        M::Insb => (true, PortWidth::Byte),
        M::Insw => (true, PortWidth::Word),
        M::Insd => (true, PortWidth::Dword),
        M::Outsb => (false, PortWidth::Byte),
        M::Outsw => (false, PortWidth::Word),
        M::Outsd => (false, PortWidth::Dword),
        _ => return Ok(None),
    };
    let memory_operand = usize::from(!input);
    let reference = match instruction.operand(memory_operand) {
        Operand::Memory(reference) => reference,
        _ => return Err(error_at(&instruction)),
    };
    let repeated = instruction.repeated.is_some();
    let mut remaining = if reference.address32 {
        regs.ecx
    } else {
        u32::from(regs.cx())
    };
    if repeated && remaining == 0 {
            return Ok(Some((decoded.next_ip, false, DataBreakpointHits::default())));
    }
    require_port_access(bus, regs.dx(), width, &instruction)?;
    let direction = if regs.eflags & DF == 0 {
        u32::from(width.bytes())
    } else {
        0_u32.wrapping_sub(u32::from(width.bytes()))
    };
    let transfers = if repeated { remaining.min(4096) } else { 1 };
    let mut data_breakpoint_hits = DataBreakpointHits::default();
    for _ in 0..transfers {
        let span = logical_span(regs, reference, usize::from(width.bytes()))?;
        let kind = if input {
            AccessKind::DataWrite
        } else {
            AccessKind::DataRead
        };
        let access = bus.prepare(AccessRequest::instruction(
            span,
            kind,
            DataAlignment::Natural(width.bytes()),
        ))?;
        if input {
            // Plan and validate INS's complete destination before consuming input.
            let value = ports.read(regs.dx(), width).map_err(CpuError::Io)? & width.mask();
            write_prepared_width(bus, access, width.bytes(), value)?;
            if reference.address32 {
                regs.edi = regs.edi.wrapping_add(direction);
            } else {
                regs.set_di(regs.di().wrapping_add(direction as u16));
            }
        } else {
            // OUTS must finish its guest read before the port write can occur.
            let value = read_prepared_width(bus, &access, width.bytes())?;
            ports
                .write(regs.dx(), width, value & width.mask())
                .map_err(CpuError::Io)?;
            if reference.address32 {
                regs.esi = regs.esi.wrapping_add(direction);
            } else {
                regs.set_si(regs.si().wrapping_add(direction as u16));
            }
        }
        if repeated {
            remaining -= 1;
            if reference.address32 {
                regs.ecx = remaining;
            } else {
                regs.set_cx(remaining as u16);
            }
        }
        let iteration_hits = bus.take_data_breakpoint_hits();
        data_breakpoint_hits = if iteration_hits.enabled != 0 {
            iteration_hits
        } else {
            data_breakpoint_hits.union(iteration_hits)
        };
        if (iteration_hits.enabled != 0 || regs.eflags & TF != 0)
            && repeated
            && remaining != 0
        {
            break;
        }
    }
    let unfinished_repeat = repeated && remaining != 0;
    Ok(Some((
        if unfinished_repeat {
            decoded.start_ip
        } else {
            decoded.next_ip
        },
        unfinished_repeat,
        data_breakpoint_hits,
    )))
}

fn bus_width(bytes: u8, instruction: &NormalizedInstruction) -> Result<PortWidth, CpuError> {
    match bytes {
        1 => Ok(PortWidth::Byte),
        2 => Ok(PortWidth::Word),
        4 => Ok(PortWidth::Dword),
        _ => Err(error_at(instruction)),
    }
}

#[cfg(test)]
mod tests;
