//! IA-32 I/O privilege and TSS bitmap checks.

use super::super::{
    CpuError, CpuExecutionMode,
    memory_access::{AccessKind, AccessRequest, CpuBus},
    x86_decode::NormalizedInstruction,
};
use guest_core::LinearAddr;
use guest_core::io::PortWidth;

const IOPL_MASK: u32 = 0x0000_3000;
const TSS32_IO_MAP_BASE_OFFSET: u32 = 0x66;

pub(super) fn require_port_access(
    bus: &mut impl CpuBus,
    port: u16,
    width: PortWidth,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if !bus.architectural_mode_active() {
        // Checked legacy selectors do not provide a trustworthy CPL/TR pair.
        // Keep their existing host port boundary; do not invent privilege state.
        return Ok(());
    }
    let mode = bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))?;
    if bus.system().execution_mode(bus.instruction_site().eflags) != Some(mode) {
        return Err(unsupported_mode(instruction));
    }
    let cpl = bus
        .current_privilege_level()
        .ok_or_else(|| unsupported_mode(instruction))?;
    if cpl > 3
        || (mode == CpuExecutionMode::RealAddress && cpl != 0)
        || (mode == CpuExecutionMode::Virtual8086 && cpl != 3)
    {
        return Err(unsupported_mode(instruction));
    }
    if mode == CpuExecutionMode::RealAddress {
        return Ok(());
    }
    let iopl = ((bus.instruction_site().eflags & IOPL_MASK) >> 12) as u8;
    if mode == CpuExecutionMode::Protected && cpl <= iopl {
        return Ok(());
    }

    check_bitmap(bus, port, width, instruction)
}

fn check_bitmap(
    bus: &mut impl CpuBus,
    port: u16,
    width: PortWidth,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    // A 16-bit TSS has no I/O-map-base field. A bitmap lookup therefore
    // denies the access as #GP(0) under the IA-32 TSS format.
    let task = bus.system().task;
    if !task.valid || !task.present || task.system_type != 0x0b || task.limit < 0x67 {
        return Err(general_protection(instruction));
    }
    let base_access = bus.prepare(AccessRequest::SystemLinear {
        address: LinearAddr(
            task.base
                .checked_add(TSS32_IO_MAP_BASE_OFFSET)
                .ok_or_else(|| general_protection(instruction))?,
        ),
        len: 2,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut base_bytes = [0_u8; 2];
    bus.read_prepared(&base_access, &mut base_bytes)?;
    let bitmap_base = u32::from(u16::from_le_bytes(base_bytes));

    let first_offset = bitmap_base
        .checked_add(u32::from(port) / 8)
        .ok_or_else(|| general_protection(instruction))?;
    let last_offset = first_offset
        .checked_add(1)
        .ok_or_else(|| general_protection(instruction))?;

    // Generic IA-32 checks the two-byte bitmap window for every I/O access.
    // Widening the port arithmetic preserves the following byte at FFFFh
    // rather than wrapping that part of the window to port zero. The base
    // field is 16-bit, but computed offsets are checked against the actual
    // TSS limit. The extra byte must be present; only selected permission bits
    // are tested, not its full value. This uses generic IA-32 behavior and does
    // not emulate the historical 486 64-KiB bitmap-wrap erratum.
    if last_offset > task.limit {
        return Err(general_protection(instruction));
    }
    let address = task
        .base
        .checked_add(first_offset)
        .ok_or_else(|| general_protection(instruction))?;
    let access = bus.prepare(AccessRequest::SystemLinear {
        address: LinearAddr(address),
        len: 2,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut bytes = [0_u8; 2];
    bus.read_prepared(&access, &mut bytes)?;
    let window = u32::from(u16::from_le_bytes(bytes));
    let width_mask = (1_u32 << u32::from(width.bytes())) - 1;
    let permissions = width_mask << (u32::from(port) & 7);
    if window & permissions != 0 {
        return Err(general_protection(instruction));
    }
    Ok(())
}

fn general_protection(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
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
