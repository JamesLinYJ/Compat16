//! Guest IVT entries for the firmware services implemented by this runtime.
//!
//! Service entries are registered ROM addresses containing ordinary IRET
//! instructions. Guest software can replace an IVT vector or chain to the
//! saved entry with PUSHF/CALL FAR. No guest opcode or application name is used
//! as a private service marker.

use crate::{RuntimeError, DiagnosticKind as Kind, runtime_error};
use x86_cpu::{Cpu, RealModeSegments};
use guest_core::{GuestMemory, PhysAddr, Registers, real_address};
use guest_core::memory::Memory;

const ROM_SEGMENT: u16 = 0xf000;
const SERVICE_BASE: u16 = 0x1000;
const SERVICE_STRIDE: u16 = 4;
const SERVICE_VECTORS: &[u8] = &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1a, 0x20, 0x21, 0x2a, 0x2f, 0x33];
// No resident timer or idle clients are configured. These are actual IRET
// chain ends, replaceable by guest software.
const EMPTY_VECTORS: &[u8] = &[0x1c, 0x28];
pub(crate) const STATUS_FLAGS: u16 = 0x08d5; // OF, SF, ZF, AF, PF, CF; not IF/TF/control bits.

fn entry_offset(vector: u8) -> u16 {
    SERVICE_BASE + u16::from(vector) * SERVICE_STRIDE
}

pub(crate) fn install_service_entries(memory: &mut Memory) -> Result<(), RuntimeError> {
    for &vector in SERVICE_VECTORS.iter().chain(EMPTY_VECTORS) {
        let offset = entry_offset(vector);
        memory.initialize_rom(real_address(ROM_SEGMENT, offset), &[0xcf])
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install interrupt firmware", error))?;
        let mut entry = [0; 4];
        entry[..2].copy_from_slice(&offset.to_le_bytes());
        entry[2..].copy_from_slice(&ROM_SEGMENT.to_le_bytes());
        memory.write(PhysAddr(u32::from(vector) * 4), &entry)
            .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant, "install interrupt vector", error))?;
    }
    Ok(())
}

pub(crate) fn service_vector(segment: u16, offset: u16) -> Option<u8> {
    let address = real_address(segment, offset);
    SERVICE_VECTORS.iter().copied().find(|&vector| {
        real_address(ROM_SEGMENT, entry_offset(vector)) == address
    })
}

pub(crate) fn enter_interrupt(cpu: &mut Cpu, memory: &mut impl GuestMemory, vector: u8) -> Result<(), RuntimeError> {
    if cpu.has_architectural_context() {
        return cpu
            .deliver_external_interrupt(vector, memory, &RealModeSegments)
            .map_err(runtime_error);
    }
    let mut entry = [0; 4];
    memory.read(PhysAddr(u32::from(vector) * 4), &mut entry).map_err(runtime_error)?;
    // The initial machine leaves unconfigured vectors null. This runtime has
    // no firmware implementation for them; explicit failure avoids executing
    // the IVT itself as accidental code. The CPU API still accepts address zero.
    if entry == [0; 4] {
        return Err(RuntimeError::new(Kind::CompatibilityGap, format!("interrupt {vector:02x} has no configured guest handler")));
    }
    cpu.enter_real_mode_interrupt(vector, memory).map_err(runtime_error)
}

fn stack_address(regs: &Registers, displacement: u16) -> PhysAddr {
    real_address(regs.ss, regs.sp().wrapping_add(displacement))
}

pub(crate) fn validate_service_frame(memory: &impl GuestMemory, regs: &Registers) -> Result<(), RuntimeError> {
    for offset in 0..6 {
        memory.validate_read(stack_address(regs, offset), 1).map_err(runtime_error)?;
    }
    for offset in [4, 5] {
        memory.validate_write(stack_address(regs, offset), 1).map_err(runtime_error)?;
    }
    Ok(())
}

pub(crate) fn store_service_return_flags(memory: &mut impl GuestMemory, regs: &Registers) -> Result<(), RuntimeError> {
    validate_service_frame(memory, regs)?;
    let low = stack_address(regs, 4);
    let high = stack_address(regs, 5);
    let previous = u16::from_le_bytes([
        memory.read_u8(low).map_err(runtime_error)?,
        memory.read_u8(high).map_err(runtime_error)?,
    ]);
    let flags = (previous & !STATUS_FLAGS) | ((regs.eflags as u16) & STATUS_FLAGS);
    let bytes = flags.to_le_bytes();
    memory.write_u8(low, bytes[0]).map_err(runtime_error)?;
    memory.write_u8(high, bytes[1]).map_err(runtime_error)?;
    Ok(())
}

#[cfg(test)]
mod tests;
