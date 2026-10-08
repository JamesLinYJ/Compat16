//! Banked VBE 1.2 BIOS functions for the modeled packed-pixel adapter.

mod control;
mod info;

use super::VgaDevice;
use crate::DeviceError;
use guest_core::{GuestMemory, PhysAddr, Registers, real_address};

const VBE_FUNCTION: u8 = 0x4f;
const VBE_SUCCESS: u16 = 0x004f;
const VBE_FAILURE: u16 = 0x014f;

/// Dispatch INT 10h VBE functions. Unknown VBE functions return the standard
/// VBE failure status; non-VBE BIOS calls are left to the caller.
pub fn dispatch(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<bool, DeviceError> {
    if regs.ah() != VBE_FUNCTION {
        return Ok(false);
    }

    match regs.al() {
        0x00 => dispatch_controller_info(regs, memory)?,
        0x01 => dispatch_mode_info(regs, memory)?,
        0x02 => control::set_mode(vga, regs),
        0x03 => control::get_mode(vga, regs),
        0x04 => super::vbe_state::dispatch_state(vga, regs, memory)?,
        0x05..=0x08 => control::dispatch(vga, regs),
        _ => regs.set_ax(VBE_FAILURE),
    }
    Ok(true)
}

fn dispatch_controller_info(
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    let address = real_address(regs.es, regs.di()).0;
    let Some(block) = info::controller_block(address) else {
        regs.set_ax(VBE_FAILURE);
        return Ok(());
    };
    write_guest_block(memory, address, &block)?;
    regs.set_ax(VBE_SUCCESS);
    Ok(())
}

fn dispatch_mode_info(
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    let Some(block) = info::mode_info_block(regs.cx()) else {
        regs.set_ax(VBE_FAILURE);
        return Ok(());
    };
    let address = real_address(regs.es, regs.di()).0;
    write_guest_block(memory, address, &block)?;
    regs.set_ax(VBE_SUCCESS);
    Ok(())
}

fn write_guest_block(
    memory: &mut impl GuestMemory,
    address: u32,
    bytes: &[u8],
) -> Result<(), DeviceError> {
    let address = PhysAddr(address);
    memory.validate_write(address, bytes.len())?;
    memory.write(address, bytes)?;
    Ok(())
}

pub(super) fn fail(regs: &mut Registers) {
    regs.set_ax(VBE_FAILURE);
}

pub(super) fn succeed(regs: &mut Registers) {
    regs.set_ax(VBE_SUCCESS);
}

#[cfg(test)]
#[path = "vbe/tests.rs"]
mod tests;
