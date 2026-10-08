use crate::bios::VIDEO_EQUIPMENT_WORD;
use crate::{BiosDevices, DeviceError};
use guest_core::{GuestMemory, Registers};

/// INT 11h equipment, INT 12h conventional memory, and INT 15h system services.
pub(super) fn dispatch(
    devices: &BiosDevices,
    interrupt: u8,
    regs: &mut Registers,
    memory: &impl GuestMemory,
) -> Result<(), DeviceError> {
    match interrupt {
        0x11 => regs.set_ax(VIDEO_EQUIPMENT_WORD),
        0x12 => regs.set_ax(devices.conventional_memory_kib),
        0x15 => match regs.ax() {
            // Extended-size and E820 queries are not implemented. In
            // particular, no memory map is published, so E820 must not return
            // a fabricated SMAP signature or write an entry to guest memory.
            0xe801 => fail_int15(regs),
            0xe820 => fail_int15(regs),
            _ if regs.ah() == 0x88 => {
                let kib = memory.len().saturating_sub(0x10_0000) / 1024;
                regs.set_ax(kib.min(u32::from(u16::MAX)) as u16);
                regs.set_carry(false);
            }
            _ => fail_int15(regs),
        },
        _ => return Err(DeviceError::UnsupportedInterrupt { interrupt, function: u16::from(regs.ah()) }),
    }
    Ok(())
}

/// Guest-facing failure result for an unsupported INT 15h service.
fn fail_int15(regs: &mut Registers) {
    regs.set_ah(0x86);
    regs.set_carry(true);
}

#[cfg(test)]
#[path = "system_bios_tests.rs"]
mod tests;
