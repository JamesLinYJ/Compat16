use crate::bios::VIDEO_EQUIPMENT_WORD;
use crate::{BiosDevices, DeviceAction, DeviceError, DispatchOutcome};
use guest_core::{GuestMemory, Registers};

/// INT 11h equipment, INT 12h conventional memory, and INT 15h system services.
pub(super) fn dispatch(
    devices: &mut BiosDevices,
    interrupt: u8,
    regs: &mut Registers,
    memory: &impl GuestMemory,
    outcome: &mut DispatchOutcome,
) -> Result<(), DeviceError> {
    match interrupt {
        0x11 => regs.set_ax(if devices.cmos_posted {
            devices.cmos().equipment_word()
        } else {
            VIDEO_EQUIPMENT_WORD
        }),
        0x12 => regs.set_ax(devices.conventional_memory_kib),
        0x15 => dispatch_int15(devices, regs, memory, outcome),
        _ => return Err(DeviceError::UnsupportedInterrupt { interrupt, function: u16::from(regs.ah()) }),
    }
    Ok(())
}

fn dispatch_int15(
    devices: &mut BiosDevices,
    regs: &mut Registers,
    memory: &impl GuestMemory,
    outcome: &mut DispatchOutcome,
) {
    match regs.ah() {
        0x24 => dispatch_a20(devices, regs, outcome),
        0x83 => dispatch_interval(devices, regs),
        0x86 => {
            if devices.cmos().user_wait_active() {
                regs.set_ah(0x80);
                regs.set_carry(true);
            } else {
                // The wait is satisfied inside this call. The HLE service does
                // not stall the host or the guest CPU.
                regs.set_ah(0);
                regs.set_carry(false);
            }
        }
        0x88 => {
            let kib = if devices.cmos_posted {
                devices.cmos().extended_memory_kib()
            } else {
                let measured = memory.len().saturating_sub(0x10_0000) / 1024;
                u16::try_from(measured).unwrap_or(u16::MAX)
            };
            regs.set_ax(kib);
            regs.set_carry(false);
        }
        // Extended-size and E820 queries are not implemented. In particular,
        // no memory map is published, so E820 must not return a fabricated
        // SMAP signature or write an entry to guest memory.
        _ => fail_int15(regs),
    }
}

fn dispatch_a20(devices: &mut BiosDevices, regs: &mut Registers, outcome: &mut DispatchOutcome) {
    match regs.al() {
        0x00 | 0x01 => {
            let enabled = regs.al() == 0x01;
            devices.set_a20_enabled(enabled);
            outcome.actions.push(DeviceAction::SetA20Gate { enabled });
            regs.set_ah(0);
            regs.set_carry(false);
        }
        0x02 => {
            regs.set_ah(0);
            regs.set_al(0);
            regs.set_bh(u8::from(devices.a20_enabled()));
            regs.set_bl(0);
            regs.set_carry(false);
        }
        0x03 => {
            regs.set_ah(0);
            regs.set_bx(0x0003);
            regs.set_carry(false);
        }
        _ => fail_int15(regs),
    }
}

fn dispatch_interval(devices: &mut BiosDevices, regs: &mut Registers) {
    match regs.al() {
        0x00 => {
            let microseconds = (u32::from(regs.cx()) << 16) | u32::from(regs.dx());
            if devices.cmos().arm_user_wait(microseconds, regs.es, regs.bx()) {
                regs.set_ah(0);
                regs.set_carry(false);
            } else {
                regs.set_ah(0x80);
                regs.set_carry(true);
            }
        }
        0x01 => {
            devices.cmos().cancel_user_wait();
            regs.set_ah(0);
            regs.set_carry(false);
        }
        _ => fail_int15(regs),
    }
}

/// Guest-facing failure result for an unsupported INT 15h service.
fn fail_int15(regs: &mut Registers) {
    regs.set_ah(0x86);
    regs.set_carry(true);
}

#[cfg(test)]
#[path = "system_bios_tests.rs"]
mod tests;
