//! INT 13h results for a machine with no attached BIOS block device.
//!
//! Directory-backed DOS files are not block devices and must not appear as
//! BIOS drives. The response shapes here follow IBM's *PS/2 and PC BIOS
//! Interface Technical Reference*, Apr. 1987, INT 13h diskette pages 2-48 to
//! 2-54 and fixed-disk pages 2-57 to 2-58. The EDD probe is a normal unsupported
//! result; it does not fabricate the 55AAh signature or a capability bitmap.
//!
use crate::DeviceError;
use guest_core::{GuestMemory, Registers};

const INVALID_COMMAND: u8 = 0x01;
const DRIVE_NOT_READY: u8 = 0x80;

/// Dispatch INT 13h for a configuration with no floppy or fixed-disk device.
///
/// This deliberately performs no guest-buffer access. Read, write, verify,
/// reset, and change-line requests report a BIOS failure; drive-presence and
/// geometry queries use their documented absence values.
pub fn dispatch(
    regs: &mut Registers,
    _memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    let function = regs.ah();
    let drive = regs.dl();

    match function {
        // Reset and status queries cannot succeed when no drive/controller is
        // installed. AH=80h is the documented not-ready status.
        0x00 | 0x01 => fail(regs, DRIVE_NOT_READY),

        // No drive exists to transfer or verify sectors. In particular, do
        // not read/write ES:BX on behalf of a DOS host-directory drive.
        0x02..=0x07 => fail(regs, DRIVE_NOT_READY),

        // IBM AT-compatible diskette BIOSes report an absent floppy with zero
        // parameters and CF clear. Fixed-disk AH=08h reports an error when no
        // disk/controller is attached, with zero geometry.
        0x08 if drive < 0x80 => {
            regs.set_ax(0);
            regs.set_bx(0);
            regs.set_cx(0);
            regs.set_dx(0);
            regs.set_di(0);
            regs.es = 0;
            regs.set_carry(false);
        }
        0x08 => {
            regs.set_ah(INVALID_COMMAND);
            regs.set_cx(0);
            regs.set_dx(0);
            regs.set_carry(true);
        }

        // AH=15h reports absence in AH with CF clear for both diskette and
        // fixed-disk namespaces. CX:DX is zero because no blocks are present.
        0x15 => {
            regs.set_ax(0);
            regs.set_cx(0);
            regs.set_dx(0);
            regs.set_carry(false);
        }

        // No diskette-change signal can be read when the drive is absent.
        0x16 => fail(regs, DRIVE_NOT_READY),

        // EDD installation check and EDD services are unsupported. Preserve
        // BX so the input 55AAh test signature is not changed to a false
        // AA55h success signature.
        0x41..=0x49 => fail(regs, INVALID_COMMAND),

        // Remaining or reserved functions are invalid for this absent-device
        // configuration and return a recoverable BIOS status, not a host
        // dispatch error.
        _ => fail(regs, INVALID_COMMAND),
    }

    Ok(())
}

fn fail(regs: &mut Registers, status: u8) {
    let function = regs.ah();
    regs.set_ah(status);
    regs.set_carry(true);
    if matches!(function, 0x02..=0x04) {
        // No sector has been transferred or verified.
        regs.set_al(0);
    }
}

#[cfg(test)]
#[path = "disk_bios_tests.rs"]
mod tests;
