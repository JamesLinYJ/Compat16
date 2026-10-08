use crate::DosAction;
use guest_core::Registers;

/// Default NTVDM-compatible DOS identity for the guest environment.
/// These are DOS API compatibility values, not the version of the host OS.
pub(super) const DOS_VERSION_AH30: u16 = 0x0005;
pub(super) const DOS_TRUE_VERSION: u16 = 0x3205;
pub(super) const DOS_BOOT_DRIVE: u8 = 3; // DOS numbering: 1=A:, 2=B:, 3=C:.

const DOS_OEM_ID_NT: u8 = 0xff;
const DOS_VERSION_FLAGS: u8 = 0x00;
const DOS_REVISION: u8 = 0x00;

impl super::DosKernel {
    /// INT 21h/AH=30h: DOS 5.00 report with NT DOS OEM identity.
    pub(super) fn dos_version(regs: &mut Registers) -> DosAction {
        let selector = regs.al();
        regs.set_ax(DOS_VERSION_AH30);
        regs.set_bl(0); // High byte of the 24-bit user serial number.
        regs.set_cx(0); // Low 16 bits of the user serial number.
        match selector {
            0x00 => regs.set_bh(DOS_OEM_ID_NT),
            0x01 => regs.set_bh(DOS_VERSION_FLAGS),
            // Only selectors 00h and 01h are defined; preserve BH for others.
            _ => {}
        }
        DosAction::Continue
    }

    /// INT 21h/AH=33h: Ctrl-Break controls, boot drive, and true DOS version.
    pub(super) fn extended_version(&mut self, regs: &mut Registers) -> DosAction {
        match regs.al() {
            0x00 => regs.set_dl(u8::from(self.break_check_enabled)),
            0x01 => self.break_check_enabled = regs.dl() != 0,
            0x02 => {
                let requested = regs.dl() != 0;
                regs.set_dl(u8::from(self.break_check_enabled));
                self.break_check_enabled = requested;
            }
            0x05 => regs.set_dl(DOS_BOOT_DRIVE),
            0x06 => {
                regs.set_bx(DOS_TRUE_VERSION);
                regs.set_dx(u16::from(DOS_REVISION) | (u16::from(DOS_VERSION_FLAGS) << 8));
            }
            _ => regs.set_al(0xff),
        }
        DosAction::Continue
    }
}
