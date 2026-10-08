//! Configured Windows compatibility identity exposed by Win16 APIs and DOS
//! multiplex version probes.
//!
//! Version values describe the guest ABI. The NT-hosted identity is reported
//! separately by GetWinFlags; neither value enumerates implemented services.

use guest_core::Registers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsCompatibilityMode {
    Enhanced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCompatibilityProfile {
    pub major: u8,
    pub minor: u8,
    pub mode: WindowsCompatibilityMode,
    pub nt_hosted: bool,
}

/// Windows 3.10 enhanced-mode compatibility identity for supported probes.
pub const WINDOWS_COMPATIBILITY_PROFILE: WindowsCompatibilityProfile =
    WindowsCompatibilityProfile {
        major: 3,
        minor: 10,
        mode: WindowsCompatibilityMode::Enhanced,
        nt_hosted: true,
    };

// Microsoft Windows 3.1 SDK, Programmer's Reference, Volume 2,
// GetWinFlags (KERNEL.132). CPU class flags are alternatives, not a hierarchy.
const WF_PMODE: u32 = 0x0001;
const WF_CPU486: u32 = 0x0008;
const WF_ENHANCED: u32 = 0x0020;
const WF_80X87: u32 = 0x0400;
// Microsoft KB Q131371: Win16 applications distinguish NT-hosted WOW from
// Windows 3.x with this bit even when GetVersion returns the same 3.10/5.0.
// https://jeffpar.github.io/kbarchive/kb/131/Q131371/
const WF_WINNT: u32 = 0x4000;

/// Features exposed by the emulated Win16 machine, independent of host CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MachineFeatures {
    pub i486: bool,
    pub x87: bool,
}

/// The current guest interpreter targets an i486 with an emulated x87.
pub const WIN16_MACHINE_FEATURES: Win16MachineFeatures = Win16MachineFeatures {
    i486: true,
    x87: true,
};

impl WindowsCompatibilityProfile {
    /// Version word used by INT 2Fh/AX=1600h (major in AL, minor in AH).
    pub const fn version_word(self) -> u16 {
        self.major as u16 | ((self.minor as u16) << 8)
    }

    /// Version word used in BX by INT 2Fh/AX=160Ah.
    pub const fn win31_check_word(self) -> u16 {
        ((self.major as u16) << 8) | self.minor as u16
    }

    /// Mode code used in CX by INT 2Fh/AX=160Ah.
    pub const fn mode_code(self) -> u16 {
        match self.mode {
            WindowsCompatibilityMode::Enhanced => 3,
        }
    }

    /// KERNEL.GetWinFlags reports the guest machine, mode and NT-hosted ABI
    /// identity. The NT bit identifies the environment, not API completeness.
    /// Paging remains absent because no guest paged-memory manager is exposed.
    pub const fn win_flags(self, machine: Win16MachineFeatures) -> u32 {
        let mut flags = WF_PMODE;
        if self.nt_hosted {
            flags |= WF_WINNT;
        }
        if machine.i486 {
            flags |= WF_CPU486;
        }
        if machine.x87 {
            flags |= WF_80X87;
        }
        match self.mode {
            WindowsCompatibilityMode::Enhanced => flags | WF_ENHANCED,
        }
    }
}

/// Handle the version/mode queries supported by this Win16 compatibility
/// profile. Return `false` for unrelated Windows, VxD, or DPMI calls.
pub fn handle_int2f_version_query(
    regs: &mut Registers,
    profile: &WindowsCompatibilityProfile,
) -> bool {
    match regs.ax() {
        0x1600 => {
            regs.set_ax(profile.version_word());
            true
        }
        0x160a => {
            regs.set_ax(0);
            regs.set_bx(profile.win31_check_word());
            regs.set_cx(profile.mode_code());
            true
        }
        0x4680 => {
            // The configured enhanced-mode profile does not install the
            // older Windows 3.0 real/standard WinOldAp path.
            regs.set_ax(0x0080);
            true
        }
        _ => false,
    }
}
