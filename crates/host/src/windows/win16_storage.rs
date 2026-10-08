//! Native Windows drive classification for Win16 KERNEL services.

use runtime::Win16HostDriveKind;
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE,
    DRIVE_REMOVABLE, DRIVE_UNKNOWN,
};

/// Query the host's actual drive type. Win16 drive numbers are zero-based;
/// invalid numbers have no root and never reach the host API.
pub(super) fn drive_kind(drive: u16) -> Win16HostDriveKind {
    if drive >= 26 {
        return Win16HostDriveKind::MissingRoot;
    }

    let root = [u16::from(b'A') + drive, u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: `root` is an owned, NUL-terminated UTF-16 drive-root string.
    // The API reads this string and returns a scalar classification.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    match drive_type {
        DRIVE_UNKNOWN => Win16HostDriveKind::Unknown,
        DRIVE_NO_ROOT_DIR => Win16HostDriveKind::MissingRoot,
        DRIVE_REMOVABLE => Win16HostDriveKind::Removable,
        DRIVE_FIXED => Win16HostDriveKind::Fixed,
        DRIVE_REMOTE => Win16HostDriveKind::Remote,
        DRIVE_CDROM => Win16HostDriveKind::CdRom,
        DRIVE_RAMDISK => Win16HostDriveKind::RamDisk,
        _ => Win16HostDriveKind::Unknown,
    }
}
