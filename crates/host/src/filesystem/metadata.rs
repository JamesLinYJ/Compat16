use std::io;

use cap_std::fs::MetadataExt;
use dos_kernel::{DosErrorCode, DosHostError};
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FileTimeToLocalFileTime,
};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

use crate::windows::{invalid, os_error};

pub(super) const DOS_ATTRIBUTE_DIRECTORY: u8 = 0x10;

pub(super) fn dos_attributes(metadata: &cap_std::fs::Metadata) -> u8 {
    let native = metadata.file_attributes();
    let mut dos = 0;
    if native & FILE_ATTRIBUTE_READONLY != 0 {
        dos |= 0x01;
    }
    if native & FILE_ATTRIBUTE_HIDDEN != 0 {
        dos |= 0x02;
    }
    if native & FILE_ATTRIBUTE_SYSTEM != 0 {
        dos |= 0x04;
    }
    if native & FILE_ATTRIBUTE_DIRECTORY != 0 {
        dos |= DOS_ATTRIBUTE_DIRECTORY;
    }
    if native & FILE_ATTRIBUTE_ARCHIVE != 0 {
        dos |= 0x20;
    }
    dos
}

pub(super) fn dos_write_time(metadata: &cap_std::fs::Metadata) -> Result<(u16, u16), DosHostError> {
    let utc = filetime(metadata.last_write_time());
    let mut local = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: Both FILETIME pointers refer to initialized, writable
    // structures of the exact Windows ABI layout.
    if unsafe { FileTimeToLocalFileTime(&utc, &mut local) } == 0 {
        return Err(os_error(io::Error::last_os_error()));
    }
    let mut system = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    // SAFETY: The FILETIME input and SYSTEMTIME output are valid ABI
    // structures and do not overlap.
    if unsafe { FileTimeToSystemTime(&local, &mut system) } == 0 {
        return Err(os_error(io::Error::last_os_error()));
    }
    if !(1980..=2107).contains(&system.wYear)
        || !(1..=12).contains(&system.wMonth)
        || !(1..=31).contains(&system.wDay)
    {
        return Ok((0, 0));
    }
    let date = ((system.wYear - 1980) << 9) | (system.wMonth << 5) | system.wDay;
    let time = (system.wHour << 11) | (system.wMinute << 5) | (system.wSecond / 2);
    Ok((time, date))
}

fn filetime(ticks: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    }
}

pub(super) fn validate_attributes(attributes: u8) -> Result<(), DosHostError> {
    if attributes & !0x27 != 0 {
        return Err(invalid(DosErrorCode::InvalidAccess));
    }
    Ok(())
}
