use std::io;

use cap_std::fs::MetadataExt;
use dos_kernel::{DosErrorCode, DosHostError};
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
};
use windows_sys::Win32::System::Time::{
    DYNAMIC_TIME_ZONE_INFORMATION, FileTimeToSystemTime, GetDynamicTimeZoneInformation,
    SystemTimeToTzSpecificLocalTimeEx, TIME_ZONE_ID_INVALID,
};

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
    let mut zone = DYNAMIC_TIME_ZONE_INFORMATION::default();
    // SAFETY: The output is a caller-owned structure of the Windows ABI layout.
    if unsafe { GetDynamicTimeZoneInformation(&mut zone) } == TIME_ZONE_ID_INVALID {
        return Err(os_error(io::Error::last_os_error()));
    }
    dos_file_time(metadata.last_write_time(), &zone)
}

fn dos_file_time(ticks: u64, zone: &DYNAMIC_TIME_ZONE_INFORMATION) -> Result<(u16, u16), DosHostError> {
    let utc = filetime(ticks);
    let mut system = SYSTEMTIME::default();
    // SAFETY: The FILETIME input and SYSTEMTIME output are valid ABI
    // structures and do not overlap.
    if unsafe { FileTimeToSystemTime(&utc, &mut system) } == 0 {
        return Err(os_error(io::Error::last_os_error()));
    }
    let mut local = SYSTEMTIME::default();
    // FileTimeToLocalFileTime applies the current DST bias even to timestamps
    // from another season. Convert the timestamp's date instead, using Windows'
    // dynamic rules and the user's dynamic-DST setting for the selected zone.
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times
    // https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetotzspecificlocaltimeex
    // SAFETY: All structures have the Windows ABI layout; inputs and output
    // are initialized and do not overlap. This only reads timezone settings.
    if unsafe { SystemTimeToTzSpecificLocalTimeEx(zone, &system, &mut local) } == 0 {
        return Err(os_error(io::Error::last_os_error()));
    }
    Ok(pack_dos_time(&local))
}

fn pack_dos_time(system: &SYSTEMTIME) -> (u16, u16) {
    // Range-check the local date, since conversion can cross a DOS year limit.
    // Native conversion supplies valid calendar/clock fields. Preserve the
    // existing zero-date fallback and truncate, rather than round, odd seconds.
    if !(1980..=2107).contains(&system.wYear)
        || !(1..=12).contains(&system.wMonth)
        || !(1..=31).contains(&system.wDay)
    {
        return (0, 0);
    }
    let date = ((system.wYear - 1980) << 9) | (system.wMonth << 5) | system.wDay;
    let time = (system.wHour << 11) | (system.wMinute << 5) | (system.wSecond / 2);
    (time, date)
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

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
