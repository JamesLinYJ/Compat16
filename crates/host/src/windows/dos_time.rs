//! Native local calendar query for the DOS scalar ABI.

use dos_kernel::DosLocalDateTime;
use windows_sys::Win32::{Foundation::SYSTEMTIME, System::SystemInformation::GetLocalTime};

pub(super) fn local_date_time() -> DosLocalDateTime {
    let mut time = SYSTEMTIME::default();
    // GetLocalTime writes a caller-owned fixed structure and has no failure
    // return. Native calendar conversion remains with Windows.
    // SAFETY: GetLocalTime writes into a caller-owned SYSTEMTIME.
    unsafe { GetLocalTime(&mut time) };
    DosLocalDateTime {
        year: time.wYear,
        month: time.wMonth as u8,
        day: time.wDay as u8,
        weekday: time.wDayOfWeek as u8,
        hour: time.wHour as u8,
        minute: time.wMinute as u8,
        second: time.wSecond as u8,
        hundredth: (time.wMilliseconds / 10) as u8,
    }
}
