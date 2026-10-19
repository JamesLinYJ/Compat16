//! Copy bounded per-user DEVMODE data out of the native level-9 record.
use super::*;
use std::mem::offset_of;
use windows_sys::Win32::{Foundation::GetLastError, Graphics::Printing::GetPrinterW};

pub(super) fn read(printer: PRINTER_HANDLE) -> Result<Option<Vec<u8>>, RuntimeError> {
    let mut required = 0;
    // SAFETY: Size query only, with a writable DWORD count.
    unsafe {
        GetPrinterW(printer, 9, ptr::null_mut(), 0, &mut required);
    }
    for _ in 0..3 {
        let capacity = usize::try_from(required)
            .ok()
            .filter(|size| *size >= size_of::<PRINTER_INFO_9W>() && *size <= 128 * 1024)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "per-user printer defaults have an invalid native size",
                )
            })?;
        // The API takes an explicit capacity and reports a changed count. A
        // u64 allocation also aligns its embedded native pointer record.
        let mut storage = Vec::<u64>::new();
        let count = capacity.div_ceil(size_of::<u64>());
        storage.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate per-user printer defaults",
                error,
            )
        })?;
        storage.resize(count, 0);
        // SAFETY: Writable aligned storage covers exactly the passed capacity.
        if unsafe {
            GetPrinterW(
                printer,
                9,
                storage.as_mut_ptr().cast(),
                capacity as u32,
                &mut required,
            )
        } == 0
        {
            if required as usize > capacity {
                continue;
            }
            // SAFETY: Read the error immediately after this failed API.
            let error = unsafe { GetLastError() };
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!("GetPrinterW level 9 failed with error {error}"),
            ));
        }
        return decode(&storage.as_bytes()[..capacity]);
    }
    Err(RuntimeError::new(
        Kind::HostFailure,
        "per-user printer defaults kept changing size",
    ))
}

pub(super) fn decode(bytes: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
    if bytes.len() < size_of::<PRINTER_INFO_9W>() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "short per-user printer response",
        ));
    }
    // SAFETY: Only the checked pointer-sized record is copied. Its pointer
    // value is never dereferenced before validating the owned response bounds.
    let info = unsafe { bytes.as_ptr().cast::<PRINTER_INFO_9W>().read_unaligned() };
    if info.pDevMode.is_null() {
        return Ok(None);
    }
    const HEADER: usize = offset_of!(DEVMODEW, dmDriverExtra) + 2;
    let offset = (info.pDevMode as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .filter(|offset| {
            *offset >= size_of::<PRINTER_INFO_9W>()
                && offset
                    .checked_add(HEADER)
                    .is_some_and(|end| end <= bytes.len())
        })
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "per-user DEVMODE pointer lies outside its owned response",
            )
        })?;
    let word = |at| {
        usize::from(u16::from_le_bytes([
            bytes[offset + at],
            bytes[offset + at + 1],
        ]))
    };
    let public_size = word(offset_of!(DEVMODEW, dmSize));
    let private_size = word(offset_of!(DEVMODEW, dmDriverExtra));
    let Some(length) = public_size
        .checked_add(private_size)
        .filter(|length| public_size >= HEADER && *length <= bytes.len() - offset)
    else {
        return Ok(None);
    };
    // Old/stale public layouts remain bounded data. The caller compares them
    // with the current driver and falls back without interpreting their fields.
    copy_bytes(&bytes[offset..offset + length]).map(Some)
}
