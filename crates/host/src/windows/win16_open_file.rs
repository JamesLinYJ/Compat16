//! KERNEL.OpenFile over Unicode host paths and owned native file handles.

use super::guest_text::GuestTextCodec;
use super::win16::{Win16Files, Win16NativeFile, open_access_and_share};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostOpenFile};
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_FUNCTION, ERROR_INVALID_NAME, FILETIME,
    GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CreateFileW, DeleteFileW,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, FILE_TYPE_PIPE,
    GetDriveTypeW, GetFileInformationByHandle, GetFileType, GetFullPathNameW,
    GetShortPathNameW, OPEN_EXISTING, SearchPathW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const OFSTRUCT_BYTES: usize = 136;
const OFSTRUCT_PATH_CAPACITY: usize = 128;
const HOST_PATH_LIMIT: usize = 32 * 1024;
const OF_PARSE: u16 = 0x0100;
const OF_DELETE: u16 = 0x0200;
const OF_CREATE: u16 = 0x1000;
const OF_SEARCH: u16 = 0x0400;
const OF_VERIFY: u16 = 0x0400;
const OF_EXIST: u16 = 0x4000;
const OF_REOPEN: u16 = 0x8000;

pub(super) fn open(
    files: &mut Win16Files,
    codec: GuestTextCodec,
    path: &[u8],
    style: u16,
    mut ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    if ofstruct.len() != OFSTRUCT_BYTES {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 OpenFile requires a complete 136-byte OFSTRUCT"));
    }
    if style & OF_REOPEN != 0 {
        return reopen(files, codec, style, ofstruct);
    }
    ofstruct[0] = OFSTRUCT_BYTES as u8;
    ofstruct[2..4].fill(0);
    let input = path;
    if input.is_empty() || input.contains(&0) {
        return Ok(failed(ofstruct, ERROR_INVALID_NAME));
    }
    let path_wide = match codec.to_wide_z(input) {
        Ok(value) => value,
        Err(error) if error.kind() == Kind::InvalidInput =>
            return Ok(failed(ofstruct, ERROR_INVALID_NAME)),
        Err(error) => return Err(error),
    };
    // Search only for an existing file; creation and parsing retain the named path.
    let search = style & OF_SEARCH != 0 && style & (OF_CREATE | OF_PARSE) == 0;
    let found = if search || (style & (OF_CREATE | OF_PARSE) == 0 && is_basename(input)) {
        query_path(&path_wide, true)?
    } else {
        None
    };
    let full_path = match found {
        Some(value) => value,
        None => match query_path(&path_wide, false)? {
            Some(value) => value,
            None => return Ok(failed(ofstruct, unsafe { GetLastError() })),
        },
    };
    let full_path = match guest_ofstruct_path(codec, &full_path)? {
        Some((guest, wide)) => {
            ofstruct[8..].fill(0);
            ofstruct[8..8 + guest.len()].copy_from_slice(&guest);
            wide
        }
        None => return Ok(failed(ofstruct, ERROR_FILENAME_EXCED_RANGE)),
    };
    if full_path.len() >= 3 && full_path[1] == b':' as u16 {
        let root = [full_path[0], b':' as u16, b'\\' as u16, 0];
        ofstruct[1] = u8::from(unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED);
    } else {
        ofstruct[1] = 0;
    }
    if style & OF_PARSE != 0 {
        return Ok(Win16HostOpenFile { result: 0, file: None, ofstruct });
    }
    let mut path_z = full_path;
    path_z.push(0);
    if style & OF_DELETE != 0 {
        let deleted = unsafe { DeleteFileW(path_z.as_ptr()) } != 0;
        return Ok(if deleted {
            Win16HostOpenFile { result: 0, file: None, ofstruct }
        } else { failed(ofstruct, unsafe { GetLastError() }) });
    }
    open_path(files, &path_z, style, ofstruct)
}

fn reopen(
    files: &mut Win16Files,
    codec: GuestTextCodec,
    style: u16,
    ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    // Reopen precedes even OF_PARSE in Win3.1. Do not search or rewrite the
    // saved pathname, fixed-disk flag, size, or successful-call error field.
    let Some(end) = ofstruct[8..].iter().position(|byte| *byte == 0) else {
        return Ok(failed(ofstruct, ERROR_INVALID_NAME));
    };
    if end == 0 {
        return Ok(failed(ofstruct, ERROR_INVALID_NAME));
    }
    let path_z = match codec.to_wide_z(&ofstruct[8..8 + end]) {
        Ok(value) => value,
        Err(error) if error.kind() == Kind::InvalidInput =>
            return Ok(failed(ofstruct, ERROR_INVALID_NAME)),
        Err(error) => return Err(error),
    };
    open_path(files, &path_z, style, ofstruct)
}

fn open_path(
    files: &mut Win16Files,
    path_z: &[u16],
    style: u16,
    ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    // Historical OF_CREATE opens/truncates before VERIFY. Verification is not
    // a promise to preserve contents when the caller also requests creation.
    let (access, share, disposition) = if style & OF_CREATE != 0 {
        (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_ALWAYS)
    } else {
        let Some((access, share)) = open_access_and_share(style & 0x0073) else {
            return Ok(failed(ofstruct, ERROR_INVALID_NAME));
        };
        (access, share, OPEN_EXISTING)
    };
    let handle = unsafe { CreateFileW(path_z.as_ptr(), access, share, std::ptr::null(),
        disposition, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut()) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(failed(ofstruct, unsafe { GetLastError() }));
    }
    // SAFETY: CreateFileW returned one valid owned HANDLE. All failure paths
    // close it; only successful retention transfers ownership to Win16Files.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let stamp = file_stamp(&handle);
    finish_open(files, path_z, style, ofstruct, handle, stamp)
}

fn finish_open(
    files: &mut Win16Files,
    path_z: &[u16],
    style: u16,
    mut ofstruct: Vec<u8>,
    handle: OwnedHandle,
    stamp: Result<(u16, u16), u32>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    let (time, date) = match stamp {
        Ok(value) => value,
        Err(code) => return Ok(failed(ofstruct, code)),
    };
    // Original SDK KRNL286 OpenFile: date at OFSTRUCT+4, time at +6.
    // Its mismatch path closes the file, returns -1, and reports nErrCode=0
    // (a non-DOS error), without overwriting the saved timestamp.
    if style & (OF_REOPEN | OF_VERIFY) == (OF_REOPEN | OF_VERIFY)
        && (ofstruct[4..6] != date.to_le_bytes() || ofstruct[6..8] != time.to_le_bytes())
    {
        return Ok(failed(ofstruct, 0));
    }
    ofstruct[4..6].copy_from_slice(&date.to_le_bytes());
    ofstruct[6..8].copy_from_slice(&time.to_le_bytes());
    if style & (OF_EXIST | OF_DELETE) != 0 {
        drop(handle);
        if style & OF_DELETE != 0 {
            // Reopen's timestamp check must happen before the delete. Normal
            // non-reopen deletion retains its existing direct path above.
            return Ok(if unsafe { DeleteFileW(path_z.as_ptr()) } != 0 {
                Win16HostOpenFile { result: 0, file: None, ofstruct }
            } else { failed(ofstruct, unsafe { GetLastError() }) });
        }
        // OpenFile's existence probe closes its native handle and reports a
        // positive result. A zero result makes legacy callers treat a present
        // file as missing; no guest HFILE remains owned after this operation.
        return Ok(Win16HostOpenFile { result: 1, file: None, ofstruct });
    }
    let file = files.retain_native(Win16NativeFile::NativeHandle(handle.into_raw_handle()))?;
    Ok(Win16HostOpenFile { result: 0, file, ofstruct })
}

fn file_stamp(handle: &OwnedHandle) -> Result<(u16, u16), u32> {
    // SAFETY: The HANDLE remains owned for both the type and metadata queries.
    let last_write = match unsafe { GetFileType(handle.as_raw_handle()) } {
        FILE_TYPE_CHAR => {
            // DOS INT 21h/5700 returns current local date/time for character
            // devices. Use the same Windows clock and DOS conversion policy
            // as files, rather than failing a previously valid NUL/CON open.
            let mut now = FILETIME::default();
            unsafe { GetSystemTimeAsFileTime(&mut now) };
            now
        }
        // OpenFile does not support named pipes. Do not fabricate a disk
        // timestamp when a CreateFileW-compatible pipe pathname reaches here.
        FILE_TYPE_PIPE => return Err(ERROR_INVALID_FUNCTION),
        _ => {
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // Read the opened object, not a second path lookup. This query
            // supports write-only opens without requesting GENERIC_READ.
            // SAFETY: The output is an initialized Windows ABI object.
            if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) } == 0 {
                return Err(unsafe { GetLastError() });
            }
            info.ftLastWriteTime
        }
    };
    let ticks = (u64::from(last_write.dwHighDateTime) << 32)
        | u64::from(last_write.dwLowDateTime);
    // Keep Compat16's DOS policy: historical local-zone rules, truncated
    // two-second slots, and zero date/time outside the DOS year range. The
    // comparison/OFSTRUCT contract does not imply byte-exact WOW conversion.
    crate::filesystem::dos_write_time_from_ticks(ticks).map_err(|error| u32::from(error.code as u16))
}

fn is_basename(path: &[u8]) -> bool {
    !path.iter().any(|byte| matches!(*byte, b'\\' | b'/' | b':'))
}

fn query_path(path: &[u16], search: bool) -> Result<Option<Vec<u16>>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        if capacity > HOST_PATH_LIMIT {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "native OpenFile path exceeds the host path limit"));
        }
        let mut output = vec![0_u16; capacity];
        let length = unsafe { if search {
            SearchPathW(std::ptr::null(), path.as_ptr(), std::ptr::null(), capacity as u32,
                output.as_mut_ptr(), std::ptr::null_mut())
        } else {
            GetFullPathNameW(path.as_ptr(), capacity as u32, output.as_mut_ptr(), std::ptr::null_mut())
        } } as usize;
        if length == 0 { return Ok(None); }
        if length < capacity {
            output.truncate(length);
            return Ok(Some(output));
        }
        capacity = length.saturating_add(1);
    }
}

fn guest_ofstruct_path(
    codec: GuestTextCodec,
    path: &[u16],
) -> Result<Option<(Vec<u8>, Vec<u16>)>, RuntimeError> {
    let encoded = codec.from_wide_bounded(path, OFSTRUCT_PATH_CAPACITY - 1)?;
    if !encoded.truncated && encoded.used_default_char != Some(true) {
        return Ok(Some((encoded.bytes, path.to_vec())));
    }

    // Resolve an 8.3 fallback only when the original path cannot fit the guest
    // OFSTRUCT. The native query allocates a full host-path buffer.
    let Some(candidate) = short_path(path)? else { return Ok(None); };
    let encoded = codec.from_wide_bounded(&candidate, OFSTRUCT_PATH_CAPACITY - 1)?;
    if !encoded.truncated && encoded.used_default_char != Some(true) {
        return Ok(Some((encoded.bytes, candidate)));
    }
    Ok(None)
}

fn short_path(path: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    let mut path_z = path.to_vec();
    path_z.push(0);
    let mut output = vec![0_u16; HOST_PATH_LIMIT];
    let length = unsafe { GetShortPathNameW(path_z.as_ptr(), output.as_mut_ptr(),
        output.len() as u32) } as usize;
    if length == 0 || length >= output.len() { return Ok(None); }
    output.truncate(length);
    Ok(Some(output))
}

fn failed(mut ofstruct: Vec<u8>, code: u32) -> Win16HostOpenFile {
    ofstruct[2..4].copy_from_slice(&(code as u16).to_le_bytes());
    Win16HostOpenFile { result: -1, file: None, ofstruct }
}

#[cfg(test)]
#[path = "win16_open_file_tests.rs"]
mod tests;
