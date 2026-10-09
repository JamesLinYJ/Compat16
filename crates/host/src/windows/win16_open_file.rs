//! KERNEL.OpenFile over Unicode host paths and owned native file handles.

use super::guest_text::GuestTextCodec;
use super::win16::{Win16Files, Win16NativeFile, open_access_and_share};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostOpenFile};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME,
    GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, DeleteFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetDriveTypeW, GetFullPathNameW, GetShortPathNameW, OPEN_EXISTING,
    SearchPathW,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const OFSTRUCT_BYTES: usize = 136;
const OFSTRUCT_PATH_CAPACITY: usize = 128;
const HOST_PATH_LIMIT: usize = 32 * 1024;
const OF_PARSE: u16 = 0x0100;
const OF_DELETE: u16 = 0x0200;
const OF_CREATE: u16 = 0x1000;
const OF_SEARCH: u16 = 0x0400;
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
    ofstruct[0] = OFSTRUCT_BYTES as u8;
    ofstruct[2..4].fill(0);
    let input = if style & OF_REOPEN != 0 {
        let end = ofstruct[8..].iter().position(|byte| *byte == 0)
            .unwrap_or(OFSTRUCT_PATH_CAPACITY);
        &ofstruct[8..8 + end]
    } else {
        path
    };
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
    if style & OF_EXIST != 0 {
        unsafe { CloseHandle(handle) };
        // OpenFile's existence probe closes its native handle and reports a
        // positive result. A zero result makes legacy callers treat a present
        // file as missing; no guest HFILE remains owned after this operation.
        return Ok(Win16HostOpenFile { result: 1, file: None, ofstruct });
    }
    let file = files.retain_native(Win16NativeFile::NativeHandle(handle))?;
    Ok(Win16HostOpenFile { result: 0, file, ofstruct })
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
    for candidate in [Some(path.to_vec()), short_path(path)?].into_iter().flatten() {
        let encoded = codec.from_wide_bounded(&candidate, OFSTRUCT_PATH_CAPACITY - 1)?;
        if !encoded.truncated && encoded.used_default_char != Some(true) {
            return Ok(Some((encoded.bytes, candidate)));
        }
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
