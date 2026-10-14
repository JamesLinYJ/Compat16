//! KERNEL.OpenFile over Unicode host paths and owned native file handles.

use super::guest_text::GuestTextCodec;
use super::win16::{Win16Files, Win16NativeFile, open_access_and_share};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostOpenFile};
use std::os::windows::io::{AsRawHandle, IntoRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_FUNCTION, ERROR_INVALID_NAME, FILETIME,
    GENERIC_READ, GENERIC_WRITE, GetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, FILE_TYPE_PIPE,
    GetDriveTypeW, GetFileInformationByHandle, GetFileType, GetFullPathNameW,
    SearchPathW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const OFSTRUCT_BYTES: usize = 136;
const OFSTRUCT_PATH_CAPACITY: usize = 128;
const HOST_PATH_LIMIT: usize = 32 * 1024;
const OF_PARSE: u16 = 0x0100;
const OF_DELETE: u16 = 0x0200;
const OF_CREATE: u16 = 0x1000;
const OF_VERIFY: u16 = 0x0400;
const OF_EXIST: u16 = 0x4000;
const OF_REOPEN: u16 = 0x8000;

pub(super) fn open(
    filesystem: &mut crate::filesystem::Filesystem,
    files: &mut Win16Files, codec: GuestTextCodec,
    guest_path: &runtime::Win16GuestPath, search_name: Option<&str>,
    style: u16, mut ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    if ofstruct.len() != OFSTRUCT_BYTES {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 OpenFile requires a complete 136-byte OFSTRUCT"));
    }
    let reopen = style & OF_REOPEN != 0;
    if !reopen { ofstruct[0] = OFSTRUCT_BYTES as u8; ofstruct[2..4].fill(0); }
    if let Some(name) = super::win16_file_devices::name(guest_path) {
        if style & OF_DELETE != 0 { return Ok(failed(ofstruct, 5)); }
        if !reopen {
            ofstruct[1] = 0;
            ofstruct[8..].fill(0);
            ofstruct[8..8 + name.len()].copy_from_slice(name.as_bytes());
        }
        if style & OF_PARSE != 0 { return Ok(Win16HostOpenFile { result: 0, file: None, ofstruct }); }
        let (access, share) = if style & OF_CREATE != 0 {
            (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE)
        } else {
            let Some(mode) = open_access_and_share(style & 0x0073) else {
                return Ok(failed(ofstruct, ERROR_INVALID_NAME));
            };
            mode
        };
        let handle = match super::win16_file_devices::open(name, access, share) {
            Ok(handle) => handle, Err(error) => return Ok(failed(ofstruct, error)),
        };
        let stamp = file_stamp(&handle);
        return finish_open(filesystem, files, std::path::Path::new(name), style,
            ofstruct, handle, stamp);
    }
    let mut resolved = super::win16_file_paths::resolve(filesystem, guest_path,
        style & OF_DELETE == 0 || reopen, style & (OF_CREATE | OF_PARSE) != 0);
    // The task directory has precedence. A Windows search only locates a
    // fallback; the resulting file is still opened through the capability.
    if resolved.is_err() && let Some(name) = search_name {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        if let Some(found) = query_path(&wide, true)? {
            let text = String::from_utf16_lossy(&found);
            resolved = filesystem.resolve_text_path(&text, false)
                .and_then(|path| filesystem.confined_path(&path, true, false));
        }
    }
    let path = match resolved {
        Ok(path) => path,
        Err(error) => return Ok(failed(ofstruct, u32::from(error.code as u16))),
    };
    if !reopen {
        use std::os::windows::ffi::OsStrExt;
        let absolute = filesystem.canonical_root.join(&path);
        let wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        let encoded = codec.from_wide_bounded(&wide, OFSTRUCT_PATH_CAPACITY - 1)?;
        let guest = if !encoded.truncated && encoded.used_default_char != Some(true) {
            encoded.bytes
        } else {
            let Some(canonical) = filesystem.canonical_win16_path(guest_path.drive, &path)
                .ok().flatten() else { return Ok(failed(ofstruct, ERROR_FILENAME_EXCED_RANGE)); };
            let Some(bytes) = filesystem.dos_path_bytes_for_canonical(&canonical) else {
                return Ok(failed(ofstruct, ERROR_FILENAME_EXCED_RANGE));
            };
            let text = filesystem.guest_code_page().decode(&bytes)
                .map_err(|error| RuntimeError::with_source(Kind::InvalidInput,
                    "decode OpenFile virtual DOS pathname", error))?;
            let encoded = codec.from_wide_bounded(&text.encode_utf16().collect::<Vec<_>>(),
                OFSTRUCT_PATH_CAPACITY - 1)?;
            if encoded.truncated || encoded.used_default_char == Some(true) {
                return Ok(failed(ofstruct, ERROR_FILENAME_EXCED_RANGE));
            }
            encoded.bytes
        };
        ofstruct[8..].fill(0);
        ofstruct[8..8 + guest.len()].copy_from_slice(&guest);
        let root = [u16::from(b'A' + guest_path.drive), b':' as u16, b'\\' as u16, 0];
        ofstruct[1] = u8::from(unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED);
        if style & OF_PARSE != 0 {
            return Ok(Win16HostOpenFile { result: 0, file: None, ofstruct });
        }
        if style & OF_DELETE != 0 {
            return Ok(match filesystem.root.remove_file(&path) {
                Ok(()) => Win16HostOpenFile { result: 0, file: None, ofstruct },
                Err(error) => failed(ofstruct, error.raw_os_error().unwrap_or(5) as u32),
            });
        }
    }
    let (access, share) = if style & OF_CREATE != 0 {
        (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE)
    } else {
        let Some(value) = open_access_and_share(style & 0x0073) else {
            return Ok(failed(ofstruct, ERROR_INVALID_NAME));
        };
        value
    };
    use cap_std::fs::{OpenOptions, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options.read(access & GENERIC_READ != 0).write(access & GENERIC_WRITE != 0)
        .share_mode(share).create(style & OF_CREATE != 0).truncate(style & OF_CREATE != 0)
        .attributes(FILE_ATTRIBUTE_NORMAL);
    let file = match filesystem.root.open_with(&path, &options) {
        Ok(file) => file,
        Err(error) => return Ok(failed(ofstruct, error.raw_os_error().unwrap_or(5) as u32)),
    };
    let handle: OwnedHandle = file.into_std().into();
    let stamp = file_stamp(&handle);
    finish_open(filesystem, files, &path, style, ofstruct, handle, stamp)
}

fn finish_open(
    filesystem: &mut crate::filesystem::Filesystem,
    files: &mut Win16Files,
    path: &std::path::Path,
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
            return Ok(match filesystem.root.remove_file(path) {
                Ok(()) => Win16HostOpenFile { result: 0, file: None, ofstruct },
                Err(error) => failed(ofstruct, error.raw_os_error().unwrap_or(5) as u32),
            });
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

fn failed(mut ofstruct: Vec<u8>, code: u32) -> Win16HostOpenFile {
    ofstruct[2..4].copy_from_slice(&(code as u16).to_le_bytes());
    Win16HostOpenFile { result: -1, file: None, ofstruct }
}

#[cfg(test)]
#[path = "win16_open_file_tests.rs"]
mod tests;
