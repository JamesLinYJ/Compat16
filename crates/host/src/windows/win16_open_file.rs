//! KERNEL.OpenFile over Unicode host paths and owned native file handles.

use super::guest_text::GuestTextCodec;
use super::win16::{Win16Files, Win16NativeFile, open_access_and_share};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostOpenFile};
use std::os::windows::io::{AsRawHandle, IntoRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME, GENERIC_READ, GENERIC_WRITE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetDriveTypeW, GetFullPathNameW, SearchPathW,
};
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
const OF_PROMPT: u16 = 0x2000;

pub(super) fn open(
    filesystem: &mut crate::filesystem::Filesystem,
    files: &mut Win16Files, codec: GuestTextCodec,
    guest_path: &runtime::Win16GuestPath, search_name: Option<&str>,
    style: u16, ofstruct: Vec<u8>,
) -> Result<Win16HostOpenFile, RuntimeError> {
    loop {
        let mut opened = open_once(filesystem, files, codec, guest_path,
            search_name, style, ofstruct.clone())?;
        if !needs_prompt(style, opened.result, &opened.ofstruct) {
            return Ok(opened);
        }
        if !prompt_retry(guest_path)? {
            opened.ofstruct[2..4].copy_from_slice(&2u16.to_le_bytes());
            return Ok(opened);
        }
    }
}

/// A failed lookup can retry through the same task-resolved capability path.
/// Sharing, permissions, verification, and parse-only results never prompt.
pub(super) fn needs_prompt(style: u16, result: i16, ofstruct: &[u8]) -> bool {
    style & OF_PROMPT != 0 && style & OF_PARSE == 0 && result < 0
        && ofstruct.get(2..4).is_some_and(|code|
            matches!(u16::from_le_bytes([code[0], code[1]]), 2 | 3))
}

pub(super) fn prompt_retry(path: &runtime::Win16GuestPath) -> Result<bool, RuntimeError> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDCANCEL, IDRETRY, MB_ICONERROR, MB_RETRYCANCEL, MB_TASKMODAL, MessageBoxW,
    };
    let drive = char::from_u32(u32::from(b'A') + u32::from(path.drive)).unwrap_or('?');
    let name = path.components.iter().map(|part| part.text.as_str()).collect::<Vec<_>>().join("\\");
    let text = format!("Cannot find the file:\n{drive}:\\{name}\n\nRetry opening the file?");
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    // SAFETY: Owned UTF-16 text with a terminator and a fixed Unicode caption.
    // This synchronous legacy prompt has the same ownerless host boundary
    // as the existing Win16 message-box service; no guest pointer is passed.
    match unsafe { MessageBoxW(std::ptr::null_mut(), wide.as_ptr(),
        windows_sys::core::w!("Open file"), MB_RETRYCANCEL | MB_ICONERROR | MB_TASKMODAL) } {
        IDRETRY => Ok(true),
        IDCANCEL => Ok(false),
        0 => Err(RuntimeError::with_source(Kind::HostFailure,
            "show file-open retry prompt", std::io::Error::last_os_error())),
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "file-open retry prompt returned an unexpected button")),
    }
}

fn open_once(
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
            ofstruct, handle, access, stamp);
    }
    let path = match resolve_search_path(filesystem, guest_path, search_name, style)? {
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
    finish_open(filesystem, files, &path, style, ofstruct, handle, access, stamp)
}

fn finish_open(
    filesystem: &mut crate::filesystem::Filesystem,
    files: &mut Win16Files,
    path: &std::path::Path,
    style: u16,
    mut ofstruct: Vec<u8>,
    handle: OwnedHandle,
    access: u32,
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
    let file = files.retain_native_with_access(
        Win16NativeFile::NativeHandle(handle.into_raw_handle()), access)?;
    Ok(Win16HostOpenFile { result: 0, file, ofstruct })
}

fn file_stamp(handle: &OwnedHandle) -> Result<(u16, u16), u32> {
    let ticks = super::win16::file_metadata::last_write_ticks(handle.as_raw_handle())?;
    // Keep Compat16's DOS policy: historical local-zone rules, truncated
    // two-second slots, and zero date/time outside the DOS year range. The
    // comparison/OFSTRUCT contract does not imply byte-exact WOW conversion.
    crate::filesystem::dos_write_time_from_ticks(ticks).map_err(|error| u32::from(error.code as u16))
}

/// Share task-first name lookup without imposing OFSTRUCT timestamp/length
/// contracts on APIs which only need an owned file (such as GetExpandedName).
pub(super) fn resolve_search_path(
    filesystem: &mut crate::filesystem::Filesystem,
    guest_path: &runtime::Win16GuestPath,
    search_name: Option<&str>,
    style: u16,
) -> Result<Result<std::path::PathBuf, dos_kernel::DosHostError>, RuntimeError> {
    let mut resolved = super::win16_file_paths::resolve(filesystem, guest_path,
        style & OF_DELETE == 0 || style & OF_REOPEN != 0, style & (OF_CREATE | OF_PARSE) != 0);
    // A Windows search only locates a fallback. The resulting file is still
    // opened through the capability root, rather than reopening guest text.
    if resolved.is_err() && let Some(name) = search_name {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        if let Some(found) = query_path(&wide, true)? {
            let text = String::from_utf16_lossy(&found);
            resolved = filesystem.resolve_text_path(&text, false)
                .and_then(|path| filesystem.confined_path(&path, true, false));
        }
    }
    Ok(resolved)
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
