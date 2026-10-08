//! Native Windows path queries for the Win16 KERNEL directory APIs.

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostPathInfoOperation as Operation,
    Win16HostPathInfoResult as ResultValue, Win16HostTempFileName};
use windows_sys::Win32::Globalization::{
    MultiByteToWideChar, WideCharToMultiByte, CP_UTF8, MB_ERR_INVALID_CHARS,
    WC_ERR_INVALID_CHARS, WC_NO_BEST_FIT_CHARS,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetFullPathNameW, GetTempFileNameW, GetTempPathW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemDirectoryA, GetWindowsDirectoryA,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_NO_ROOT_DIR;

const TF_FORCEDRIVE: u8 = 0x80;
const TEMP_FILE_NAME_BUFFER_BYTES: usize = 144;
const HOST_PATH_LIMIT: usize = 32 * 1024;

/// Execute one synchronous path query without entering the USER worker.
pub(super) fn execute(
    operation: Operation,
    guest_oem_page: u32,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::WindowsDirectory => Ok(ResultValue::Directory(
            native_directory(GetWindowsDirectoryA, "query host Windows directory")?,
        )),
        Operation::SystemDirectory => Ok(ResultValue::Directory(
            native_directory(GetSystemDirectoryA, "query host system directory")?,
        )),
        Operation::TempFileName { drive, prefix, unique } => Ok(ResultValue::TempFileName(
            temp_file_name(drive, prefix.as_deref(), unique, guest_oem_page)?,
        )),
    }
}

type DirectoryApi = unsafe extern "system" fn(*mut u8, u32) -> u32;

fn native_directory(
    api: DirectoryApi,
    operation: &'static str,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        if capacity > HOST_PATH_LIMIT {
            return Err(resource_limit(operation));
        }
        let mut buffer = zeroed_buffer(capacity, operation)?;
        let length = unsafe { api(buffer.as_mut_ptr(), capacity as u32) } as usize;
        if length == 0 { return Ok(None); }
        if length < capacity {
            buffer.truncate(length);
            if buffer.contains(&0) {
                return Err(invariant("Windows directory API returned an embedded NUL"));
            }
            return Ok(Some(buffer));
        }
        capacity = length.checked_add(1).ok_or_else(|| resource_limit(operation))?;
    }
}

fn temp_file_name(
    drive: u8,
    prefix: Option<&[u8]>,
    unique: u16,
    guest_oem_page: u32,
) -> Result<Option<Win16HostTempFileName>, RuntimeError> {
    if prefix.is_some_and(|bytes| bytes.contains(&0)) { return Ok(None); }
    let Some(directory) = temp_directory(drive)? else { return Ok(None); };
    let directory = nul_terminated_wide(&directory, "terminate temporary directory")?;
    let prefix = match prefix {
        Some(value) => match guest_oem_to_wide(value, guest_oem_page)? {
            Some(prefix) => Some(prefix),
            None => return Ok(None),
        },
        None => None,
    };
    let prefix = prefix.as_deref().map(|value| nul_terminated_wide(value, "terminate temporary prefix"))
        .transpose()?;
    let prefix_ptr = prefix.as_ref().map_or(std::ptr::null(), |bytes| bytes.as_ptr());

    // Reserve every buffer needed after GetTempFileNameW(unique=0) before it
    // can create a caller-owned file. The conversion buffers are reused for
    // the noncreating probe and the final native result.
    let mut native = zeroed_buffer_u16(HOST_PATH_LIMIT, "allocate host temporary-file path")?;
    let mut roundtrip = zeroed_buffer_u16(HOST_PATH_LIMIT, "allocate temporary-path roundtrip")?;
    let mut guest_path = zeroed_buffer(TEMP_FILE_NAME_BUFFER_BYTES - 1,
        "allocate guest temporary-file path")?;

    if unique == 0 {
        // A nonzero GetTempFileName value probes a noncreating path with the
        // same directory and prefix. The SDK's four-hex-digit suffix keeps
        // path length and guest-code-page representability stable.
        let Some(_) = generate_temp_path(&directory, prefix_ptr, u16::MAX, &mut native)? else {
            return Ok(None);
        };
        let probe_len = match wide_path_to_guest_oem(
            temp_path_units(&native)?, guest_oem_page, &mut roundtrip,
            &mut guest_path,
        )? {
            Some(length) => length,
            None => return Ok(None),
        };
        if probe_len >= TEMP_FILE_NAME_BUFFER_BYTES { return Ok(None); }
    }

    let Some(returned_unique) = generate_temp_path(&directory, prefix_ptr, unique, &mut native)? else {
        return Ok(None);
    };
    let path_len = match wide_path_to_guest_oem(
        temp_path_units(&native)?, guest_oem_page, &mut roundtrip,
        &mut guest_path,
    )? {
        Some(length) => length,
        None if unique == 0 => return Err(invariant(
            "temporary path failed its preflight after GetTempFileName created the file")),
        None => return Ok(None),
    };
    if path_len >= TEMP_FILE_NAME_BUFFER_BYTES {
        if unique == 0 {
            return Err(invariant("GetTempFileName created a path beyond its preflighted Win16 buffer"));
        }
        return Ok(None);
    }
    guest_path.truncate(path_len);

    // The zero-unique API creates and closes the selected file and leaves it
    // for the guest; this adapter does not claim or delete that file.
    Ok(Some(Win16HostTempFileName {
        path: guest_path,
        unique: returned_unique,
        created: unique == 0,
    }))
}

fn temp_directory(drive: u8) -> Result<Option<Vec<u16>>, RuntimeError> {
    if drive & TF_FORCEDRIVE == 0 {
        // Map the optional Win16 drive suggestion to the host's real temp
        // directory policy. This uses modern GetTempPathW search semantics;
        // it does not reproduce Windows 3.1's legacy TEMP search algorithm.
        return native_temp_directory();
    }

    let letter = drive & !TF_FORCEDRIVE;
    if letter == 0 {
        return native_full_path(&[b'.' as u16, 0], "resolve default-drive current directory");
    }
    let root = [u16::from(letter), b':' as u16, b'\\' as u16, 0];
    if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_NO_ROOT_DIR {
        // Windows 3.0 Programmer's Reference, GetTempFileName Comments:
        // TF_FORCEDRIVE requires the selected drive's current directory.
        return Ok(None);
    }

    let mut drive_current = Vec::new();
    drive_current.try_reserve_exact(4).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate forced-drive path", error,
    ))?;
    drive_current.extend_from_slice(&[u16::from(letter), b':' as u16, b'.' as u16, 0]);
    native_full_path(&drive_current, "resolve forced-drive current directory")
}

fn native_temp_directory() -> Result<Option<Vec<u16>>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        if capacity > HOST_PATH_LIMIT { return Err(resource_limit("query host temporary directory")); }
        let mut buffer = zeroed_buffer_u16(capacity, "allocate host temporary directory")?;
        let length = unsafe { GetTempPathW(capacity as u32, buffer.as_mut_ptr()) } as usize;
        if length == 0 { return Ok(None); }
        if length < capacity {
            buffer.truncate(length);
            if buffer.contains(&0) { return Err(invariant("GetTempPathW returned an embedded NUL")); }
            return Ok(Some(buffer));
        }
        capacity = length.checked_add(1).ok_or_else(|| resource_limit("query host temporary directory"))?;
    }
}

fn native_full_path(
    path: &[u16],
    operation: &'static str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        if capacity > HOST_PATH_LIMIT { return Err(resource_limit(operation)); }
        let mut buffer = zeroed_buffer_u16(capacity, operation)?;
        let length = unsafe {
            GetFullPathNameW(path.as_ptr(), capacity as u32, buffer.as_mut_ptr(), std::ptr::null_mut())
        } as usize;
        if length == 0 { return Ok(None); }
        if length < capacity {
            buffer.truncate(length);
            if buffer.contains(&0) { return Err(invariant("GetFullPathNameW returned an embedded NUL")); }
            return Ok(Some(buffer));
        }
        capacity = length.checked_add(1).ok_or_else(|| resource_limit(operation))?;
    }
}

fn generate_temp_path(
    directory: &[u16],
    prefix: *const u16,
    unique: u16,
    buffer: &mut [u16],
) -> Result<Option<u16>, RuntimeError> {
    buffer.fill(0xffff);
    let result = unsafe {
        GetTempFileNameW(directory.as_ptr(), prefix, u32::from(unique), buffer.as_mut_ptr())
    };
    if result == 0 { return Ok(None); }
    if unique != 0 && result != u32::from(unique) {
        return Err(invariant("GetTempFileNameW returned a different requested unique value"));
    }
    let returned_unique = u16::try_from(result)
        .map_err(|_| invariant("GetTempFileNameW returned a value outside the Win16 word"))?;
    if returned_unique == 0 { return Err(invariant("GetTempFileNameW returned a zero unique value")); }
    if !buffer.contains(&0) { return Err(invariant("GetTempFileNameW omitted its output terminator")); }
    Ok(Some(returned_unique))
}

fn temp_path_units(buffer: &[u16]) -> Result<&[u16], RuntimeError> {
    let Some(end) = buffer.iter().position(|byte| *byte == 0) else {
        return Err(invariant("GetTempFileNameW omitted its output terminator"));
    };
    if end == 0 { return Err(invariant("GetTempFileNameW returned an empty path")); }
    Ok(&buffer[..end])
}

fn guest_oem_to_wide(
    source: &[u8],
    guest_oem_page: u32,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if source.is_empty() { return Ok(Some(Vec::new())); }
    if source.contains(&0) { return Ok(None); }
    let wide_length = multibyte_length(guest_oem_page, source, "decode Win16 OEM prefix")?;
    let mut wide = zeroed_buffer_u16(wide_length, "allocate decoded Win16 OEM prefix")?;
    let decoded = decode_multibyte(guest_oem_page, source, &mut wide,
        "decode Win16 OEM prefix")?;
    let guest_roundtrip_len = encoded_length(guest_oem_page, &wide[..decoded],
        "size Win16 OEM prefix roundtrip")?;
    let mut guest_roundtrip = zeroed_buffer(guest_roundtrip_len, "allocate Win16 OEM prefix roundtrip")?;
    if encode_multibyte(guest_oem_page, &wide[..decoded], &mut guest_roundtrip,
        "roundtrip Win16 OEM prefix")? != Some(guest_roundtrip_len)
        || guest_roundtrip.as_slice() != source {
        return Ok(None);
    }
    wide.truncate(decoded);
    Ok(Some(wide))
}

/// Convert the native UTF-16 path into the guest OEM page without best-fit or
/// default-character substitution. Both conversion buffers are supplied by
/// the caller so the zero-unique path has no post-creation allocation.
fn wide_path_to_guest_oem(
    source: &[u16],
    guest_oem_page: u32,
    roundtrip: &mut [u16],
    output: &mut Vec<u8>,
) -> Result<Option<usize>, RuntimeError> {
    if source.is_empty() || source.contains(&0) { return Ok(None); }
    let required = encoded_length(guest_oem_page, source,
        "size guest OEM temporary path")?;
    if required >= TEMP_FILE_NAME_BUFFER_BYTES { return Ok(None); }
    if required > output.capacity() { return Err(resource_limit("guest temporary path exceeds preallocated buffer")); }
    output.resize(required, 0);
    if encode_multibyte(guest_oem_page, source, output,
        "encode guest OEM temporary path")? != Some(required) {
        return Ok(None);
    }
    let roundtrip_length = multibyte_length(guest_oem_page, output,
        "roundtrip guest OEM temporary path")?;
    if roundtrip_length > roundtrip.len() { return Err(resource_limit("roundtrip guest temporary path")); }
    let roundtrip_written = decode_multibyte(guest_oem_page, output, roundtrip,
        "roundtrip guest OEM temporary path")?;
    if roundtrip_written != source.len() || roundtrip[..roundtrip_written] != source[..] {
        return Ok(None);
    }
    Ok(Some(required))
}

fn multibyte_length(code_page: u32, source: &[u8], operation: &'static str)
    -> Result<usize, RuntimeError> {
    let source_length = i32::try_from(source.len()).map_err(|_| resource_limit(operation))?;
    let flags = if code_page == CP_UTF8 { MB_ERR_INVALID_CHARS } else { 0 };
    let length = unsafe { MultiByteToWideChar(code_page, flags, source.as_ptr(), source_length,
        std::ptr::null_mut(), 0) };
    if length == 0 { return Err(host_conversion_error(operation)); }
    usize::try_from(length).map_err(|_| resource_limit(operation))
}

fn decode_multibyte(code_page: u32, source: &[u8], output: &mut [u16],
    operation: &'static str) -> Result<usize, RuntimeError> {
    let source_length = i32::try_from(source.len()).map_err(|_| resource_limit(operation))?;
    let capacity = i32::try_from(output.len()).map_err(|_| resource_limit(operation))?;
    let flags = if code_page == CP_UTF8 { MB_ERR_INVALID_CHARS } else { 0 };
    let written = unsafe { MultiByteToWideChar(code_page, flags, source.as_ptr(), source_length,
        output.as_mut_ptr(), capacity) };
    if written == 0 { return Err(host_conversion_error(operation)); }
    usize::try_from(written).map_err(|_| resource_limit(operation))
}

fn encoded_length(code_page: u32, source: &[u16], operation: &'static str)
    -> Result<usize, RuntimeError> {
    let source_length = i32::try_from(source.len()).map_err(|_| resource_limit(operation))?;
    let (flags, _) = encoding_flags(code_page);
    let length = unsafe { WideCharToMultiByte(code_page, flags, source.as_ptr(), source_length,
        std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut()) };
    if length == 0 { return Err(host_conversion_error(operation)); }
    usize::try_from(length).map_err(|_| resource_limit(operation))
}

fn encode_multibyte(code_page: u32, source: &[u16], output: &mut [u8],
    operation: &'static str) -> Result<Option<usize>, RuntimeError> {
    let source_length = i32::try_from(source.len()).map_err(|_| resource_limit(operation))?;
    let capacity = i32::try_from(output.len()).map_err(|_| resource_limit(operation))?;
    let (flags, supports_default) = encoding_flags(code_page);
    let mut used_default = 0;
    let default_ptr = if supports_default { &mut used_default } else { std::ptr::null_mut() };
    let written = unsafe { WideCharToMultiByte(code_page, flags, source.as_ptr(), source_length,
        output.as_mut_ptr(), capacity, std::ptr::null(), default_ptr) };
    if written == 0 { return Err(host_conversion_error(operation)); }
    if used_default != 0 { return Ok(None); }
    usize::try_from(written).map(Some).map_err(|_| resource_limit(operation))
}

fn encoding_flags(code_page: u32) -> (u32, bool) {
    if code_page == CP_UTF8 { (WC_ERR_INVALID_CHARS, false) }
    else { (WC_NO_BEST_FIT_CHARS, true) }
}

fn host_conversion_error(operation: &'static str) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, operation, std::io::Error::last_os_error())
}

fn nul_terminated_wide(units: &[u16], operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    if units.contains(&0) { return Err(invariant("host path input contains an embedded NUL")); }
    let length = units.len().checked_add(1).ok_or_else(|| resource_limit(operation))?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, operation, error,
    ))?;
    result.extend_from_slice(units);
    result.push(0_u16);
    Ok(result)
}

fn zeroed_buffer(length: usize, operation: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, operation, error,
    ))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn zeroed_buffer_u16(length: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, operation, error,
    ))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn resource_limit(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, operation)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
