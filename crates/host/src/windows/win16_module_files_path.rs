use super::{MAX_WIDE_PATH_UNITS, NativeFile, nul_terminated_wide, wide_os_units};
use crate::windows::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use std::path::Path;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, GetShortPathNameW,
    OPEN_EXISTING,
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeFileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

/// Convert a canonical host module path to the fixed guest code page.
///
/// Rust's Windows canonical paths can use the `\\?\` namespace. For only
/// drive and UNC forms, try the corresponding ordinary Win32 path and adopt it
/// only when Windows reports the same volume/file identity for both names.
/// Prefer a native short path for Win16 callers with DOS-era path buffers,
/// using it only after the same identity and exact encoding checks. When
/// Windows provides no usable alias, preserve an exactly representable long
/// path. Unknown device/volume forms
/// and unverified conversions are never rewritten.
pub(super) fn win16_main_module_path(
    path: &Path,
    codec: GuestTextCodec,
) -> Result<Vec<u8>, RuntimeError> {
    let original = wide_os_units(path.as_os_str())?;
    win16_module_path(&original, codec)
}

pub(super) fn win16_module_path(
    original: &[u16],
    codec: GuestTextCodec,
) -> Result<Vec<u8>, RuntimeError> {
    if original.is_empty() || original.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 module path is empty or contains a null character",
        ));
    }
    let standard = standard_path_from_extended(original)?;
    let selected = if let Some(standard) = standard.as_deref() {
        if same_native_file(original, standard)? {
            standard
        } else {
            original
        }
    } else {
        original
    };
    // GetShortPathNameW can also return the unchanged long path (for example
    // on ReFS). Do not invent an alias or assume that API success shortened it.
    if let Some(short) = short_path_units(selected)? {
        if same_native_file(original, &short)? {
            match encode_exact_guest_path(codec, &short) {
                Ok(bytes) => return Ok(bytes),
                Err(error) if error.kind() == Kind::InvalidInput => {}
                Err(error) => return Err(error),
            }
        }
    }
    encode_exact_guest_path(codec, selected)
}

pub(super) fn encode_exact_guest_path(
    codec: GuestTextCodec,
    wide: &[u16],
) -> Result<Vec<u8>, RuntimeError> {
    let encoded = codec.from_wide(wide)?;
    if encoded.used_default_char == Some(true) || codec.to_wide(&encoded.bytes)? != wide {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 executable path conversion would change its identity",
        ));
    }
    Ok(encoded.bytes)
}

fn short_path_units(path: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    let path_z = nul_terminated_wide(path)?;
    let mut output = Vec::new();
    output.try_reserve_exact(260).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate short Win16 executable path buffer",
            error,
        )
    })?;
    output.resize(260, 0);
    loop {
        let capacity = u32::try_from(output.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "short Win16 executable path capacity exceeds DWORD",
                error,
            )
        })?;
        // SAFETY: path_z is NUL terminated and output has the advertised
        // writable UTF-16 capacity for this synchronous API call.
        let length = unsafe { GetShortPathNameW(path_z.as_ptr(), output.as_mut_ptr(), capacity) };
        if length == 0 {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "short Win16 executable path length does not fit host memory",
                error,
            )
        })?;
        if length < output.len() {
            if output.get(length) != Some(&0) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "GetShortPathNameW returned an unterminated path",
                ));
            }
            output.truncate(length);
            return Ok(Some(output));
        }
        let doubled = output.len().checked_mul(2).unwrap_or(MAX_WIDE_PATH_UNITS);
        let next = length.max(doubled);
        if next > MAX_WIDE_PATH_UNITS || next <= output.len() {
            return Ok(None);
        }
        output
            .try_reserve_exact(next - output.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "grow short Win16 executable path buffer",
                    error,
                )
            })?;
        output.resize(next, 0);
    }
}

pub(super) fn standard_path_from_extended(path: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    let (replacement, removed) = if wide_ascii_prefix_eq(path, b"\\\\?\\UNC\\") {
        (&[b'\\' as u16, b'\\' as u16][..], 8)
    } else if path.get(..4) == Some(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16][..])
        && path.get(5) == Some(&(b':' as u16))
        && path.get(6) == Some(&(b'\\' as u16))
        && path.get(4).is_some_and(|unit| {
            (u16::from(b'A')..=u16::from(b'Z')).contains(unit)
                || (u16::from(b'a')..=u16::from(b'z')).contains(unit)
        })
    {
        (&[][..], 4)
    } else {
        return Ok(None);
    };
    if path.len() < removed {
        return Ok(None);
    }
    let length = replacement
        .len()
        .checked_add(path.len() - removed)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 executable path length overflow",
            )
        })?;
    let mut standard = Vec::new();
    standard.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate normalized Win16 executable path",
            error,
        )
    })?;
    standard.extend_from_slice(replacement);
    standard.extend_from_slice(&path[removed..]);
    Ok(Some(standard))
}

fn wide_ascii_prefix_eq(path: &[u16], prefix: &[u8]) -> bool {
    prefix.iter().enumerate().all(|(index, byte)| {
        path.get(index).is_some_and(|unit| {
            *unit == u16::from(byte.to_ascii_uppercase())
                || *unit == u16::from(byte.to_ascii_lowercase())
        })
    })
}

fn same_native_file(left: &[u16], right: &[u16]) -> Result<bool, RuntimeError> {
    let Some(left) = open_for_identity(left)? else {
        return Ok(false);
    };
    let Some(right) = open_for_identity(right)? else {
        return Ok(false);
    };
    let Some(left_identity) = native_file_identity(&left) else {
        return Ok(false);
    };
    let Some(right_identity) = native_file_identity(&right) else {
        return Ok(false);
    };
    Ok(left_identity == right_identity)
}

fn open_for_identity(path: &[u16]) -> Result<Option<NativeFile>, RuntimeError> {
    let terminated = nul_terminated_wide(path)?;
    // SAFETY: terminated is an owned NUL-terminated path; this requests only
    // file identity metadata, with sharing that leaves the executable usable.
    let handle = unsafe {
        CreateFileW(
            terminated.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(None);
    }
    Ok(Some(NativeFile(handle)))
}

fn native_file_identity(file: &NativeFile) -> Option<NativeFileIdentity> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: The handle remains owned by `file`; the writable SDK structure
    // has the size and alignment required for FileIdInfo.
    // Microsoft defines same-file identity as volume plus the complete 128-bit
    // file ID: https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_id_info
    if unsafe {
        GetFileInformationByHandleEx(
            file.0,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return None;
    }
    let file_id = information.FileId.Identifier;
    if file_id.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(NativeFileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id,
    })
}
