//! Windows path and ANSI conversion for Win16 SHELL executable queries.

use crate::windows::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostShellPathEncodingCause,
    Win16HostShellPathEncodingFailure,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetBinaryTypeW, GetFullPathNameW, GetShortPathNameW,
};
use windows_sys::Win32::UI::Shell::{PATHCCH_ALLOW_LONG_PATHS, PATHCCH_MAX_CCH, PathCchCombineEx};

pub(super) enum PathEncodingOutcome {
    Encoded(Vec<u8>),
    Unrepresentable(Win16HostShellPathEncodingFailure),
}

pub(super) enum AnsiInputConversion {
    Encoded(Vec<u16>),
    Unrepresentable(Win16HostShellPathEncodingCause),
}

enum AnsiPathConversion {
    Encoded(Vec<u8>),
    Unrepresentable(Win16HostShellPathEncodingCause),
}

enum ShortPathLookup {
    Path(Vec<u16>),
    Unavailable(Win16HostShellPathEncodingCause),
}

pub(super) fn resolve_executable_input(
    file: &[u16],
    directory: Option<&[u16]>,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if file.len() <= 1 || file.last() != Some(&0) {
        return Ok(None);
    }
    let mut combined = allocate_wide(
        PATHCCH_MAX_CCH as usize,
        "reserve combined SHELL input path",
    )?;
    combined.fill(u16::MAX);
    if let Some(directory) = directory.filter(|value| value.len() > 1) {
        if directory.last() != Some(&0) {
            return Ok(None);
        }
        let output = combined.as_mut_ptr();
        let capacity = combined.len();
        let directory_path = directory.as_ptr();
        let file_path = file.as_ptr();
        // SAFETY: `output` addresses `capacity` initialized UTF-16 units in
        // `combined`, and that buffer stays live for this call.
        // `directory_path` and `file_path` point at the NUL-terminated UTF-16
        // directory and file, which stay live. PathCchCombineEx writes the
        // combined path into `output` and returns an HRESULT. It retains no
        // pointer. No pointer is a guest address.
        let result = unsafe {
            PathCchCombineEx(
                output,
                capacity,
                directory_path,
                file_path,
                PATHCCH_ALLOW_LONG_PATHS,
            )
        };
        if result < 0 {
            return Ok(None);
        }
    } else {
        if file.len() > combined.len() {
            return Ok(None);
        }
        combined[..file.len()].copy_from_slice(file);
    }
    if !combined.contains(&0) {
        return Ok(None);
    }

    let mut full_path = allocate_wide(
        PATHCCH_MAX_CCH as usize,
        "reserve absolute SHELL input path",
    )?;
    full_path.fill(u16::MAX);
    let path = combined.as_ptr();
    let capacity = full_path.len() as u32;
    let output = full_path.as_mut_ptr();
    // SAFETY: `path` points at the NUL-terminated UTF-16 path in `combined`,
    // which stays live for this call. `output` addresses `capacity` initialized
    // UTF-16 units in `full_path`, and that buffer stays live. The file-part
    // pointer is null. GetFullPathNameW writes the full path into `output` and
    // returns the unit count, excluding the terminator. It retains no pointer.
    // No pointer is a guest address.
    let length = unsafe { GetFullPathNameW(path, capacity, output, std::ptr::null_mut()) } as usize;
    if length == 0 || length >= full_path.len() || full_path[length] != 0 {
        return Ok(None);
    }
    full_path.truncate(length + 1);
    let mut binary_type: u32 = 0;
    let path = full_path.as_ptr();
    let binary_type_slot = &mut binary_type;
    // SAFETY: `path` points at the NUL-terminated UTF-16 path in `full_path`,
    // which stays live for this call. `binary_type_slot` addresses the local
    // `binary_type`, which stays live. GetBinaryTypeW writes the binary type
    // there and returns nonzero on success. It retains no pointer. No pointer
    // is a guest address.
    if unsafe { GetBinaryTypeW(path, binary_type_slot) } == 0 {
        return Ok(None);
    }
    Ok(Some(full_path))
}

pub(super) fn lossless_executable_path(
    codec: GuestTextCodec,
    full_path: Vec<u16>,
) -> Result<PathEncodingOutcome, RuntimeError> {
    if full_path.len() <= 1 || full_path.last() != Some(&0) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "resolved executable path lost its UTF-16 terminator",
        ));
    }
    let full_path_cause = match wide_path_to_ansi(codec, &full_path[..full_path.len() - 1])? {
        AnsiPathConversion::Encoded(path) => return Ok(PathEncodingOutcome::Encoded(path)),
        AnsiPathConversion::Unrepresentable(cause) => cause,
    };
    let short_path_cause = match short_executable_path(&full_path)? {
        ShortPathLookup::Path(path) => match wide_path_to_ansi(codec, &path[..path.len() - 1])? {
            AnsiPathConversion::Encoded(path) => return Ok(PathEncodingOutcome::Encoded(path)),
            AnsiPathConversion::Unrepresentable(cause) => cause,
        },
        ShortPathLookup::Unavailable(cause) => cause,
    };
    Ok(PathEncodingOutcome::Unrepresentable(
        Win16HostShellPathEncodingFailure {
            path: full_path,
            full_path_cause,
            short_path_cause,
        },
    ))
}

pub(super) fn ansi_path_to_wide(
    codec: GuestTextCodec,
    bytes: &[u8],
) -> Result<AnsiInputConversion, RuntimeError> {
    if bytes.is_empty() {
        return Ok(AnsiInputConversion::Encoded(allocate_wide(
            1,
            "reserve empty Win16 SHELL path",
        )?));
    }
    let mut wide = match codec.to_wide(bytes) {
        Ok(wide) => wide,
        Err(error) => {
            return match conversion_failure(error) {
                Ok(cause) => Ok(AnsiInputConversion::Unrepresentable(cause)),
                Err(error) => Err(error),
            };
        }
    };
    if let Err(cause) = wide_round_trip_as_ansi(codec, &wide, bytes)? {
        return Ok(AnsiInputConversion::Unrepresentable(cause));
    }
    wide.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate converted Win16 SHELL path",
            error,
        )
    })?;
    wide.push(0);
    Ok(AnsiInputConversion::Encoded(wide))
}

fn wide_round_trip_as_ansi(
    codec: GuestTextCodec,
    wide: &[u16],
    expected: &[u8],
) -> Result<Result<(), Win16HostShellPathEncodingCause>, RuntimeError> {
    if wide.is_empty() {
        return Ok(if expected.is_empty() {
            Ok(())
        } else {
            Err(Win16HostShellPathEncodingCause::RoundTripMismatch)
        });
    }
    let encoded = match codec.from_wide(wide) {
        Ok(encoded) => encoded,
        Err(error) => {
            return match conversion_failure(error) {
                Ok(cause) => Ok(Err(cause)),
                Err(error) => Err(error),
            };
        }
    };
    if encoded.used_default_char == Some(true) {
        return Ok(Err(Win16HostShellPathEncodingCause::DefaultCharacterUsed));
    }
    Ok(if encoded.bytes == expected {
        Ok(())
    } else {
        Err(Win16HostShellPathEncodingCause::RoundTripMismatch)
    })
}

fn wide_path_to_ansi(
    codec: GuestTextCodec,
    wide: &[u16],
) -> Result<AnsiPathConversion, RuntimeError> {
    if wide.is_empty() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "cannot convert an empty executable path",
        ));
    }
    let encoded = match codec.from_wide(wide) {
        Ok(encoded) => encoded,
        Err(error) => {
            return match conversion_failure(error) {
                Ok(cause) => Ok(AnsiPathConversion::Unrepresentable(cause)),
                Err(error) => Err(error),
            };
        }
    };
    if encoded.used_default_char == Some(true) {
        return Ok(AnsiPathConversion::Unrepresentable(
            Win16HostShellPathEncodingCause::DefaultCharacterUsed,
        ));
    }
    if !ansi_bytes_match_wide(codec, wide, &encoded.bytes)? {
        return Ok(AnsiPathConversion::Unrepresentable(
            Win16HostShellPathEncodingCause::RoundTripMismatch,
        ));
    }
    Ok(AnsiPathConversion::Encoded(encoded.bytes))
}

fn ansi_bytes_match_wide(
    codec: GuestTextCodec,
    wide: &[u16],
    bytes: &[u8],
) -> Result<bool, RuntimeError> {
    if bytes.is_empty() {
        return Ok(wide.is_empty());
    }
    match codec.to_wide(bytes) {
        Ok(converted) => Ok(converted == wide),
        Err(error) if error.kind() == Kind::ResourceExhausted => Err(error),
        Err(_) => Ok(false),
    }
}

fn conversion_failure(
    error: RuntimeError,
) -> Result<Win16HostShellPathEncodingCause, RuntimeError> {
    if error.kind() == Kind::HostFailure {
        Ok(Win16HostShellPathEncodingCause::ConversionFailed {
            last_error: (crate::windows::win32_safe::last_error()),
        })
    } else {
        Err(error)
    }
}

fn allocate_wide(length: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut wide = Vec::new();
    wide.try_reserve_exact(length)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    wide.resize(length, 0);
    Ok(wide)
}

fn short_executable_path(full_path: &[u16]) -> Result<ShortPathLookup, RuntimeError> {
    let mut short_path = allocate_wide(
        PATHCCH_MAX_CCH as usize,
        "reserve short SHELL executable path",
    )?;
    short_path.fill(u16::MAX);
    let path = full_path.as_ptr();
    let output = short_path.as_mut_ptr();
    let capacity = short_path.len() as u32;
    // SAFETY: `path` points at the NUL-terminated UTF-16 path in `full_path`,
    // which stays live for this call. `output` addresses `capacity` initialized
    // UTF-16 units in `short_path`, and that buffer stays live.
    // GetShortPathNameW writes the short path into `output` and returns the
    // unit count, excluding the terminator. It retains no pointer. No pointer
    // is a guest address.
    let length = unsafe { GetShortPathNameW(path, output, capacity) } as usize;
    if length == 0 {
        return Ok(ShortPathLookup::Unavailable(
            Win16HostShellPathEncodingCause::ShortAliasUnavailable {
                last_error: (crate::windows::win32_safe::last_error()),
            },
        ));
    }
    if length >= short_path.len() {
        return Ok(ShortPathLookup::Unavailable(
            Win16HostShellPathEncodingCause::ShortAliasTooLong { required: length },
        ));
    }
    if short_path[length] != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "GetShortPathNameW reported success without a terminated path",
        ));
    }
    short_path.truncate(length + 1);
    let mut binary_type: u32 = 0;
    let path = short_path.as_ptr();
    let binary_type_slot = &mut binary_type;
    // SAFETY: `path` points at the NUL-terminated UTF-16 path in `short_path`,
    // which stays live for this call. `binary_type_slot` addresses the local
    // `binary_type`, which stays live. GetBinaryTypeW writes the binary type
    // there and returns nonzero on success. It retains no pointer. No pointer
    // is a guest address.
    if unsafe { GetBinaryTypeW(path, binary_type_slot) } == 0 {
        return Ok(ShortPathLookup::Unavailable(
            Win16HostShellPathEncodingCause::ShortAliasUnavailable {
                last_error: (crate::windows::win32_safe::last_error()),
            },
        ));
    }
    Ok(ShortPathLookup::Path(short_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn ansi_shell_path_decodes_with_guest_page_and_keeps_utf16_terminator() {
        let codec = cp936();
        let AnsiInputConversion::Encoded(path) = ansi_path_to_wide(codec, &[0xd6, 0xd0]).unwrap()
        else {
            panic!("valid guest code-page bytes should round-trip")
        };
        assert_eq!(path, [0x4e2d, 0]);
    }

    #[test]
    fn resolved_shell_path_returns_guest_bytes_only_after_exact_roundtrip() {
        let codec = cp936();
        let AnsiPathConversion::Encoded(bytes) =
            wide_path_to_ansi(codec, &[0x4e2d, b'\\' as u16, b'a' as u16]).unwrap()
        else {
            panic!("representable path should encode")
        };
        assert_eq!(bytes, [0xd6, 0xd0, b'\\', b'a']);
        assert!(matches!(
            wide_path_to_ansi(codec, &[0xd83d, 0xde00]),
            Ok(AnsiPathConversion::Unrepresentable(_))
        ));
    }
}
