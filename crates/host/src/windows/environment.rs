//! Inherited Windows process environment adapted to the guest DOS namespace.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use dos_kernel::{DosErrorCode, DosHostError};
use windows_sys::Win32::Globalization::WideCharToMultiByte;

use crate::filesystem::Filesystem;

/// Non-fatal environment adaptation outcomes for launcher diagnostics.
#[derive(Debug, Default)]
pub struct EnvironmentReport {
    /// Number of returned environment entries where Windows substituted its
    /// default OEM character during conversion.
    pub replacement_entries: usize,
}

/// Build inherited DOS `NAME=VALUE` entries, mapping host path variables only
/// when their targets are reachable through the existing filesystem root.
pub(super) fn inherited_environment(
    filesystem: &mut Filesystem,
    code_page: u32,
) -> Result<(Vec<Vec<u8>>, EnvironmentReport), DosHostError> {
    let mut entries = Vec::new();
    let mut report = EnvironmentReport::default();

    for (name, value) in std::env::vars_os() {
        let mut name_units = wide_units(name.as_os_str())?;
        if name_units.is_empty()
            || name_units.first().copied() == Some(b'=' as u16)
            || name_units.contains(&(b'=' as u16))
        {
            // Windows per-drive current-directory entries (for example
            // `=C:=...`) are not DOS NAME=VALUE variables.
            continue;
        }

        let name_ascii = ascii_environment_name(&name_units)?;
        uppercase_ascii(&mut name_units);
        let (name_bytes, name_replaced) = encode_wide(&name_units, code_page)?;

        match name_ascii.as_deref() {
            Some("PATH") => {
                let Some(path_value) = map_path_list(filesystem, value.as_os_str())? else {
                    continue;
                };
                push_entry(&mut entries, &mut report, name_bytes, &path_value, name_replaced)?;
            }
            Some("COMSPEC") => {
                let Some(host_path) = absolute_host_path(value.as_os_str()) else {
                    continue;
                };
                let Some(guest_path) = map_optional_path(
                    filesystem.guest_path_for_host_path(&host_path),
                )? else {
                    continue;
                };
                // COMSPEC must name a file. A mapped directory is not a usable
                // command processor and must not leak through under this key.
                if map_optional_path(
                    filesystem.guest_directory_for_host_path(&host_path),
                )?
                .is_some()
                {
                    continue;
                }
                push_entry(&mut entries, &mut report, name_bytes, &guest_path, name_replaced)?;
            }
            Some(name) if is_host_directory_variable(name) => {
                let Some(host_path) = absolute_host_path(value.as_os_str()) else {
                    continue;
                };
                let Some(guest_path) = map_optional_path(
                    filesystem.guest_directory_for_host_path(&host_path),
                )? else {
                    continue;
                };
                push_entry(&mut entries, &mut report, name_bytes, &guest_path, name_replaced)?;
            }
            Some("HOMEDRIVE") | Some("HOMEPATH") | Some("SYSTEMDRIVE") => {
                // These host path fragments cannot safely be translated
                // independently into the single-root guest drive namespace.
            }
            _ => {
                // Unclassified values are caller data, even when they begin
                // with a drive path. They may contain lists or command lines;
                // interpreting them as one filename changes their meaning.
                let value_units = wide_units(value.as_os_str())?;
                let (value_bytes, value_replaced) = encode_wide(&value_units, code_page)?;
                push_entry(
                    &mut entries,
                    &mut report,
                    name_bytes,
                    &value_bytes,
                    name_replaced || value_replaced,
                )?;
            }
        }
    }

    Ok((entries, report))
}

fn is_optional_path_error(code: DosErrorCode) -> bool {
    matches!(
        code,
        DosErrorCode::FileNotFound
            | DosErrorCode::PathNotFound
            | DosErrorCode::AccessDenied
            | DosErrorCode::InvalidData
            | DosErrorCode::UnknownUnit
    )
}

fn map_optional_path(
    result: Result<Option<Vec<u8>>, DosHostError>,
) -> Result<Option<Vec<u8>>, DosHostError> {
    match result {
        Ok(path) => Ok(path),
        Err(error) if is_optional_path_error(error.code) => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_host_directory_variable(name: &str) -> bool {
    matches!(
        name,
        "WINDIR"
            | "TEMP"
            | "TMP"
            | "SYSTEMROOT"
            | "USERPROFILE"
            | "ALLUSERSPROFILE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "PROGRAMW6432"
            | "COMMONPROGRAMFILES"
            | "COMMONPROGRAMFILES(X86)"
            | "COMMONPROGRAMW6432"
            | "PUBLIC"
    )
}

fn ascii_environment_name(name: &[u16]) -> Result<Option<String>, DosHostError> {
    if name.iter().any(|unit| *unit > 0x7F) {
        return Ok(None);
    }
    let mut output = String::new();
    output.try_reserve(name.len()).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    output.extend(name.iter().map(|unit| (*unit as u8 as char).to_ascii_uppercase()));
    Ok(Some(output))
}

fn uppercase_ascii(name: &mut [u16]) {
    for unit in name {
        if (b'a' as u16..=b'z' as u16).contains(unit) {
            *unit -= b'a' as u16 - b'A' as u16;
        }
    }
}

fn wide_units(value: &OsStr) -> Result<Vec<u16>, DosHostError> {
    let length = value.encode_wide().count();
    let mut units = Vec::new();
    units.try_reserve_exact(length).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    units.extend(value.encode_wide());
    Ok(units)
}

fn absolute_host_path(value: &OsStr) -> Option<PathBuf> {
    let path = Path::new(value);
    path.is_absolute().then(|| path.to_path_buf())
}

fn map_path_list(
    filesystem: &mut Filesystem,
    value: &OsStr,
) -> Result<Option<Vec<u8>>, DosHostError> {
    let mut result = Vec::new();
    for host_path in std::env::split_paths(value) {
        if host_path.is_absolute() {
            if let Some(guest_path) = map_optional_path(
                filesystem.guest_directory_for_host_path(&host_path),
            )? {
                if !result.is_empty() {
                    push_byte(&mut result, b';')?;
                }
                append_bytes(&mut result, &guest_path)?;
            }
        }
    }

    Ok((!result.is_empty()).then_some(result))
}

fn push_entry(
    entries: &mut Vec<Vec<u8>>,
    report: &mut EnvironmentReport,
    name: Vec<u8>,
    value: &[u8],
    replaced: bool,
) -> Result<(), DosHostError> {
    let length = name
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| DosHostError::new(DosErrorCode::InsufficientMemory))?;
    let mut entry = Vec::new();
    entry.try_reserve_exact(length).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    entry.extend_from_slice(&name);
    entry.push(b'=');
    entry.extend_from_slice(value);
    entries.try_reserve(1).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    entries.push(entry);
    if replaced {
        report.replacement_entries = report
            .replacement_entries
            .checked_add(1)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InsufficientMemory))?;
    }
    Ok(())
}

fn push_byte(output: &mut Vec<u8>, byte: u8) -> Result<(), DosHostError> {
    output.try_reserve(1).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    output.push(byte);
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), DosHostError> {
    output.try_reserve(value.len()).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_wide(input: &[u16], code_page: u32) -> Result<(Vec<u8>, bool), DosHostError> {
    if input.is_empty() {
        return Ok((Vec::new(), false));
    }
    let input_length = i32::try_from(input.len()).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InvalidData, error)
    })?;

    // SAFETY: `input` is a valid UTF-16 slice held for both calls. The first
    // call requests the required byte count and supplies no output buffer.
    let required = unsafe {
        WideCharToMultiByte(
            code_page,
            0,
            input.as_ptr(),
            input_length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if required <= 0 {
        return Err(super::last_error());
    }

    let output_length = usize::try_from(required).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InvalidData, error)
    })?;
    let mut output = Vec::new();
    output.try_reserve_exact(output_length).map_err(|error| {
        DosHostError::with_source(DosErrorCode::InsufficientMemory, error)
    })?;
    output.resize(output_length, 0);
    let mut used_default_character = 0i32;

    // SAFETY: `output` has exactly the size reported by the sizing call; both
    // buffers remain alive and nonoverlapping for the duration of conversion.
    let written = unsafe {
        WideCharToMultiByte(
            code_page,
            0,
            input.as_ptr(),
            input_length,
            output.as_mut_ptr(),
            required,
            std::ptr::null(),
            &mut used_default_character,
        )
    };
    if written <= 0 {
        return Err(super::last_error());
    }
    if written != required {
        return Err(DosHostError::with_source(
            DosErrorCode::GeneralFailure,
            io::Error::new(
                io::ErrorKind::Other,
                format!("WideCharToMultiByte wrote {written} of {required} bytes"),
            ),
        ));
    }

    Ok((output, used_default_character != 0))
}
