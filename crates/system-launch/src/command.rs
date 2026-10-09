#![forbid(unsafe_code)]

use windows_sys::Win32::Foundation::{
    ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME, ERROR_NOT_ENOUGH_MEMORY,
};

// CreateProcessW permits 32,767 UTF-16 units including the terminating NUL.
pub(crate) const MAX_COMMAND_UNITS: usize = 32_767;

pub(crate) fn mapped_command(
    launcher: &[u16],
    program: &[u16],
    original: &[u16],
) -> Result<Vec<u16>, u32> {
    if launcher.is_empty() || program.is_empty()
        || launcher.contains(&u16::from(b'"')) || program.contains(&u16::from(b'"'))
    {
        return Err(ERROR_INVALID_NAME);
    }
    let tail = command_tail(original);
    let module_marker = " --system-module ";
    let command_marker = " --system-command ";
    let length = launcher.len() + program.len() + tail.len()
        + module_marker.len() + command_marker.len() + 5;
    if length > MAX_COMMAND_UNITS {
        return Err(ERROR_FILENAME_EXCED_RANGE);
    }
    let mut mapped = Vec::new();
    mapped.try_reserve_exact(length).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
    quote(&mut mapped, launcher);
    mapped.extend(module_marker.encode_utf16());
    quote(&mut mapped, program);
    mapped.extend(command_marker.encode_utf16());
    mapped.extend_from_slice(tail);
    mapped.push(0);
    Ok(mapped)
}

fn quote(output: &mut Vec<u16>, path: &[u16]) {
    output.push(u16::from(b'"'));
    output.extend_from_slice(path);
    output.push(u16::from(b'"'));
}

fn command_tail(original: &[u16]) -> &[u16] {
    // Windows' argument decoder returns parsed arguments, not the original
    // UTF-16 tail. Scan only argv0 so guest quotes and whitespace stay intact.
    let mut quoted = false;
    for (index, &unit) in original.iter().enumerate() {
        if unit == u16::from(b'"') {
            quoted = !quoted;
        } else if !quoted && (unit == u16::from(b' ') || unit == u16::from(b'\t')) {
            return &original[index + 1..];
        }
    }
    &[]
}
