//! LoadModule shares filename search and launches its already copied image.

use super::*;
use runtime::{Win16HostProgramLoadInput, Win16HostShellExecutionOperation};
use std::io::{Read, Seek, Write};

fn operation(
    host: &super::super::WindowsHost,
    input: &Win16HostProgramLoadInput,
) -> Result<Result<Win16HostShellExecutionOperation, u16>, RuntimeError> {
    let wide = match host.win16_dcs.text_codec().to_wide(&input.name) {
        Ok(wide) => wide,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(11)),
        Err(error) => return Err(error),
    };
    if wide.is_empty() {
        return Ok(Err(2));
    }
    if wide.iter().any(|unit| matches!(unit, 0 | 0x22)) {
        return Ok(Err(11));
    }
    // Quote the complete filename, with no argument round trip through a
    // command-line parser. DBCS trail bytes remain inside the filename.
    let mut command_line = vec![b'"'];
    command_line.extend_from_slice(&input.name);
    command_line.push(b'"');
    Ok(Ok(Win16HostShellExecutionOperation::WinExec {
        command_line,
        directory: input.directory.clone(),
        application_path: input.application_path.clone(),
        environment: input.environment.clone(),
        owner: input.owner,
        show: 1,
    }))
}

pub(in crate::windows) fn read_image(
    host: &mut super::super::WindowsHost,
    input: &Win16HostProgramLoadInput,
) -> Result<Result<runtime::Win16ModuleImage, u16>, RuntimeError> {
    let operation = match operation(host, input)? {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    let mut prepared = match prepare(host, &operation)? {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    let mut image = Vec::new();
    Read::by_ref(&mut prepared.file)
        .take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut image)
        .map_err(|error| failure("copy owned LoadModule image", error))?;
    if image.len() as u64 > MAX_IMAGE_BYTES {
        return Ok(Err(8));
    }
    let path = match host.win16_main_module_path(&prepared.program) {
        Ok(path) => path,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(11)),
        Err(error) => return Err(error),
    };
    Ok(Ok(runtime::Win16ModuleImage { path, image }))
}

pub(super) fn prepare_module(
    host: &mut super::super::WindowsHost,
    input: &Win16HostProgramLoadInput,
    image: &runtime::Win16ModuleImage,
    command_tail: &[u8],
    environment: &[u8],
    show: u16,
) -> Result<Result<PreparedLaunch, u16>, RuntimeError> {
    let mut resolved = input.clone();
    resolved.name = image.path.clone();
    let operation = match operation(host, &resolved)? {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    let mut prepared = match prepare(host, &operation)? {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    if image.image.len() as u64 > MAX_IMAGE_BYTES || command_tail.len() > 126 {
        return Ok(Err(8));
    }
    // The runtime classified this exact owned image. Passing it through an
    // anonymous file preserves that decision across reentrant USER calls;
    // reopening the pathname must never substitute executable bytes.
    let mut file = tempfile::tempfile()
        .map_err(|error| failure("create owned LoadModule image transfer", error))?;
    file.write_all(&image.image)
        .map_err(|error| failure("write owned LoadModule image transfer", error))?;
    file.rewind()
        .map_err(|error| failure("rewind owned LoadModule image transfer", error))?;
    prepared.guest = super::prepare::is_guest(&mut file, &prepared.program)?;
    file.rewind()
        .map_err(|error| failure("rewind classified LoadModule image", error))?;
    prepared._source_file = Some(std::mem::replace(&mut prepared.file, file));
    prepared.request.command_tail = command_tail.to_vec();
    prepared.request.environment = environment
        .split(|byte| *byte == 0)
        .take_while(|entry| !entry.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    prepared.request.show = show;
    if !prepared.guest {
        prepared.native_environment = Some(match native_environment(host, environment) {
            Ok(block) => block,
            Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(11)),
            Err(error) => return Err(error),
        });
        let tail = host.win16_dcs.text_codec().to_wide(command_tail)?;
        if tail.contains(&0) {
            return Ok(Err(11));
        }
        prepared.native_command.pop();
        if !tail.is_empty() {
            prepared.native_command.push(0x20);
            prepared.native_command.extend(tail);
        }
        prepared.native_command.push(0);
        if prepared.native_command.len() > 32_767 {
            return Ok(Err(11));
        }
    }
    Ok(Ok(prepared))
}

fn native_environment(
    host: &super::super::WindowsHost,
    environment: &[u8],
) -> Result<Vec<u16>, RuntimeError> {
    use std::cmp::Ordering;
    use windows_sys::Win32::Globalization::CompareStringOrdinal;
    let mut entries = Vec::new();
    for entry in environment
        .split(|byte| *byte == 0)
        .take_while(|entry| !entry.is_empty())
    {
        let text = host
            .filesystem
            .guest_code_page()
            .decode(entry)
            .map_err(|error| failure("decode native program environment", error))?;
        let wide: Vec<u16> = text.encode_utf16().collect();
        let name_end = wide
            .iter()
            .position(|unit| *unit == u16::from(b'='))
            .filter(|offset| *offset > 0)
            .ok_or_else(|| invalid("native program environment has an invalid variable name"))?;
        entries.push((name_end, wide));
    }
    let mut failed = None;
    // Windows environment blocks use ordinal, case-insensitive name order.
    // A stable sort preserves the source order of duplicate guest names.
    entries.sort_by(|(left_end, left), (right_end, right)| {
        // SAFETY: CompareStringOrdinal reads two caller-owned UTF-16 spans of the lengths passed with them.
        let result = unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                *left_end as i32,
                right.as_ptr(),
                *right_end as i32,
                1,
            )
        };
        match result {
            1 => Ordering::Less,
            2 => Ordering::Equal,
            3 => Ordering::Greater,
            _ => {
                failed.get_or_insert_with(std::io::Error::last_os_error);
                Ordering::Equal
            }
        }
    });
    if let Some(error) = failed {
        return Err(failure("order native program environment", error));
    }
    let mut block = Vec::new();
    for (_, entry) in entries {
        block.extend(entry);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}
