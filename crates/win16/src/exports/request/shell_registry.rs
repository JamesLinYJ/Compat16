//! Typed requests for the SHELL DLL's Win16 registry API.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};
use crate::strings::read_ansi_z;

const MAX_WIN16_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ShellRegistryRequest {
    OpenKey { root: u32, subkey: Vec<u8>, output: u32 },
    CreateKey { root: u32, subkey: Vec<u8>, output: u32 },
    CloseKey { key: u32 },
    DeleteKey { root: u32, subkey: Vec<u8> },
    SetValue {
        key: u32,
        subkey: Vec<u8>,
        value_type: u32,
        value: Vec<u8>,
        declared_byte_count: u32,
    },
    QueryValue {
        key: u32,
        subkey: Vec<u8>,
        output: u32,
        byte_count: u32,
        byte_count_output: u32,
    },
    EnumKey { key: u32, index: u32, output: u32, capacity: u32 },
}

/// Decode the known SHELL registry exports by exact ordinal. Pointer fields
/// remain guest FAR values for runtime-side preflight and transactional output.
pub fn decode_shell_registry_export(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ShellRegistryRequest, Win16Error> {
    let request = match ordinal {
        1 => Win16ShellRegistryRequest::OpenKey {
            root: dword(arguments, 0)?,
            subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
            output: dword(arguments, 2)?,
        },
        2 => Win16ShellRegistryRequest::CreateKey {
            root: dword(arguments, 0)?,
            subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
            output: dword(arguments, 2)?,
        },
        3 => Win16ShellRegistryRequest::CloseKey { key: dword(arguments, 0)? },
        4 => Win16ShellRegistryRequest::DeleteKey {
            root: dword(arguments, 0)?,
            subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
        },
        5 => {
            let length = dword(arguments, 4)?;
            let value_far = dword(arguments, 3)?;
            Win16ShellRegistryRequest::SetValue {
                key: dword(arguments, 0)?,
                subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
                value_type: dword(arguments, 2)?,
                value: read_fixed_buffer(value_far, length, selectors, memory)?,
                declared_byte_count: length,
            }
        }
        6 => {
            let byte_count = read_u32_far(dword(arguments, 3)?, selectors, memory)?;
            Win16ShellRegistryRequest::QueryValue {
                key: dword(arguments, 0)?,
                subkey: optional_string(dword(arguments, 1)?, selectors, memory)?,
                output: dword(arguments, 2)?,
                byte_count,
                byte_count_output: dword(arguments, 3)?,
            }
        }
        7 => Win16ShellRegistryRequest::EnumKey {
            key: dword(arguments, 0)?,
            index: dword(arguments, 1)?,
            output: dword(arguments, 2)?,
            capacity: dword(arguments, 3)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn optional_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if far == 0 { Ok(Vec::new()) }
    else { read_ansi_z(selectors, memory, far, MAX_WIN16_STRING_BYTES) }
}

fn read_fixed_buffer(
    far: u32,
    length: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let length = usize::try_from(length).map_err(|_| Win16Error::InvalidRange)?;
    if length > MAX_WIN16_STRING_BYTES { return Err(Win16Error::InvalidRange); }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    if length != 0 {
        selectors.read(memory, selectors.pointer_from_far(far)?, &mut bytes)?;
    }
    Ok(bytes)
}

fn read_u32_far(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u32, Win16Error> {
    let mut bytes = [0_u8; 4];
    selectors.read(memory, selectors.pointer_from_far(far)?, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}
