//! Checked argument decoder for the known NDDEAPI and NETAPI declarations.
//! COMM and the unknown NDDE password/window stubs never enter this decoder.

use super::request::network_admin::*;
use crate::{Access, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode_nddeapi(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16NetworkAdminRequest>, Win16Error> {
    let request = match ordinal {
        100 => Win16NddeRequest::ShareAdd {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            level: word(arguments, 1)?,
            info: read_sized(dword(arguments, 2)?, dword(arguments, 3)?, selectors, memory)?,
            declared_size: dword(arguments, 3)?,
        },
        101 => Win16NddeRequest::ShareDelete {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            share: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            reserved: word(arguments, 2)?,
        },
        102 => Win16NddeRequest::ShareEnum {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            level: word(arguments, 1)?,
            output: output_buffer(dword(arguments, 2)?, dword(arguments, 3)?, selectors, memory)?,
            entries_read: checked_output(dword(arguments, 4)?, 4, selectors, memory)?,
            total_entries: checked_output(dword(arguments, 5)?, 4, selectors, memory)?,
        },
        103 => Win16NddeRequest::ShareGetInfo {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            share: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            level: word(arguments, 2)?,
            output: output_buffer(dword(arguments, 3)?, dword(arguments, 4)?, selectors, memory)?,
            entries_read: checked_output(dword(arguments, 5)?, 4, selectors, memory)?,
            total_entries: checked_output(dword(arguments, 6)?, 4, selectors, memory)?,
        },
        104 => Win16NddeRequest::ShareSetInfo {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            share: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            level: word(arguments, 2)?,
            info: read_sized(dword(arguments, 3)?, dword(arguments, 4)?, selectors, memory)?,
            declared_size: dword(arguments, 4)?,
            reserved: word(arguments, 5)?,
        },
        105 => Win16NddeRequest::GetClientInfo {
            level: word(arguments, 0)?,
            client_name: output_buffer(dword(arguments, 1)?, dword(arguments, 2)?, selectors, memory)?,
            user_name: output_buffer(dword(arguments, 3)?, dword(arguments, 4)?, selectors, memory)?,
        },
        106 => Win16NddeRequest::GetNodeName {
            output: output_buffer(dword(arguments, 0)?, dword(arguments, 1)?, selectors, memory)?,
        },
        107 => Win16NddeRequest::GetErrorString {
            error: word(arguments, 0)?,
            output: output_buffer(dword(arguments, 1)?, dword(arguments, 2)?, selectors, memory)?,
        },
        108 => Win16NddeRequest::ConnectionEnum {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            share: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            user: dword(arguments, 2)?,
            level: word(arguments, 3)?,
            output: output_buffer(dword(arguments, 4)?, dword(arguments, 5)?, selectors, memory)?,
            entries_read: checked_output(dword(arguments, 6)?, 4, selectors, memory)?,
            total_entries: checked_output(dword(arguments, 7)?, 4, selectors, memory)?,
        },
        109 => Win16NddeRequest::IsValidShareName(read_nullable_z(dword(arguments, 0)?, selectors, memory)?),
        110 => Win16NddeRequest::IsValidPassword(read_nullable_z(dword(arguments, 0)?, selectors, memory)?),
        111 => Win16NddeRequest::IsValidTopic(read_nullable_z(dword(arguments, 0)?, selectors, memory)?),
        112 => Win16NddeRequest::SessionEnum {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            level: word(arguments, 1)?,
            output: output_buffer(dword(arguments, 2)?, dword(arguments, 3)?, selectors, memory)?,
            entries_read: checked_output(dword(arguments, 4)?, 4, selectors, memory)?,
            total_entries: checked_output(dword(arguments, 5)?, 4, selectors, memory)?,
        },
        113 => Win16NddeRequest::SessionClose {
            server: read_nullable_z(dword(arguments, 0)?, selectors, memory)?,
            client: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            session: dword(arguments, 2)?,
        },
        114 => Win16NddeRequest::GetWindow,
        // Ordinals 115, 200-205 have unknown signatures and are intentionally
        // not accepted as calls.
        _ => return Ok(None),
    };
    Ok(Some(Win16NetworkAdminRequest::Ndde(request)))
}

pub(super) fn decode_netapi(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16NetworkAdminRequest>, Win16Error> {
    if ordinal != 249 { return Ok(None); }
    let server = read_nullable_z(dword(arguments, 0)?, selectors, memory)?;
    let level = word(arguments, 1)?;
    let output_pointer = dword(arguments, 2)?;
    let capacity = u32::from(word(arguments, 3)?);
    let output = output_buffer(output_pointer, capacity, selectors, memory)?;
    let bytes_read_output = checked_output(dword(arguments, 4)?, 4, selectors, memory)?;
    Ok(Some(Win16NetworkAdminRequest::NetWkstaGetInfo {
        server, level, output, bytes_read_output,
    }))
}

fn output_buffer(
    far_pointer: u32,
    capacity: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16NetworkAdminBuffer, Win16Error> {
    if far_pointer == 0 && capacity == 0 {
        return Ok(Win16NetworkAdminBuffer { far_pointer, capacity });
    }
    checked_output(far_pointer, usize::try_from(capacity).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)?;
    Ok(Win16NetworkAdminBuffer { far_pointer, capacity })
}

fn read_sized(
    far_pointer: u32,
    size: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if size == 0 { return Ok(Vec::new()); }
    read_bytes(far_pointer, usize::try_from(size).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)
}

fn read_nullable_z(
    far_pointer: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    if far_pointer == 0 { return Ok(None); }
    crate::strings::read_ansi_z(selectors, memory, far_pointer, crate::exports::MAX_WIN16_STRING_BYTES).map(Some)
}

fn checked_output(
    far_pointer: u32,
    capacity: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u32, Win16Error> {
    let pointer = selectors.pointer_from_far(far_pointer)?;
    selectors.translate(pointer, Access::Write, capacity, memory)?;
    Ok(far_pointer)
}

fn read_bytes(
    far_pointer: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let pointer = selectors.pointer_from_far(far_pointer)?;
    let address = selectors.translate(pointer, Access::Read, length, memory)?;
    let mut bytes = vec![0; length];
    memory.read(address, &mut bytes)?;
    Ok(bytes)
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}
