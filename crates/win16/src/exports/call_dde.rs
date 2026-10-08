//! Guest-memory decoder for DDEML's typed Win16 stack exports.
//!
//! This file accepts only known DDEML function ordinals. It copies the
//! CONVCONTEXT16 and transaction data bytes it needs, checks writable guest
//! ranges, and preserves callback FAR values solely for runtime dispatch.

use super::request::dde::*;
use crate::{Access, SelectorTable, Win16Argument, Win16Error};
use guest_core::{GuestMemory, PhysAddr};

const CONVCONTEXT16_SIZE: usize = 16;

pub(super) fn decode_ddeml(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16DdeRequest>, Win16Error> {
    let request = match ordinal {
        2 => {
            let instance_output = dword(arguments, 0)?;
            checked_output(instance_output, 4, selectors, memory)?;
            let initial_instance = u32::from_le_bytes(
                read_bytes(instance_output, 4, selectors, memory)?
                    .try_into()
                    .map_err(|_| Win16Error::InvalidRange)?,
            );
            Win16DdeRequest::Initialize {
                instance_output,
                initial_instance,
                callback: dword(arguments, 1)?,
                flags: dword(arguments, 2)?,
                reserved: dword(arguments, 3)?,
            }
        }
        3 => Win16DdeRequest::Uninitialize { instance: dword(arguments, 0)? },
        4 => Win16DdeRequest::ConnectList {
            instance: dword(arguments, 0)?,
            service: dword(arguments, 1)?,
            topic: dword(arguments, 2)?,
            list: dword(arguments, 3)?,
            context: optional_context(dword(arguments, 4)?, selectors, memory)?,
        },
        5 => Win16DdeRequest::QueryNextServer { list: dword(arguments, 0)?, previous: dword(arguments, 1)? },
        6 => Win16DdeRequest::DisconnectList { list: dword(arguments, 0)? },
        7 => Win16DdeRequest::Connect {
            instance: dword(arguments, 0)?,
            service: optional_dword(arguments, 1)?,
            topic: optional_dword(arguments, 2)?,
            context: optional_context(dword(arguments, 3)?, selectors, memory)?,
        },
        8 => Win16DdeRequest::Disconnect { conversation: dword(arguments, 0)? },
        9 => {
            let output = dword(arguments, 2)?;
            let header = read_bytes(output, 4, selectors, memory)?;
            let guest_size = u32::from_le_bytes(header.try_into().map_err(|_| Win16Error::InvalidRange)?);
            checked_output(output, usize::try_from(guest_size).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)?;
            Win16DdeRequest::QueryConversationInfo {
                conversation: dword(arguments, 0)?,
                transaction: dword(arguments, 1)?,
                output,
                guest_size,
            }
        }
        10 => Win16DdeRequest::SetUserHandle {
            conversation: dword(arguments, 0)?, transaction: dword(arguments, 1)?, user_data: dword(arguments, 2)?,
        },
        11 => {
            let transaction_type = word(arguments, 5)?;
            // SDK 3.1 documents lpvData/cbData only for XTYP_EXECUTE and
            // XTYP_POKE. Do not translate or dereference their union storage
            // for other transaction types; the native call receives no data.
            let transaction_base = u32::from(transaction_type) & 0x00f0;
            let data = if matches!(transaction_base, 0x0050 | 0x0090) {
                let count = dword(arguments, 1)?;
                let source = dword(arguments, 0)?;
                match count {
                    0 => Win16DdeTransactionData::None,
                    u32::MAX => Win16DdeTransactionData::DataHandle(source),
                    byte_count => Win16DdeTransactionData::Bytes(read_huge_bytes(
                        source,
                        usize::try_from(byte_count).map_err(|_| Win16Error::InvalidRange)?,
                        selectors,
                        memory,
                    )?),
                }
            } else { Win16DdeTransactionData::None };
            let result_output = dword(arguments, 7)?;
            if result_output != 0 { checked_output(result_output, 4, selectors, memory)?; }
            Win16DdeRequest::ClientTransaction {
                data,
                conversation: dword(arguments, 2)?,
                item: dword(arguments, 3)?,
                format: word(arguments, 4)?,
                transaction_type,
                timeout: dword(arguments, 6)?,
                result_output,
            }
        }
        12 => Win16DdeRequest::AbandonTransaction {
            instance: dword(arguments, 0)?, conversation: optional_dword(arguments, 1)?, transaction: dword(arguments, 2)?,
        },
        13 => Win16DdeRequest::PostAdvise {
            instance: dword(arguments, 0)?, topic: optional_dword(arguments, 1)?, item: optional_dword(arguments, 2)?,
        },
        14 => {
            let count = dword(arguments, 2)?;
            let source = dword(arguments, 1)?;
            // The SDK allows a NULL pSrc to allocate an uninitialized object;
            // keep cb independent instead of reading NULL or replacing it with zero.
            let data = if source == 0 { None } else if count == 0 {
                Some(Vec::new())
            } else {
                Some(read_huge_bytes(source, usize::try_from(count).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)?)
            };
            Win16DdeRequest::CreateData {
                instance: dword(arguments, 0)?, data, count, offset: dword(arguments, 3)?, item: dword(arguments, 4)?,
                format: word(arguments, 5)?, flags: word(arguments, 6)?,
            }
        }
        15 => {
            let length = dword(arguments, 2)?;
            let bytes = if length == 0 { Vec::new() } else {
                read_huge_bytes(
                    dword(arguments, 1)?,
                    usize::try_from(length).map_err(|_| Win16Error::InvalidRange)?,
                    selectors,
                    memory,
                )?
            };
            Win16DdeRequest::AddData {
                data: dword(arguments, 0)?,
                bytes,
                offset: dword(arguments, 3)?,
            }
        }
        16 => {
            let length = dword(arguments, 2)?;
            let far_pointer = dword(arguments, 1)?;
            if far_pointer != 0 {
                checked_huge_output(far_pointer, usize::try_from(length).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)?;
            }
            Win16DdeRequest::GetData {
                data: dword(arguments, 0)?,
                output: Win16DdeBuffer { far_pointer, capacity: length },
                offset: dword(arguments, 3)?,
            }
        }
        17 => {
            let size_output = dword(arguments, 1)?;
            if size_output != 0 { checked_output(size_output, 4, selectors, memory)?; }
            Win16DdeRequest::AccessData { data: dword(arguments, 0)?, size_output }
        }
        18 => Win16DdeRequest::UnaccessData { data: dword(arguments, 0)? },
        19 => Win16DdeRequest::FreeData { data: dword(arguments, 0)? },
        20 => Win16DdeRequest::GetLastError { instance: dword(arguments, 0)? },
        21 => Win16DdeRequest::CreateString {
            instance: dword(arguments, 0)?,
            value: read_z(dword(arguments, 1)?, selectors, memory)?,
            code_page: signed_word(arguments, 2)?,
        },
        22 => Win16DdeRequest::FreeString { instance: dword(arguments, 0)?, string: dword(arguments, 1)? },
        23 => {
            let output = dword(arguments, 2)?;
            let capacity = dword(arguments, 3)?;
            checked_optional_output(output, usize::try_from(capacity).map_err(|_| Win16Error::InvalidRange)?, selectors, memory)?;
            Win16DdeRequest::QueryString {
                instance: dword(arguments, 0)?, string: dword(arguments, 1)?,
                output: Win16DdeBuffer { far_pointer: output, capacity },
                code_page: signed_word(arguments, 4)?,
            }
        }
        24 => Win16DdeRequest::KeepString { instance: dword(arguments, 0)?, string: dword(arguments, 1)? },
        26 => Win16DdeRequest::EnableCallback {
            instance: dword(arguments, 0)?, conversation: dword(arguments, 1)?, command: word(arguments, 2)?,
        },
        27 => Win16DdeRequest::NameService {
            instance: dword(arguments, 0)?, service: dword(arguments, 1)?, reserved: dword(arguments, 2)?, command: word(arguments, 3)?,
        },
        36 => Win16DdeRequest::CompareStrings { left: dword(arguments, 0)?, right: dword(arguments, 1)? },
        37 => Win16DdeRequest::Reconnect { conversation: dword(arguments, 0)? },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn optional_context(far_pointer: u32, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Option<Vec<u8>>, Win16Error> {
    if far_pointer == 0 { return Ok(None); }
    let bytes = read_bytes(far_pointer, CONVCONTEXT16_SIZE, selectors, memory)?;
    let declared = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if declared != CONVCONTEXT16_SIZE { return Err(Win16Error::InvalidRange); }
    Ok(Some(bytes))
}

fn checked_output(far_pointer: u32, capacity: usize, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<(), Win16Error> {
    let pointer = selectors.pointer_from_far(far_pointer)?;
    selectors.translate(pointer, Access::Write, capacity, memory)?;
    Ok(())
}

fn checked_optional_output(far_pointer: u32, _capacity: usize, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<(), Win16Error> {
    if far_pointer == 0 {
        return Ok(());
    }
    checked_output(far_pointer, _capacity, selectors, memory)
}

fn read_bytes(far_pointer: u32, length: usize, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Vec<u8>, Win16Error> {
    let pointer = selectors.pointer_from_far(far_pointer)?;
    let address = selectors.translate(pointer, Access::Read, length, memory)?;
    let mut bytes = vec![0; length];
    memory.read(address, &mut bytes)?;
    Ok(bytes)
}

/// The DDEML data-management APIs accept huge buffers. Validate the complete
/// selector chain through `add_bytes`, which enforces one allocation and one
/// descriptor generation; physical adjacency alone is never sufficient.
fn huge_ranges(
    far_pointer: u32,
    length: usize,
    access: Access,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<(PhysAddr, usize)>, Win16Error> {
    let pointer = selectors.pointer_from_far(far_pointer)?;
    if length == 0 {
        selectors.translate(pointer, access, 0, memory)?;
        return Ok(Vec::new());
    }
    let mut ranges = Vec::new();
    ranges.try_reserve(length.div_ceil(0x1_0000)).map_err(|_| Win16Error::OutOfMemory)?;
    let mut consumed = 0usize;
    while consumed < length {
        let amount = u32::try_from(consumed).map_err(|_| Win16Error::InvalidRange)?;
        let current = selectors.add_bytes(pointer, amount)?;
        let descriptor = selectors.describe(current.selector())?;
        let remaining = descriptor.limit.checked_sub(u32::from(current.offset()))
            .and_then(|value| value.checked_add(1))
            .ok_or(Win16Error::InvalidRange)? as usize;
        let count = remaining.min(length - consumed);
        if count == 0 { return Err(Win16Error::InvalidRange); }
        let address = selectors.translate(current, access, count, memory)?;
        ranges.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        ranges.push((address, count));
        consumed = consumed.checked_add(count).ok_or(Win16Error::InvalidRange)?;
    }
    Ok(ranges)
}

fn read_huge_bytes(
    far_pointer: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let ranges = huge_ranges(far_pointer, length, Access::Read, selectors, memory)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    let mut offset = 0;
    for (address, count) in ranges {
        memory.read(address, &mut bytes[offset..offset + count])?;
        offset = offset.checked_add(count).ok_or(Win16Error::InvalidRange)?;
    }
    Ok(bytes)
}

fn checked_huge_output(
    far_pointer: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(), Win16Error> {
    huge_ranges(far_pointer, length, Access::Write, selectors, memory).map(|_| ())
}

fn read_z(far_pointer: u32, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Vec<u8>, Win16Error> {
    crate::strings::read_ansi_z(selectors, memory, far_pointer, crate::exports::MAX_WIN16_STRING_BYTES)
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) { Some(Win16Argument::Word(value)) => Ok(*value), _ => Err(Win16Error::InvalidRange) }
}

fn signed_word(arguments: &[Win16Argument], index: usize) -> Result<i16, Win16Error> {
    Ok(word(arguments, index)? as i16)
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) { Some(Win16Argument::Dword(value)) => Ok(*value), _ => Err(Win16Error::InvalidRange) }
}

fn optional_dword(arguments: &[Win16Argument], index: usize) -> Result<Option<u32>, Win16Error> {
    let value = dword(arguments, index)?;
    Ok((value != 0).then_some(value))
}
