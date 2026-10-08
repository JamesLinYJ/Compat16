//! Guest-memory decoder for the Winsock 1.x export family.
//!
//! This decoder is intentionally a private family function. The shared export
//! catalog calls it after ABI metadata has decoded argument widths and stack
//! order. Guest output addresses remain numeric and are never passed to a host
//! API.

use super::request::network::*;
use crate::{Access, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode_winsock(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16WinsockRequest>, Win16Error> {
    match decode_winsock_inner(ordinal, arguments, selectors, memory) {
        Err(error) if guest_pointer_fault(&error) => Ok(Some(Win16WinsockRequest::DecodeFailure {
            ordinal,
            failure: Win16WinsockDecodeFailure::PointerFault,
        })),
        Err(Win16Error::InvalidSize) => Ok(Some(Win16WinsockRequest::DecodeFailure {
            ordinal,
            failure: Win16WinsockDecodeFailure::InvalidArgument,
        })),
        result => result,
    }
}

fn decode_winsock_inner(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16WinsockRequest>, Win16Error> {
    let request = match ordinal {
        1 => Win16WinsockRequest::Accept {
            socket: word(arguments, 0)?,
            address: optional_inout(dword(arguments, 1)?, dword(arguments, 2)?),
        },
        2 => Win16WinsockRequest::Bind {
            socket: word(arguments, 0)?,
            address: read_bytes(dword(arguments, 1)?, signed_length(word(arguments, 2)?)?, selectors, memory)?,
        },
        3 => Win16WinsockRequest::CloseSocket { socket: word(arguments, 0)? },
        4 => Win16WinsockRequest::Connect {
            socket: word(arguments, 0)?,
            address: read_bytes(dword(arguments, 1)?, signed_length(word(arguments, 2)?)?, selectors, memory)?,
        },
        5 => Win16WinsockRequest::GetPeerName {
            socket: word(arguments, 0)?,
            address: required_inout(dword(arguments, 1)?, dword(arguments, 2)?),
        },
        6 => Win16WinsockRequest::GetSocketName {
            socket: word(arguments, 0)?,
            address: required_inout(dword(arguments, 1)?, dword(arguments, 2)?),
        },
        7 => Win16WinsockRequest::GetSocketOption {
            socket: word(arguments, 0)?,
            level: word(arguments, 1)? as i16,
            option: word(arguments, 2)? as i16,
            value: required_inout(dword(arguments, 3)?, dword(arguments, 4)?),
        },
        8 => Win16WinsockRequest::HostToNetworkLong(dword(arguments, 0)?),
        9 => Win16WinsockRequest::HostToNetworkShort(word(arguments, 0)?),
        10 => Win16WinsockRequest::InetAddress(read_z(dword(arguments, 0)?, selectors, memory)?),
        11 => Win16WinsockRequest::InetName(dword(arguments, 0)?),
        12 => {
            let value_pointer = dword(arguments, 2)?;
            Win16WinsockRequest::IoctlSocket {
                socket: word(arguments, 0)?,
                command: dword(arguments, 1)?,
                value_pointer,
            }
        }
        13 => Win16WinsockRequest::Listen { socket: word(arguments, 0)?, backlog: word(arguments, 1)? as i16 },
        14 => Win16WinsockRequest::NetworkToHostLong(dword(arguments, 0)?),
        15 => Win16WinsockRequest::NetworkToHostShort(word(arguments, 0)?),
        16 => Win16WinsockRequest::Receive {
            socket: word(arguments, 0)?,
            output: writable_buffer(dword(arguments, 1)?, word(arguments, 2)?),
            flags: word(arguments, 3)? as i16,
        },
        17 => Win16WinsockRequest::ReceiveFrom {
            socket: word(arguments, 0)?,
            output: writable_buffer(dword(arguments, 1)?, word(arguments, 2)?),
            flags: word(arguments, 3)? as i16,
            address: optional_inout(dword(arguments, 4)?, dword(arguments, 5)?),
        },
        18 => Win16WinsockRequest::Select(decode_select(arguments, selectors, memory)?),
        19 => Win16WinsockRequest::Send {
            socket: word(arguments, 0)?,
            bytes: read_bytes(dword(arguments, 1)?, signed_length(word(arguments, 2)?)?, selectors, memory)?,
            flags: word(arguments, 3)? as i16,
        },
        20 => Win16WinsockRequest::SendTo {
            socket: word(arguments, 0)?,
            bytes: read_bytes(dword(arguments, 1)?, signed_length(word(arguments, 2)?)?, selectors, memory)?,
            flags: word(arguments, 3)? as i16,
            address: read_bytes(dword(arguments, 4)?, signed_length(word(arguments, 5)?)?, selectors, memory)?,
        },
        21 => Win16WinsockRequest::SetSocketOption {
            socket: word(arguments, 0)?,
            level: word(arguments, 1)? as i16,
            option: word(arguments, 2)? as i16,
            value: read_bytes(dword(arguments, 3)?, signed_length(word(arguments, 4)?)?, selectors, memory)?,
        },
        22 => Win16WinsockRequest::Shutdown { socket: word(arguments, 0)?, how: word(arguments, 1)? as i16 },
        23 => Win16WinsockRequest::CreateSocket {
            address_family: word(arguments, 0)? as i16, socket_type: word(arguments, 1)? as i16,
            protocol: word(arguments, 2)? as i16,
        },
        51 => Win16WinsockRequest::Query(Win16HostQuery::HostByAddress {
            address: read_bytes(dword(arguments, 0)?, signed_length(word(arguments, 1)?)?, selectors, memory)?,
            address_type: word(arguments, 2)? as i16,
        }),
        52 => Win16WinsockRequest::Query(Win16HostQuery::HostByName(read_z(dword(arguments, 0)?, selectors, memory)?)),
        53 => Win16WinsockRequest::Query(Win16HostQuery::ProtocolByName(read_z(dword(arguments, 0)?, selectors, memory)?)),
        54 => Win16WinsockRequest::Query(Win16HostQuery::ProtocolByNumber(word(arguments, 0)? as i16)),
        55 => Win16WinsockRequest::Query(Win16HostQuery::ServiceByName {
            name: read_z(dword(arguments, 0)?, selectors, memory)?,
            protocol: read_optional_z(dword(arguments, 1)?, selectors, memory)?,
        }),
        56 => Win16WinsockRequest::Query(Win16HostQuery::ServiceByPort {
            port_network_order: word(arguments, 0)?,
            protocol: read_optional_z(dword(arguments, 1)?, selectors, memory)?,
        }),
        57 => Win16WinsockRequest::GetHostName {
            output: writable_buffer(dword(arguments, 0)?, word(arguments, 1)?),
        },
        101 => Win16WinsockRequest::AsyncSelect {
            socket: word(arguments, 0)?, window: word(arguments, 1)?, message: word(arguments, 2)?, events: dword(arguments, 3)?,
        },
        102 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::HostByAddress {
                address: read_bytes(
                    dword(arguments, 2)?,
                    signed_length(word(arguments, 3)?)?,
                    selectors,
                    memory,
                )?,
                address_type: word(arguments, 4)? as i16,
            },
            output: writable_buffer(dword(arguments, 5)?, word(arguments, 6)?),
        },
        103 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::HostByName(read_z(dword(arguments, 2)?, selectors, memory)?),
            output: writable_buffer(dword(arguments, 3)?, word(arguments, 4)?),
        },
        104 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::ProtocolByNumber(word(arguments, 2)? as i16),
            output: writable_buffer(dword(arguments, 3)?, word(arguments, 4)?),
        },
        105 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::ProtocolByName(read_z(dword(arguments, 2)?, selectors, memory)?),
            output: writable_buffer(dword(arguments, 3)?, word(arguments, 4)?),
        },
        106 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::ServiceByPort {
                port_network_order: word(arguments, 2)?,
                protocol: read_optional_z(dword(arguments, 3)?, selectors, memory)?,
            },
            output: writable_buffer(dword(arguments, 4)?, word(arguments, 5)?),
        },
        107 => Win16WinsockRequest::AsyncQuery {
            window: word(arguments, 0)?,
            message: word(arguments, 1)?,
            lookup: Win16AsyncLookup::ServiceByName {
                name: read_z(dword(arguments, 2)?, selectors, memory)?,
                protocol: read_optional_z(dword(arguments, 3)?, selectors, memory)?,
            },
            output: writable_buffer(dword(arguments, 4)?, word(arguments, 5)?),
        },
        108 => Win16WinsockRequest::CancelAsyncRequest { task: word(arguments, 0)? },
        109 => Win16WinsockRequest::SetBlockingHook { callback: dword(arguments, 0)? },
        110 => Win16WinsockRequest::UnhookBlockingHook,
        111 => Win16WinsockRequest::GetLastError,
        112 => Win16WinsockRequest::SetLastError(word(arguments, 0)?),
        113 => Win16WinsockRequest::CancelBlockingCall,
        114 => Win16WinsockRequest::IsBlocking,
        115 => Win16WinsockRequest::Startup {
            version: word(arguments, 0)?,
            output: writable_buffer(dword(arguments, 1)?, 398),
        },
        116 => Win16WinsockRequest::Cleanup,
        151 => Win16WinsockRequest::IsSocketInSet {
            socket: word(arguments, 0)?,
            set: read_fd_set(dword(arguments, 1)?, selectors, memory)?,
        },
        1107 => Win16WinsockRequest::ReceiveEx {
            socket: word(arguments, 0)?,
            output: writable_buffer(dword(arguments, 1)?, word(arguments, 2)?),
            flags_output: dword(arguments, 3)?,
        },
        2000 => Win16WinsockRequest::DefaultHook,
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn guest_pointer_fault(error: &Win16Error) -> bool {
    matches!(error,
        Win16Error::InvalidRange | Win16Error::InvalidSelector
            | Win16Error::StaleSelector | Win16Error::ForeignSelector
            | Win16Error::LimitViolation { .. } | Win16Error::AccessDenied { .. }
            | Win16Error::Memory(guest_core::MemoryError::AddressOverflow
                | guest_core::MemoryError::OutOfBounds { .. }
                | guest_core::MemoryError::InvalidMapping))
}

fn signed_length(word: u16) -> Result<usize, Win16Error> {
    let length = word as i16;
    if length < 0 { return Err(Win16Error::InvalidSize); }
    Ok(length as usize)
}

fn decode_select(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16SelectInput, Win16Error> {
    let read = socket_set(dword(arguments, 1)?, selectors, memory)?;
    let write = socket_set(dword(arguments, 2)?, selectors, memory)?;
    let except = socket_set(dword(arguments, 3)?, selectors, memory)?;
    let timeout_far = dword(arguments, 4)?;
    let timeout = if timeout_far == 0 {
        None
    } else {
        let bytes = read_bytes(timeout_far, 8, selectors, memory)?;
        Some(bytes.try_into().map_err(|_| Win16Error::InvalidRange)?)
    };
    Ok(Win16SelectInput { nfds: word(arguments, 0)? as i16, read, write, except, timeout })
}

fn socket_set(far: u32, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Win16SocketSetInput, Win16Error> {
    if far == 0 { return Ok(Win16SocketSetInput::Null); }
    let bytes = read_fd_set(far, selectors, memory)?;
    Ok(Win16SocketSetInput::Encoded { far_pointer: far, bytes })
}

fn required_inout(buffer_far: u32, length_far: u32) -> Win16GuestInOutBuffer {
    Win16GuestInOutBuffer { buffer_far, length_pointer: length_far }
}

fn optional_inout(buffer_far: u32, length_far: u32) -> Option<Win16GuestInOutBuffer> {
    (buffer_far != 0).then_some(Win16GuestInOutBuffer { buffer_far, length_pointer: length_far })
}

fn writable_buffer(far_pointer: u32, capacity: u16) -> Win16GuestBuffer {
    Win16GuestBuffer { far_pointer, capacity }
}

fn read_fd_set(far_pointer: u32, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Vec<u8>, Win16Error> {
    let header = read_bytes(far_pointer, 2, selectors, memory)?;
    let count = usize::from(u16::from_le_bytes([header[0], header[1]]));
    if count > 64 { return Ok(header); }
    read_bytes(far_pointer, 2 + count * 2, selectors, memory)
}

fn read_bytes(
    far_pointer: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if far_pointer == 0 && length == 0 { return Ok(Vec::new()); }
    let pointer = selectors.pointer_from_far(far_pointer)?;
    let address = selectors.translate(pointer, Access::Read, length, memory)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    memory.read(address, &mut bytes)?;
    Ok(bytes)
}

fn read_z(far_pointer: u32, selectors: &SelectorTable, memory: &impl GuestMemory)
    -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far_pointer)?;
    let descriptor = selectors.describe(start.selector())?;
    let remaining = descriptor.limit.checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1)).and_then(|length| usize::try_from(length).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let bound = remaining.min(crate::exports::MAX_WIN16_STRING_BYTES);
    let mut result = Vec::new();
    result.try_reserve(bound.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..bound {
        let pointer = selectors.add_bytes(start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?)?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(result); }
        result.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        result.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

fn read_optional_z(
    far_pointer: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    if far_pointer == 0 { return Ok(None); }
    read_z(far_pointer, selectors, memory).map(Some)
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::UnsupportedCallingConvention),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::UnsupportedCallingConvention),
    }
}
