//! Checked argument decoding for USER/WFW network redirector exports.

use super::request::{Win16UserNetworkBuffer, Win16UserNetworkRequest};
use crate::{Access, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

const MAX_NETWORK_STRING_BYTES: usize = 64 * 1024;
const MAX_BROWSE_PATH_BYTES: u16 = 128;

enum DecodeFailure {
    GuestPointer,
    Abi(Win16Error),
}

pub(super) fn decode(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16UserNetworkRequest>, Win16Error> {
    let expected_arguments = match ordinal {
        499 => 3,
        501 => 4,
        502 | 510 => 3,
        503..=506 => 2,
        509 | 511 | 514 | 519 => 1,
        507 | 512 | 515 | 517 | 520 | 524 | 531 => 3,
        523 | 530 => 2,
        508 => 4,
        529 => 5,
        513 => 1,
        516 | 518 | 525..=528 => 2,
        521..=522 | 533 => 0,
        532 => 6,
        _ => return Ok(None),
    };
    if arguments.len() != expected_arguments {
        return Err(Win16Error::InvalidRange);
    }

    let request = match decode_checked(ordinal, arguments, selectors, memory) {
        Ok(request) => request,
        Err(DecodeFailure::GuestPointer) => {
            if ordinal == 499 {
                Win16UserNetworkRequest::ErrorTextBadPointer
            } else {
                Win16UserNetworkRequest::BadPointer
            }
        }
        Err(DecodeFailure::Abi(error)) => return Err(error),
    };
    Ok(Some(request))
}

fn decode_checked(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16UserNetworkRequest, DecodeFailure> {
    Ok(match ordinal {
        499 => Win16UserNetworkRequest::ErrorText {
            error: word(arguments, 0)?,
            output: output_buffer(dword(arguments, 1)?, word(arguments, 2)?, selectors, memory)?,
        },
        501 => Win16UserNetworkRequest::OpenJob {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            job_name: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            copies: word(arguments, 2)?,
            hfile_output: checked_output(dword(arguments, 3)?, 2, selectors, memory)?,
        },
        502 => Win16UserNetworkRequest::CloseJob {
            hfile: word(arguments, 0)?,
            job_id_output: checked_output(dword(arguments, 1)?, 2, selectors, memory)?,
            queue_name_output: checked_output(dword(arguments, 2)?, 1, selectors, memory)?,
        },
        503 => Win16UserNetworkRequest::AbortJob {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            hfile: word(arguments, 1)?,
        },
        504 => Win16UserNetworkRequest::HoldJob {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            job_id: word(arguments, 1)?,
        },
        505 => Win16UserNetworkRequest::ReleaseJob {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            job_id: word(arguments, 1)?,
        },
        506 => Win16UserNetworkRequest::CancelJob {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            job_id: word(arguments, 1)?,
        },
        507 => Win16UserNetworkRequest::SetJobCopies {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            job_id: word(arguments, 1)?,
            copies: word(arguments, 2)?,
        },
        508 => Win16UserNetworkRequest::WatchQueue {
            owner: word(arguments, 0)?,
            local_device: read_z(dword(arguments, 1)?, selectors, memory)?,
            user: read_nullable_z(dword(arguments, 2)?, selectors, memory)?,
            n_queue: word(arguments, 3)?,
        },
        509 => Win16UserNetworkRequest::UnwatchQueue {
            local_device: read_z(dword(arguments, 0)?, selectors, memory)?,
        },
        510 => Win16UserNetworkRequest::LockQueueData {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
            user: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            output: checked_output(dword(arguments, 2)?, 4, selectors, memory)?,
        },
        511 => Win16UserNetworkRequest::UnlockQueueData {
            queue: read_z(dword(arguments, 0)?, selectors, memory)?,
        },
        512 => {
            let local_name = read_z(dword(arguments, 0)?, selectors, memory)?;
            let output_pointer = dword(arguments, 1)?;
            let length_output = dword(arguments, 2)?;
            let capacity = read_u16_inout(length_output, selectors, memory)?;
            Win16UserNetworkRequest::GetConnection {
                local_name,
                output: output_buffer(output_pointer, capacity, selectors, memory)?,
                length_output,
            }
        }
        513 => Win16UserNetworkRequest::GetCaps {
            index: word(arguments, 0)?,
        },
        514 => Win16UserNetworkRequest::DeviceMode {
            owner: word(arguments, 0)?,
        },
        515 => Win16UserNetworkRequest::BrowseDialog {
            owner: word(arguments, 0)?,
            resource_type: word(arguments, 1)?,
            path_output: checked_output(
                dword(arguments, 2)?,
                usize::from(MAX_BROWSE_PATH_BYTES),
                selectors,
                memory,
            )?,
        },
        516 => {
            let output_pointer = dword(arguments, 0)?;
            let length_output = dword(arguments, 1)?;
            let capacity = read_u16_inout(length_output, selectors, memory)?;
            Win16UserNetworkRequest::GetUser {
                output: output_buffer(output_pointer, capacity, selectors, memory)?,
                length_output,
            }
        }
        517 => Win16UserNetworkRequest::AddConnection {
            remote_name: read_z(dword(arguments, 0)?, selectors, memory)?,
            password: read_nullable_z(dword(arguments, 1)?, selectors, memory)?,
            local_name: read_nullable_z(dword(arguments, 2)?, selectors, memory)?,
        },
        518 => Win16UserNetworkRequest::CancelConnection {
            local_name: read_z(dword(arguments, 0)?, selectors, memory)?,
            force: word(arguments, 1)? != 0,
        },
        519 => Win16UserNetworkRequest::GetError {
            error_output: checked_output(dword(arguments, 0)?, 2, selectors, memory)?,
        },
        520 => {
            let error = word(arguments, 0)?;
            let output_pointer = dword(arguments, 1)?;
            let length_output = dword(arguments, 2)?;
            let capacity = read_u16_inout(length_output, selectors, memory)?;
            Win16UserNetworkRequest::GetErrorText {
                error,
                output: output_buffer(output_pointer, capacity, selectors, memory)?,
                length_output,
            }
        }
        521 => Win16UserNetworkRequest::Enable,
        522 => Win16UserNetworkRequest::Disable,
        533 => Win16UserNetworkRequest::Initialize,
        523 => Win16UserNetworkRequest::RestoreConnection {
            owner: word(arguments, 0)?,
            local_name: match dword(arguments, 1)? {
                0 | u32::MAX => None,
                value => read_nullable_z(value, selectors, memory)?,
            },
        },
        524 => {
            let hfile = word(arguments, 0)?;
            Win16UserNetworkRequest::WriteJob {
                hfile,
                data_far: dword(arguments, 1)?,
                length_far: dword(arguments, 2)?,
            }
        }
        525 => Win16UserNetworkRequest::ConnectDialog {
            owner: word(arguments, 0)?,
            resource_type: word(arguments, 1)?,
        },
        526 => Win16UserNetworkRequest::DisconnectDialog {
            owner: word(arguments, 0)?,
            resource_type: word(arguments, 1)?,
        },
        527 => Win16UserNetworkRequest::ConnectionDialog {
            owner: word(arguments, 0)?,
            resource_type: word(arguments, 1)?,
        },
        528 => Win16UserNetworkRequest::ViewQueueDialog {
            owner: word(arguments, 0)?,
            queue: read_z(dword(arguments, 1)?, selectors, memory)?,
        },
        529 => Win16UserNetworkRequest::PropertyDialog {
            owner: word(arguments, 0)?,
            button: word(arguments, 1)?,
            property: word(arguments, 2)?,
            name: read_z(dword(arguments, 3)?, selectors, memory)?,
            resource_type: word(arguments, 4)?,
        },
        530 => Win16UserNetworkRequest::GetDirectoryType {
            path: read_z(dword(arguments, 0)?, selectors, memory)?,
            type_output: checked_output(dword(arguments, 1)?, 2, selectors, memory)?,
        },
        531 => Win16UserNetworkRequest::DirectoryNotify {
            owner: word(arguments, 0)?,
            path: read_z(dword(arguments, 1)?, selectors, memory)?,
            notification: word(arguments, 2)?,
        },
        532 => Win16UserNetworkRequest::GetPropertyText {
            button: word(arguments, 0)?,
            property: word(arguments, 1)?,
            name: read_z(dword(arguments, 2)?, selectors, memory)?,
            button_name_output: output_buffer(
                dword(arguments, 3)?,
                word(arguments, 4)?,
                selectors,
                memory,
            )?,
            resource_type: word(arguments, 5)?,
        },
        _ => return Err(DecodeFailure::Abi(Win16Error::InvalidRange)),
    })
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, DecodeFailure> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(DecodeFailure::Abi(Win16Error::InvalidRange)),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, DecodeFailure> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(DecodeFailure::Abi(Win16Error::InvalidRange)),
    }
}

fn read_z(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, DecodeFailure> {
    crate::strings::read_ansi_z(selectors, memory, raw, MAX_NETWORK_STRING_BYTES)
        .map_err(pointer_error)
}

fn read_nullable_z(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, DecodeFailure> {
    if raw == 0 {
        Ok(None)
    } else {
        read_z(raw, selectors, memory).map(Some)
    }
}

fn output_buffer(
    far_pointer: u32,
    capacity: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16UserNetworkBuffer, DecodeFailure> {
    Ok(Win16UserNetworkBuffer {
        far_pointer: checked_output(far_pointer, usize::from(capacity), selectors, memory)?,
        capacity,
    })
}

fn checked_output(
    far_pointer: u32,
    capacity: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u32, DecodeFailure> {
    let pointer = selectors
        .pointer_from_far(far_pointer)
        .map_err(pointer_error)?;
    selectors
        // WFW's Win32 thunk still dereferences a one-byte temporary when the
        // caller advertises a zero-byte buffer, so require a valid guest byte.
        .translate(pointer, Access::Write, capacity.max(1), memory)
        .map_err(pointer_error)?;
    Ok(far_pointer)
}

fn read_u16_inout(
    far_pointer: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u16, DecodeFailure> {
    let pointer = selectors
        .pointer_from_far(far_pointer)
        .map_err(pointer_error)?;
    selectors
        .translate(pointer, Access::Read, 2, memory)
        .map_err(pointer_error)?;
    selectors
        .translate(pointer, Access::Write, 2, memory)
        .map_err(pointer_error)?;
    let mut bytes = [0_u8; 2];
    selectors
        .read(memory, pointer, &mut bytes)
        .map_err(pointer_error)?;
    Ok(u16::from_le_bytes(bytes))
}

fn pointer_error(error: Win16Error) -> DecodeFailure {
    match error {
        Win16Error::OutOfMemory => DecodeFailure::Abi(Win16Error::OutOfMemory),
        _ => DecodeFailure::GuestPointer,
    }
}
