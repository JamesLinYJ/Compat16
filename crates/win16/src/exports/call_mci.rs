//! Checked Win16 MCI stack and parameter-block decoder.

use crate::{Access, SegmentedPointer, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

use super::Win16ExportDescriptor;
use super::request::{
    Win16MciGuestRange, Win16MciOpenExtension, Win16MciOpenValue, Win16MciOutputBuffer,
    Win16MciParameters, Win16MciRequest, Win16MciResourceName, Win16MciSetExtension,
};
#[path = "request/mci_wire.rs"]
mod mci_wire;
#[path = "call_mci_open.rs"]
mod open;

const MCI_OPEN: u16 = 0x0803;
const MCI_CLOSE: u16 = 0x0804;
const MCI_ESCAPE: u16 = 0x0805;
const MCI_PLAY: u16 = 0x0806;
const MCI_SEEK: u16 = 0x0807;
const MCI_STOP: u16 = 0x0808;
const MCI_PAUSE: u16 = 0x0809;
const MCI_INFO: u16 = 0x080a;
const MCI_GETDEVCAPS: u16 = 0x080b;
const MCI_SPIN: u16 = 0x080c;
const MCI_SET: u16 = 0x080d;
const MCI_STEP: u16 = 0x080e;
const MCI_RECORD: u16 = 0x080f;
const MCI_SYSINFO: u16 = 0x0810;
const MCI_BREAK: u16 = 0x0811;
const MCI_SOUND: u16 = 0x0812;
const MCI_SAVE: u16 = 0x0813;
const MCI_STATUS: u16 = 0x0814;
const MCI_CUE: u16 = 0x0830;
const MCI_UNFREEZE: u16 = 0x0845;
const MCI_WINDOW: u16 = 0x0841;
const MCI_PUT: u16 = 0x0842;
const MCI_WHERE: u16 = 0x0843;
const MCI_FREEZE: u16 = 0x0844;
const MCI_LOAD: u16 = 0x0850;
const MCI_RESUME: u16 = 0x0855;
const MCI_DELETE: u16 = 0x0856;
// The SDK 3.1 header labels this flag for MCI_PUT, while Microsoft documents
// the same overlay RECT parameter for FREEZE/UNFREEZE as well.
const MCI_OVLY_RECT: u32 = 0x0001_0000;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM")
        || arguments.len() != descriptor.parameters.len()
    {
        return Err(Win16Error::InvalidRange);
    }

    Ok(match descriptor.ordinal() {
        701 => {
            let device_id = word(arguments, 0)?;
            let message = word(arguments, 1)?;
            let flags = dword(arguments, 2)?;
            let parameter_far = dword(arguments, 3)?;
            let parameters = decode_parameters(message, flags, parameter_far, selectors, memory)?;
            let parameter_output =
                parameter_output_range(message, parameter_far, selectors, memory)?;
            Win16MciRequest::SendCommand {
                device_id,
                message,
                flags,
                parameter_far,
                parameter_output,
                reserved_device_id: None,
                parameters,
            }
        }
        702 => {
            let output = output_buffer(
                dword(arguments, 1)?,
                u32::from(word(arguments, 2)?),
                selectors,
                memory,
            )?;
            Win16MciRequest::SendString {
                command: read_far_string(dword(arguments, 0)?, selectors, memory)?,
                output,
                callback_window: word(arguments, 3)?,
                reserved_device_id: None,
            }
        }
        703 => Win16MciRequest::GetDeviceId {
            name: read_far_string(dword(arguments, 0)?, selectors, memory)?,
        },
        705 => Win16MciRequest::LoadCommandResource {
            instance: word(arguments, 0)?,
            resource: resource_name(dword(arguments, 1)?, selectors, memory)?,
            resource_type: word(arguments, 2)?,
        },
        706 => {
            let output = output_buffer(
                dword(arguments, 1)?,
                u32::from(word(arguments, 2)?),
                selectors,
                memory,
            )?;
            Win16MciRequest::GetErrorString {
                error: dword(arguments, 0)?,
                output,
            }
        }
        707 => Win16MciRequest::SetDriverData {
            device_id: word(arguments, 0)?,
            data: dword(arguments, 1)?,
        },
        708 => Win16MciRequest::GetDriverData {
            device_id: word(arguments, 0)?,
        },
        710 => Win16MciRequest::DriverYield {
            device_id: word(arguments, 0)?,
        },
        711 => Win16MciRequest::DriverNotify {
            window: word(arguments, 0)?,
            device_id: word(arguments, 1)?,
            status: word(arguments, 2)?,
        },
        712 => Win16MciRequest::Execute {
            command: read_far_string(dword(arguments, 0)?, selectors, memory)?,
            reserved_device_id: None,
        },
        713 => Win16MciRequest::FreeCommandResource {
            resource_id: word(arguments, 0)?,
        },
        714 => {
            let procedure = dword(arguments, 1)?;
            let procedure_pointer = if procedure == 0 {
                None
            } else {
                let pointer = selectors.pointer_from_far(procedure)?;
                // Capture the selector generation and prove this address is
                // executable before native MCI stores the Win16 callback.
                selectors.translate(pointer, Access::Execute, 1, memory)?;
                Some(pointer)
            };
            Win16MciRequest::SetYieldProc {
                device_id: word(arguments, 0)?,
                procedure,
                procedure_pointer,
                data: dword(arguments, 2)?,
            }
        }
        715 => Win16MciRequest::GetDeviceIdFromElement {
            element_id: dword(arguments, 0)?,
            device_type: read_far_string(dword(arguments, 1)?, selectors, memory)?,
        },
        716 => {
            let device_id = word(arguments, 0)?;
            let data_output = dword(arguments, 1)?;
            Win16MciRequest::GetYieldProc {
                device_id,
                data_output: if data_output == 0 {
                    None
                } else {
                    Some(capture_far_range(data_output, 0, 4, selectors, memory)?)
                },
            }
        }
        717 => Win16MciRequest::GetCreatorTask {
            device_id: word(arguments, 0)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    })
}

fn decode_parameters(
    message: u16,
    flags: u32,
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciParameters, Win16Error> {
    if far == 0 {
        return Ok(match message {
            MCI_CLOSE | MCI_STOP | MCI_PAUSE | MCI_SPIN | MCI_CUE | MCI_RESUME => {
                Win16MciParameters::Null
            }
            MCI_OPEN | MCI_PLAY | MCI_SEEK | MCI_INFO | MCI_GETDEVCAPS | MCI_SYSINFO | MCI_SET
            | MCI_RECORD | MCI_BREAK | MCI_SOUND | MCI_SAVE | MCI_LOAD | MCI_STEP | MCI_ESCAPE
            | MCI_WINDOW | MCI_PUT | MCI_WHERE | MCI_FREEZE | MCI_UNFREEZE | MCI_DELETE => {
                Win16MciParameters::Null
            }
            _ => Win16MciParameters::Unsupported { message, flags },
        });
    }
    match message {
        MCI_OPEN => open::decode_open(flags, far, selectors, memory),
        MCI_PLAY => {
            // Both videodisc and animation speed extensions append one DWORD
            // in the SDK 3.1 records; the data is copied only for the flags
            // that document that field.
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let base =
                mci_wire::read::<mci_wire::Play>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Play {
                callback: base.callback.get(),
                from: base.from.get(),
                to: base.to.get(),
                parameter_pointer: selectors
                    .pointer_from_far(far)
                    .map_err(|_| Win16Error::InvalidRange)?,
            })
        }
        MCI_SEEK => {
            let bytes = read_struct(far, 8, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Seek>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Seek {
                callback: record.callback.get(),
                to: record.to.get(),
            })
        }
        MCI_STATUS => {
            let bytes = read_struct(far, 16, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Status>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Status {
                callback: record.callback.get(),
                returned: record.returned.get(),
                item: record.item.get(),
                track: record.track.get(),
            })
        }
        MCI_INFO => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Info>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            let output = output_buffer(
                record.output.get(),
                record.capacity.get(),
                selectors,
                memory,
            )?;
            Ok(Win16MciParameters::Info {
                callback: record.callback.get(),
                output,
                item: flags,
            })
        }
        MCI_GETDEVCAPS => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::GetDeviceCaps>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::GetDeviceCaps {
                callback: record.callback.get(),
                returned: record.returned.get(),
                item: record.item.get(),
            })
        }
        MCI_SYSINFO => {
            let bytes = read_struct(far, 20, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::SystemInfo>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            let output = output_buffer(
                record.output.get(),
                record.capacity.get(),
                selectors,
                memory,
            )?;
            Ok(Win16MciParameters::SystemInfo {
                callback: record.callback.get(),
                output,
                item: flags,
                number: record.number.get(),
                device_type: record.device_type.get(),
            })
        }
        MCI_SET => decode_set(flags, far, selectors, memory),
        MCI_RECORD => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Record>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Record {
                callback: record.callback.get(),
                from: record.from.get(),
                to: record.to.get(),
            })
        }
        MCI_BREAK => {
            let callback = read_u32_at_far(far, 0, selectors, memory)?;
            let break_off = flags & 0x0000_0400 != 0;
            let virtual_key = if !break_off && flags & 0x0000_0100 != 0 {
                read_u16_at_far(far, 4, selectors, memory)?
            } else {
                0
            };
            let window = if !break_off && flags & 0x0000_0200 != 0 {
                read_u16_at_far(far, 8, selectors, memory)?
            } else {
                0
            };
            Ok(Win16MciParameters::Break {
                callback,
                virtual_key,
                window,
            })
        }
        MCI_SAVE | MCI_LOAD => {
            let parameter_pointer = selectors
                .pointer_from_far(far)
                .map_err(|_| Win16Error::InvalidRange)?;
            let bytes = read_struct(far, 8, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::File>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            let filename = read_far_string(record.filename.get(), selectors, memory)?;
            Ok(Win16MciParameters::File {
                callback: record.callback.get(),
                filename,
                parameter_pointer,
            })
        }
        MCI_SOUND => {
            let bytes = read_struct(far, 8, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::File>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            let name = read_far_string(record.filename.get(), selectors, memory)?;
            Ok(Win16MciParameters::Sound {
                callback: record.callback.get(),
                name,
            })
        }
        MCI_STEP => {
            let bytes = read_struct(far, 8, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Step>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Step {
                callback: record.callback.get(),
                frames: record.frames.get(),
            })
        }
        MCI_ESCAPE => {
            let bytes = read_struct(far, 8, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::File>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            let command = read_far_string(record.filename.get(), selectors, memory)?;
            Ok(Win16MciParameters::Escape {
                callback: record.callback.get(),
                command,
            })
        }
        MCI_WINDOW => {
            let callback = read_u32_at_far(far, 0, selectors, memory)?;
            let window = if flags & 0x0001_0000 != 0 {
                read_u16_at_far(far, 4, selectors, memory)?
            } else {
                0
            };
            let show_command = if flags & 0x0004_0000 != 0 {
                read_u16_at_far(far, 8, selectors, memory)?
            } else {
                0
            };
            let text_pointer = if flags & 0x0008_0000 != 0 {
                read_u32_at_far(far, 12, selectors, memory)?
            } else {
                0
            };
            let text = if text_pointer == 0 {
                None
            } else {
                Some(read_far_string(text_pointer, selectors, memory)?)
            };
            Ok(Win16MciParameters::Window {
                callback,
                window,
                show_command,
                text,
            })
        }
        MCI_PUT | MCI_WHERE => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Rect>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Rectangle {
                callback: record.callback.get(),
                rectangle: crate::window_geometry::Rect16 {
                    left: record.left.get(),
                    top: record.top.get(),
                    right: record.right.get(),
                    bottom: record.bottom.get(),
                },
                output: message == MCI_WHERE,
            })
        }
        MCI_DELETE => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Delete>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Delete {
                callback: record.callback.get(),
                from: record.from.get(),
                to: record.to.get(),
            })
        }
        MCI_FREEZE | MCI_UNFREEZE if flags & MCI_OVLY_RECT != 0 => {
            let bytes = read_struct(far, 12, false, selectors, memory)?;
            let record =
                mci_wire::read::<mci_wire::Rect>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Rectangle {
                callback: record.callback.get(),
                rectangle: crate::window_geometry::Rect16 {
                    left: record.left.get(),
                    top: record.top.get(),
                    right: record.right.get(),
                    bottom: record.bottom.get(),
                },
                output: false,
            })
        }
        MCI_FREEZE | MCI_UNFREEZE => {
            let bytes = read_struct(far, 4, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::Generic>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Generic {
                callback: record.callback.get(),
            })
        }
        MCI_CLOSE | MCI_STOP | MCI_PAUSE | MCI_SPIN | MCI_CUE | MCI_RESUME => {
            let bytes = read_struct(far, 4, false, selectors, memory)?;
            let record = mci_wire::read::<mci_wire::Generic>(&bytes)
                .map_err(|_| Win16Error::InvalidRange)?;
            Ok(Win16MciParameters::Generic {
                callback: record.callback.get(),
            })
        }
        _ => Ok(Win16MciParameters::Unsupported { message, flags }),
    }
}

fn decode_set(
    flags: u32,
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciParameters, Win16Error> {
    let bytes = read_struct(far, 12, false, selectors, memory)?;
    let record = mci_wire::read::<mci_wire::Set>(&bytes).map_err(|_| Win16Error::InvalidRange)?;
    // SDK 3.1 places ANYINPUT/ANYOUTPUT outside the contiguous format flags;
    // waveform drivers still consume the extended WAVE_SET record for them.
    let extension_flags = flags & (0x01ff_0000 | 0x0c00_0000);
    Ok(Win16MciParameters::Set {
        callback: record.callback.get(),
        time_format: record.time_format.get(),
        audio: record.audio.get(),
        extension: if extension_flags == 0 {
            Win16MciSetExtension::None
        } else {
            Win16MciSetExtension::DeviceSpecific {
                parameter_far: far,
                flags,
            }
        },
    })
}

fn output_buffer(
    far: u32,
    capacity: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciOutputBuffer, Win16Error> {
    let range = if far == 0 || capacity == 0 {
        None
    } else {
        Some(capture_far_range(
            far,
            0,
            usize::try_from(capacity).map_err(|_| Win16Error::InvalidRange)?,
            selectors,
            memory,
        )?)
    };
    Ok(Win16MciOutputBuffer {
        far,
        capacity,
        range,
    })
}

fn parameter_output_range(
    message: u16,
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16MciGuestRange>, Win16Error> {
    let (offset, length) = match message {
        MCI_OPEN => (4, 2),
        MCI_STATUS | MCI_GETDEVCAPS => (4, 4),
        MCI_WHERE => (4, 8),
        _ => return Ok(None),
    };
    if far == 0 {
        return Ok(None);
    }
    capture_far_range(far, offset, length, selectors, memory).map(Some)
}

fn capture_far_range(
    far: u32,
    offset: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciGuestRange, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let pointer = selectors.add_bytes(start, offset)?;
    validate_single_segment(pointer, length, selectors)?;
    selectors.translate(pointer, Access::Write, length, memory)?;
    Ok(Win16MciGuestRange {
        pointer,
        length: u32::try_from(length).map_err(|_| Win16Error::InvalidRange)?,
    })
}

fn validate_far_write_at(
    far: u32,
    offset: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(), Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let pointer = selectors.add_bytes(start, offset)?;
    validate_single_segment(pointer, length, selectors)?;
    selectors.translate(pointer, Access::Write, length, memory)?;
    Ok(())
}

fn read_struct(
    far: u32,
    length: usize,
    writable: bool,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let pointer = selectors.pointer_from_far(far)?;
    validate_single_segment(pointer, length, selectors)?;
    selectors.translate(pointer, Access::Read, length, memory)?;
    if writable {
        selectors.translate(pointer, Access::Write, length, memory)?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    selectors.read(memory, pointer, &mut bytes)?;
    Ok(bytes)
}

fn read_u16_at_far(
    far: u32,
    offset: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u16, Win16Error> {
    let bytes = read_far_field(far, offset, 2, selectors, memory)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_at_far(
    far: u32,
    offset: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<u32, Win16Error> {
    let bytes = read_far_field(far, offset, 4, selectors, memory)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_far_field(
    far: u32,
    offset: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<[u8; 4], Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let pointer = selectors.add_bytes(start, offset)?;
    validate_single_segment(pointer, length, selectors)?;
    selectors.translate(pointer, Access::Read, length, memory)?;
    let mut bytes = [0_u8; 4];
    selectors.read(memory, pointer, &mut bytes[..length])?;
    Ok(bytes)
}

fn read_far_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let pointer = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(pointer.selector())?;
    let available = descriptor
        .limit
        .checked_sub(u32::from(pointer.offset()))
        .and_then(|size| size.checked_add(1))
        .ok_or(Win16Error::InvalidRange)?;
    let count = usize::try_from(available)
        .map_err(|_| Win16Error::InvalidRange)?
        .min(crate::MAX_WIN16_STRING_BYTES);
    let mut bytes = Vec::new();
    bytes
        .try_reserve(count.min(128))
        .map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..count {
        let offset = u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?;
        let pointer = selectors.add_bytes(pointer, offset)?;
        let mut byte = [0_u8; 1];
        selectors.translate(pointer, Access::Read, 1, memory)?;
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        bytes.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

fn resource_name(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MciResourceName, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16MciResourceName::Id(raw as u16))
    } else {
        Ok(Win16MciResourceName::Name(read_far_string(
            raw, selectors, memory,
        )?))
    }
}

fn validate_single_segment(
    pointer: SegmentedPointer,
    length: usize,
    selectors: &SelectorTable,
) -> Result<(), Win16Error> {
    let descriptor = selectors.describe(pointer.selector())?;
    let remaining = descriptor
        .limit
        .checked_sub(u32::from(pointer.offset()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Win16Error::InvalidRange)?;
    if length > remaining {
        Err(Win16Error::InvalidRange)
    } else {
        Ok(())
    }
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
