//! Checked guest MCI parameter conversion to pointer-free host records.

use guest_core::memory::Memory;
use win16_abi::{
    Access, Win16MciOpenExtension, Win16MciOpenValue, Win16MciParameters,
    Win16MciSetExtension,
};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciParameters as HostParameters,
    Win16HostMciSetExtension as HostSetExtension, Win16HostMciValue, Win16HostWindow,
};

pub(super) fn parameter_callback(parameters: &Win16MciParameters) -> Option<u32> {
    Some(match parameters {
        Win16MciParameters::Null => 0,
        Win16MciParameters::Generic { callback }
        | Win16MciParameters::Play { callback, .. }
        | Win16MciParameters::Seek { callback, .. }
        | Win16MciParameters::Status { callback, .. }
        | Win16MciParameters::Info { callback, .. }
        | Win16MciParameters::GetDeviceCaps { callback, .. }
        | Win16MciParameters::SystemInfo { callback, .. }
        | Win16MciParameters::Set { callback, .. }
        | Win16MciParameters::Record { callback, .. }
        | Win16MciParameters::Break { callback, .. }
        | Win16MciParameters::File { callback, .. }
        | Win16MciParameters::Sound { callback, .. }
        | Win16MciParameters::Step { callback, .. }
        | Win16MciParameters::Escape { callback, .. }
        | Win16MciParameters::Window { callback, .. }
        | Win16MciParameters::Rectangle { callback, .. }
        | Win16MciParameters::Delete { callback, .. } => *callback,
        Win16MciParameters::Open { callback, .. } => *callback,
        Win16MciParameters::Unsupported { .. } | Win16MciParameters::UnsupportedHandle { .. } => {
            return None;
        }
    })
}

pub(super) fn callback_window(state: &Win16State, callback: u32) -> Result<Win16HostWindow, ()> {
    let guest = u16::try_from(callback).map_err(|_| ())?;
    state.resolve_mci_window(guest).ok_or(())
}

pub(super) fn embedded_window(parameters: &Win16MciParameters) -> Option<u16> {
    match parameters {
        Win16MciParameters::Open {
            extension: Win16MciOpenExtension::Window { parent_window, .. },
            ..
        } => Some(*parent_window),
        _ => None,
    }
}

pub(super) fn host_parameters(
    state: &Win16State,
    parameters: &Win16MciParameters,
    device_id: u16,
    command_flags: u32,
    memory: &Memory,
) -> Result<Option<HostParameters>, RuntimeError> {
    let parameters = match parameters {
        Win16MciParameters::Null => HostParameters::Null,
        Win16MciParameters::Generic { .. } => HostParameters::Generic,
        Win16MciParameters::Open {
            device_type,
            element,
            alias,
            extension,
            ..
        } => {
            let (buffer_seconds, style, parent) = match extension {
                Win16MciOpenExtension::None => (None, None, None),
                Win16MciOpenExtension::Wave { buffer_seconds } => {
                    (Some(*buffer_seconds), None, None)
                }
                Win16MciOpenExtension::Window {
                    style,
                    parent_window,
                } => {
                    let parent = if *parent_window == 0 {
                        None
                    } else {
                        Some(match state.resolve_mci_window(*parent_window) {
                            Some(window) => window,
                            None => return Ok(None),
                        })
                    };
                    (None, Some(*style), parent)
                }
            };
            HostParameters::Open {
                device_type: device_type.as_ref().map(host_open_value),
                element: element.as_ref().map(host_open_value),
                alias: alias.clone(),
                buffer_seconds,
                style,
                parent,
            }
        }
        Win16MciParameters::Play {
            from,
            to,
            parameter_pointer,
            ..
        } => {
            const MCI_VD_PLAY_SPEED: u32 = 0x0004_0000;
            const MCI_ANIM_PLAY_SPEED: u32 = 0x0001_0000;
            let device_type = state
                .resolve_mci_device(device_id)
                .and_then(|entry| entry.device_type);
            let selected_speed_flag = match device_type {
                // 0x0001_0000 is MCI_VD_PLAY_REVERSE for videodiscs; it is
                // not the animation speed extension in this device family.
                Some(514) => MCI_VD_PLAY_SPEED,
                Some(519) => MCI_ANIM_PLAY_SPEED,
                None if command_flags & (MCI_VD_PLAY_SPEED | MCI_ANIM_PLAY_SPEED) != 0 => {
                    // Without a resolved device family, the overlapping bit
                    // cannot safely select a native parameter layout.
                    return Ok(None);
                }
                _ => 0,
            };
            let selected_speed = if selected_speed_flag != 0
                && command_flags & selected_speed_flag != 0
            {
                Some(read_guest_dword_at(state, *parameter_pointer, 12, memory)?)
            } else {
                None
            };
            HostParameters::Play {
                from: *from,
                to: *to,
                speed: selected_speed,
            }
        }
        Win16MciParameters::Seek { to, .. } => HostParameters::Seek { to: *to },
        Win16MciParameters::Status { item, track, .. } => HostParameters::Status {
            item: *item,
            track: *track,
        },
        Win16MciParameters::Info { output, item, .. } => HostParameters::Info {
            item_flags: *item,
            capacity: (output.far != 0).then_some(output.capacity),
        },
        Win16MciParameters::GetDeviceCaps { item, .. } => {
            HostParameters::GetDeviceCaps { item: *item }
        }
        Win16MciParameters::SystemInfo {
            output,
            item,
            number,
            device_type,
            ..
        } => HostParameters::SystemInfo {
            item_flags: *item,
            number: *number,
            device_type: *device_type,
            capacity: (output.far != 0).then_some(output.capacity),
        },
        Win16MciParameters::Set {
            time_format,
            audio,
            extension,
            ..
        } => {
            let extension = match extension {
                Win16MciSetExtension::None => HostSetExtension::None,
                Win16MciSetExtension::DeviceSpecific { parameter_far, .. } => {
                    let Some(entry) = state.resolve_mci_device(device_id) else {
                        return Ok(None);
                    };
                    match entry.device_type {
                        Some(522) => {
                            let bytes = read_far_record(state, *parameter_far, 44, memory)?;
                            let record = super::wire::read::<super::wire::WaveSet>(&bytes)
                                .map_err(|_| RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "captured MCI WAVE_SET extent does not match its SDK wire record",
                                ))?;
                            HostSetExtension::Wave {
                                input: record.input.get(),
                                output: record.output.get(),
                                format_tag: record.format_tag.get(),
                                channels: record.channels.get(),
                                samples_per_second: record.samples_per_second.get(),
                                average_bytes_per_second: record.average_bytes_per_second.get(),
                                block_align: record.block_align.get(),
                                bits_per_sample: record.bits_per_sample.get(),
                            }
                        }
                        Some(523) => {
                            let bytes = read_far_record(state, *parameter_far, 32, memory)?;
                            let record = super::wire::read::<super::wire::SequencerSet>(&bytes)
                                .map_err(|_| RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "captured MCI SEQ_SET extent does not match its SDK wire record",
                                ))?;
                            HostSetExtension::Sequencer {
                                tempo: record.tempo.get(),
                                port: record.port.get(),
                                slave: record.slave.get(),
                                master: record.master.get(),
                                offset: record.offset.get(),
                            }
                        }
                        _ => return Ok(None),
                    }
                }
                Win16MciSetExtension::Wave {
                    input,
                    output,
                    format_tag,
                    channels,
                    samples_per_second,
                    average_bytes_per_second,
                    block_align,
                    bits_per_sample,
                } => HostSetExtension::Wave {
                    input: *input,
                    output: *output,
                    format_tag: *format_tag,
                    channels: *channels,
                    samples_per_second: *samples_per_second,
                    average_bytes_per_second: *average_bytes_per_second,
                    block_align: *block_align,
                    bits_per_sample: *bits_per_sample,
                },
                Win16MciSetExtension::Sequencer {
                    tempo,
                    port,
                    slave,
                    master,
                    offset,
                } => HostSetExtension::Sequencer {
                    tempo: *tempo,
                    port: *port,
                    slave: *slave,
                    master: *master,
                    offset: *offset,
                },
            };
            HostParameters::Set {
                time_format: *time_format,
                audio: *audio,
                extension,
            }
        }
        Win16MciParameters::Record { from, to, .. } => HostParameters::Record {
            from: *from,
            to: *to,
        },
        Win16MciParameters::Break {
            virtual_key,
            window,
            ..
        } => {
            const MCI_BREAK_KEY: u32 = 0x0000_0100;
            const MCI_BREAK_HWND: u32 = 0x0000_0200;
            const MCI_BREAK_OFF: u32 = 0x0000_0400;
            let break_off = command_flags & MCI_BREAK_OFF != 0;
            HostParameters::Break {
                virtual_key: if !break_off && command_flags & MCI_BREAK_KEY != 0 {
                    *virtual_key
                } else {
                    0
                },
                window: if !break_off && command_flags & MCI_BREAK_HWND != 0 {
                    if *window == 0 {
                        None
                    } else {
                        Some(match state.resolve_mci_window(*window) {
                            Some(window) => window,
                            None => return Ok(None),
                        })
                    }
                } else {
                    None
                },
            }
        }
        Win16MciParameters::File {
            filename,
            parameter_pointer,
            ..
        } => {
            let device_type = state
                .resolve_mci_device(device_id)
                .and_then(|entry| entry.device_type);
            let rectangle = match device_type {
                Some(515) => {
                    let bytes = read_captured_record(state, *parameter_pointer, 16, memory)?;
                    let record = super::wire::read::<super::wire::OverlayFile>(&bytes).map_err(
                        |_| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "captured MCI overlay file extent does not match its SDK wire record",
                            )
                        },
                    )?;
                    Some([
                        record.left.get(),
                        record.top.get(),
                        record.right.get(),
                        record.bottom.get(),
                    ])
                }
                Some(_) => None,
                // SAVE/LOAD have different generic and overlay records. An
                // unknown device family cannot safely select either layout.
                None => return Ok(None),
            };
            HostParameters::File {
                filename: filename.clone(),
                rectangle,
            }
        }
        Win16MciParameters::Sound { name, .. } => HostParameters::Sound { name: name.clone() },
        Win16MciParameters::Step { frames, .. } => HostParameters::Step { frames: *frames },
        Win16MciParameters::Escape { command, .. } => HostParameters::Escape {
            command: command.clone(),
        },
        Win16MciParameters::Window {
            window,
            show_command,
            text,
            ..
        } => {
            const MCI_ANIM_WINDOW_HWND: u32 = 0x0001_0000;
            const MCI_ANIM_WINDOW_STATE: u32 = 0x0004_0000;
            const MCI_ANIM_WINDOW_TEXT: u32 = 0x0008_0000;
            let window = if command_flags & MCI_ANIM_WINDOW_HWND != 0 && *window != 0 {
                Some(match state.resolve_mci_window(*window) {
                    Some(window) => window,
                    None => return Ok(None),
                })
            } else {
                None
            };
            HostParameters::Window {
                window,
                show_command: if command_flags & MCI_ANIM_WINDOW_STATE != 0 {
                    *show_command
                } else {
                    0
                },
                text: if command_flags & MCI_ANIM_WINDOW_TEXT != 0 {
                    text.clone()
                } else {
                    None
                },
            }
        }
        Win16MciParameters::Rectangle {
            rectangle, output, ..
        } => HostParameters::Rectangle {
            rectangle: [
                rectangle.left,
                rectangle.top,
                rectangle.right,
                rectangle.bottom,
            ],
            output: *output,
        },
        Win16MciParameters::Delete { from, to, .. } => HostParameters::Delete {
            from: *from,
            to: *to,
        },
        Win16MciParameters::Unsupported { .. } | Win16MciParameters::UnsupportedHandle { .. } => {
            return Ok(None);
        }
    };
    Ok(Some(parameters))
}

fn read_far_record(
    state: &Win16State,
    far: u32,
    length: usize,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer = state
        .selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    read_captured_record(state, pointer, length, memory)
}

fn read_captured_record(
    state: &Win16State,
    pointer: win16_abi::SegmentedPointer,
    length: usize,
    memory: &Memory,
) -> Result<Vec<u8>, RuntimeError> {
    let descriptor = state
        .selectors
        .describe(pointer.selector())
        .map_err(crate::runtime_error)?;
    let remaining = descriptor
        .limit
        .checked_sub(u32::from(pointer.offset()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "invalid MCI parameter FAR extent"))?;
    if length > remaining {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "MCI device-specific parameter block crosses its FAR selector",
        ));
    }
    state
        .selectors
        .translate(pointer, Access::Read, length, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy MCI device-specific parameter block",
            error,
        )
    })?;
    bytes.resize(length, 0);
    state
        .selectors
        .read(memory, pointer, &mut bytes)
        .map_err(crate::runtime_error)?;
    Ok(bytes)
}

fn read_guest_dword_at(
    state: &Win16State,
    start: win16_abi::SegmentedPointer,
    offset: u32,
    memory: &Memory,
) -> Result<u32, RuntimeError> {
    let pointer = state
        .selectors
        .add_bytes(start, offset)
        .map_err(crate::runtime_error)?;
    state
        .selectors
        .translate(pointer, Access::Read, 4, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = [0_u8; 4];
    state
        .selectors
        .read(memory, pointer, &mut bytes)
        .map_err(crate::runtime_error)?;
    Ok(u32::from_le_bytes(bytes))
}

fn host_open_value(value: &Win16MciOpenValue) -> Win16HostMciValue {
    match value {
        Win16MciOpenValue::Ansi(bytes) => Win16HostMciValue::Ansi(bytes.clone()),
        Win16MciOpenValue::ResourceId(id) => Win16HostMciValue::ResourceId(u32::from(*id)),
        Win16MciOpenValue::ElementId(id) => Win16HostMciValue::ElementId(*id),
    }
}
