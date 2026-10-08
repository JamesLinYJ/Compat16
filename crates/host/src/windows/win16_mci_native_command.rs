//! Typed MCI command parameter projection to official Windows MCI structures.

use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciOutput, Win16HostMciParameters as P,
    Win16HostMciResult, Win16HostMciTarget,
};
use windows_sys::Win32::Media::Multimedia::*;

use super::open::{
    MciOpenRegistrationFailure, OpenArgumentError, open_argument, open_device_type, rect16,
};
use super::{
    MciNativeContext, bind_open_notification, cancel_notification, disable_yield_sources_for_close,
    guest_output_from_wide, guest_output_projection, quarantine_open_notification,
    query_device_type, reserve_notification, retire_failed_open_notification, unsupported,
    wide_capacity, wide_terminated, zeroed_wide_buffer,
};

#[path = "win16_mci_native_command_call.rs"]
mod call;
#[path = "win16_mci_native_command_file.rs"]
mod file;
#[path = "win16_mci_native_command_notify.rs"]
mod notify;
#[path = "win16_mci_native_command_overlay.rs"]
mod overlay;
use call::{call_native, call_native_null};

const MCIERR_UNSUPPORTED_FUNCTION_VALUE: u32 = 274;
const MCIERR_NO_WINDOW_VALUE: u32 = 346;
const MCI_NOTIFY_VALUE: u32 = 1;
const MCI_OPEN_VALUE: u16 = 0x0803;
const MCI_CLOSE_VALUE: u16 = 0x0804;
const MCI_ALL_DEVICE_ID: u32 = u32::MAX;

pub(super) fn send_command(
    context: &MciNativeContext,
    target: Win16HostMciTarget,
    message: u16,
    flags: u32,
    parameters: P,
    notify_target: Option<runtime::Win16HostWindow>,
) -> Result<Win16HostMciResult, RuntimeError> {
    let native_id = match target {
        Win16HostMciTarget::All => MCI_ALL_DEVICE_ID,
        Win16HostMciTarget::Device(device) => context.state.native_id(device)?.0,
    };
    let open_source_id = if message == MCI_OPEN_VALUE {
        // Reserve host identity map capacity before MCI can create a native
        // device whose returned ID would otherwise become unowned on OOM.
        Some(context.state.reserve_device_slot()?)
    } else {
        None
    };
    let callback = if flags & MCI_NOTIFY_VALUE != 0 {
        context.state.sink as usize
    } else {
        0
    };
    let notification = if flags & MCI_NOTIFY_VALUE != 0 {
        let Some(notification_window) = notify_target else {
            return Ok(unsupported(MCIERR_NO_WINDOW_VALUE));
        };
        Some(notify::reserve_command_notification(
            context,
            message,
            native_id,
            &parameters,
            notification_window,
            open_source_id,
        )?)
    } else {
        None
    };
    if message == MCI_CLOSE_VALUE {
        let closing_device = match target {
            Win16HostMciTarget::Device(device) => Some(device),
            Win16HostMciTarget::All => None,
        };
        if let Err(primary) = disable_yield_sources_for_close(&context.state, closing_device) {
            // The native command has not been submitted, so release only its exact reserved route.
            if let Some(id) = notification {
                cancel_notification(context, id);
            }
            return Err(primary);
        }
    }
    let (result, returned_device) =
        match unsafe { command_unsafe(context, native_id, message, flags, callback, parameters) } {
            Ok(result) => result,
            Err(primary) => {
                if let Some(id) = notification {
                    cancel_notification(context, id);
                }
                return Err(primary);
            }
        };
    if let Some((native, device_type)) = returned_device {
        let device = match context
            .state
            .register_device(native, device_type, open_source_id)
        {
            Ok(device) => device,
            Err(primary) => {
                if let Some(id) = notification {
                    quarantine_open_notification(context, id, native, None);
                }
                let close_result = super::close_native_device(native, context.state.sink);
                if close_result != 0 {
                    context.state.retain_orphan_native_id(native);
                    return Err(RuntimeError::with_source(
                        super::classify_mci_cleanup(primary.kind(), Some(Kind::HostFailure)),
                        "MCI_OPEN identity registration failed and native rollback close also failed",
                        MciOpenRegistrationFailure {
                            primary,
                            close_result,
                        },
                    ));
                }
                if let Some(id) = notification {
                    retire_failed_open_notification(context, id);
                }
                return Err(primary.with_context(
                    "MCI_OPEN host identity allocation failed; native rollback close succeeded",
                ));
            }
        };
        if let Some(notification_id) = notification {
            let bind =
                bind_open_notification(context, notification_id, native, device, open_source_id);
            if let Err(primary) = bind {
                if let Some(id) = notification {
                    quarantine_open_notification(context, id, native, Some(device));
                }
                let close_result = super::close_native_device(native, context.state.sink);
                if close_result == 0 {
                    context.state.retire_device(device)?;
                } else {
                    context.state.retain_orphan_native_id(native);
                    return Err(RuntimeError::with_source(
                        super::classify_mci_cleanup(primary.kind(), Some(Kind::HostFailure)),
                        "MCI_OPEN notification binding failed and native rollback close also failed",
                        MciOpenRegistrationFailure {
                            primary,
                            close_result,
                        },
                    ));
                }
                if let Some(id) = notification {
                    retire_failed_open_notification(context, id);
                }
                return Err(primary.with_context(
                    "MCI_OPEN notification binding failed; native rollback close succeeded",
                ));
            }
        }
        return Ok(Win16HostMciResult {
            return_value: result.return_value,
            output: Win16HostMciOutput::Device {
                device,
                device_type,
            },
        });
    }
    if result.return_value != 0 {
        if let Some(id) = notification {
            cancel_notification(context, id);
        }
    } else if message == MCI_CLOSE_VALUE {
        if let Win16HostMciTarget::Device(device) = target {
            context.state.retire_device(device)?;
        } else {
            context.state.retire_all_devices()?;
        }
    }
    Ok(result)
}

fn target_device(
    _parameters: &P,
    native_id: u32,
    context: &MciNativeContext,
) -> Option<runtime::Win16HostMciDevice> {
    context
        .state
        .devices
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .by_native
        .get(&native_id)
        .map(|entry| entry.identity)
}

unsafe fn command_unsafe(
    context: &MciNativeContext,
    native_id: u32,
    message: u16,
    flags: u32,
    callback: usize,
    parameters: P,
) -> Result<(Win16HostMciResult, Option<(u32, Option<u32>)>), RuntimeError> {
    let mut output = Win16HostMciOutput::None;
    let code = match (message, parameters) {
        (
            MCI_OPEN_VALUE,
            P::Open {
                device_type,
                element,
                alias,
                buffer_seconds,
                style,
                parent,
            },
        ) => {
            if parent.is_some() {
                return Ok((unsupported(MCIERR_NO_WINDOW_VALUE), None));
            }
            let type_text = match open_argument(device_type.as_ref(), context.state.text_codec) {
                Ok(value) => value,
                Err(OpenArgumentError::Runtime(error)) => return Err(error),
            };
            let element_text = match open_argument(element.as_ref(), context.state.text_codec) {
                Ok(value) => value,
                Err(OpenArgumentError::Runtime(error)) => return Err(error),
            };
            let alias_text = alias
                .as_deref()
                .map(|value| wide_terminated(context.state.text_codec, value))
                .transpose()?;
            let mut open_flags = flags;
            if type_text.resource_id().is_some() {
                open_flags |= MCI_OPEN_TYPE_ID as u32;
            }
            if element_text.resource_id().is_some() {
                open_flags |= MCI_OPEN_ELEMENT_ID as u32;
            }
            if let Some(seconds) = buffer_seconds {
                if open_device_type(device_type.as_ref()) != Some(522) {
                    return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
                }
                let mut parms = MCI_WAVE_OPEN_PARMSW {
                    dwCallback: callback,
                    lpstrDeviceType: type_text.as_ptr(),
                    lpstrElementName: element_text.as_ptr(),
                    lpstrAlias: alias_text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                    dwBufferSeconds: seconds,
                    ..Default::default()
                };
                let code = unsafe { call_native(native_id, message, open_flags, &mut parms) };
                let opened =
                    (code == 0).then_some((parms.wDeviceID, query_device_type(parms.wDeviceID)));
                let result = Win16HostMciResult {
                    return_value: code,
                    output: Win16HostMciOutput::None,
                };
                return Ok((result, opened));
            }
            if let Some(style) = style {
                if parent.is_some() {
                    return Ok((unsupported(MCIERR_NO_WINDOW_VALUE), None));
                }
                let Some(kind) = open_device_type(device_type.as_ref()) else {
                    return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
                };
                if kind == 519 {
                    let mut parms = MCI_ANIM_OPEN_PARMSW {
                        dwCallback: callback,
                        lpstrDeviceType: type_text.as_ptr(),
                        lpstrElementName: element_text.as_ptr(),
                        lpstrAlias: alias_text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                        dwStyle: style,
                        ..Default::default()
                    };
                    let code =
                        unsafe { call_native(MCI_ALL_DEVICE_ID, message, open_flags, &mut parms) };
                    let opened = (code == 0)
                        .then_some((parms.wDeviceID, query_device_type(parms.wDeviceID)));
                    return Ok((
                        Win16HostMciResult {
                            return_value: code,
                            output,
                        },
                        opened,
                    ));
                }
                if kind == 515 {
                    let mut parms = MCI_OVLY_OPEN_PARMSW {
                        dwCallback: callback,
                        lpstrDeviceType: type_text.as_ptr(),
                        lpstrElementName: element_text.as_ptr(),
                        lpstrAlias: alias_text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                        dwStyle: style,
                        ..Default::default()
                    };
                    let code =
                        unsafe { call_native(MCI_ALL_DEVICE_ID, message, open_flags, &mut parms) };
                    let opened = (code == 0)
                        .then_some((parms.wDeviceID, query_device_type(parms.wDeviceID)));
                    return Ok((
                        Win16HostMciResult {
                            return_value: code,
                            output,
                        },
                        opened,
                    ));
                }
                return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
            }
            if parent.is_some() {
                return Ok((unsupported(MCIERR_NO_WINDOW_VALUE), None));
            }
            let mut parms = MCI_OPEN_PARMSW {
                dwCallback: callback,
                lpstrDeviceType: type_text.as_ptr(),
                lpstrElementName: element_text.as_ptr(),
                lpstrAlias: alias_text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                ..Default::default()
            };
            let code = unsafe { call_native(MCI_ALL_DEVICE_ID, message, open_flags, &mut parms) };
            let opened =
                (code == 0).then_some((parms.wDeviceID, query_device_type(parms.wDeviceID)));
            let result = Win16HostMciResult {
                return_value: code,
                output,
            };
            return Ok((result, opened));
        }
        (MCI_CLOSE_VALUE, P::Null) => {
            return Ok((
                Win16HostMciResult {
                    return_value: unsafe {
                        mciSendCommandW(native_id, u32::from(message), flags as usize, 0)
                    },
                    output,
                },
                None,
            ));
        }
        (MCI_CLOSE_VALUE, P::Generic) => {
            let mut parms = MCI_GENERIC_PARMS {
                dwCallback: callback,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x0806,
            P::Play {
                from,
                to,
                speed: None,
            },
        ) => {
            let mut parms = MCI_PLAY_PARMS {
                dwCallback: callback,
                dwFrom: from,
                dwTo: to,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x0806,
            P::Play {
                from,
                to,
                speed: Some(speed),
            },
        ) => match context.state.device_type(native_id) {
            Some(514) => {
                let mut parms = MCI_VD_PLAY_PARMS {
                    dwCallback: callback,
                    dwFrom: from,
                    dwTo: to,
                    dwSpeed: speed,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            }
            Some(519) => {
                let mut parms = MCI_ANIM_PLAY_PARMS {
                    dwCallback: callback,
                    dwFrom: from,
                    dwTo: to,
                    dwSpeed: speed,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            }
            _ => return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None)),
        },
        (0x0807, P::Seek { to }) => {
            let mut parms = MCI_SEEK_PARMS {
                dwCallback: callback,
                dwTo: to,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (0x0814, P::Status { item, track }) => {
            let mut parms = MCI_STATUS_PARMS {
                dwCallback: callback,
                dwItem: item,
                dwTrack: track,
                ..Default::default()
            };
            let code = unsafe { call_native(native_id, message, flags, &mut parms) };
            let Ok(value) = u32::try_from(parms.dwReturn) else {
                return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
            };
            output = Win16HostMciOutput::Scalar(value);
            code
        }
        (0x080b, P::GetDeviceCaps { item }) => {
            let mut parms = MCI_GETDEVCAPS_PARMS {
                dwCallback: callback,
                dwItem: item,
                ..Default::default()
            };
            let code = unsafe { call_native(native_id, message, flags, &mut parms) };
            output = Win16HostMciOutput::Scalar(parms.dwReturn);
            code
        }
        (
            0x080a,
            P::Info {
                item_flags,
                capacity,
            },
        ) => {
            let mut wide = zeroed_wide_buffer(wide_capacity(capacity)?)?;
            let mut parms = MCI_INFO_PARMSW {
                dwCallback: callback,
                lpstrReturn: if wide.is_empty() {
                    ptr::null_mut()
                } else {
                    wide.as_mut_ptr()
                },
                dwRetSize: u32::try_from(wide.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "MCI_INFO UTF-16 capacity exceeds the Windows API width",
                        error,
                    )
                })?,
            };
            let code = unsafe { call_native(native_id, message, flags | item_flags, &mut parms) };
            output = Win16HostMciOutput::Bytes(guest_output_from_wide(
                context.state.text_codec,
                &wide,
                capacity,
            )?);
            code
        }
        (
            0x0810,
            P::SystemInfo {
                item_flags,
                number,
                device_type,
                capacity,
            },
        ) => {
            let quantity = item_flags & MCI_SYSINFO_QUANTITY as u32 != 0;
            if quantity {
                // MCI_SYSINFO_QUANTITY returns a DWORD although the W record
                // describes its shared buffer as UTF-16. Provide the four
                // WCHAR units reported below while preserving DWORD alignment.
                let mut value = [0_u32; 2];
                let mut parms = MCI_SYSINFO_PARMSW {
                    dwCallback: callback,
                    lpstrReturn: value.as_mut_ptr().cast::<u16>(),
                    dwRetSize: 4,
                    dwNumber: number,
                    wDeviceType: u32::from(device_type),
                };
                let code =
                    unsafe { call_native(native_id, message, flags | item_flags, &mut parms) };
                output = Win16HostMciOutput::Scalar(value[0]);
                code
            } else {
                let mut wide = zeroed_wide_buffer(wide_capacity(capacity)?)?;
                let mut parms = MCI_SYSINFO_PARMSW {
                    dwCallback: callback,
                    lpstrReturn: if wide.is_empty() {
                        ptr::null_mut()
                    } else {
                        wide.as_mut_ptr()
                    },
                    dwRetSize: u32::try_from(wide.len()).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "MCI_SYSINFO UTF-16 capacity exceeds the Windows API width",
                            error,
                        )
                    })?,
                    dwNumber: number,
                    wDeviceType: u32::from(device_type),
                };
                let code =
                    unsafe { call_native(native_id, message, flags | item_flags, &mut parms) };
                let (bytes, truncated) =
                    guest_output_projection(context.state.text_codec, &wide, capacity)?;
                output = Win16HostMciOutput::Bytes(bytes);
                if code == 0 && truncated {
                    MCIERR_PARAM_OVERFLOW
                } else {
                    code
                }
            }
        }
        (
            0x080d,
            P::Set {
                time_format,
                audio,
                extension: runtime::Win16HostMciSetExtension::None,
            },
        ) => {
            let mut parms = MCI_SET_PARMS {
                dwCallback: callback,
                dwTimeFormat: time_format,
                dwAudio: audio,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x080d,
            P::Set {
                time_format,
                audio,
                extension:
                    runtime::Win16HostMciSetExtension::Wave {
                        input,
                        output,
                        format_tag,
                        channels,
                        samples_per_second,
                        average_bytes_per_second,
                        block_align,
                        bits_per_sample,
                    },
            },
        ) => {
            let mut parms = MCI_WAVE_SET_PARMS {
                dwCallback: callback,
                dwTimeFormat: time_format,
                dwAudio: audio,
                wInput: u32::from(input),
                wOutput: u32::from(output),
                wFormatTag: format_tag,
                nChannels: channels,
                nSamplesPerSec: samples_per_second,
                nAvgBytesPerSec: average_bytes_per_second,
                nBlockAlign: block_align,
                wBitsPerSample: bits_per_sample,
                ..Default::default()
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x080d,
            P::Set {
                time_format,
                audio,
                extension:
                    runtime::Win16HostMciSetExtension::Sequencer {
                        tempo,
                        port,
                        slave,
                        master,
                        offset,
                    },
            },
        ) => {
            let mut parms = MCI_SEQ_SET_PARMS {
                dwCallback: callback,
                dwTimeFormat: time_format,
                dwAudio: audio,
                dwTempo: tempo,
                dwPort: port,
                dwSlave: slave,
                dwMaster: master,
                dwOffset: offset,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (0x080f, P::Record { from, to }) => {
            let mut parms = MCI_RECORD_PARMS {
                dwCallback: callback,
                dwFrom: from,
                dwTo: to,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x0811,
            P::Break {
                virtual_key,
                window: None,
            },
        ) => {
            let mut parms = MCI_BREAK_PARMS {
                dwCallback: callback,
                nVirtKey: i32::from(virtual_key),
                hwndBreak: ptr::null_mut(),
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x0811,
            P::Break {
                window: Some(_), ..
            },
        ) => return Ok((unsupported(MCIERR_NO_WINDOW_VALUE), None)),
        (
            0x0813 | 0x0850,
            P::File {
                filename,
                rectangle,
            },
        ) => file::send(
            context,
            native_id,
            message,
            flags,
            callback,
            filename,
            rectangle,
            context.state.text_codec,
        )?,
        (0x080e, P::Step { frames }) => {
            let device_type = context.state.device_type(native_id);
            if device_type == Some(514) {
                let mut parms = MCI_VD_STEP_PARMS {
                    dwCallback: callback,
                    dwFrames: frames,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            } else if matches!(device_type, Some(519)) {
                let mut parms = MCI_ANIM_STEP_PARMS {
                    dwCallback: callback,
                    dwFrames: frames,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            } else if matches!(device_type, Some(520)) {
                let mut parms = MCI_DGV_STEP_PARMS {
                    dwCallback: callback,
                    dwFrames: frames,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            } else {
                return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
            }
        }
        (0x0812, P::Sound { name }) => {
            #[repr(C)]
            struct SoundParms {
                callback: usize,
                name: *const u16,
            }
            let name = wide_terminated(context.state.text_codec, &name)?;
            let mut parms = SoundParms {
                callback,
                name: name.as_ptr(),
            };
            // Win16 SDK 3.1's guest record has LPCSTR; the native MCI command
            // boundary uses the equivalent MCI_SOUND_PARMSW LPCWSTR field.
            // windows-sys has no named binding for this legacy MCI message.
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (0x0805, P::Escape { command }) => {
            if context.state.device_type(native_id) != Some(514) {
                return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None));
            }
            let command = wide_terminated(context.state.text_codec, &command)?;
            let mut parms = MCI_VD_ESCAPE_PARMSW {
                dwCallback: callback,
                lpstrCommand: command.as_ptr(),
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (
            0x0841,
            P::Window {
                window: None,
                show_command,
                text,
            },
        ) => {
            let mut text = text
                .as_deref()
                .map(|value| wide_terminated(context.state.text_codec, value))
                .transpose()?;
            match context.state.device_type(native_id) {
                Some(519) => {
                    let mut parms = MCI_ANIM_WINDOW_PARMSW {
                        dwCallback: callback,
                        hWnd: ptr::null_mut(),
                        nCmdShow: u32::from(show_command),
                        lpstrText: text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                    };
                    unsafe { call_native(native_id, message, flags, &mut parms) }
                }
                Some(515) => {
                    let mut parms = MCI_OVLY_WINDOW_PARMSW {
                        dwCallback: callback,
                        hWnd: ptr::null_mut(),
                        nCmdShow: u32::from(show_command),
                        lpstrText: text.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                    };
                    unsafe { call_native(native_id, message, flags, &mut parms) }
                }
                Some(520) => {
                    let mut parms = MCI_DGV_WINDOW_PARMSW {
                        dwCallback: callback,
                        hWnd: ptr::null_mut(),
                        nCmdShow: u32::from(show_command),
                        lpstrText: text.as_mut().map_or(ptr::null_mut(), |v| v.as_mut_ptr()),
                    };
                    unsafe { call_native(native_id, message, flags, &mut parms) }
                }
                _ => return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None)),
            }
        }
        (
            0x0841,
            P::Window {
                window: Some(_), ..
            },
        ) => return Ok((unsupported(MCIERR_NO_WINDOW_VALUE), None)),
        (0x0844 | 0x0845, parameters) => {
            overlay::send(context, native_id, message, flags, callback, parameters)
        }
        (
            0x0842 | 0x0843,
            P::Rectangle {
                rectangle,
                output: is_output,
            },
        ) => {
            let [left, top, right, bottom] = rectangle;
            let rc = windows_sys::Win32::Foundation::RECT {
                left: i32::from(left),
                top: i32::from(top),
                right: i32::from(right),
                bottom: i32::from(bottom),
            };
            match context.state.device_type(native_id) {
                Some(519) => {
                    let mut parms = MCI_ANIM_RECT_PARMS {
                        dwCallback: callback,
                        rc,
                    };
                    let code = unsafe { call_native(native_id, message, flags, &mut parms) };
                    if is_output && code == 0 {
                        let Some(value) = rect16(parms.rc) else {
                            return Ok((unsupported(MCIERR_PARAM_OVERFLOW), None));
                        };
                        output = Win16HostMciOutput::Rectangle(value);
                    }
                    code
                }
                Some(515) => {
                    let mut parms = MCI_OVLY_RECT_PARMS {
                        dwCallback: callback,
                        rc,
                    };
                    let code = unsafe { call_native(native_id, message, flags, &mut parms) };
                    if is_output && code == 0 {
                        let Some(value) = rect16(parms.rc) else {
                            return Ok((unsupported(MCIERR_PARAM_OVERFLOW), None));
                        };
                        output = Win16HostMciOutput::Rectangle(value);
                    }
                    code
                }
                Some(520) => {
                    let mut parms = MCI_DGV_RECT_PARMS {
                        dwCallback: callback,
                        rc,
                    };
                    let code = unsafe { call_native(native_id, message, flags, &mut parms) };
                    if is_output && code == 0 {
                        let Some(value) = rect16(parms.rc) else {
                            return Ok((unsupported(MCIERR_PARAM_OVERFLOW), None));
                        };
                        output = Win16HostMciOutput::Rectangle(value);
                    }
                    code
                }
                _ => return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None)),
            }
        }
        (0x0856, P::Delete { from, to }) => match context.state.device_type(native_id) {
            Some(522) => {
                let mut parms = MCI_WAVE_DELETE_PARMS {
                    dwCallback: callback,
                    dwFrom: from,
                    dwTo: to,
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            }
            Some(520) => {
                let mut parms = MCI_DGV_DELETE_PARMS {
                    dwCallback: callback,
                    dwFrom: from,
                    dwTo: to,
                    ..Default::default()
                };
                unsafe { call_native(native_id, message, flags, &mut parms) }
            }
            _ => return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None)),
        },
        (0x0808 | 0x0809 | 0x080c | 0x0830 | 0x0855, P::Generic) => {
            let mut parms = MCI_GENERIC_PARMS {
                dwCallback: callback,
            };
            unsafe { call_native(native_id, message, flags, &mut parms) }
        }
        (0x0808 | 0x0809 | 0x080c | 0x0830 | 0x0855, P::Null) => unsafe {
            call_native_null(native_id, message, flags)
        },
        _ => return Ok((unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE), None)),
    };
    Ok((
        Win16HostMciResult {
            return_value: code,
            output,
        },
        None,
    ))
}
