//! Native WinMM MCI calls. All pointers here refer to call-local owned storage
//! or the owner thread's hidden notification HWND; guest pointers never cross.

use std::ffi::c_void;
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciCall, Win16HostMciOutput,
    Win16HostMciQuiescenceEvidence, Win16HostMciResult, Win16HostMciStep,
    Win16HostMciYieldRegistration, Win16MciCommandSyntaxError, Win16MciCommandToken,
    parse_win16_mci_command,
};
use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::Media::Multimedia::*;

use super::{MciNativeContext, WorkerThreadState, worker_loop::mci_yield_proc};
use crate::windows::guest_text::GuestTextCodec;

const MCIERR_NO_WINDOW_VALUE: u32 = 346;
const MCIERR_UNSUPPORTED_FUNCTION_VALUE: u32 = 274;
const MCIERR_DUPLICATE_ALIAS_VALUE: u32 = MCIERR_DUPLICATE_ALIAS;

#[path = "win16_mci_native_command.rs"]
mod command;
#[path = "win16_mci_native_error_string.rs"]
mod error_string;
#[path = "win16_mci_native_open.rs"]
mod open;
#[path = "win16_mci_native_retirement.rs"]
mod retirement;
#[path = "win16_mci_native_string_notify.rs"]
mod string_notify;
#[cfg(test)]
#[path = "win16_mci_native_text_tests.rs"]
mod text_tests;
#[path = "win16_mci_native_yield.rs"]
mod yield_source;

// Keep helpers local except the exact preflight used by the worker quiescer.
use retirement::{
    bind_open_notification, device_lookup, disable_yield_sources_for_close, query_device_type,
};
pub(super) use retirement::{classify_mci_cleanup, ensure_no_active_yields_for_close};
pub(super) use yield_source::disable_yield_registration;

pub(super) fn execute(
    context: MciNativeContext,
    call: Win16HostMciCall,
) -> Result<Win16HostMciStep, RuntimeError> {
    let result = match call {
        Win16HostMciCall::SendCommand {
            target,
            message,
            flags,
            parameters,
            notify_target,
        } => command::send_command(&context, target, message, flags, parameters, notify_target)?,
        Win16HostMciCall::SendString {
            command,
            output_capacity,
            callback_target,
        } => send_string(&context, &command, output_capacity, callback_target)?,
        Win16HostMciCall::GetDeviceId { name } => {
            let name = wide_terminated(context.state.text_codec, &name)?;
            // SAFETY: `name` is owned and UTF-16 NUL-terminated for this call.
            let native = unsafe { mciGetDeviceIDW(name.as_ptr()) };
            device_lookup(&context, native)?
        }
        Win16HostMciCall::GetDeviceIdFromElement {
            element_id,
            device_type,
        } => {
            let device_type = wide_terminated(context.state.text_codec, &device_type)?;
            // SAFETY: The UTF-16 NUL-terminated device-type string remains alive for the call.
            let native = unsafe { mciGetDeviceIDFromElementIDW(element_id, device_type.as_ptr()) };
            device_lookup(&context, native)?
        }
        Win16HostMciCall::GetErrorString { error, capacity } => {
            error_string::get_error_string(error, capacity, context.state.text_codec)?
        }
        Win16HostMciCall::SetDriverData { device: _, data: _ }
        | Win16HostMciCall::GetDriverData { device: _ } => {
            // The Win16 contract is a DWORD, while the modern native API uses
            // a pointer-sized driver-private slot. Without a target driver ABI
            // proof, neither direction can safely alias or truncate that slot.
            unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE)
        }
        Win16HostMciCall::DriverYield { device } => {
            let (native, _) = context.state.native_id(device)?;
            Win16HostMciResult {
                return_value: 0,
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                output: Win16HostMciOutput::Scalar(unsafe { mciDriverYield(native) }),
            }
        }
        Win16HostMciCall::DriverNotify {
            device,
            target,
            status,
        } => {
            let (native, _) = context.state.native_id(device)?;
            let id = retirement::reserve_device_notification(&context, native, device, target)?;
            let ok =
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                unsafe { mciDriverNotify(context.state.sink as HANDLE, native, u32::from(status)) }
                    != 0;
            if !ok {
                cancel_notification(&context, id);
            }
            Win16HostMciResult {
                return_value: u32::from(ok),
                output: Win16HostMciOutput::None,
            }
        }
        Win16HostMciCall::SetYieldProc {
            device,
            enabled,
            data,
        } => {
            let (native, _) = context.state.native_id(device)?;
            let (ok, installed, registration) = if enabled {
                let registration = match context.state.current_yield_registration(device) {
                    Some(registration) => registration,
                    None => context.state.reserve_yield_registration(device)?,
                };
                // SAFETY: `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let ok = unsafe { mciSetYieldProc(native, Some(mci_yield_proc), data) } != 0;
                if ok {
                    context
                        .state
                        .publish_yield_registration(device, registration);
                }
                (ok, ok, if ok { Some(registration) } else { None })
            } else {
                let registration = context.state.current_yield_registration(device);
                if let Some(registration) = registration {
                    match yield_source::disable_yield_registration(
                        &context.state,
                        Win16HostMciYieldRegistration {
                            device,
                            registration,
                        },
                    )? {
                        Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                            set_result,
                            observed_installed,
                            ..
                        } => (
                            set_result != 0 && !observed_installed,
                            observed_installed,
                            None,
                        ),
                        _ => unreachable!("MCI yield disable returns source-phase evidence"),
                    }
                } else {
                    let mut current_data = 0_u32;
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    match unsafe { mciGetYieldProc(native, &mut current_data) } {
                        Some(proc) if proc as usize == mci_yield_proc as *const () as usize => {
                            return Err(RuntimeError::new(
                                Kind::CompatibilityGap,
                                format!(
                                    "MCI device {}:{} exposes the runtime yield thunk without its exact registration identity",
                                    device.token, device.generation
                                ),
                            ));
                        }
                        _ => {}
                    }
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    let ok = unsafe { mciSetYieldProc(native, None, data) } != 0;
                    (ok, false, None)
                }
            };
            Win16HostMciResult {
                return_value: u32::from(ok),
                output: Win16HostMciOutput::YieldProc {
                    installed,
                    data,
                    registration,
                },
            }
        }
        Win16HostMciCall::GetYieldProc { device } => {
            let (native, _) = context.state.native_id(device)?;
            let mut data = 0_u32;
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let proc = unsafe { mciGetYieldProc(native, &mut data) };
            let registration = context.state.current_yield_registration(device);
            let installed = proc.map(|value| value as usize)
                == Some(mci_yield_proc as *const () as usize)
                && registration.is_some();
            Win16HostMciResult {
                return_value: 0,
                output: Win16HostMciOutput::YieldProc {
                    installed,
                    data,
                    registration: if installed { registration } else { None },
                },
            }
        }
        Win16HostMciCall::CloseDevice { device } => {
            let (native, _) = context.state.native_id(device)?;
            disable_yield_sources_for_close(&context.state, Some(device))?;
            let code = close_native_device(native, context.state.sink);
            if code == 0 {
                context.state.retire_device(device)?;
            }
            Win16HostMciResult {
                return_value: code,
                output: Win16HostMciOutput::None,
            }
        }
    };
    Ok(Win16HostMciStep::Complete(result))
}

fn send_string(
    context: &MciNativeContext,
    command: &[u8],
    capacity: Option<u32>,
    target: Option<runtime::Win16HostWindow>,
) -> Result<Win16HostMciResult, RuntimeError> {
    let action = analyze_string_action(context, command)?;
    let open_alias_z = match &action {
        MciStringAction::Open(Some(alias)) => {
            // Allocate and validate the exact alias lookup string before OPEN
            // can create a native device. This leaves no post-side-effect
            // allocation needed to recover its owner identity.
            let terminated_alias = wide_terminated(context.state.text_codec, alias)?;
            // SAFETY: mciGetDeviceIDW reads a caller-owned device name.
            let existing = unsafe { mciGetDeviceIDW(terminated_alias.as_ptr()) };
            if existing != 0 {
                return Ok(Win16HostMciResult {
                    return_value: MCIERR_DUPLICATE_ALIAS_VALUE,
                    output: Win16HostMciOutput::StringCommand {
                        bytes: zeroed_buffer(capacity)?,
                        opened: None,
                        closed: None,
                        closed_all: false,
                        unsupported_owner: false,
                    },
                });
            }
            Some(terminated_alias)
        }
        _ => None,
    };
    if matches!(&action, MciStringAction::Open(None)) {
        return Ok(Win16HostMciResult {
            return_value: MCIERR_UNSUPPORTED_FUNCTION_VALUE,
            output: Win16HostMciOutput::StringCommand {
                bytes: zeroed_buffer(capacity)?,
                opened: None,
                closed: None,
                closed_all: false,
                unsupported_owner: true,
            },
        });
    }
    let open_source_id = if matches!(&action, MciStringAction::Open(Some(_))) {
        Some(context.state.reserve_device_slot()?)
    } else {
        None
    };
    let Some(requests_notify) = string_notify::has_unquoted_notify_token(command)? else {
        // An unrecognized command grammar plus an unquoted `notify` token is
        // ambiguous between a driver-specific string value and MCI_NOTIFY.
        // Do not forward it with a guessed callback route.
        return Ok(unsupported(MCIERR_UNSUPPORTED_FUNCTION_VALUE));
    };
    if requests_notify && target.is_none() {
        return Ok(unsupported(MCIERR_NO_WINDOW_VALUE));
    }
    let notify = requests_notify;
    let (native_for_route, device_for_route, allow_new_device) = match &action {
        MciStringAction::Open(Some(_)) => (None, None, true),
        MciStringAction::Close { native, device } => (*native, *device, false),
        MciStringAction::CloseAll => (None, None, false),
        MciStringAction::Other => {
            let native = if notify {
                string_device_id(command, context.state.text_codec)?
            } else {
                None
            };
            let device = native.and_then(|native| context.state.existing_identity(native));
            (native, device, false)
        }
        MciStringAction::Open(None) => unreachable!("handled before native dispatch"),
    };
    let notification_source_id = retirement::string_notification_source_id(
        &context,
        notify,
        allow_new_device,
        open_source_id,
        device_for_route,
    )?;
    let sysinfo = command
        .split(|byte| byte.is_ascii_whitespace())
        .find(|token| !token.is_empty())
        .is_some_and(|token| token.eq_ignore_ascii_case(b"sysinfo"));
    let command = wide_terminated(context.state.text_codec, command)?;
    let mut output = zeroed_wide_buffer(wide_capacity(capacity)?)?;
    let native_output_capacity = u32::try_from(output.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "MCI string output capacity exceeds the Windows API width",
            error,
        )
    })?;
    let callback: HWND = if notify {
        context.state.sink
    } else {
        ptr::null_mut()
    };
    let notification = if let (true, Some(target)) = (notify, target) {
        Some(reserve_notification(
            context,
            native_for_route,
            device_for_route,
            target,
            allow_new_device,
            notification_source_id,
        )?)
    } else {
        None
    };
    let close_preflight = match &action {
        MciStringAction::Close {
            device: Some(device),
            ..
        } => disable_yield_sources_for_close(&context.state, Some(*device)),
        MciStringAction::CloseAll => disable_yield_sources_for_close(&context.state, None),
        _ => Ok(()),
    };
    if let Err(primary) = close_preflight {
        // The native string was not submitted; cancel only its exact reserved route.
        if let Some(id) = notification {
            cancel_notification(context, id);
        }
        return Err(primary);
    }
    let output_pointer = if output.is_empty() {
        ptr::null_mut()
    } else {
        output.as_mut_ptr()
    };
    // SAFETY: mciSendStringW reads a caller-owned command and writes a caller-owned buffer.
    let mut code = unsafe {
        mciSendStringW(
            command.as_ptr(),
            output_pointer,
            native_output_capacity,
            callback,
        )
    };
    let output = guest_output_projection(context.state.text_codec, &output, capacity).map(
        |(bytes, truncated)| {
            if code == 0 && sysinfo && truncated {
                code = MCIERR_PARAM_OVERFLOW;
            }
            bytes
        },
    );
    if code != 0 {
        if let Some(id) = notification {
            cancel_notification(context, id);
        }
    }
    let mut opened = None;
    let mut closed = None;
    let mut closed_all = false;
    if code == 0 {
        match action {
            MciStringAction::Open(Some(alias)) => {
                let alias_z = open_alias_z.as_deref().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "MCI string OPEN lost its preallocated alias lookup string",
                    )
                })?;
                // SAFETY: mciGetDeviceIDW reads a caller-owned device name.
                let native_id = unsafe { mciGetDeviceIDW(alias_z.as_ptr()) };
                if native_id == 0 || native_id == u32::MAX {
                    let primary = RuntimeError::new(
                        Kind::HostFailure,
                        "MCI string OPEN succeeded but mciGetDeviceID returned no alias identity",
                    );
                    if let Some(id) = notification {
                        quarantine_unbound_open_notification(context, id);
                    }
                    let cleanup = match close_string_alias(&alias, context.state.text_codec) {
                        Ok(code) => {
                            if code != 0 {
                                context.state.retain_orphan_alias(alias);
                            }
                            MciStringCloseOutcome {
                                result: Some(code),
                                failure: None,
                            }
                        }
                        Err(error) => {
                            context.state.retain_orphan_alias(alias);
                            MciStringCloseOutcome {
                                result: None,
                                failure: Some(error),
                            }
                        }
                    };
                    if cleanup.result == Some(0) && cleanup.failure.is_none() {
                        if let Some(id) = notification {
                            retire_failed_open_notification(context, id);
                        }
                        return Err(primary.with_context(
                            "MCI string OPEN alias lookup failed; native rollback close succeeded",
                        ));
                    }
                    return Err(RuntimeError::with_source(
                        classify_mci_cleanup(primary.kind(), cleanup_failure_kind(&cleanup)),
                        "MCI string OPEN succeeded but its explicit alias did not resolve to a host device identity",
                        MciStringOpenFailure { primary, cleanup },
                    ));
                }
                let device_type = query_device_type(native_id);
                match context
                    .state
                    .register_device(native_id, device_type, open_source_id)
                {
                    Ok(device) => {
                        if let Some(notification_id) = notification {
                            let binding = retirement::bind_open_notification(
                                &context,
                                notification_id,
                                native_id,
                                device,
                                open_source_id,
                            );
                            if let Err(primary) = binding {
                                quarantine_open_notification(
                                    context,
                                    notification_id,
                                    native_id,
                                    Some(device),
                                );
                                let close_result =
                                    close_native_device(native_id, context.state.sink);
                                if close_result == 0 {
                                    context.state.retire_device(device)?;
                                    retire_failed_open_notification(context, notification_id);
                                } else {
                                    context.state.retain_orphan_native_id(native_id);
                                    return Err(RuntimeError::with_source(
                                        classify_mci_cleanup(
                                            primary.kind(),
                                            Some(Kind::HostFailure),
                                        ),
                                        "MCI string OPEN notification binding failed and native rollback close also failed",
                                        MciStringRegistrationFailure {
                                            primary,
                                            cleanup: MciStringCloseOutcome {
                                                result: Some(close_result),
                                                failure: None,
                                            },
                                        },
                                    ));
                                }
                                return Err(primary.with_context(
                                    "MCI string OPEN notification binding failed; native rollback close succeeded",
                                ));
                            }
                        }
                        opened = Some((device, device_type));
                    }
                    Err(primary) => {
                        if let Some(id) = notification {
                            quarantine_open_notification(context, id, native_id, None);
                        }
                        let cleanup = match close_string_alias(&alias, context.state.text_codec) {
                            Ok(code) => {
                                if code != 0 {
                                    context.state.retain_orphan_alias(alias);
                                }
                                MciStringCloseOutcome {
                                    result: Some(code),
                                    failure: None,
                                }
                            }
                            Err(error) => {
                                context.state.retain_orphan_alias(alias);
                                MciStringCloseOutcome {
                                    result: None,
                                    failure: Some(error),
                                }
                            }
                        };
                        if cleanup.result == Some(0) && cleanup.failure.is_none() {
                            if let Some(id) = notification {
                                retire_failed_open_notification(context, id);
                            }
                            return Err(primary.with_context(
                                "MCI string OPEN identity allocation failed; native rollback close succeeded",
                            ));
                        }
                        return Err(RuntimeError::with_source(
                            classify_mci_cleanup(primary.kind(), cleanup_failure_kind(&cleanup)),
                            "MCI string OPEN succeeded but its host identity could not be retained",
                            MciStringRegistrationFailure { primary, cleanup },
                        ));
                    }
                }
            }
            MciStringAction::Close { device, .. } => {
                if code == 0 {
                    if let Some(device) = device {
                        context.state.retire_device(device)?;
                        closed = Some(device);
                    }
                }
            }
            MciStringAction::CloseAll => {
                context.state.retire_all_devices()?;
                closed_all = true;
            }
            MciStringAction::Other | MciStringAction::Open(None) => {}
        }
    }
    Ok(Win16HostMciResult {
        return_value: code,
        output: Win16HostMciOutput::StringCommand {
            bytes: output?,
            opened,
            closed,
            closed_all,
            unsupported_owner: false,
        },
    })
}

fn string_device_id(command: &[u8], codec: GuestTextCodec) -> Result<Option<u32>, RuntimeError> {
    let tokens = match parse_win16_mci_command(command)? {
        Ok(tokens) => tokens,
        Err(_) => return Ok(None),
    };
    let Some(device) = tokens.get(1) else {
        return Ok(None);
    };
    string_device_id_by_name(&device.bytes, codec)
}

fn string_device_id_by_name(
    name: &[u8],
    codec: GuestTextCodec,
) -> Result<Option<u32>, RuntimeError> {
    let owned = wide_terminated(codec, name)?;
    // SAFETY: the copied name is UTF-16 NUL-terminated and remains alive for the call.
    let native = unsafe { mciGetDeviceIDW(owned.as_ptr()) };
    Ok((native != 0 && native != u32::MAX).then_some(native))
}

fn owned_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI string token", error)
    })?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

enum MciStringAction {
    Open(Option<Vec<u8>>),
    Close {
        native: Option<u32>,
        device: Option<runtime::Win16HostMciDevice>,
    },
    CloseAll,
    Other,
}

fn analyze_string_action(
    context: &MciNativeContext,
    command: &[u8],
) -> Result<MciStringAction, RuntimeError> {
    let tokens = match parse_win16_mci_command(command)? {
        Ok(tokens) => tokens,
        Err(
            Win16MciCommandSyntaxError::NoClosingQuote
            | Win16MciCommandSyntaxError::ExtraCharacters,
        ) => {
            return Ok(MciStringAction::Other);
        }
    };
    let Some(verb) = tokens.first() else {
        return Ok(MciStringAction::Other);
    };
    if keyword(verb, b"open") {
        let mut alias = None;
        for index in 2..tokens.len() {
            if keyword(&tokens[index], b"alias") {
                let Some(name) = tokens.get(index + 1) else {
                    return Ok(MciStringAction::Open(None));
                };
                alias = Some(owned_bytes(&name.bytes)?);
                break;
            }
        }
        return Ok(MciStringAction::Open(alias));
    }
    if keyword(verb, b"close") {
        let Some(name) = tokens.get(1) else {
            return Ok(MciStringAction::Other);
        };
        if keyword(name, b"all") {
            return Ok(MciStringAction::CloseAll);
        }
        let native = string_device_id_by_name(&name.bytes, context.state.text_codec)?;
        let device = native.and_then(|native| context.state.existing_identity(native));
        return Ok(MciStringAction::Close { native, device });
    }
    Ok(MciStringAction::Other)
}

pub(super) fn close_string_alias(alias: &[u8], codec: GuestTextCodec) -> Result<u32, RuntimeError> {
    if alias.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "MCI rollback alias contains an embedded terminator",
        ));
    }
    let escaped_quotes = alias.iter().filter(|byte| **byte == b'"').count();
    let mut command = owned_bytes(b"close \"")?;
    command
        .try_reserve(alias.len().saturating_add(escaped_quotes).saturating_add(2))
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "build MCI close rollback command",
                error,
            )
        })?;
    for &byte in alias {
        command.push(byte);
        if byte == b'"' {
            // The shared parser and MCI command grammar encode a quote inside
            // a quoted token as a doubled quote pair.
            command.push(byte);
        }
    }
    command.push(b'"');
    let command = wide_terminated(codec, &command)?;
    // SAFETY: this rollback command owns a complete UTF-16 NUL-terminated string.
    Ok(unsafe { mciSendStringW(command.as_ptr(), ptr::null_mut(), 0, ptr::null_mut()) })
}

fn keyword(token: &Win16MciCommandToken, value: &[u8]) -> bool {
    !token.quoted && token.bytes.eq_ignore_ascii_case(value)
}

pub(super) fn close_native_device(native: u32, _sink: HWND) -> u32 {
    // SAFETY: mciSendCommandW receives an integer device id. A null parameter pointer carries no record; a non-null record stays live for the call.
    unsafe { mciSendCommandW(native, MCI_CLOSE, 0, 0) }
}

fn reserve_notification(
    context: &MciNativeContext,
    native: Option<u32>,
    device: Option<runtime::Win16HostMciDevice>,
    target: runtime::Win16HostWindow,
    allow_new_device: bool,
    source_id: Option<u64>,
) -> Result<runtime::Win16HostMciNotificationId, RuntimeError> {
    // The guest target is stored in the route at decode time. The owner receives
    // only that opaque window identity; HWND remains this worker's hidden sink.
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reserve(native, device, target, allow_new_device, source_id)
}

fn cancel_notification(context: &MciNativeContext, id: runtime::Win16HostMciNotificationId) {
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .cancel(id);
}

pub(super) fn quarantine_open_notification(
    context: &MciNativeContext,
    id: runtime::Win16HostMciNotificationId,
    native: u32,
    device: Option<runtime::Win16HostMciDevice>,
) {
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .quarantine_open(id, native, device);
}

pub(super) fn retire_failed_open_notification(
    context: &MciNativeContext,
    id: runtime::Win16HostMciNotificationId,
) {
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retire_failed_open_callback(id);
}

pub(super) fn quarantine_unbound_open_notification(
    context: &MciNativeContext,
    id: runtime::Win16HostMciNotificationId,
) {
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .quarantine_unbound_open(id);
}

#[path = "win16_mci_native_text.rs"]
mod text;
pub(super) use text::{
    guest_output_from_wide, guest_output_projection, wide_capacity, wide_terminated, zeroed_buffer,
    zeroed_wide_buffer,
};

#[derive(Debug)]
struct MciStringCloseOutcome {
    result: Option<u32>,
    failure: Option<RuntimeError>,
}

fn cleanup_failure_kind(cleanup: &MciStringCloseOutcome) -> Option<Kind> {
    cleanup
        .failure
        .as_ref()
        .map(RuntimeError::kind)
        .or_else(|| {
            cleanup
                .result
                .filter(|code| *code != 0)
                .map(|_| Kind::HostFailure)
        })
}

impl std::fmt::Display for MciStringCloseOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.result, &self.failure) {
            (Some(code), _) => write!(f, "rollback MCI close returned 0x{code:08X}"),
            (None, Some(error)) => write!(f, "rollback MCI close could not be issued: {error}"),
            (None, None) => f.write_str("rollback MCI close outcome is unavailable"),
        }
    }
}
impl std::error::Error for MciStringCloseOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug)]
struct MciStringOpenFailure {
    primary: RuntimeError,
    cleanup: MciStringCloseOutcome,
}
impl std::fmt::Display for MciStringOpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup: {}", self.primary, self.cleanup)
    }
}
impl std::error::Error for MciStringOpenFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

#[derive(Debug)]
struct MciStringRegistrationFailure {
    primary: RuntimeError,
    cleanup: MciStringCloseOutcome,
}
impl std::fmt::Display for MciStringRegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup: {}", self.primary, self.cleanup)
    }
}
impl std::error::Error for MciStringRegistrationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn unsupported(code: u32) -> Win16HostMciResult {
    Win16HostMciResult {
        return_value: code,
        output: Win16HostMciOutput::None,
    }
}
