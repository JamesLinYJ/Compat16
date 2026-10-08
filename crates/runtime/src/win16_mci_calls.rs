//! MCI request translation. Guest IDs and HWNDs are resolved before host calls.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16MciParameters, Win16MciRequest};

use super::{
    parameters::{callback_window, embedded_window, host_parameters, parameter_callback},
    Win16State,
};
use crate::{
    parse_win16_mci_command, Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMciCall, Win16HostMciOutput, Win16HostMciResult, Win16MciCommandSyntaxError,
    Win16MciCommandToken, Win16HostMciTarget,
};

const MCI_NOTIFY: u32 = 1;
const MCI_ALL_DEVICE_ID: u16 = 0xffff;
const MCIERR_INVALID_DEVICE_ID: u32 = 257;
const MCIERR_NO_CLOSING_QUOTE: u32 = 294;
const MCIERR_EXTRA_CHARACTERS: u32 = 305;
const MCIERR_UNSUPPORTED_FUNCTION: u32 = 274;
// The WinMM DDK defines MCI_NO_COMMAND_TABLE as UINT(-1). The Win16 export
// returns a WORD, so the unsupported table-resource result is its all-ones
// value; SDK 3.1's MMSYSTEM.H does not spell out this constant.
const MCI_NO_COMMAND_TABLE: u32 = u16::MAX as u32;
// SDK 3.1 MMSYSTEM.H defines MCIERR_NULL_PARAMETER_BLOCK as MCIERR_BASE + 41.
const MCIERR_NULL_PARAMETER_BLOCK: u32 = 297;
const MCIERR_NO_WINDOW: u32 = 346;
const MCIERR_PARAM_OVERFLOW: u32 = 268;

pub(super) enum PreparedMciCall {
    Host(Win16HostMciCall),
    Immediate(Win16HostMciResult),
}

pub(super) fn string_open_needs_owner(command: &[u8]) -> Result<bool, RuntimeError> {
    if !first_token_is_open(command) {
        return Ok(false);
    }
    let tokens = match parse_win16_mci_command(command)? {
        Ok(tokens) => tokens,
        Err(_) => return Ok(false),
    };
    Ok(open_alias(&tokens).is_some())
}

fn first_token_is_open(command: &[u8]) -> bool {
    let command = command
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&[][..], |start| &command[start..]);
    let end = command
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(command.len());
    command[..end].eq_ignore_ascii_case(b"open")
}

fn keyword(token: &Win16MciCommandToken, value: &[u8]) -> bool {
    !token.quoted && token.bytes.eq_ignore_ascii_case(value)
}

/// Identify MCI string forms whose variables are actual USER/GDI handles.
/// WinMM parses these ASCII numbers as native HWND/HDC values; the string-call
/// ABI has neither a typed host identity nor a guest-handle projection, so
/// reject them before the raw command reaches the native API.
fn string_uses_unprojected_graphic_handle(tokens: &[Win16MciCommandToken]) -> bool {
    let Some(verb) = tokens.first() else {
        return false;
    };
    if keyword(verb, b"open") {
        let mut index = 2;
        while index < tokens.len() {
            if keyword(&tokens[index], b"parent") {
                return true;
            }
            let has_value = [
                b"type".as_slice(),
                b"alias",
                b"elementname",
                b"buffer",
                b"style",
            ]
            .iter()
            .any(|value| keyword(&tokens[index], value));
            index += if has_value { 2 } else { 1 };
        }
    } else if keyword(verb, b"window") {
        let mut index = 2;
        while index < tokens.len() {
            if keyword(&tokens[index], b"handle") {
                match tokens.get(index + 1) {
                    // SDK 3.1 defines DEFAULT as the zero-handle sentinel.
                    // Every other operand is a guest HWND value; the string
                    // ABI has no checked guest-to-host identity projection.
                    Some(value) if keyword(value, b"default") => index += 2,
                    Some(_) | None => return true,
                }
                continue;
            }
            if [b"state".as_slice(), b"show", b"text", b"caption"]
                .iter()
                .any(|value| keyword(&tokens[index], value))
            {
                index += 2;
            } else {
                index += 1;
            }
        }
    } else if keyword(verb, b"update") {
        return tokens
            .iter()
            .skip(2)
            .any(|token| keyword(token, b"hdc"));
    } else if keyword(verb, b"status") {
        let mut index = 2;
        while index + 1 < tokens.len() {
            if keyword(&tokens[index], b"drive") || keyword(&tokens[index], b"track") {
                index += 2;
                continue;
            }
            if (keyword(&tokens[index], b"window")
                || keyword(&tokens[index], b"palette"))
                && keyword(&tokens[index + 1], b"handle")
            {
                return true;
            }
            index += 1;
        }
    }
    false
}

fn open_alias(tokens: &[Win16MciCommandToken]) -> Option<&[u8]> {
    if !tokens.first().is_some_and(|token| keyword(token, b"open")) {
        return None;
    }
    for index in 2..tokens.len() {
        if keyword(&tokens[index], b"alias") {
            return tokens.get(index + 1).map(|token| token.bytes.as_slice());
        }
    }
    None
}

fn close_all_requests_notify(tokens: &[Win16MciCommandToken]) -> bool {
    tokens.first().is_some_and(|token| keyword(token, b"close"))
        && tokens.get(1).is_some_and(|token| keyword(token, b"all"))
        && tokens[2..]
            .iter()
            .any(|token| keyword(token, b"notify"))
}

enum ParsedCommand {
    Valid(Vec<Win16MciCommandToken>),
    Invalid(u32),
}

fn parse_command_for_dispatch(command: &[u8]) -> Result<ParsedCommand, RuntimeError> {
    match parse_win16_mci_command(command)? {
        Ok(tokens) => Ok(ParsedCommand::Valid(tokens)),
        Err(Win16MciCommandSyntaxError::NoClosingQuote) => {
            Ok(ParsedCommand::Invalid(MCIERR_NO_CLOSING_QUOTE))
        }
        Err(Win16MciCommandSyntaxError::ExtraCharacters) => {
            Ok(ParsedCommand::Invalid(MCIERR_EXTRA_CHARACTERS))
        }
    }
}

pub(super) fn prepare(
    state: &mut Win16State,
    request: &Win16MciRequest,
    memory: &Memory,
    host: &mut impl RuntimeHost,
) -> Result<PreparedMciCall, RuntimeError> {
    let call = match request {
        Win16MciRequest::SendCommand {
            device_id,
            message,
            flags,
            parameters,
            ..
        } => {
            if flags & MCI_NOTIFY != 0 && *device_id == MCI_ALL_DEVICE_ID && *message != 0x0803 {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 MCI NOTIFY on the all-devices target has no single guest device-generation route",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            let Some(target) = command_target(state, *device_id, *message) else {
                return Ok(immediate(MCIERR_INVALID_DEVICE_ID));
            };
            let device_type = if *device_id == MCI_ALL_DEVICE_ID {
                None
            } else {
                state
                    .resolve_mci_device(*device_id)
                    .and_then(|entry| entry.device_type)
            };
            if let Win16MciParameters::Status { item, .. } = parameters
                && mci_status_returns_native_handle(device_type, *item)
            {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 MCI STATUS item returns a native HWND/HPALETTE without a checked guest-handle projection",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            if matches!(parameters, Win16MciParameters::Null)
                && !null_parameter_block_is_allowed(*message)
            {
                return Ok(immediate(MCIERR_NULL_PARAMETER_BLOCK));
            }
            if matches!(*message, 0x0844 | 0x0845) {
                let overlay_device = state
                    .resolve_mci_device(*device_id)
                    .is_some_and(|entry| entry.device_type == Some(515));
                let has_supported_layout = overlay_device
                    && match (*message, parameters) {
                        (0x0844, Win16MciParameters::Generic { .. })
                        | (0x0844, Win16MciParameters::Rectangle { .. })
                        | (0x0845, Win16MciParameters::Rectangle { .. }) => true,
                        _ => false,
                    };
                if !has_supported_layout {
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::CompatibilityGap,
                        "Win16 MCI FREEZE/UNFREEZE only projects the documented video-overlay generic/RECT layouts",
                    ));
                    return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
                }
            }
            let Some(callback) = parameter_callback(parameters) else {
                return unsupported_command(host, *message, *flags);
            };
            let notify_target = if flags & MCI_NOTIFY != 0 {
                match callback_window(state, callback) {
                    Ok(window) => Some(window),
                    Err(()) => return Ok(immediate(MCIERR_NO_WINDOW)),
                }
            } else {
                None
            };
            if embedded_window(parameters)
                .is_some_and(|window| window != 0 && state.resolve_mci_window(window).is_none())
            {
                return Ok(immediate(MCIERR_NO_WINDOW));
            }
            if let Win16MciParameters::SystemInfo { output, item, .. } = parameters
                && item & 0x0100 != 0
                && (output.far == 0 || output.capacity < 4)
            {
                return Ok(immediate(MCIERR_PARAM_OVERFLOW));
            }
            let Some(parameters) = host_parameters(state, parameters, *device_id, *flags, memory)?
            else {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    format!(
                        "Win16 MCI command 0x{message:04X} has no safe host parameter projection"
                    ),
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            };
            Win16HostMciCall::SendCommand {
                target,
                message: *message,
                flags: *flags,
                parameters,
                notify_target,
            }
        }
        Win16MciRequest::SendString {
            command,
            output,
            callback_window: guest_window,
            ..
        } => {
            let tokens = match parse_command_for_dispatch(command)? {
                ParsedCommand::Valid(tokens) => tokens,
                ParsedCommand::Invalid(code) => return Ok(immediate(code)),
            };
            if string_uses_unprojected_graphic_handle(&tokens) {
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            if close_all_requests_notify(&tokens) {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "MCI string CLOSE ALL with NOTIFY has no exact per-device notification route",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            let is_open = tokens.first().is_some_and(|token| keyword(token, b"open"));
            let alias = open_alias(&tokens);
            if is_open && alias.is_none_or(|value| value.is_empty()) {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "MCI string OPEN without an explicit alias cannot be retained by the host device ledger",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            let callback_target = if *guest_window == 0 {
                None
            } else {
                match state.resolve_mci_window(*guest_window) {
                    Some(window) => Some(window),
                    None => return Ok(immediate(MCIERR_NO_WINDOW)),
                }
            };
            Win16HostMciCall::SendString {
                command: command.clone(),
                output_capacity: (output.far != 0).then_some(output.capacity),
                callback_target,
            }
        }
        Win16MciRequest::GetDeviceId { name, .. } => {
            Win16HostMciCall::GetDeviceId { name: name.clone() }
        }
        Win16MciRequest::LoadCommandResource { .. } => {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 mciLoadCommandResource cannot safely forward a guest HINSTANCE/resource without owned resource bytes"));
            return Ok(immediate(MCI_NO_COMMAND_TABLE));
        }
        Win16MciRequest::GetErrorString { error, output } => Win16HostMciCall::GetErrorString {
            error: *error,
            capacity: (output.far != 0).then_some(output.capacity),
        },
        Win16MciRequest::SetDriverData { device_id, data } => {
            let Some(entry) = state.resolve_mci_device(*device_id) else {
                return Ok(immediate(0));
            };
            // Keep the Win16 DWORD in a generation-keyed guest sidecar. Modern
            // WinMM's native driver-data slot is pointer-sized and must never
            // receive a widened guest integer as an address.
            state.mci.driver_data.insert(entry.host, *data);
            return Ok(immediate(1));
        }
        Win16MciRequest::GetDriverData { device_id } => {
            let value = state
                .resolve_mci_device(*device_id)
                .and_then(|entry| state.mci.driver_data.get(&entry.host).copied())
                .unwrap_or(0);
            return Ok(immediate_value(0, value));
        }
        Win16MciRequest::DriverYield { device_id } => {
            let Some(entry) = state.resolve_mci_device(*device_id) else {
                return Ok(immediate(0));
            };
            Win16HostMciCall::DriverYield { device: entry.host }
        }
        Win16MciRequest::DriverNotify {
            window,
            device_id,
            status,
        } => {
            let (Some(entry), Some(target)) = (
                state.resolve_mci_device(*device_id),
                state.resolve_mci_window(*window),
            ) else {
                return Ok(immediate(0));
            };
            Win16HostMciCall::DriverNotify {
                device: entry.host,
                target,
                status: *status,
            }
        }
        Win16MciRequest::Execute { command, .. } => {
            let tokens = match parse_command_for_dispatch(command)? {
                ParsedCommand::Valid(tokens) => tokens,
                ParsedCommand::Invalid(code) => return Ok(immediate(code)),
            };
            if string_uses_unprojected_graphic_handle(&tokens) {
                // SDK 3.1 declares mciExecute as BOOL: FALSE is its documented
                // failure result. A nonzero internal MCI completion status is
                // consumed below and projected to guest BOOL FALSE.
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            if close_all_requests_notify(&tokens) {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "MCI EXECUTE CLOSE ALL with NOTIFY has no exact per-device notification route",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            let is_open = tokens.first().is_some_and(|token| keyword(token, b"open"));
            if is_open && open_alias(&tokens).is_none_or(|value| value.is_empty()) {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "MCI EXECUTE OPEN without an explicit alias cannot be retained by the host device ledger",
                ));
                return Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION));
            }
            Win16HostMciCall::SendString {
                command: command.clone(),
                output_capacity: None,
                callback_target: None,
            }
        }
        Win16MciRequest::FreeCommandResource { .. } => {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 mciFreeCommandResource has no host-owned command table to release",
            ));
            return Ok(immediate(0));
        }
        Win16MciRequest::SetYieldProc {
            device_id,
            procedure,
            procedure_pointer,
            data,
        } => {
            let Some(entry) = state.resolve_mci_device(*device_id) else {
                return Ok(immediate(0));
            };
            if *procedure != 0 {
                let pointer = procedure_pointer.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "non-null guest MCI yield procedure has no captured selector identity",
                    )
                })?;
                if state
                    .selectors
                    .pointer_from_far(*procedure)
                    .map_err(crate::runtime_error)?
                    != pointer
                {
                    return Err(RuntimeError::new(
                        Kind::GuestFault,
                        "guest MCI yield procedure selector changed after decode",
                    ));
                }
                state.mci.yield_procedures.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve guest MCI yield-procedure owner before native registration",
                        error,
                    )
                })?;
                state
                    .selectors
                    .translate(pointer, Access::Execute, 1, memory)
                    .map_err(crate::runtime_error)?;
            } else if procedure_pointer.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "null guest MCI yield procedure carries a selector identity",
                ));
            }
            Win16HostMciCall::SetYieldProc {
                device: entry.host,
                enabled: *procedure != 0,
                data: *data,
            }
        }
        Win16MciRequest::GetDeviceIdFromElement {
            element_id,
            device_type,
            ..
        } => Win16HostMciCall::GetDeviceIdFromElement {
            element_id: *element_id,
            device_type: device_type.clone(),
        },
        Win16MciRequest::GetYieldProc { device_id, .. } => {
            let Some(entry) = state.resolve_mci_device(*device_id) else {
                return Ok(immediate_output(
                    0,
                    Win16HostMciOutput::YieldProc {
                        installed: false,
                        data: 0,
                        registration: None,
                    },
                ));
            };
            Win16HostMciCall::GetYieldProc { device: entry.host }
        }
        Win16MciRequest::GetCreatorTask { device_id } => {
            let task = state
                .resolve_mci_device(*device_id)
                .map_or(0, |entry| entry.creator_task);
            return Ok(immediate_value(0, u32::from(task)));
        }
    };
    Ok(PreparedMciCall::Host(call))
}

fn command_target(state: &Win16State, guest: u16, message: u16) -> Option<Win16HostMciTarget> {
    if message == 0x0803 {
        return Some(Win16HostMciTarget::All);
    }
    if guest == MCI_ALL_DEVICE_ID {
        return Some(Win16HostMciTarget::All);
    }
    state
        .resolve_mci_device(guest)
        .map(|entry| Win16HostMciTarget::Device(entry.host))
}

fn mci_status_returns_native_handle(device_type: Option<u32>, item: u32) -> bool {
    // SDK 3.1 MMSYSTEM.H defines ANIM_STATUS_HWND/HPAL and OVLY_STATUS_HWND.
    // These fields are host handles; copying their DWORD bits to a guest WORD
    // would alias unrelated USER/GDI identities.
    match device_type {
        Some(515) => item == 0x4001,
        Some(519) => matches!(item, 0x4003 | 0x4004),
        // These are modern host Digital Video status items, not a claim that
        // Windows 3.1 declared that device-specific Win16 extension. They must
        // remain unsupported until a guest handle identity can be projected.
        Some(520) => matches!(item, 0x4001 | 0x4004),
        Some(_) => false,
        None => matches!(item, 0x4001 | 0x4003 | 0x4004),
    }
}

fn unsupported_command(
    host: &mut impl RuntimeHost,
    message: u16,
    flags: u32,
) -> Result<PreparedMciCall, RuntimeError> {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        format!("Win16 MCI command 0x{message:04X} flags 0x{flags:08X} has no known SDK 3.1 parameter layout")));
    // Without a known parameter-block contract this bridge cannot safely
    // dispatch to the driver, so report the documented unsupported-function
    // result rather than guessing a native MCI command structure.
    Ok(immediate(MCIERR_UNSUPPORTED_FUNCTION))
}

fn null_parameter_block_is_allowed(message: u16) -> bool {
    matches!(message, 0x0804 | 0x0808 | 0x0809 | 0x080c | 0x0830 | 0x0855)
}

fn immediate(code: u32) -> PreparedMciCall {
    immediate_value(code, 0)
}

fn immediate_value(code: u32, value: u32) -> PreparedMciCall {
    PreparedMciCall::Immediate(Win16HostMciResult {
        return_value: code,
        output: Win16HostMciOutput::Scalar(value),
    })
}

fn immediate_output(code: u32, output: Win16HostMciOutput) -> PreparedMciCall {
    PreparedMciCall::Immediate(Win16HostMciResult {
        return_value: code,
        output,
    })
}
