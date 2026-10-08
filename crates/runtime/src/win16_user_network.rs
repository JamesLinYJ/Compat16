//! USER/WFW redirector calls with checked Win16 buffers and WN results.
//!
//! XP's WOW bridge maps Win32 MPR status codes to the WN values below and
//! reports returned string lengths in guest bytes including the NUL.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16UserNetworkBuffer, Win16UserNetworkRequest};
use win16_abi::network_print_abi::{
    WN_BAD_POINTER, WN_CANCEL, WN_MORE_DATA, WN_NET_ERROR, WN_NOT_CONNECTED,
    WN_NOT_SUPPORTED, WN_SUCCESS,
};

use super::Win16State;
use super::network_print_dispatch::is_print_request;
use crate::{
    RuntimeError, RuntimeHost, Win16HostNetworkRedirectorCall as HostCall,
    Win16HostNetworkRedirectorValue as HostValue,
};

impl Win16State {
    pub(super) fn dispatch_network_redirector(
        &mut self,
        request: Win16UserNetworkRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if is_print_request(&request) {
            let Some(status) = self.dispatch_network_print(request, memory, host)? else {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "WNet print request was not claimed by the printing dispatcher",
                ));
            };
            return Ok(status);
        }
        match request {
            Win16UserNetworkRequest::ErrorTextBadPointer => Ok(0),
            Win16UserNetworkRequest::BadPointer => Ok(WN_BAD_POINTER),
            Win16UserNetworkRequest::GetCaps { index } => host.win16_wnet_get_caps(index),
            Win16UserNetworkRequest::AddConnection {
                remote_name,
                password,
                local_name,
            } => {
                if local_name.is_none() {
                    // XP's Win16 WNet thunk rejects a NULL local-name pointer
                    // even though the native WNet API permits NULL for a
                    // connection without a redirected local device.
                    return Ok(WN_BAD_POINTER);
                }
                let result = host.win16_network_redirector(HostCall::AddConnection {
                    remote_name,
                    password,
                    local_name,
                })?;
                Ok(map_windows_error(result.status))
            }
            Win16UserNetworkRequest::CancelConnection { local_name, force } => {
                let result = host
                    .win16_network_redirector(HostCall::CancelConnection { local_name, force })?;
                Ok(map_windows_error(result.status))
            }
            Win16UserNetworkRequest::GetConnection {
                local_name,
                output,
                length_output,
            } => {
                let result =
                    host.win16_network_redirector(HostCall::GetConnection { local_name })?;
                let status = result.status;
                if status != 0 {
                    if status == 234 {
                        self.write_word(memory, length_output, u16::MAX)?;
                    }
                    return Ok(map_windows_error(status));
                }
                match result.value {
                    HostValue::Text(text) => {
                        self.write_text_result(memory, output, length_output, &text)
                    }
                    _ => Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "successful WNet connection query omitted its text result",
                    )),
                }
            }
            Win16UserNetworkRequest::GetUser {
                output,
                length_output,
            } => {
                let result = host.win16_network_redirector(HostCall::GetUser)?;
                let status = result.status;
                if status != 0 {
                    if status == 234 {
                        self.write_word(memory, length_output, u16::MAX)?;
                    }
                    return Ok(map_windows_error(status));
                }
                match result.value {
                    HostValue::Text(text) => {
                        self.write_text_result(memory, output, length_output, &text)
                    }
                    _ => Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "successful WNet user query omitted its text result",
                    )),
                }
            }
            Win16UserNetworkRequest::GetError { error_output } => {
                let result = host.win16_network_redirector(HostCall::GetLastError)?;
                if result.status != 0 {
                    return Ok(map_windows_error(result.status));
                }
                let HostValue::LastError { code, .. } = result.value else {
                    return Ok(WN_NOT_SUPPORTED);
                };
                // This payload belongs to the network provider, not WinError.
                // Preserve its WORD projection required by the Win16 ABI.
                self.write_word(memory, error_output, code as u16)?;
                Ok(WN_SUCCESS)
            }
            Win16UserNetworkRequest::ErrorText { error, output } => {
                let result = host.win16_network_redirector(HostCall::GetLastError)?;
                let Some(text) = matching_error_text(result.status, result.value, error) else {
                    self.clear_text(memory, output)?;
                    return Ok(0);
                };
                if required_text_length(&text) > usize::from(output.capacity) {
                    return Ok(0);
                }
                self.write_text(memory, output, &text)?;
                Ok(1)
            }
            Win16UserNetworkRequest::GetErrorText {
                error,
                output,
                length_output,
            } => {
                let result = host.win16_network_redirector(HostCall::GetLastError)?;
                if result.status != 0 {
                    if result.status == 234 {
                        // Native retrieval exhausted its buffer before a full
                        // provider string was available. Preserve MORE_DATA;
                        // the WORD ABI cannot report a larger exact capacity.
                        self.write_word(memory, length_output, u16::MAX)?;
                    }
                    return Ok(map_windows_error(result.status));
                }
                let Some(text) = matching_error_text(result.status, result.value, error) else {
                    self.clear_text(memory, output)?;
                    self.write_word(memory, length_output, 0)?;
                    return Ok(WN_NOT_SUPPORTED);
                };
                self.write_text_result(memory, output, length_output, &text)
            }
            // XP's USER redirector returns success without work for this call.
            Win16UserNetworkRequest::DirectoryNotify { .. } => Ok(WN_SUCCESS),
            // The corresponding XP USER entry points are void no-ops.
            Win16UserNetworkRequest::Enable | Win16UserNetworkRequest::Disable => Ok(WN_SUCCESS),
            Win16UserNetworkRequest::OpenJob { .. } => not_implemented(host, "WNetOpenJob"),
            Win16UserNetworkRequest::CloseJob { .. } => not_implemented(host, "WNetCloseJob"),
            Win16UserNetworkRequest::AbortJob { .. } => not_implemented(host, "WNetAbortJob"),
            Win16UserNetworkRequest::HoldJob { .. } => not_implemented(host, "WNetHoldJob"),
            Win16UserNetworkRequest::ReleaseJob { .. } => not_implemented(host, "WNetReleaseJob"),
            Win16UserNetworkRequest::CancelJob { .. } => not_implemented(host, "WNetCancelJob"),
            Win16UserNetworkRequest::SetJobCopies { .. } => {
                not_implemented(host, "WNetSetJobCopies")
            }
            Win16UserNetworkRequest::WatchQueue { .. } => not_implemented(host, "WNetWatchQueue"),
            Win16UserNetworkRequest::UnwatchQueue { .. } => {
                not_implemented(host, "WNetUnwatchQueue")
            }
            Win16UserNetworkRequest::LockQueueData { .. } => {
                not_implemented(host, "WNetLockQueueData")
            }
            Win16UserNetworkRequest::UnlockQueueData { .. } => {
                not_implemented(host, "WNetUnlockQueueData")
            }
            Win16UserNetworkRequest::DeviceMode { .. } => not_implemented(host, "WNetDeviceMode"),
            Win16UserNetworkRequest::BrowseDialog { .. } => {
                not_implemented(host, "WNetBrowseDialog")
            }
            Win16UserNetworkRequest::RestoreConnection { .. } => {
                not_implemented(host, "WNetRestoreConnection")
            }
            Win16UserNetworkRequest::WriteJob { .. } => not_implemented(host, "WNetWriteJob"),
            Win16UserNetworkRequest::ConnectDialog { .. } => {
                not_implemented(host, "WNetConnectDialog")
            }
            Win16UserNetworkRequest::DisconnectDialog { .. } => {
                not_implemented(host, "WNetDisconnectDialog")
            }
            Win16UserNetworkRequest::ConnectionDialog { .. } => {
                not_implemented(host, "WNetConnectionDialog")
            }
            Win16UserNetworkRequest::ViewQueueDialog { .. } => {
                not_implemented(host, "WNetViewQueueDialog")
            }
            Win16UserNetworkRequest::PropertyDialog { .. } => {
                not_implemented(host, "WNetPropertyDialog")
            }
            Win16UserNetworkRequest::GetDirectoryType { .. } => {
                not_implemented(host, "WNetGetDirectoryType")
            }
            Win16UserNetworkRequest::GetPropertyText { .. } => {
                not_implemented(host, "WNetGetPropertyText")
            }
            Win16UserNetworkRequest::Initialize => not_implemented(host, "WNetInitialize"),
        }
    }

    fn write_text_result(
        &self,
        memory: &mut Memory,
        output: Win16UserNetworkBuffer,
        length_output: u32,
        text: &[u8],
    ) -> Result<u16, RuntimeError> {
        let required = required_text_length(text);
        if required > usize::from(output.capacity) || required > usize::from(u16::MAX) {
            self.write_word(
                memory,
                length_output,
                u16::try_from(required).unwrap_or(u16::MAX),
            )?;
            return Ok(WN_MORE_DATA);
        }
        self.write_text(memory, output, text)?;
        self.write_word(memory, length_output, required as u16)?;
        Ok(WN_SUCCESS)
    }

    fn write_text(
        &self,
        memory: &mut Memory,
        output: Win16UserNetworkBuffer,
        text: &[u8],
    ) -> Result<(), RuntimeError> {
        let mut terminated = Vec::new();
        terminated
            .try_reserve_exact(text.len().saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "allocate WNet guest output string",
                    error,
                )
            })?;
        terminated.extend_from_slice(text);
        terminated.push(0);
        let pointer = self
            .selectors
            .pointer_from_far(output.far_pointer)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Write, terminated.len(), memory)
            .map_err(crate::runtime_error)?;
        self.selectors
            .write(memory, pointer, &terminated)
            .map_err(crate::runtime_error)
    }

    fn clear_text(
        &self,
        memory: &mut Memory,
        output: Win16UserNetworkBuffer,
    ) -> Result<(), RuntimeError> {
        if output.capacity > 0 {
            self.write_text(memory, output, &[])?;
        }
        Ok(())
    }

    fn write_word(
        &self,
        memory: &mut Memory,
        far_pointer: u32,
        value: u16,
    ) -> Result<(), RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far_pointer)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Write, 2, memory)
            .map_err(crate::runtime_error)?;
        self.selectors
            .write(memory, pointer, &value.to_le_bytes())
            .map_err(crate::runtime_error)
    }
}

fn not_implemented(
    host: &mut impl RuntimeHost,
    function: &'static str,
) -> Result<u16, RuntimeError> {
    host.report_diagnostic(&crate::Diagnostic::warning(
        crate::DiagnosticKind::CompatibilityGap,
        format!("{function} has a host service path, but the Win16 bridge is not wired yet"),
    ));
    Ok(WN_NOT_SUPPORTED)
}

fn matching_error_text(status: u32, value: HostValue, requested: u16) -> Option<Vec<u8>> {
    if status != 0 {
        return None;
    }
    let HostValue::LastError { code, message } = value else {
        return None;
    };
    (code as u16 == requested).then_some(message)
}

fn required_text_length(text: &[u8]) -> usize {
    text.len().checked_add(1).unwrap_or(usize::MAX)
}

/// Matches XP NTVDM's MapWin32ErrorToWN16 table; unknown values retain the
/// historical low-word projection used by that bridge.
fn map_windows_error(error: u32) -> u16 {
    match error {
        0 => WN_SUCCESS,
        50 => WN_NOT_SUPPORTED,
        1223 => WN_CANCEL, // ERROR_CANCELLED -> Win16 WN_CANCEL (NTVDM locals.h/to32.c).
        59 | 1208 => WN_NET_ERROR,
        234 => WN_MORE_DATA,
        87 => 5,
        86 => 6,
        5 => 7,
        54 => 8,
        8 => 11,
        67 | 53 => 0x32,
        15 => 0x33,
        85 => 0x34,
        31 => 0x35,
        2250 => WN_NOT_CONNECTED,
        other => other as u16,
    }
}
