//! WINNLS IME control, profile execution, and checked guest writeback.

use guest_core::{Registers, memory::Memory};
use win16_abi::{ImeProfile16, Win16ReturnKind, Win16WinnlsRequest, winnls_abi};

use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostImeProfile,
    Win16HostImeProfileCall as HostCall, Win16HostImeProfileResult as HostResult,
};
use crate::win16_host_window_ops::{Win16WindowCall, Win16WindowCallOutput};

impl Win16State {
    pub(super) fn begin_winnls_ime_control(
        &mut self,
        request: Win16WinnlsRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let call = match request {
            Win16WinnlsRequest::EnableIme { hwnd, enable } => Win16WindowCall::EnableIme {
                window: self.native_window(hwnd), enable,
            },
            Win16WinnlsRequest::GetEnableStatus { hwnd } => Win16WindowCall::GetImeEnableStatus {
                window: self.native_window(hwnd),
            },
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-control WINNLS request reached the resumable IME bridge")),
        };
        self.submit_call(
            registers,
            memory,
            host,
            call,
            Win16WindowCallOutput::Boolean,
            return_to,
            return_kind,
            None,
        )
    }

    pub(super) fn winnls_api(
        &mut self,
        request: Win16WinnlsRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16WinnlsRequest::EnableIme { .. } | Win16WinnlsRequest::GetEnableStatus { .. } => {
                Err(RuntimeError::new(Kind::InternalInvariant,
                    "WINNLS IME control bypassed its resumable USER operation"))
            }
            Win16WinnlsRequest::QueryIme { name, output } => {
                let Some(name) = name else {
                    return Ok(0);
                };
                let Some(output) = output else {
                    return Ok(0);
                };
                let Some(range) = capture_profile_output(self, memory, output)? else {
                    return Ok(0);
                };
                match host.win16_ime_profile(HostCall::Query { name })? {
                    HostResult::Profile(Some(profile)) => {
                        commit_profile(self, memory, range, profile)
                            .map(|written| if written { 1 } else { 0 })
                    }
                    HostResult::Profile(None) => Ok(0),
                    HostResult::Status(_) => Err(unexpected_result("IMPQueryIME")),
                }
            }
            Win16WinnlsRequest::GetIme {
                hwnd: _guest_hwnd,
                output,
            } => {
                // The target WOW adapter asks for the default profile with a
                // native NULL HWND, regardless of the guest HWND argument.
                let Some(output) = output else {
                    return Ok(0);
                };
                let Some(range) = capture_profile_output(self, memory, output)? else {
                    return Ok(0);
                };
                match host.win16_ime_profile(HostCall::Get)? {
                    HostResult::Profile(Some(profile)) => {
                        commit_profile(self, memory, range, profile)
                            .map(|written| if written { 1 } else { 0 })
                    }
                    HostResult::Profile(None) => Ok(0),
                    HostResult::Status(_) => Err(unexpected_result("IMPGetIME")),
                }
            }
            Win16WinnlsRequest::SetIme {
                hwnd: _guest_hwnd,
                name,
            } => {
                // The legacy host call also uses native NULL HWND and consumes
                // only the fixed-width profile name; it has no guest writeback.
                let Some(name) = name else {
                    return Ok(0);
                };
                match host.win16_ime_profile(HostCall::Set { name })? {
                    HostResult::Status(success) => Ok(if success { 1 } else { 0 }),
                    HostResult::Profile(_) => Err(unexpected_result("IMPSetIME")),
                }
            }
            Win16WinnlsRequest::UnsupportedProfileMutation => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "WINNLS profile modification and default-profile calls are unsupported; returned zero"));
                Ok(0)
            }
        }
    }
}

fn commit_profile(
    state: &mut Win16State,
    memory: &mut Memory,
    range: GuestOutputRange,
    profile: Win16HostImeProfile,
) -> Result<bool, RuntimeError> {
    let hwnd = match profile.window {
        Some(window) => state.map_window_handle(window, false)?,
        None => 0,
    };
    let guest = ImeProfile16 {
        hwnd,
        date: profile.date,
        version: profile.version as u16,
        description: profile.description,
        name: profile.name,
        options: profile.options,
    };
    let wire = winnls_abi::encode_ime_profile16(&guest);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(wire.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate WINNLS profile writeback",
            error,
        )
    })?;
    bytes.extend_from_slice(&wire);
    match commit_guest_writes(state, memory, vec![(range, bytes)]) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == Kind::GuestFault || error.kind() == Kind::InvalidInput => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn capture_profile_output(
    state: &Win16State,
    memory: &Memory,
    pointer: win16_abi::SegmentedPointer,
) -> Result<Option<GuestOutputRange>, RuntimeError> {
    match GuestOutputRange::capture(state, memory, pointer, winnls_abi::IMEPRO16_SIZE) {
        Ok(range) => Ok(Some(range)),
        Err(error) if error.kind() == Kind::GuestFault || error.kind() == Kind::InvalidInput => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn unexpected_result(api: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("host {api} returned a result variant that does not match its operation"),
    )
}
