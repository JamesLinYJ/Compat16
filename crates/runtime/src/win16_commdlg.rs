//! Runtime-side validation and result commit for Win16 common dialogs.

use guest_core::{memory::Memory, Registers};
use win16_abi::{Win16CommdlgRequest, Win16ReturnKind};

use super::{windows::WindowReturn, Win16State};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16WindowOperation};

#[path = "win16_commdlg_support.rs"]
mod support;
use super::guest_ranges as ranges;
#[path = "win16_commdlg_find_replace.rs"]
mod find_replace;
#[path = "win16_commdlg_prepare.rs"]
mod prepare;
#[path = "win16_commdlg_finish.rs"]
mod finish;
#[cfg(test)]
#[path = "win16_commdlg_hook_tests.rs"]
mod hook_tests;

pub(in crate::win16_runtime) use find_replace::Win16CommonDialogState;
use ranges::GuestOutputRange;
use support::GuestGlobalCapture;

pub(in crate::win16_runtime) struct Win16CommonDialogCall {
    pub operation: crate::Win16HostCommonDialogOperation,
    pub continuation: Win16CommonDialogContinuation,
}

pub(in crate::win16_runtime) enum Win16CommonDialogPreparation {
    Immediate(u32),
    WindowService(Win16CommonDialogCall),
}

#[derive(Clone)]
pub(in crate::win16_runtime) struct Win16CommonDialogContinuation {
    pub(super) return_kind: Win16ReturnKind,
    pub(super) guest_failure_value: u32,
    pub(super) output: Win16CommonDialogOutput,
}

#[derive(Clone)]
pub(in crate::win16_runtime) enum Win16CommonDialogOutput {
    File {
        structure: GuestOutputRange,
        file: GuestOutputRange,
        file_far: u32,
        file_capacity: usize,
        file_title: Option<GuestOutputRange>,
        file_title_far: u32,
        file_title_capacity: u32,
        custom_filter: Option<GuestOutputRange>,
        custom_filter_far: u32,
        custom_filter_capacity: u32,
    },
    Color {
        structure: GuestOutputRange,
        custom_colors: GuestOutputRange,
        custom_colors_far: u32,
    },
    FindReplace { request_id: u64 },
    Font {
        structure: GuestOutputRange,
        log_font: GuestOutputRange,
        log_font_far: u32,
        style: Option<GuestOutputRange>,
        style_far: u32,
    },
    Print {
        structure: GuestOutputRange,
        input_dev_mode: u16,
        dev_mode_capture: Option<GuestGlobalCapture>,
        input_dev_names: u16,
        dev_names_capture: Option<GuestGlobalCapture>,
    },
    FileTitle { output: Option<GuestOutputRange> },
}

impl Win16CommonDialogContinuation {
    pub(super) fn terminal_find_replace_request_id(&self) -> Option<u64> {
        match &self.output {
            Win16CommonDialogOutput::FindReplace { request_id } => Some(*request_id),
            _ => None,
        }
    }

    fn find_replace_request_id(&self) -> Option<u64> {
        self.terminal_find_replace_request_id()
    }
}

impl Win16State {
    pub(in crate::win16_runtime) fn begin_common_dialog_request(
        &mut self,
        request: Win16CommdlgRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        if matches!(request, Win16CommdlgRequest::ExtendedError) {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, self.common_dialog_state.last_extended_error, return_kind);
        }

        let guest_failure_value = if matches!(&request,
            Win16CommdlgRequest::GetFileTitle { .. })
        { u16::MAX as u32 } else { 0 };
        self.common_dialog_state.last_extended_error = 0;
        let prepared = match self.prepare_common_dialog(memory, request, return_kind, host) {
            Ok(prepared) => prepared,
            Err(error) if is_guest_api_failure(&error) => {
                return self.complete_return(registers, return_to.0, return_to.1,
                    return_to.2, guest_failure_value, return_kind);
            }
            Err(error) => return Err(error),
        };
        match prepared {
            Win16CommonDialogPreparation::Immediate(value) => self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, value, return_kind,
            ),
            Win16CommonDialogPreparation::WindowService(call) => {
                let request_id = call.continuation.find_replace_request_id();
                let started = self.begin_window_operation(registers, memory, host,
                    Win16WindowOperation::CommonDialog(call.operation),
                    WindowReturn::CommonDialog(call.continuation), return_to);
                match (started, request_id) {
                    (Err(primary), Some(request_id)) => match self.cancel_find_replace(request_id) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(RuntimeError::with_source(Kind::InternalInvariant,
                            format!("{primary}; Find/Replace setup cleanup failed"), cleanup)),
                    },
                    (result, _) => result,
                }
            }
        }
    }

    pub(in crate::win16_runtime) fn finish_common_dialog(
        &mut self,
        continuation: Win16CommonDialogContinuation,
        result: crate::Win16HostCommonDialogResult,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        finish::finish_common_dialog(self, continuation, result, memory, host)
    }
}

pub(super) fn report_common_dialog_gap(host: &mut impl RuntimeHost, message: &str) {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message));
}

pub(in crate::win16_runtime) fn is_guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

pub(super) fn finish_guest_failure(
    error: RuntimeError,
    guest_failure_value: u32,
) -> Result<u32, RuntimeError> {
    if is_guest_api_failure(&error) { Ok(guest_failure_value) } else { Err(error) }
}
