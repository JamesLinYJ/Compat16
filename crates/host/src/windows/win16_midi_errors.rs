//! Preserve typed primary and cleanup failures for MIDI ownership paths.

use runtime::RuntimeError;

pub(super) fn host_result(operation: &'static str, result: u32) -> RuntimeError {
    RuntimeError::new(runtime::DiagnosticKind::HostFailure,
        format!("{operation} returned WinMM result {result}"))
}
