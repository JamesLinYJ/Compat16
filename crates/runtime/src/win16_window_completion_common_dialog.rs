//! Replay-safe owner for Win16 common-dialog result projection.

use std::sync::Arc;

use win16_abi::Win16ReturnKind;

use super::super::Win16State;
use crate::{RuntimeError, RuntimeHost, Win16HostCommonDialogResult};

#[derive(Debug)]
enum ProjectionState {
    Ready,
    Attempted,
    Failed(Arc<RuntimeError>),
    Complete { value: u32, return_kind: Win16ReturnKind },
}

/// Lives on the exact WindowOperationCompletion that owns the native result.
/// A failed one-shot legacy projection is retained so a retry cannot repeat
/// partial global-memory, HDC, or modeless-session side effects.
#[derive(Debug)]
pub(in crate::win16_runtime) struct CommonDialogProjection {
    state: ProjectionState,
}

impl CommonDialogProjection {
    pub(in crate::win16_runtime) fn new() -> Self {
        Self { state: ProjectionState::Ready }
    }
}

pub(in crate::win16_runtime) fn finish_common_dialog_projection(
    runtime: &mut Win16State,
    continuation: &super::super::commdlg::Win16CommonDialogContinuation,
    result: &Win16HostCommonDialogResult,
    projection: &mut CommonDialogProjection,
    memory: &mut guest_core::memory::Memory,
    host: &mut impl RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    match &projection.state {
        ProjectionState::Complete { value, return_kind } => return Ok((*value, *return_kind)),
        ProjectionState::Failed(cause) => {
            return Err(super::super::callback_lifo::shared_runtime_error(Arc::clone(cause)));
        }
        ProjectionState::Attempted => return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "common-dialog projection was re-entered while its first attempt remained unresolved",
        )),
        ProjectionState::Ready => {}
    }

    // The existing full completion routine owns all ABI-specific validation,
    // exact selector-generation checks, transactional guest writes, HGLOBAL
    // updates, HDC allocation, and Find/Replace publication/cancellation.
    // Mark the attempt before invoking it: if any later step fails after an
    // earlier side effect, retaining the error prevents those effects from
    // being performed twice on a retry.
    projection.state = ProjectionState::Attempted;
    match runtime.finish_common_dialog(continuation.clone(), result.clone(), memory, host) {
        Ok((value, return_kind)) => {
            projection.state = ProjectionState::Complete { value, return_kind };
            Ok((value, return_kind))
        }
        Err(error) => {
            let cause = Arc::new(error);
            projection.state = ProjectionState::Failed(Arc::clone(&cause));
            Err(super::super::callback_lifo::shared_runtime_error(cause))
        }
    }
}
