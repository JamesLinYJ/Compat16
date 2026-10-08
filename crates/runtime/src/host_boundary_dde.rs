//! DDE-specific host operations for Win16 callback and operation ownership.

use crate::{DiagnosticKind, RuntimeError};

/// Native DDE source proofs remain distinct from USER and guest-frame identities.
pub trait RuntimeDdeHost {
    /// Poll one unsolicited DDE callback at a guest safe point.
    fn win16_dde_poll_callback(
        &mut self,
    ) -> Result<Option<std::sync::Arc<crate::Win16HostDdeCallbackStep>>, RuntimeError> {
        Ok(None)
    }

    fn win16_dde_callback_published(
        &mut self,
        _step: &crate::Win16HostDdeCallbackStep,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE callback publication is unavailable",
        ))
    }

    /// Resume the exact suspended native callback with the checked guest return.
    fn win16_dde_callback_reply(
        &mut self,
        _resume: crate::Win16HostDdeResume,
    ) -> Result<crate::Win16HostDdeStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE callback continuation is unavailable",
        ))
    }

    /// Read the exact pending source or its cached ACK before replaying a
    /// callback retirement. Absence alone is never a retirement proof.
    fn win16_dde_callback_retirement_is_pending(
        &mut self,
        _frame: crate::Win16HostDdeCallbackFrame,
        _parent: Option<crate::Win16HostDdeOperation>,
        _instance: crate::Win16HostDdeInstance,
        _owner: crate::Win16HostDdeOwner,
        _worker_generation: u64,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(DiagnosticKind::CompatibilityGap,
            "host Win16 DDE callback retirement readback is unavailable"))
    }

    /// Retire one native callback source after its runtime-owned resources and
    /// callback bindings have completed cleanup.
    fn win16_dde_callback_retired(
        &mut self,
        _frame: crate::Win16HostDdeCallbackFrame,
        _parent: Option<crate::Win16HostDdeOperation>,
        _instance: crate::Win16HostDdeInstance,
        _owner: crate::Win16HostDdeOwner,
        _worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE callback retirement is unavailable",
        ))
    }

    /// Retire the exact normal DDE operation source after the host has observed
    /// its actual Complete result. Implementations must match both arguments
    /// to the cached native completion, require that operation to be the exact
    /// shared USER/DDE source top with no live child callback, reserve the
    /// retirement record before popping, and retain the result on any failure.
    /// This proves only per-operation source retirement, not guest-resource or
    /// native-instance retirement.
    fn win16_dde_retire_completed_source(
        &mut self,
        _operation: crate::Win16HostDdeOperation,
        _result: &crate::Win16HostDdeResult,
    ) -> Result<crate::Win16HostDdeStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE normal-completion source retirement is unavailable",
        ))
    }

    /// Retire one canceled source only after its exact native receipt validates.
    fn win16_dde_operation_retired(
        &mut self,
        _proof: &crate::Win16DdeOperationRetirementProof,
        _receipt: &crate::Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE operation retirement is unavailable",
        ))
    }

    /// Verify an exact normal-completion tombstone; unknown identity is an error.
    fn win16_dde_source_retirement(
        &mut self,
        _proof: &crate::Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE normal source retirement is unavailable",
        ))
    }

    /// Consume the exact normal-completion tombstone after checked guest cleanup.
    fn win16_dde_source_retirement_consumed(
        &mut self,
        _proof: &crate::Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE normal source retirement consumption is unavailable",
        ))
    }

    /// Retire canceled operation sources after exact guest callback and route cleanup.
    fn win16_dde_runtime_resources_retired(
        &mut self,
        _receipt: &crate::Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 DDE guest-resource retirement is unavailable",
        ))
    }

    /// Stop DDE callback forwarding and return exact native owner evidence.
    /// Unsupported or retained owners cannot be reported as quiescent.
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt;
}
