//! MCI-specific host operations kept at their own host-boundary seam.

use crate::{DiagnosticKind, RuntimeError};

pub trait RuntimeMciHost {
    /// Begin an owned MCI call. A Yield result identifies the exact operation
    /// and callback frame; the host retains both until `win16_mci_resume`.
    fn win16_mci_call(
        &mut self,
        _call: crate::Win16HostMciCall,
    ) -> Result<crate::Win16HostMciStep, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI services are unavailable",
        ))
    }

    /// Reconcile the original result of a Begin command which the host
    /// confirms was enqueued. `None` means that exact command still has no
    /// available result; it never means that the operation id was unknown.
    fn win16_mci_reconcile_begin(
        &mut self,
        _operation: crate::Win16HostMciOperationId,
    ) -> Result<Option<crate::Win16HostMciStep>, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI Begin-result reconciliation is unavailable",
        ))
    }

    /// Resume one suspended MCI yield frame with the checked guest return.
    fn win16_mci_resume(
        &mut self,
        _resume: crate::Win16HostMciResume,
    ) -> Result<crate::Win16HostMciResumeReceipt, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI continuation is unavailable",
        ))
    }

    /// Peek without consuming. The runtime ACKs the exact MCI source only
    /// after USER's separate normal-retirement proof was consumed, or after
    /// the exact USER terminal failure ACK completed.
    fn win16_mci_peek_notification(
        &mut self,
    ) -> Result<Option<crate::Win16HostMciNotification>, RuntimeError> {
        Ok(None)
    }

    fn win16_mci_ack_notification(
        &mut self,
        _source: crate::Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI notification ACK is unavailable",
        ))
    }

    /// Stop admission of new MCI notification routes and disable every exact
    /// installed YIELDPROC source while preserving devices, active calls, and
    /// already accepted routes/events for the later source-retirement phase.
    fn win16_mci_quiesce_producers(
        &mut self,
        _request: crate::Win16HostMciProducerQuiescenceRequest,
    ) -> Result<crate::Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI producer-quiescence receipts are unavailable",
        ))
    }

    /// Disable native yield sources and retire task-owned devices while
    /// returning exact phase evidence for both completed and retained owners.
    fn win16_mci_quiesce_owned(
        &mut self,
        request: crate::Win16HostMciQuiesceRequest,
    ) -> Result<crate::Win16HostMciQuiescenceReceipt, RuntimeError> {
        if request.devices.is_empty()
            && request.registrations.is_empty()
            && request.pending_begins.is_empty()
            && request.active_yields.is_empty()
            && request.returned_yields.is_empty()
            && request.completed_operations.is_empty()
        {
            let mut resolved_causes = Vec::new();
            resolved_causes
                .try_reserve_exact(request.resolved_causes.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::ResourceExhausted,
                        "retain prior MCI causes for an empty quiescence request",
                        error,
                    )
                })?;
            resolved_causes.extend(request.resolved_causes.iter().cloned());
            return Ok(crate::Win16HostMciQuiescenceReceipt {
                resolved_causes,
                request,
                status: crate::Win16HostMciQuiescenceStatus::NotStarted,
                confirmed: Vec::new(),
                retained: Vec::new(),
                causes: Vec::new(),
            });
        }
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host Win16 MCI quiescence receipts are unavailable for a nonempty owner request",
        ))
    }
}
