//! Portable host defaults for owned Win16 NetBIOS requests.

use crate::{DiagnosticKind, RuntimeError};

/// Host services used by the Win16 NetBIOS adapter.
///
/// Keeping this family in its own trait groups its exact provider operations.
pub trait RuntimeNetbiosHost {
    /// Execute a decoded synchronous NCB with owned buffers.
    /// Guest FAR values and callback identities never cross this boundary.
    fn win16_netbios_call(
        &mut self,
        _call: crate::Win16HostNetbiosCall,
    ) -> Result<crate::Win16HostNetbiosResult, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host synchronous NetBIOS service is unavailable",
        ))
    }

    /// Submit an asynchronous NCB. A host without a provider returns an
    /// immediate NRC_NODRIVER result and claims no retained source.
    fn win16_netbios_submit(
        &mut self,
        call: crate::Win16HostNetbiosCall,
    ) -> Result<crate::Win16HostNetbiosSubmission, RuntimeError> {
        let result = result_without_provider(&call);
        Ok(crate::Win16HostNetbiosSubmission {
            id: crate::Win16HostNetbiosId(0),
            initial: result.clone(),
            completion: Some(result),
            inline_terminal: false,
        })
    }

    /// Observe a terminal snapshot without releasing its exact host owner.
    fn win16_netbios_completion(
        &mut self,
        _id: crate::Win16HostNetbiosId,
    ) -> Result<Option<crate::Win16HostNetbiosResult>, RuntimeError> {
        Ok(None)
    }

    /// Request cancellation against the exact retained native NCB.
    fn win16_netbios_cancel(
        &mut self,
        _id: crate::Win16HostNetbiosId,
    ) -> Result<crate::Win16HostNetbiosResult, RuntimeError> {
        Ok(crate::Win16HostNetbiosResult::status(0x26))
    }

    /// Release a completed source after guest projection and any verified
    /// continuation cleanup. `false` keeps the exact owner live for retry.
    fn win16_netbios_ack(
        &mut self,
        id: crate::Win16HostNetbiosId,
    ) -> Result<bool, RuntimeError> {
        Ok(id.0 == 0)
    }

    /// Hand one exact source to native teardown after terminal USER wake loss
    /// or explicit task teardown. Providers retain the source by default.
    fn win16_netbios_teardown(
        &mut self,
        id: crate::Win16HostNetbiosId,
        reason: crate::Win16HostNetbiosTeardownReason,
    ) -> Result<crate::Win16HostNetbiosTeardownReceipt, RuntimeError> {
        if id.0 == 0 {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "zero Win16 NetBIOS identity cannot name a teardown source",
            ));
        }
        Ok(crate::Win16HostNetbiosTeardownReceipt {
            id,
            reason,
            phase: crate::Win16HostNetbiosTeardownPhase::NativePending,
            completion_publication: crate::Win16HostNetbiosCompletionPublication::None,
            native_terminal: false,
            event_closed: false,
            worker_joined: false,
            cause: None,
            cleanup_error: None,
            failure_diagnostics: crate::Win16HostNetbiosFailureDiagnostics::default(),
        })
    }

    /// Acknowledge the exact cached native-retirement receipt after the Runtime
    /// has completed logical source cleanup. This is distinct from guest ACK.
    fn win16_netbios_teardown_ack(
        &mut self,
        _receipt: &crate::Win16HostNetbiosTeardownReceipt,
    ) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    /// Read the shared USER/modal lane's terminal state before choosing the
    /// typed reason for a NetBIOS cleanup handoff.
    fn win16_netbios_terminal_wake_unavailable(&self) -> Result<bool, RuntimeError> {
        Err(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "host cannot verify whether the shared Win16 USER wake lane is terminal",
        ))
    }
}

fn result_without_provider(
    call: &crate::Win16HostNetbiosCall,
) -> crate::Win16HostNetbiosResult {
    let mut result = crate::Win16HostNetbiosResult::status(0xfb);
    result.lsn = call.lsn;
    result.num = call.num;
    result.length = call.length;
    result
}
