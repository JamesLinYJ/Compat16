//! Winsock startup-reference release and native socket retirement ownership.

use compat_services::win16_network::{WSAENOBUFS, WSANOTINITIALISED};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostNetworkCall, Win16HostNetworkValue, Win16HostNetworkReferenceRelease,
    Win16HostSocketRetirementFailure, Win16NetworkTaskIdentity,
};
use super::{SOCKET_ERROR_WORD, Win16State};
use crate::win16_network::Win16NetworkSocketRetirementPhase;

impl Win16State {
    pub(super) fn winsock_cleanup(
        &mut self,
        task: u16,
        task_identity: Win16NetworkTaskIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if self.network.startup_references_for_task(task_identity) == 0 {
            return Ok(self.fail_int(task, WSANOTINITIALISED));
        }
        let task_final = self.network.startup_references_for_task(task_identity) == 1;
        if task_final {
            if self.network.reserve_task_socket_retirements(task_identity).is_err() {
                return Ok(self.fail_int(task, WSAENOBUFS));
            }
            if self.network.reserve_orphan_sockets(
                self.network.socket_count_for_task(task_identity),
            ).is_err()
            {
                return Ok(self.fail_int(task, WSAENOBUFS));
            }
        }
        if self.network.startup_references() == 1
            && self.network.reserve_retired_async_selects(
                self.network.async_select_route_count(),
            ).is_err()
        {
            return Ok(self.fail_int(task, WSAENOBUFS));
        }
        let result = host.win16_network(Win16HostNetworkCall::Cleanup {
            task: task_identity, task_final,
        })?;
        if result.wsa_error != 0 {
            return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD));
        }
        let (reference_release, failures) = Self::cleanup_retirement_errors(result.value)?;
        if reference_release.owner != task_identity {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock Cleanup released a startup reference for a different task incarnation"));
        }
        // The provider has already irreversibly released this exact reference.
        // Account for it before processing the independent socket-close phase.
        if !self.network.note_cleanup(task_identity) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock startup reference disappeared after native Cleanup succeeded"));
        }
        let retention = self.retain_cleanup_failures(task_identity, &failures);
        Self::report_retirement_errors(host, &failures);
        if reference_release.task_final != task_final {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock Cleanup released a different task-reference phase than Runtime reserved"));
        }
        if task_final && retention.is_ok() {
            self.network.retire_task_sockets(task_identity)?;
            self.free_result_blocks_for_task(task)?;
        }
        if self.network.startup_references() == 0 && retention.is_ok() {
            self.network.clear_sockets()?;
        }
        retention?;
        // WSACleanup succeeded. Socket retirement errors are retained and
        // diagnosed separately; they are not a guest WSACleanup failure.
        Ok(0)
    }

    pub(super) fn cleanup_retirement_errors(
        value: Win16HostNetworkValue,
    ) -> Result<(Win16HostNetworkReferenceRelease, Vec<Win16HostSocketRetirementFailure>), RuntimeError> {
        match value {
            Win16HostNetworkValue::Cleanup { reference_release, socket_retire_failures } =>
                Ok((reference_release, socket_retire_failures)),
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock Cleanup returned an unexpected host result")),
        }
    }

    pub(super) fn retain_cleanup_failures(
        &mut self,
        task: Win16NetworkTaskIdentity,
        failures: &[Win16HostSocketRetirementFailure],
    ) -> Result<(), RuntimeError> {
        let mut mismatch = None;
        for (index, failure) in failures.iter().enumerate() {
            if failure.wsa_error == 0
                || failure.owner != task
                || failure.phase != crate::Win16HostSocketRetirementPhase::GuestCleanupReferenceReleased
                || !(self.network.socket_is_owned_by_task(failure.socket, task)
                    || self.network.orphan_socket_is_owned_by_task(failure.socket, task))
                || failures[..index].iter().any(|previous| previous.socket == failure.socket)
            {
                mismatch.get_or_insert_with(|| RuntimeError::new(Kind::InternalInvariant,
                    "WinSock Cleanup returned an invalid or duplicate socket owner"));
            }
            if !self.network.retain_orphan_socket(
                failure.socket, task, Win16NetworkSocketRetirementPhase::GuestCleanupReferenceReleased,
                std::sync::Arc::clone(&failure.first_cause),
            ) {
                mismatch.get_or_insert_with(|| RuntimeError::new(Kind::InternalInvariant,
                    "WinSock Cleanup changed the task identity of a retained socket owner"));
            }
        }
        if let Some(error) = mismatch { Err(error) } else { Ok(()) }
    }

    pub(super) fn report_retirement_errors(
        host: &mut impl RuntimeHost,
        failures: &[Win16HostSocketRetirementFailure],
    ) {
        if let Some(first) = failures.first() {
            host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure, format!(
                "WinSock task cleanup retained {} native socket retirement failures; first token {} failed with WSA error {}",
                failures.len(), first.socket.0, first.wsa_error)));
        }
    }
}
