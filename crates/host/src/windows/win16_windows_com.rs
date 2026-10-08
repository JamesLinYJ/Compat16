//! Runtime-facing COM commands backed by the existing USER worker.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ComHostContinue,
    Win16ComHostOperationIdentity, Win16ComHostOwnerIdentity, Win16ComHostShutdownOperation,
    Win16ComHostShutdownStep, Win16ComHostStart, Win16ComHostStep,
};

use crate::filesystem::Filesystem;
use super::Win16Windows;

impl Win16Windows {
    pub(in crate::windows) fn com_owner(&self) -> Result<Win16ComHostOwnerIdentity, RuntimeError> {
        self.worker()?.com_owner()
    }

    pub(in crate::windows) fn shutdown_com(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostShutdownOperation,
    ) -> Result<Win16ComHostShutdownStep, RuntimeError> {
        self.worker()?.shutdown_com(owner, operation)
    }

    pub(in crate::windows) fn begin_com(
        &self,
        filesystem: &mut Filesystem,
        owner: Win16ComHostOwnerIdentity,
        start: Win16ComHostStart,
    ) -> Result<Win16ComHostStep, RuntimeError> {
        let worker = self.worker()?;
        if owner != worker.com_owner()? {
            return Err(RuntimeError::new(Kind::InvalidInput, "COM start names a retired USER STA owner"));
        }
        // Resolve and confine paths in the capability filesystem owner before
        // sending the host-private prepared request to the native STA.
        let prepared = super::super::win16_com_request_executor::prepare_start(filesystem, start)?;
        worker.begin_com(owner, prepared)
    }

    pub(in crate::windows) fn poll_com_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        self.worker()?.poll_com_callback(owner)
    }

    pub(in crate::windows) fn continue_com_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
        continuation: Win16ComHostContinue,
    ) -> Result<Win16ComHostStep, RuntimeError> {
        self.worker()?.continue_com_callback(owner, continuation)
    }

    pub(in crate::windows) fn poll_com_terminal(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        self.worker()?.poll_com_terminal(owner, operation)
    }

    pub(in crate::windows) fn acknowledge_com_terminal(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        self.worker()?.acknowledge_com_terminal(owner, operation)
    }
}
