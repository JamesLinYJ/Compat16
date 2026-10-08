//! Typed COM client operations on the existing Win16 USER worker.

use std::sync::mpsc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ComHostContinue,
    Win16ComHostOperationIdentity, Win16ComHostOwnerIdentity,
    Win16ComHostShutdownOperation, Win16ComHostShutdownStep, Win16ComHostStep,
};

use super::super::super::win16_com_request_executor::PreparedWin16ComStart;
use super::{WorkerCommand, WindowWorker};

impl WindowWorker {
    pub(in crate::windows) fn com_owner(&self) -> Result<Win16ComHostOwnerIdentity, RuntimeError> {
        if self.com_client.owner_sealed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 COM owner is permanently sealed for teardown",
            ));
        }
        Ok(self.com_client.owner)
    }

    pub(in crate::windows) fn shutdown_com(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostShutdownOperation,
    ) -> Result<Win16ComHostShutdownStep, RuntimeError> {
        if owner != self.com_client.owner || !owner.is_valid() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM owner shutdown names another USER STA incarnation",
            ));
        }
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::ComShutdown { owner, operation, response })
            .map_err(|_| RuntimeError::new(
                Kind::HostFailure,
                "enqueue exact COM owner shutdown on the Win16 USER STA",
            ))?;
        receive.recv().map_err(|error| RuntimeError::with_source(
            Kind::HostFailure,
            "receive exact COM owner shutdown from the Win16 USER STA",
            error,
        ))?
    }

    pub(in crate::windows) fn begin_com(
        &self,
        owner: Win16ComHostOwnerIdentity,
        start: PreparedWin16ComStart,
    ) -> Result<Win16ComHostStep, RuntimeError> {
        if owner != self.com_client.owner
            || !owner.is_valid()
            || !start.operation.is_valid()
            || self.com_client.owner_sealed.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(RuntimeError::new(Kind::InvalidInput, "COM start names another owner or an invalid operation"));
        }
        let operation = start.operation;
        let (accepted, receive) = mpsc::channel();
        self.send(WorkerCommand::ComBegin { owner, start, accepted })
            .map_err(|_| RuntimeError::new(Kind::HostFailure, "enqueue a typed COM operation on the Win16 USER STA"))?;
        receive.recv().map_err(|error| RuntimeError::with_source(
            Kind::HostFailure, "receive COM operation acceptance from the Win16 USER STA", error,
        ))??;
        // This is an acceptance acknowledgement; terminal completion is polled separately.
        Ok(Win16ComHostStep::Running(operation))
    }

    pub(in crate::windows) fn poll_com_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        self.com_client.poll_callback(owner)
    }

    pub(in crate::windows) fn continue_com_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
        continuation: Win16ComHostContinue,
    ) -> Result<Win16ComHostStep, RuntimeError> {
        self.com_client.continue_callback(owner, continuation)
    }

    pub(in crate::windows) fn poll_com_terminal(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        self.com_client.poll_terminal(owner, operation)
    }

    pub(in crate::windows) fn acknowledge_com_terminal(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        if owner != self.com_client.owner {
            return Err(RuntimeError::new(Kind::InvalidInput, "COM terminal acknowledgement names another owner"));
        }
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::ComAcknowledgeTerminal { owner, operation, response })
            .map_err(|_| RuntimeError::new(Kind::HostFailure, "enqueue COM terminal ownership acknowledgement"))?;
        receive.recv().map_err(|error| RuntimeError::with_source(
            Kind::HostFailure, "receive COM terminal ownership acknowledgement", error,
        ))?
    }
}
