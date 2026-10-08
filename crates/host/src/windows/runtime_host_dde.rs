//! WindowsHost implementation of the DDE-specific runtime host contract.

use super::*;

impl runtime::RuntimeDdeHost for WindowsHost {
    fn win16_dde_poll_callback(
        &mut self,
    ) -> Result<Option<std::sync::Arc<runtime::Win16HostDdeCallbackStep>>, RuntimeError> {
        runtime_host_windows::win16_dde_poll_callback(self)
    }

    fn win16_dde_callback_published(
        &mut self,
        step: &runtime::Win16HostDdeCallbackStep,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_dde_callback_published(self, step)
    }

    fn win16_dde_callback_reply(
        &mut self,
        resume: runtime::Win16HostDdeResume,
    ) -> Result<runtime::Win16HostDdeStep, RuntimeError> {
        runtime_host_windows::win16_dde_callback_reply(self, resume)
    }

    fn win16_dde_callback_retirement_is_pending(
        &mut self,
        frame: runtime::Win16HostDdeCallbackFrame,
        parent: Option<runtime::Win16HostDdeOperation>,
        instance: runtime::Win16HostDdeInstance,
        owner: runtime::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_dde_callback_retirement_is_pending(
            self, frame, parent, instance, owner, worker_generation,
        )
    }

    fn win16_dde_callback_retired(
        &mut self,
        frame: runtime::Win16HostDdeCallbackFrame,
        parent: Option<runtime::Win16HostDdeOperation>,
        instance: runtime::Win16HostDdeInstance,
        owner: runtime::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_dde_callback_retired(
            self,
            frame,
            parent,
            instance,
            owner,
            worker_generation,
        )
    }

    fn win16_dde_retire_completed_source(
        &mut self,
        operation: runtime::Win16HostDdeOperation,
        result: &runtime::Win16HostDdeResult,
    ) -> Result<runtime::Win16HostDdeStep, RuntimeError> {
        runtime_host_windows::win16_dde_retire_completed_source(self, operation, result)
    }

    fn win16_dde_operation_retired(
        &mut self,
        proof: &runtime::Win16DdeOperationRetirementProof,
        receipt: &runtime::Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_dde_operation_retired(self, proof, receipt)
    }

    fn win16_dde_source_retirement(
        &mut self,
        proof: &runtime::Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        runtime_host_windows::win16_dde_source_retirement(self, proof)
    }

    fn win16_dde_source_retirement_consumed(
        &mut self,
        proof: &runtime::Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_dde_source_retirement_consumed(self, proof)
    }

    fn win16_dde_runtime_resources_retired(
        &mut self,
        receipt: &runtime::Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        runtime_host_windows::win16_dde_runtime_resources_retired(self, receipt)
    }

    fn win16_dde_abort(&mut self) -> runtime::Win16DdeAbortReceipt {
        runtime_host_windows::win16_dde_abort(self)
    }
}
