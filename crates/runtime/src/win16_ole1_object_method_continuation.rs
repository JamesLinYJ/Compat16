//! Checked caller continuation and return for typed OLE1 object methods.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use x86_cpu::{Cpu, CallEffectPolicy, CallResumeBoundary};
use crate::{DiagnosticKind as Kind, RuntimeError};
use super::Win16State;

impl Win16State {
    pub(super) fn retire_acknowledged_object_method_step(
        &mut self,
        index: usize,
        current: crate::win16_runtime::com_operations::Win16ComGuestOperationId,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self
            .checked_object_method_com_continuation(index, current)?
            .legacy_cpu_frame;
        self.release_legacy_cpu_frame(frame, dos, memory)?;
        self.retire_acknowledged_com_guest_step(current, frame)?;
        self.ole1_client_documents.pending_object_methods[index].current = None;
        Ok(())
    }

    pub(super) fn return_ole1_object_method(
        &mut self,
        index: usize,
        current: crate::win16_runtime::com_operations::Win16ComGuestOperationId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let (saved, return_to, return_kind, frame) = {
            let continuation =
                self.checked_object_method_com_continuation(index, current)?;
            (
                continuation.saved_registers.clone(),
                continuation.return_to,
                continuation.return_kind,
                continuation.legacy_cpu_frame,
            )
        };
        let target = crate::win16_runtime::call_return::checked_return_target(
            &saved,
            return_to,
            u32::from(self.ole1_client_documents.pending_object_methods[index].guest_status),
            return_kind,
        );
        self.return_legacy_cpu_call_frame(
            frame,
            cpu,
            memory,
            CallEffectPolicy::PreserveX87,
            CallResumeBoundary::NoGuestExecution,
            target,
        )?;
        self.mark_com_guest_returned(current)?;
        self.release_legacy_cpu_frame(frame, dos, memory)?;
        self.retire_returned_com_guest_call(current, frame)?;
        self.ole1_client_documents.pending_object_methods.remove(index);
        Ok(())
    }

    pub(super) fn checked_object_method_com_continuation(
        &self,
        index: usize,
        current: crate::win16_runtime::com_operations::Win16ComGuestOperationId,
    ) -> Result<crate::win16_runtime::com_operations::GuestContinuation<'_>, RuntimeError> {
        let sequence = self
            .ole1_client_documents
            .pending_object_methods
            .get(index)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 method continuation has no exact caller sequence",
                )
            })?;
        self.checked_ole1_com_continuation(
            current,
            sequence.owner,
            sequence.record.callback_route,
            sequence.return_to,
            sequence.return_kind,
            crate::win16_runtime::com_operations::Win16ComOperationOrigin::Ole1ObjectMethod {
                proxy_id: sequence.record.id,
                slot: sequence.slot,
            },
        )
    }
}
