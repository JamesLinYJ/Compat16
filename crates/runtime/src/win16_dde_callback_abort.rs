//! Exact runtime cancellation after the native DDE owner supplies its receipt.

use guest_core::memory::Memory;
use dos_kernel::DosKernel;
use x86_cpu::Cpu;

use super::{Win16DdeCallbackOrigin, Win16State, invariant};
use crate::{
    DiagnosticKind as Kind, Win16DdeAbortReceipt, Win16DdeCallbackCancellationStatus,
    Win16DdeCancellationSource, Win16DdeOperationCancellationStatus,
};

impl Win16State {
    pub(in crate::win16_runtime) fn cancel_dde_callback_after_abort(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl crate::RuntimeHost,
    ) -> Result<(), crate::RuntimeError> {
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("DDE callback cancellation has no retained family frame")
        })?;
        let callback_id = frame.callback_id;
        let host_frame = frame.host_frame;
        let host_instance = frame.host_instance;
        let origin = frame.origin;
        let callback_kind_active = frame.callback_kind_active;
        let guest_context_restored = frame.guest_context_restored;

        if callback_kind_active && self.require_callback_top(super::CallbackKind::Dde)? != callback_id {
            return Err(invariant("DDE cancellation frame is not the exact central LIFO top"));
        }
        if !callback_kind_active && self.callback_frame_ids.contains(&callback_id) {
            return Err(invariant(
                "DDE readback frame unexpectedly retains a central callback binding",
            ));
        }
        let receipt = self.dde_abort_receipt.as_ref().filter(|receipt| receipt.is_quiesced())
            .ok_or_else(|| crate::RuntimeError::new(
                Kind::HostFailure,
                "DDE runtime frame cannot retire without a complete native owner receipt",
            ))?;
        let cancellation_source =
            require_exact_callback_receipt(receipt, host_frame, origin, host_instance)?;
        if let Win16DdeCallbackOrigin::Foreground(operation)
        | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } = origin
        {
            require_exact_operation_receipt(receipt, operation, host_instance)?;
        }
        let pending = host.win16_dde_callback_retirement_is_pending(
            host_frame,
            parent_for_origin(origin),
            host_instance,
            self.dde_callbacks.last().expect("frame checked").source_step.owner,
            self.dde_callbacks.last().expect("frame checked").source_step.worker_generation,
        )?;
        if !pending && cancellation_source != Win16DdeCancellationSource::GuestReply
            && cancellation_source != Win16DdeCancellationSource::OwnerShutdown
        {
            return Err(invariant("DDE abort readback returned an invalid callback source"));
        }
        if !self.dde_callbacks.last().expect("frame checked").runtime_published
            && cancellation_source != Win16DdeCancellationSource::OwnerShutdown
        {
            return Err(invariant(
                "unpublished DDE callback was retired without owner-shutdown proof",
            ));
        }
        {
            let frame = self.dde_callbacks.last_mut().expect("frame checked");
            if frame.native_reply_source.is_some_and(|source| source != cancellation_source) {
                return Err(invariant(
                    "DDE abort receipt changed the callback's retained reply source",
                ));
            }
            frame.native_reply_source = Some(cancellation_source);
            if !pending {
                frame.native_source_retired = true;
            }
        }

        if callback_kind_active {
            let mut active = self.dde_callbacks.last_mut().expect("frame checked")
                .active_call.take();
            if let Some(mut active) = active.take() {
                let aborted = self.abort_guest_far_callback_after_task_execution_ended(
                    ended,
                    super::CallbackKind::Dde,
                    callback_id,
                    cpu,
                    dos,
                    memory,
                    &mut active,
                );
                if let Err(error) = aborted {
                    self.dde_callbacks.last_mut().expect("frame checked").active_call = Some(active);
                    return Err(error);
                }
            }
        }
        if matches!(origin, Win16DdeCallbackOrigin::GuestExecution { .. }) && !guest_context_restored {
            self.restore_dde_guest_context_for_abort(ended, cpu, memory, host_frame, origin)?;
        }
        self.finish_dde_callback_frame_after_task_execution_ended(ended, dos, memory, host)
    }

    /// Retire a native callback carrier accepted by a USER operation frame
    /// before the full-CPU DDE entry service could publish it.
    pub(in crate::win16_runtime) fn retire_pending_window_dde_callback_after_abort(
        &mut self,
        window_frame_id: u64,
        host: &mut impl crate::RuntimeHost,
    ) -> Result<bool, crate::RuntimeError> {
        let Some((origin, source)) = self.window_operations.last()
            .filter(|frame| frame.id == window_frame_id)
            .and_then(|frame| frame.pending_dde_callback.as_ref())
            .map(|(origin, source)| (*origin, std::sync::Arc::clone(source)))
        else {
            return Ok(false);
        };
        if !source.has_valid_identity() {
            return Err(invariant("pending DDE callback carrier has invalid identity"));
        }
        match origin {
            Win16DdeCallbackOrigin::WindowWait { operation }
                if operation == window_frame_id && source.parent.is_none() => {}
            Win16DdeCallbackOrigin::Foreground(operation)
                if source.parent == Some(operation)
                    && self.window_operations.last().is_some_and(|frame| {
                        matches!(frame.result.as_ref(), Some(super::super::windows::WindowReturn::Dde(c))
                            if c.host_operation() == Some(operation))
                    }) => {}
            _ => return Err(invariant(
                "pending DDE callback changed its exact USER operation origin",
            )),
        }
        let receipt = self.dde_abort_receipt.as_ref().filter(|receipt| receipt.is_quiesced())
            .ok_or_else(|| crate::RuntimeError::new(
                Kind::HostFailure,
                "pending DDE callback cannot retire without the exact native abort receipt",
            ))?;
        let parent = parent_for_origin(origin);
        let cancellation_source = require_exact_callback_receipt(
            receipt,
            source.frame,
            origin,
            source.callback.host_instance,
        )?;
        if let Some(operation) = parent {
            require_exact_operation_receipt(receipt, operation, source.callback.host_instance)?;
        }
        let pending = host.win16_dde_callback_retirement_is_pending(
            source.frame,
            parent,
            source.callback.host_instance,
            source.owner,
            source.worker_generation,
        )?;
        if pending {
            host.win16_dde_callback_retired(
                source.frame,
                parent,
                source.callback.host_instance,
                source.owner,
                source.worker_generation,
            )?;
        } else if !matches!(
            cancellation_source,
            Win16DdeCancellationSource::GuestReply | Win16DdeCancellationSource::OwnerShutdown
        ) {
            return Err(invariant("pending DDE callback receipt has no exact ACK source"));
        }
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == window_frame_id)
            .ok_or_else(|| invariant("pending DDE callback lost its exact USER owner"))?;
        if !frame.pending_dde_callback.as_ref().is_some_and(|(actual_origin, actual)| {
            *actual_origin == origin && std::sync::Arc::ptr_eq(actual, &source)
        }) {
            return Err(invariant("pending DDE callback changed before exact retirement"));
        }
        frame.pending_dde_callback = None;
        Ok(true)
    }

    fn restore_dde_guest_context_for_abort(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host_frame: crate::Win16HostDdeCallbackFrame,
        origin: Win16DdeCallbackOrigin,
    ) -> Result<(), crate::RuntimeError> {
        if origin != (Win16DdeCallbackOrigin::GuestExecution { frame: host_frame }) {
            return Err(invariant("DDE guest-context cancellation changed frame identity"));
        }
        self.restore_dde_guest_context_after_task_execution_ended(
            ended,
            host_frame,
            cpu,
            memory,
        )?;
        self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback frame disappeared after guest-context restoration")
        })?.guest_context_restored = true;
        Ok(())
    }
}

fn require_exact_callback_receipt(
    receipt: &Win16DdeAbortReceipt,
    frame: crate::Win16HostDdeCallbackFrame,
    origin: Win16DdeCallbackOrigin,
    instance: crate::Win16HostDdeInstance,
) -> Result<crate::Win16DdeCancellationSource, crate::RuntimeError> {
    let expected_parent = match origin {
        Win16DdeCallbackOrigin::Foreground(operation)
        | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
        Win16DdeCallbackOrigin::WindowWait { .. }
        | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
    };
    let mut matches = receipt.cancelled_callbacks.iter().filter(|entry| entry.frame == frame);
    let proof = matches.next().ok_or_else(|| crate::RuntimeError::new(
        Kind::HostFailure,
        "DDE abort receipt omitted the exact runtime callback frame",
    ))?;
    if matches.next().is_some()
        || proof.parent_operation != expected_parent
        || proof.instance != Some(instance)
        || proof.status != Win16DdeCallbackCancellationStatus::FrameAcknowledged
        || !matches!(
            proof.source,
            Win16DdeCancellationSource::OwnerShutdown | Win16DdeCancellationSource::GuestReply
        )
    {
        return Err(crate::RuntimeError::new(
            Kind::InternalInvariant,
            "DDE abort receipt does not match the exact callback frame, operation, instance, and reply source",
        ));
    }
    Ok(proof.source)
}

fn require_exact_operation_receipt(
    receipt: &Win16DdeAbortReceipt,
    operation: crate::Win16HostDdeOperation,
    instance: crate::Win16HostDdeInstance,
) -> Result<(), crate::RuntimeError> {
    let mut matches = receipt.cancelled_operations.iter().filter(|entry| entry.operation == operation);
    let proof = matches.next().ok_or_else(|| crate::RuntimeError::new(
        Kind::HostFailure,
        "DDE abort receipt omitted the exact foreground native operation",
    ))?;
    if matches.next().is_some()
        || proof.instance != Some(instance)
        || !matches!(
            proof.status,
            Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                | Win16DdeOperationCancellationStatus::CompletedDuringAbort
                | Win16DdeOperationCancellationStatus::NativeCompleteError
        )
    {
        return Err(crate::RuntimeError::new(
            Kind::InternalInvariant,
            "DDE abort receipt does not match the exact foreground operation and instance",
        ));
    }
    Ok(())
}

fn parent_for_origin(origin: Win16DdeCallbackOrigin) -> Option<crate::Win16HostDdeOperation> {
    match origin {
        Win16DdeCallbackOrigin::Foreground(operation)
        | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
        Win16DdeCallbackOrigin::WindowWait { .. }
        | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
    }
}
