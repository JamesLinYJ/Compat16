//! Context restoration and exact source acknowledgement for guest callbacks.

use std::sync::Arc;

use super::{
    callback_binding_error, AsynchronousCallbackPhase,
    AsynchronousCallbackRetirement, Win16State,
};
use crate::{DiagnosticKind as Kind, RuntimeError};
use guest_core::memory::Memory;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_asynchronous_guest_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<AsynchronousCallbackRetirement, RuntimeError> {
        let (callback_id, callback_token, phase, mut active_call) = {
            let frame = self.callback_scheduler.active.last().ok_or_else(||
                RuntimeError::new(Kind::GuestFault,
                    "Win16 callback gate has no asynchronous callback frame"))?;
            self.require_asynchronous_callback_top(frame.callback_id, frame.callback_token)?;
            (
                frame.callback_id,
                frame.callback_token,
                frame.phase,
                frame.active_call.clone(),
            )
        };
        if phase == AsynchronousCallbackPhase::Guest {
            // A completed checked FAR return restores only this callback's
            // register/x87 policy. Enclosing tickets and live events survive.
            {
                let frame = self.callback_scheduler.active.last_mut().ok_or_else(||
                    callback_binding_error("asynchronous callback frame disappeared"))?;
                frame.phase = AsynchronousCallbackPhase::ReturnValidation;
            }
            let returned = self.finish_guest_callback_entry_checked(
                cpu, dos, memory, &mut active_call,
            );
            let frame = self.callback_scheduler.active.last_mut().ok_or_else(||
                callback_binding_error("asynchronous callback frame disappeared"))?;
            // Publish even a partially successful CPU-owner transition before
            // returning an error; cleanup retries must not replay the restore.
            frame.active_call = active_call;
            match returned {
                Ok(()) => frame.phase = AsynchronousCallbackPhase::Returned,
                Err(error) => {
                    // Retain the same frame, callback id, source owner and
                    // typed cause. ReturnFailed suppresses repeated validation.
                    frame.phase = AsynchronousCallbackPhase::ReturnFailed;
                    frame.return_failure = Some(Arc::new(error));
                }
            }
        } else if phase == AsynchronousCallbackPhase::ReturnValidation {
            return Err(callback_binding_error(
                "asynchronous callback return validation is already in progress",
            ));
        }
        let return_failure = self.callback_scheduler.active.last().ok_or_else(||
            callback_binding_error("asynchronous callback frame disappeared before restoration"))?
            .return_failure.clone();
        if let Some(error) = return_failure {
            // Preserve the exact original cause for a retry or terminal
            // cancellation; neither callback stack is retired on this path.
            return Err(RuntimeError::with_source(
                error.kind(), "asynchronous callback return validation failed", error,
            ));
        }
        let mut buffers = {
            let frame = self.callback_scheduler.active.last_mut().ok_or_else(||
                callback_binding_error("asynchronous callback frame disappeared before cleanup"))?;
            std::mem::take(&mut frame.buffers)
        };
        if let Err(error) = self.release_callback_buffers(&mut buffers) {
            if let Some(frame) = self.callback_scheduler.active.last_mut() {
                frame.buffers = buffers;
            }
            return Err(error);
        }
        self.require_asynchronous_callback_top(callback_id, callback_token)?;
        let frame = self.callback_scheduler.active.last().ok_or_else(||
            callback_binding_error("asynchronous callback frame disappeared after buffer cleanup"))?;
        let retirement = AsynchronousCallbackRetirement {
            callback_id,
            callback_token,
            source_bound: frame.source_bound,
            midi_source: frame.midi_source,
            source_acknowledged: frame.source_acknowledged,
            terminal_cancelled: false,
        };
        if retirement.source_bound {
            // The source can still reject its ACK. Keep the exact family
            // frame and registration rooted until that ACK succeeds.
            self.validate_asynchronous_callback_retirement(retirement)?;
            Ok(retirement)
        } else {
            let retirement = self.retire_asynchronous_callback_top(dos, memory, callback_id, callback_token)?;
            self.callback_scheduler.retire_requested_registration(callback_token);
            Ok(retirement)
        }
    }

    pub(in crate::win16_runtime) fn validate_asynchronous_callback_retirement(
        &self,
        retirement: AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        self.require_asynchronous_callback_top(
            retirement.callback_id, retirement.callback_token,
        )?;
        let frame = self.callback_scheduler.active.last().ok_or_else(||
            callback_binding_error("asynchronous callback retirement has no exact frame"))?;
        if !retirement.source_bound || !frame.source_bound
            || retirement.midi_source != frame.midi_source
            || frame.phase != AsynchronousCallbackPhase::Returned
            || frame.return_failure.is_some()
            || frame.buffers.iter().any(|buffer| buffer.allocation.is_some() || buffer.locked)
        {
            return Err(callback_binding_error(
                "asynchronous callback source ACK precedes context restoration and buffer-owner transfer",
            ));
        }
        Ok(())
    }

    /// Called only after the family source has accepted this exact receipt.
    pub(in crate::win16_runtime) fn complete_asynchronous_callback_retirement(
        &mut self,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        retirement: AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        self.validate_asynchronous_callback_retirement(retirement)?;
        self.retire_asynchronous_callback_top(
            dos, memory, retirement.callback_id, retirement.callback_token,
        )?;
        self.callback_scheduler.retire_requested_registration(retirement.callback_token);
        Ok(())
    }

    /// Cache source consumption on the exact active callback frame. If a
    /// later family-stack retirement fails, retry cannot issue the same ACK.
    pub(in crate::win16_runtime) fn mark_asynchronous_callback_source_acknowledged(
        &mut self,
        retirement: AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        self.require_asynchronous_callback_top(
            retirement.callback_id, retirement.callback_token,
        )?;
        let frame = self.callback_scheduler.active.last_mut().ok_or_else(||
            callback_binding_error("acknowledged asynchronous source lost its callback frame"))?;
        if !retirement.source_bound || !frame.source_bound
            || frame.callback_id != retirement.callback_id
            || frame.callback_token != retirement.callback_token
            || frame.midi_source != retirement.midi_source
        {
            return Err(callback_binding_error(
                "source ACK does not match the exact active asynchronous callback frame",
            ));
        }
        frame.source_acknowledged = true;
        Ok(())
    }

    /// Cache a terminal source ACK on the retained receipt before removing it
    /// from the scheduler. This keeps retries from issuing a non-idempotent
    /// host ACK twice after the callback frame itself has been cancelled.
    pub(in crate::win16_runtime) fn mark_pending_asynchronous_source_acknowledged(
        &mut self,
        retirement: AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        let receipt = self.callback_scheduler.pending_source_retirements.iter_mut()
            .find(|receipt| receipt.callback_id == retirement.callback_id
                && receipt.callback_token == retirement.callback_token)
            .ok_or_else(|| callback_binding_error(
                "terminal source ACK has no exact retained asynchronous receipt",
            ))?;
        if !receipt.source_bound || !retirement.source_bound
            || receipt.midi_source != retirement.midi_source
        {
            return Err(callback_binding_error(
                "terminal source ACK does not match its retained callback identity",
            ));
        }
        receipt.source_acknowledged = true;
        Ok(())
    }

    /// Producer quiescence must already be proved by the source owner.
    /// Cancellation restores state without synthesizing a guest FAR return.
    pub(in crate::win16_runtime) fn cancel_asynchronous_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<AsynchronousCallbackRetirement, RuntimeError> {
        let frame = self.callback_scheduler.active.last().ok_or_else(||
            RuntimeError::new(Kind::GuestFault,
                "asynchronous callback teardown has no exact family frame"))?;
        let callback_id = frame.callback_id;
        let callback_token = frame.callback_token;
        self.require_asynchronous_callback_top(callback_id, callback_token)?;
        let source_bound = frame.source_bound;
        let mut active_call = frame.active_call.clone();
        if source_bound {
            self.callback_scheduler.reserve_source_retirement()?;
        }
        let aborted = self.abort_guest_callback_entry_after_task_execution_ended(
            ended, callback_id, cpu, dos, memory, &mut active_call,
        );
        self.callback_scheduler.active.last_mut().ok_or_else(||
            callback_binding_error("asynchronous callback frame disappeared during cancellation"))?
            .active_call = active_call;
        aborted?;
        let mut buffers = {
            let frame = self.callback_scheduler.active.last_mut().ok_or_else(||
                callback_binding_error("asynchronous callback frame disappeared before cancellation"))?;
            std::mem::take(&mut frame.buffers)
        };
        if let Err(error) = self.release_callback_buffers(&mut buffers) {
            if let Some(frame) = self.callback_scheduler.active.last_mut() {
                frame.buffers = buffers;
            }
            return Err(error);
        }
        let mut retirement = self.retire_asynchronous_callback_top(dos, memory, callback_id, callback_token)?;
        retirement.terminal_cancelled = true;
        if retirement.source_bound {
            self.callback_scheduler.retain_source_retirement(retirement);
        }
        self.callback_scheduler.retire_requested_registration(retirement.callback_token);
        Ok(retirement)
    }
}
