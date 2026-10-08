//! Exact cleanup and terminal acknowledgement for DDE callback owners.

use compat_services::win16_dde::transaction_type;

use super::{
    CallbackFrameId, CallbackKind, Win16DdeCallbackOrigin,
    Win16DdeContinuation, Win16State, invariant,
};
use super::super::runtime_dde::DdeCompletionAccess;
use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use crate::{RuntimeError, RuntimeHost};

impl Win16State {
    pub(in crate::win16_runtime) fn finish_dde_callback_frame(
        &mut self,
        returned_data: Option<u32>,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.finish_dde_callback_frame_inner(returned_data, host, None)
    }

    pub(in crate::win16_runtime) fn finish_dde_callback_frame_after_task_execution_ended(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.finish_dde_callback_frame_inner(None, host, Some((ended, dos, memory)))
    }

    fn finish_dde_callback_frame_inner(
        &mut self,
        returned_data: Option<u32>,
        host: &mut impl RuntimeHost,
        task_ended: Option<(
            &super::super::execute::Win16TaskExecutionEnded,
            &mut DosKernel,
            &mut Memory,
        )>,
    ) -> Result<(), RuntimeError> {
        let parent = self.dde_callbacks.last().and_then(|frame| match frame.origin {
            Win16DdeCallbackOrigin::Foreground(operation)
            | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
        });
        let retiring_host_frame = self.dde_callbacks.last().map(|frame| frame.host_frame)
            .ok_or_else(|| invariant("DDE callback frame disappeared before retirement"))?;
        let ticket = self.with_dde_completion_access(|access| {
            access.prepare_dde_callback_frame_retirement(returned_data, host)
        })?;
        self.with_dde_completion_access(|access| {
            access.validate_dde_callback_frame_retirement(&ticket)
        })?;
        if let Some((ended, dos, memory)) = task_ended {
            let release_frame = self.dde_callbacks.last().and_then(|frame| {
                (matches!(frame.origin, Win16DdeCallbackOrigin::GuestExecution { .. })
                    && frame.guest_context_restored
                    && !frame.guest_context_owner_released)
                    .then_some(frame.host_frame)
            });
            if let Some(host_frame) = release_frame {
                self.release_dde_guest_context_after_task_execution_ended(
                    ended,
                    host_frame,
                    dos,
                    memory,
                )?;
                let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                    invariant("DDE callback disappeared after terminal CPU-owner release")
                })?;
                if frame.host_frame != host_frame {
                    return Err(invariant(
                        "DDE callback owner changed after terminal CPU-owner release",
                    ));
                }
                frame.guest_context_owner_released = true;
            }
        }
        if let Some(operation) = parent {
            let origin = self.dde_callbacks.last().map(|frame| frame.origin)
                .ok_or_else(|| invariant("DDE callback owner disappeared before phase update"))?;
            match origin {
                Win16DdeCallbackOrigin::Foreground(_) => {
                    self.mark_foreground_dde_callback_retired(operation)?;
                }
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    owner,
                    worker_generation,
                    ..
                } => self.with_dde_completion_access(|access| {
                    access.mark_callback_follow_up_completion_retired(
                        callback_id,
                        host_frame,
                        retiring_host_frame,
                        operation,
                        owner,
                        worker_generation,
                    )
                })?,
                _ => {}
            }
        }
        self.with_dde_completion_access(|access| {
            access.commit_dde_callback_frame_retirement(ticket)
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DdeCallbackRetirementTicket {
    callback_id: CallbackFrameId,
    callback_kind_active: bool,
    guest_conversation: u32,
    origin: Win16DdeCallbackOrigin,
    host_frame: crate::Win16HostDdeCallbackFrame,
    owner: crate::Win16HostDdeOwner,
    worker_generation: u64,
    host_instance: crate::Win16HostDdeInstance,
    native_reply_source: crate::Win16DdeCancellationSource,
    disconnect: bool,
}

impl DdeCompletionAccess<'_> {
    pub(in crate::win16_runtime) fn finish_dde_callback_frame_with_continuation(
        &mut self,
        returned_data: Option<u32>,
        host: &mut impl RuntimeHost,
        continuation: Option<&mut Win16DdeContinuation>,
    ) -> Result<(), RuntimeError> {
        let ticket = self.prepare_dde_callback_frame_retirement(returned_data, host)?;
        self.validate_dde_callback_frame_retirement(&ticket)?;
        let operation = match ticket.origin {
            Win16DdeCallbackOrigin::Foreground(operation)
            | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
        };
        if let Some(operation) = operation {
            if let Some(continuation) = continuation {
                match continuation.host_operation() {
                    Some(owner) if owner == operation => {
                        if continuation.normal_completion_phase(operation).is_some() {
                            continuation.mark_normal_callback_retired(operation)?;
                        }
                    }
                    Some(_) => return Err(invariant(
                        "DDE callback retirement continuation belongs to another native operation",
                    )),
                    None => {}
                }
            }
        }
        self.commit_dde_callback_frame_retirement(ticket)
    }

    fn validate_dde_callback_frame_retirement(
        &self,
        ticket: &DdeCallbackRetirementTicket,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("DDE callback frame disappeared before its exact LIFO pop")
        })?;
        if frame.callback_id != ticket.callback_id
            || frame.host_frame != ticket.host_frame
            || frame.source_step.owner != ticket.owner
            || frame.source_step.worker_generation != ticket.worker_generation
            || frame.source_step.callback.host_instance != ticket.host_instance
            || (!frame.runtime_published
                && ticket.native_reply_source != crate::Win16DdeCancellationSource::OwnerShutdown)
            || frame.origin != ticket.origin
            || frame.host_instance != ticket.host_instance
            || frame.native_reply_source != Some(ticket.native_reply_source)
            || !frame.native_source_retired
        {
            return Err(invariant(
                "DDE callback retirement ticket no longer matches its exact live frame",
            ));
        }
        if ticket.callback_kind_active {
            self.require_dde_callback_top(ticket.callback_id)?;
        } else if self.callback_frame_ids.contains(&ticket.callback_id) {
            return Err(invariant(
                "DDE callback readback unexpectedly regained a central LIFO binding",
            ));
        }
        Ok(())
    }

    fn prepare_dde_callback_frame_retirement(
        &mut self,
        returned_data: Option<u32>,
        host: &mut impl RuntimeHost,
    ) -> Result<DdeCallbackRetirementTicket, RuntimeError> {
        let active = self.dde_callbacks.last().ok_or_else(|| {
            invariant("DDE callback frame disappeared after native acknowledgement")
        })?;
        let ticket = DdeCallbackRetirementTicket {
            callback_id: active.callback_id,
            callback_kind_active: active.callback_kind_active,
            guest_conversation: active.guest_conversation,
            origin: active.origin,
            host_frame: active.host_frame,
            owner: active.source_step.owner,
            worker_generation: active.source_step.worker_generation,
            host_instance: active.host_instance,
            native_reply_source: active.native_reply_source.ok_or_else(|| {
                invariant("DDE runtime frame has no exact native acknowledgement proof")
            })?,
            disconnect: transaction_type::base(active.transaction_type)
                == transaction_type::base(transaction_type::DISCONNECT),
        };
        if active.active_call.is_some() {
            return Err(invariant(
                "DDE callback frame still has active guest execution at completion",
            ));
        }
        if ticket.callback_kind_active {
            self.require_dde_callback_top(ticket.callback_id)?;
        } else if self.callback_frame_ids.contains(&ticket.callback_id) {
            return Err(invariant(
                "DDE callback readback retained a central callback-kind binding",
            ));
        }
        let native_source_retired = active.native_source_retired;
        self.retire_top_dde_callback_frame(returned_data)?;
            if !native_source_retired {
            let parent = match ticket.origin {
                Win16DdeCallbackOrigin::Foreground(operation)
                | Win16DdeCallbackOrigin::CallbackFollowUp { operation, .. } => Some(operation),
                Win16DdeCallbackOrigin::WindowWait { .. }
                | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
            };
            host.win16_dde_callback_retired(
                ticket.host_frame,
                parent,
                ticket.host_instance,
                ticket.owner,
                ticket.worker_generation,
            )?;
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("DDE callback frame disappeared after host source retirement")
            })?;
            frame.native_reply_source = Some(ticket.native_reply_source);
            frame.native_source_retired = true;
        }
        Ok(ticket)
    }

    fn commit_dde_callback_frame_retirement(
        &mut self,
        ticket: DdeCallbackRetirementTicket,
    ) -> Result<(), RuntimeError> {
        self.validate_dde_callback_frame_retirement(&ticket)?;
        if ticket.callback_kind_active {
            super::super::retire_callback_binding_from_stacks(
                self.callback_kinds,
                self.callback_frame_ids,
                CallbackKind::Dde,
                ticket.callback_id,
            )?;
            self.dde_callbacks.pop();
        } else {
            self.dde_callbacks.pop();
        }
        if ticket.disconnect {
            self.dde.remove_conversation(ticket.guest_conversation);
        }
        Ok(())
    }

    fn require_dde_callback_top(&self, expected: CallbackFrameId) -> Result<(), RuntimeError> {
        if self.callback_kinds.len() != self.callback_frame_ids.len()
            || self.callback_kinds.last().copied() != Some(CallbackKind::Dde)
            || self.callback_frame_ids.last().copied() != Some(expected)
            || !self.dde_callbacks.last().is_some_and(|frame| {
                frame.callback_id == expected && frame.callback_kind_active
            })
        {
            return Err(invariant("DDE callback is not the exact shared callback LIFO top"));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn mark_callback_follow_up_completion_retired(
        &mut self,
        callback_id: CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        retiring_host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("nested DDE callback has no retained follow-up parent")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("nested DDE callback follow-up parent disappeared")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "nested DDE callback retirement changed its callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("nested DDE callback retirement lost its follow-up journal")
        })?;
        if follow_up.owner.native_owner_identity() != Some((owner, worker_generation)) {
            return Err(invariant(
                "nested DDE callback retirement changed its native owner generation",
            ));
        }
        match follow_up.pending_child_callback.as_ref() {
            Some(child) if child.frame == retiring_host_frame
                && child.parent == Some(operation)
                && child.owner == owner
                && child.worker_generation == worker_generation => {
                    follow_up.pending_child_callback = None;
                }
            Some(_) => {
                return Err(invariant(
                    "retired DDE callback is not the exact published follow-up child",
                ));
            }
            None => {}
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("nested DDE callback retirement lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "nested DDE callback retirement changed its submitted operation",
            ));
        }
        if continuation.cached_native_completion(operation).is_some() {
            continuation.mark_normal_callback_retired(operation)?;
        }
        Ok(())
    }

    /// Retry each fallible native/guest owner cleanup while the exact DDE
    /// frame remains rooted in both its family stack and, when active, the
    /// central callback LIFO. Unlock progress and route retirement are saved
    /// before attempting the next cleanup step.
    pub(in crate::win16_runtime) fn retire_top_dde_callback_frame(
        &mut self,
        returned_data: Option<u32>,
    ) -> Result<(), RuntimeError> {
        if let Some(frame) = self.dde_callbacks.last_mut() {
            if frame.pending_returned_data.is_none() {
                frame.pending_returned_data = returned_data;
            }
        }

        if let Some((raw, mut locked)) = self.dde_callbacks.last().and_then(|frame| {
            frame.context_allocation.map(|allocation| {
                (allocation, frame.context_allocation_locked)
            })
        }) {
            let result = self.free_runtime_dde_block_progress(raw, &mut locked);
            if let Some(frame) = self.dde_callbacks.last_mut() {
                frame.context_allocation_locked = locked;
            }
            result?;
            if let Some(frame) = self.dde_callbacks.last_mut() {
                frame.context_allocation = None;
            }
        }

        let resources_ended = self.dde_callbacks.last().is_some_and(|frame| {
            frame.callback_resources_ended
        });
        if !resources_ended {
            self.reserve_dde_guest_block_retirement()?;
            let (route, guest_data, strings, borrowed) = {
                let frame = self.dde_callbacks.last().ok_or_else(|| {
                    invariant("DDE callback frame disappeared during resource cleanup")
                })?;
                (
                    frame.callback_route,
                    frame.guest_data,
                    frame.callback_strings.clone(),
                    frame.borrowed_strings.clone(),
                )
            };
            let removed = self.dde.end_callback(route, guest_data, &strings, &borrowed)
                .map_err(|_| invariant("DDE callback frame lost a retained route or HSZ pin"))?;
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("DDE callback frame disappeared after route retirement")
            })?;
            frame.callback_resources_ended = true;
            if let Some(block) = removed.and_then(|removed| removed.access_block) {
                frame.pending_access_block = Some(block.identity);
                frame.pending_access_block_locked = true;
            }
        }

        self.finish_pending_dde_callback_access_block()?;

        if let Some(data) = self.dde_callbacks.last()
            .and_then(|frame| frame.pending_returned_data)
        {
            self.reserve_dde_guest_block_retirement()?;
            let guest_data = self.dde_callbacks.last().ok_or_else(|| {
                invariant("DDE callback frame disappeared during returned-data cleanup")
            })?.guest_data;
            let removed = if data != guest_data {
                self.dde.release_unowned_data(data)
            } else {
                None
            };
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("DDE callback frame disappeared after returned-data cleanup")
            })?;
            frame.pending_returned_data = None;
            if let Some(block) = removed.and_then(|removed| removed.access_block) {
                frame.pending_access_block = Some(block.identity);
                frame.pending_access_block_locked = true;
            }
        }

        self.finish_pending_dde_callback_access_block()?;
        self.unregister_retired_dde_callbacks()
    }

    pub(in crate::win16_runtime) fn finish_pending_dde_callback_access_block(&mut self) -> Result<(), RuntimeError> {
        let Some((raw, mut locked)) = self.dde_callbacks.last().and_then(|frame| {
            frame.pending_access_block.map(|identity| (identity, frame.pending_access_block_locked))
        }) else {
            return Ok(());
        };
        let result = self.free_runtime_dde_block_progress(raw, &mut locked);
        if let Some(frame) = self.dde_callbacks.last_mut() {
            frame.pending_access_block_locked = locked;
        }
        result?;
        if let Some(frame) = self.dde_callbacks.last_mut() {
            frame.pending_access_block = None;
            frame.pending_access_block_locked = false;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn mark_callback_returned_data(&mut self, guest_data: u32) -> Result<(), RuntimeError> {
        let origin = self.dde.data_origin(guest_data).ok_or_else(|| {
            invariant("DDE callback data token disappeared before native acknowledgement")
        })?;
        if matches!(origin, crate::win16_dde::Win16DdeDataOrigin::Created { .. }) {
            self.dde.mark_data_transferred(guest_data).ok_or_else(|| {
                invariant(
                    "created DDE callback data token disappeared before native acknowledgement",
                )
            })?;
        }
        // CallbackBorrowed remains valid through its frame pin. ClientResult
        // remains guest-owned. The host copies either source into a fresh
        // native Created handle before returning it to DDEML.
        Ok(())
    }

}
