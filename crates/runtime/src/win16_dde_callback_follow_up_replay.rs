//! Exact callback-child replay and returned-step acceptance.

use super::*;

impl Win16State {
    /// Recover the step already owned by the callback journal if the caller
    /// lost the returned carrier after the child callback was retired. This
    /// prevents a cached Complete from replaying the old Callback carrier and
    /// re-entering guest code or issuing another native operation.
    pub(super) fn replay_cached_callback_follow_up_step(
        &mut self,
        callback_id: super::CallbackFrameId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(step) = self.dde_callbacks.last().and_then(|frame| {
            (frame.callback_id == callback_id
                && !frame.callback_kind_active
                && frame.active_call.is_none())
            .then(|| frame.pending_follow_up.as_ref()?.completed_step.clone())
            .flatten()
        }) else {
            return Ok(());
        };
        let result = match step {
            Win16HostDdeStep::Complete(result) => self
                .callback_follow_up_native_identity(callback_id)
                .and_then(|(operation, _)| {
                    self.retire_callback_owned_dde_completion(
                        callback_id,
                        operation,
                        &result,
                        host,
                    )
                    .map(|_| ())
                }),
            Win16HostDdeStep::SourceRetired { proof, result } => {
                self.cache_callback_follow_up_retired_source(callback_id, proof, result)
            }
            Win16HostDdeStep::Callback(step) => {
                self.cache_next_callback_follow_up_child(callback_id, step)
            }
            Win16HostDdeStep::CallbackFrameComplete { .. } => {
                Err(invariant(
                    "callback-owned DDE operation retained a parentless callback-frame completion",
                ))
            }
        };
        if let Err(error) = result {
            return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
        }
        Ok(())
    }

    pub(super) fn replay_entered_callback_follow_up_child(
        &self,
        callback_id: super::CallbackFrameId,
    ) -> Result<Option<Win16DdeCallbackFollowUpDispatch>, RuntimeError> {
        let Some(child_index) = self.dde_callbacks.len().checked_sub(1) else {
            return Ok(None);
        };
        let Some(parent_index) = child_index.checked_sub(1) else {
            return Ok(None);
        };
        let parent = &self.dde_callbacks[parent_index];
        let child = &self.dde_callbacks[child_index];
        let Some(follow_up) = parent.pending_follow_up.as_ref() else {
            return Ok(None);
        };
        let super::runtime_dde::Win16DdeFollowUpOwner::Callback {
            callback_id: expected_parent,
            host_frame,
            owner,
            worker_generation,
            ..
        } = follow_up.owner
        else {
            return Ok(None);
        };
        if expected_parent != callback_id || parent.callback_id != callback_id {
            return Ok(None);
        }
        let expected_step = follow_up.pending_child_callback.as_ref();
        let exact_child = child.callback_kind_active
            && child.active_call.is_some()
            && child.runtime_published
            && child.host_frame != host_frame
            && matches!(child.origin, Win16DdeCallbackOrigin::CallbackFollowUp {
                callback_id: actual_parent,
                host_frame: actual_frame,
                owner: actual_owner,
                worker_generation: actual_generation,
                ..
            } if actual_parent == callback_id
                && actual_frame == host_frame
                && actual_owner == owner
                && actual_generation == worker_generation)
            && expected_step.is_some_and(|step| std::sync::Arc::ptr_eq(step, &child.source_step));
        if !exact_child {
            return Err(invariant(
                "DDE callback follow-up retry found a different live child frame",
            ));
        }
        Ok(Some(Win16DdeCallbackFollowUpDispatch::GuestEntered))
    }

    pub(super) fn accept_resumed_callback_follow_up_step(
        &mut self,
        callback_id: super::CallbackFrameId,
        step: Win16HostDdeStep,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let result = match step {
            Win16HostDdeStep::Complete(result) => {
                let (operation, _) = self.callback_follow_up_native_identity(callback_id)?;
                self.retire_callback_owned_dde_completion(
                    callback_id,
                    operation,
                    &result,
                    host,
                )?;
                Ok(())
            }
            Win16HostDdeStep::SourceRetired { proof, result } => {
                self.cache_callback_follow_up_retired_source(callback_id, proof, result)
            }
            Win16HostDdeStep::Callback(step) => {
                self.cache_next_callback_follow_up_child(callback_id, step)
            }
            Win16HostDdeStep::CallbackFrameComplete { .. } => {
                Err(invariant(
                    "callback-owned DDE operation returned a parentless callback-frame completion",
                ))
            }
        };
        if let Err(error) = result {
            return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
        }
        Ok(())
    }
}
