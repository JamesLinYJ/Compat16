use super::*;

impl Win16State {
    pub(super) fn cache_callback_owned_dde_return_transfer(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        callback_return_frame: crate::Win16HostDdeCallbackFrame,
        transfer: x86_cpu::ControlTransfer,
    ) -> Result<(), RuntimeError> {
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("nested DDE callback has no exact retained follow-up owner")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("nested DDE callback follow-up owner disappeared")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "nested DDE callback return event belongs to another callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("nested DDE callback follow-up lost its exact continuation")
        })?;
        if follow_up.owner.native_owner_identity() != Some((owner, worker_generation)) {
            return Err(invariant(
                "nested DDE callback return event changed its native owner generation",
            ));
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("nested DDE callback return event has no continuation owner")
        })?;
        continuation.cache_guest_return_transfer(
            operation,
            callback_return_frame,
            transfer,
        )
    }

    pub(super) fn cache_callback_follow_up_native_completion(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        result: crate::Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        let child_returned_complete = self.callback_follow_up_child_returned_step_matches(
            callback_id,
            host_frame,
            operation,
            owner,
            worker_generation,
            &Win16HostDdeStep::Complete(result.clone()),
        );
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("callback-owned DDE completion has no exact follow-up owner")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("callback-owned DDE completion lost its callback frame")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "callback-owned DDE completion changed its exact callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE completion lost its follow-up journal")
        })?;
        if follow_up.owner.native_owner_identity() != Some((owner, worker_generation)) {
            return Err(invariant(
                "callback-owned DDE completion changed its native owner generation",
            ));
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE completion lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "callback-owned DDE completion changed its submitted operation",
            ));
        }
        match follow_up.completed_step.as_ref() {
            None => {
                follow_up.completed_step = Some(Win16HostDdeStep::Complete(result.clone()));
            }
            Some(Win16HostDdeStep::Complete(existing)) if existing == &result => {}
            Some(Win16HostDdeStep::SourceRetired {
                proof,
                result: existing,
            }) if proof.operation == operation && existing == &result => {}
            Some(Win16HostDdeStep::Callback(_)) if child_returned_complete => {
                follow_up.completed_step = Some(Win16HostDdeStep::Complete(result.clone()));
            }
            Some(_) => {
                return Err(invariant(
                    "callback-owned DDE completion changed its cached native step",
                ));
            }
        }
        continuation.cache_native_completion(operation, result)
    }

    /// Retain a callback-produced native step on the exact parent callback
    /// owner before the nested callback frame can be popped. Proof activation
    /// is deferred until that callback's own cleanup has completed.
    pub(super) fn cache_callback_follow_up_returned_step(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        step: &Win16HostDdeStep,
    ) -> Result<(), RuntimeError> {
        match step {
            Win16HostDdeStep::Complete(result) => self.cache_callback_follow_up_native_completion(
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
                result.clone(),
            ),
            Win16HostDdeStep::Callback(callback) => {
                self.cache_callback_follow_up_child_returned_step(
                    callback_id,
                    host_frame,
                    operation,
                    owner,
                    worker_generation,
                    Win16HostDdeStep::Callback(std::sync::Arc::clone(callback)),
                )
            }
            Win16HostDdeStep::SourceRetired { proof, result } => {
                self.cache_callback_follow_up_source_before_child_pop(
                    callback_id,
                    host_frame,
                    operation,
                    owner,
                    worker_generation,
                    std::sync::Arc::clone(proof),
                    result.clone(),
                )
            }
            Win16HostDdeStep::CallbackFrameComplete { frame } => {
                self.cache_callback_follow_up_child_returned_step(
                    callback_id,
                    host_frame,
                    operation,
                    owner,
                    worker_generation,
                    Win16HostDdeStep::CallbackFrameComplete { frame: *frame },
                )?;
                Err(invariant(
                    "callback-owned DDE operation returned a parentless callback-frame completion",
                ))
            }
        }
    }

    fn cache_callback_follow_up_child_returned_step(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        step: Win16HostDdeStep,
    ) -> Result<(), RuntimeError> {
        let child_returned_step = self.callback_follow_up_child_returned_step_matches(
            callback_id,
            host_frame,
            operation,
            owner,
            worker_generation,
            &step,
        );
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("DDE follow-up callback result has no exact retained parent")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("DDE follow-up callback result lost its parent owner")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "DDE follow-up callback result changed its exact callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE follow-up callback result lost its journal")
        })?;
        let continuation = follow_up.continuation.as_deref().ok_or_else(|| {
            invariant("DDE follow-up callback result lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation)
            || continuation.host_owner_identity() != Some((owner, worker_generation))
        {
            follow_up.completed_step = Some(step);
            return Err(invariant(
                "DDE follow-up callback result changed its exact native operation owner",
            ));
        }
        match follow_up.completed_step.as_ref() {
            None => follow_up.completed_step = Some(step),
            Some(existing) if existing == &step => {}
            Some(Win16HostDdeStep::Callback(_)) if child_returned_step => {
                follow_up.completed_step = Some(step);
            }
            Some(_) => {
                return Err(invariant(
                    "DDE follow-up callback result changed its cached native step",
                ));
            }
        }
        if let Win16HostDdeStep::Callback(callback) = follow_up.completed_step.as_ref().unwrap() {
            if !callback.has_valid_identity()
                || callback.parent != Some(operation)
                || callback.owner != owner
                || callback.worker_generation != worker_generation
            {
                return Err(invariant(
                    "DDE follow-up emitted a child callback for a different operation owner",
                ));
            }
        }
        Ok(())
    }

    /// A child callback may return the next native step only while its exact
    /// frame still owns the old cached Callback carrier. This permits the
    /// operation journal to advance Callback→Complete or Callback→Callback
    /// after the host reply was cached, without accepting a foreign step or
    /// losing the child frame before its exact cleanup runs.
    fn callback_follow_up_child_returned_step_matches(
        &self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        returned: &Win16HostDdeStep,
    ) -> bool {
        let Some(child_index) = self.dde_callbacks.len().checked_sub(1) else {
            return false;
        };
        let Some(parent_index) = child_index.checked_sub(1) else {
            return false;
        };
        let parent = &self.dde_callbacks[parent_index];
        let child = &self.dde_callbacks[child_index];
        let Some(follow_up) = parent.pending_follow_up.as_ref() else {
            return false;
        };
        parent.callback_id == callback_id
            && parent.host_frame == host_frame
            && child.callback_kind_active
            && child.active_call.is_none()
            && child.runtime_published
            && matches!(
                child.origin,
                super::Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id: actual_callback,
                    host_frame: actual_frame,
                    operation: actual_operation,
                    owner: actual_owner,
                    worker_generation: actual_generation,
                } if actual_callback == callback_id
                    && actual_frame == host_frame
                    && actual_operation == operation
                    && actual_owner == owner
                    && actual_generation == worker_generation
            )
            && child.source_step.has_valid_identity()
            && child.source_step.parent == Some(operation)
            && child.source_step.owner == owner
            && child.source_step.worker_generation == worker_generation
            && follow_up.owner.native_owner_identity() == Some((owner, worker_generation))
            && follow_up.continuation.as_deref().is_some_and(|continuation| {
                continuation.host_operation() == Some(operation)
                    && continuation.host_owner_identity() == Some((owner, worker_generation))
            })
            && follow_up.pending_child_callback.as_ref().is_some_and(|source| {
                std::sync::Arc::ptr_eq(source, &child.source_step)
            })
            && follow_up.completed_step.as_ref().is_some_and(|cached| {
                matches!(cached, Win16HostDdeStep::Callback(source)
                    if std::sync::Arc::ptr_eq(source, &child.source_step))
            })
            && child.pending_resumed_step.as_ref() == Some(returned)
    }

    fn cache_callback_follow_up_source_before_child_pop(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        proof: std::sync::Arc<crate::Win16DdeSourceRetiredProof>,
        result: crate::Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("DDE source-retired callback result has no exact retained parent")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("DDE source-retired callback result lost its parent owner")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "DDE source-retired callback result changed its exact callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE source-retired callback result lost its journal")
        })?;
        let step = Win16HostDdeStep::SourceRetired {
            proof: std::sync::Arc::clone(&proof),
            result: result.clone(),
        };
        match follow_up.completed_step.as_ref() {
            None => follow_up.completed_step = Some(step),
            Some(Win16HostDdeStep::Complete(cached)) if cached == &result => {
                follow_up.completed_step = Some(step);
            }
            Some(existing) if existing == &step => {}
            Some(_) => {
                return Err(invariant(
                    "DDE source-retired callback result changed its cached native step",
                ));
            }
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("DDE source-retired callback result lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation)
            || continuation.host_owner_identity() != Some((owner, worker_generation))
            || !proof.has_valid_identity()
            || proof.operation != operation
            || proof.owner != owner
            || proof.worker_generation != worker_generation
        {
            return Err(invariant(
                "DDE source-retired callback result changed its exact native identity",
            ));
        }
        continuation.cache_native_completion(operation, result)
    }

    pub(super) fn retain_callback_follow_up_failure(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        error: RuntimeError,
    ) -> Result<RuntimeError, RuntimeError> {
        let parent_index = self.dde_callbacks.len().checked_sub(2).ok_or_else(|| {
            invariant("callback-owned DDE failure has no exact follow-up owner")
        })?;
        let parent = self.dde_callbacks.get_mut(parent_index).ok_or_else(|| {
            invariant("callback-owned DDE failure lost its callback frame")
        })?;
        if parent.callback_id != callback_id || parent.host_frame != host_frame {
            return Err(invariant(
                "callback-owned DDE failure changed its exact callback owner",
            ));
        }
        let follow_up = parent.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE failure lost its follow-up journal")
        })?;
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE failure lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "callback-owned DDE failure changed its submitted operation",
            ));
        }
        if continuation.cached_native_completion(operation).is_some() {
            continuation.retain_normal_completion_failure(operation, error)
        } else {
            Ok(continuation.retain_finish_failure(error))
        }
    }

    pub(super) fn retain_dde_callback_entry_error(
        &mut self,
        callback_id: super::CallbackFrameId,
        error: RuntimeError,
    ) -> RuntimeError {
        let error = std::sync::Arc::new(error);
        if let Some(frame) = self.dde_callbacks.last_mut()
            && frame.callback_id == callback_id
            && frame.pending_callback_error.is_none()
        {
            frame.pending_callback_error = Some(std::sync::Arc::clone(&error));
        }
        super::super::callback_lifo::shared_runtime_error(error)
    }

}
