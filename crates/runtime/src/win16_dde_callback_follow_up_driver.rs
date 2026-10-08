use super::*;
use dos_kernel::DosKernel;
use std::sync::Arc;
use x86_cpu::Cpu;

#[path = "win16_dde_callback_follow_up_replay.rs"]
mod replay;

impl Win16State {
    /// Drive a WILDCONNECT GetData follow-up under the exact DDE callback
    /// frame that owns it. `resumed_step` is supplied only after the exact
    /// child callback has returned and its frame has retired. A repeated call
    /// after a lost `GuestEntered` response reads the already-entered exact
    /// child and never enters its guest procedure twice.
    pub(in crate::win16_runtime) fn drive_callback_owned_dde_follow_up(
        &mut self,
        callback_id: super::CallbackFrameId,
        resumed_step: Option<Win16HostDdeStep>,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16DdeCallbackFollowUpDispatch, RuntimeError> {
        if let Some(dispatch) = self.replay_entered_callback_follow_up_child(callback_id)? {
            if resumed_step.is_some() {
                return Err(invariant(
                    "DDE callback follow-up received a returned step while its exact child guest frame is still active",
                ));
            }
            return Ok(dispatch);
        }

        if let Some(step) = resumed_step {
            if let Err(error) = self.accept_resumed_callback_follow_up_step(callback_id, step, host) {
                return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
            }
        } else {
            if let Err(error) = self.replay_cached_callback_follow_up_step(callback_id, host) {
                return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
            }
        }

        loop {
            let (owner, carrier) = self.submit_dde_callback_follow_up(callback_id, host)?;
            match carrier {
                super::runtime_dde::Win16DdeFollowUpCarrier::Callback(callback) => {
                    let (origin, step) = match super::runtime_dde::callback_owned_follow_up_origin(
                        owner,
                        &super::runtime_dde::Win16DdeFollowUpCarrier::Callback(
                            std::sync::Arc::clone(&callback),
                        ),
                    ) {
                        Ok(dispatch) => dispatch,
                        Err(error) => {
                            return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
                        }
                    };
                    let entered = match self.begin_dde_callback(
                        step,
                        origin,
                        cpu,
                        dos,
                        memory,
                        host,
                    ) {
                        Ok(entered) => entered,
                        Err(error) => {
                            return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
                        }
                    };
                    match entered {
                        None => {
                            let child = self.dde_callbacks.last().ok_or_else(|| {
                                invariant(
                                    "entered DDE follow-up callback lost its exact guest frame",
                                )
                            })?;
                            if !matches!(child.origin, Win16DdeCallbackOrigin::CallbackFollowUp {
                                callback_id: parent, ..
                            } if parent == callback_id)
                                || !child.callback_kind_active
                                || child.active_call.is_none()
                            {
                                return Err(invariant(
                                    "DDE follow-up guest entry changed its exact callback owner",
                                ));
                            }
                            return Ok(Win16DdeCallbackFollowUpDispatch::GuestEntered);
                        }
                        Some((returned_origin, returned_step)) => {
                            if returned_origin != origin {
                                return Err(invariant(
                                    "DDE follow-up fallback changed its exact callback origin",
                                ));
                            }
                            self.accept_resumed_callback_follow_up_step(
                                callback_id,
                                returned_step,
                                host,
                            )?;
                        }
                    }
                }
                super::runtime_dde::Win16DdeFollowUpCarrier::StartedFailure(failure) => {
                    let shared = super::super::callback_lifo::shared_runtime_error(
                        std::sync::Arc::clone(&failure.cause),
                    );
                    let _ = self.retain_follow_up_failure_from_owner(callback_id, shared)?;
                    return Ok(Win16DdeCallbackFollowUpDispatch::StartedFailure { failure });
                }
                super::runtime_dde::Win16DdeFollowUpCarrier::SourceRetired {
                    proof,
                    result,
                } => {
                    if let Err(error) = self.cache_callback_follow_up_retired_source(
                        callback_id,
                        std::sync::Arc::clone(&proof),
                        result.clone(),
                    ) {
                        return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
                    }
                    match self.finish_callback_owned_readback(callback_id, result.clone(), host) {
                        Ok(super::readback::CallbackOwnedReadbackProgress::Continue) => continue,
                        Ok(super::readback::CallbackOwnedReadbackProgress::Resume {
                            origin,
                            step,
                            returned_data,
                            retained_failure,
                        }) => {
                            if let Some(error) = retained_failure.as_ref()
                                && let Err(retain_error) = self
                                    .retain_callback_readback_failure_for_origin(
                                        origin,
                                        std::sync::Arc::clone(error),
                                    )
                            {
                                return Err(self.retain_dde_callback_entry_error(
                                    callback_id,
                                    retain_error,
                                ));
                            }
                            if let Err(error) = self.finish_dde_callback_frame(returned_data, host) {
                                return Err(self.retain_dde_callback_entry_error(callback_id, error));
                            }
                            return Ok(Win16DdeCallbackFollowUpDispatch::Resume { origin, step });
                        }
                        Err(error) => {
                            return Err(self.retain_follow_up_failure_from_owner(callback_id, error)?);
                        }
                    }
                }
            }
        }
    }

    fn retain_callback_readback_failure_for_origin(
        &mut self,
        origin: Win16DdeCallbackOrigin,
        error: std::sync::Arc<RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let shared = super::super::callback_lifo::shared_runtime_error(error);
        match origin {
            Win16DdeCallbackOrigin::Foreground(operation) => self
                .retain_foreground_dde_completion_failure(operation, shared)
                .map(|_| ()),
            Win16DdeCallbackOrigin::CallbackFollowUp {
                callback_id,
                host_frame,
                operation,
                ..
            } => self
                .retain_callback_follow_up_failure(
                    callback_id,
                    host_frame,
                    operation,
                    shared,
                )
                .map(|_| ()),
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => Ok(()),
        }
    }


    fn callback_follow_up_native_identity(
        &self,
        callback_id: super::CallbackFrameId,
    ) -> Result<(crate::Win16HostDdeOperation, (crate::Win16HostDdeOwner, u64)), RuntimeError> {
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("DDE callback follow-up lost its exact callback owner")
        })?;
        if frame.callback_id != callback_id || frame.callback_kind_active || frame.active_call.is_some() {
            return Err(invariant(
                "DDE callback follow-up completion is not at its exact retained callback top",
            ));
        }
        let follow_up = frame.pending_follow_up.as_ref().ok_or_else(|| {
            invariant("DDE callback follow-up completion lost its journal")
        })?;
        let continuation = follow_up.continuation.as_deref().ok_or_else(|| {
            invariant("DDE callback follow-up completion lost its continuation")
        })?;
        let operation = continuation.host_operation().ok_or_else(|| {
            invariant("DDE callback follow-up completion has no exact operation identity")
        })?;
        let identity = continuation.host_owner_identity().ok_or_else(|| {
            invariant("DDE callback follow-up completion has no exact native owner generation")
        })?;
        Ok((operation, identity))
    }

    fn cache_next_callback_follow_up_child(
        &mut self,
        callback_id: super::CallbackFrameId,
        step: std::sync::Arc<Win16HostDdeCallbackStep>,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE follow-up child callback has no exact callback owner")
        })?;
        if frame.callback_id != callback_id || frame.callback_kind_active || frame.active_call.is_some() {
            return Err(invariant(
                "DDE follow-up child callback changed its exact retained owner",
            ));
        }
        let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE follow-up child callback lost its owner journal")
        })?;
        let operation = follow_up.continuation.as_deref().and_then(|next| next.host_operation())
            .ok_or_else(|| invariant("DDE follow-up child callback has no exact operation"))?;
        let (owner, generation) = follow_up.continuation.as_deref()
            .and_then(|next| next.host_owner_identity())
            .ok_or_else(|| invariant("DDE follow-up child callback has no owner generation"))?;
        if !step.has_valid_identity()
            || step.parent != Some(operation)
            || step.owner != owner
            || step.worker_generation != generation
        {
            follow_up.completed_step = Some(Win16HostDdeStep::Callback(Arc::clone(&step)));
            return Err(invariant(
                "DDE follow-up child callback changed its exact operation or owner generation",
            ));
        }
        if follow_up.pending_child_callback.is_some() {
            return Err(invariant(
                "DDE follow-up tried to publish a second child before the previous frame retired",
            ));
        }
        if let Some(existing) = follow_up.completed_step.as_ref() {
            if existing != &Win16HostDdeStep::Callback(Arc::clone(&step)) {
                return Err(invariant(
                    "DDE follow-up child callback changed its cached returned step",
                ));
            }
        }
        follow_up.completed_step = Some(Win16HostDdeStep::Callback(Arc::clone(&step)));
        follow_up.pending_child_callback = Some(Arc::clone(&step));
        follow_up.phase = super::runtime_dde::Win16DdeFollowUpPhase::Committed {
            owner: follow_up.owner,
            carrier: super::runtime_dde::Win16DdeFollowUpCarrier::Callback(step),
        };
        Ok(())
    }

    fn cache_callback_follow_up_retired_source(
        &mut self,
        callback_id: super::CallbackFrameId,
        proof: std::sync::Arc<crate::Win16DdeSourceRetiredProof>,
        result: crate::Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE source proof has no callback-owned continuation")
        })?;
        if frame.callback_id != callback_id || frame.callback_kind_active || frame.active_call.is_some() {
            return Err(invariant("DDE source proof changed its exact callback owner"));
        }
        let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE source proof lost its callback-owned follow-up journal")
        })?;
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("DDE source proof lost its exact continuation")
        })?;
        let operation = continuation.host_operation().ok_or_else(|| {
            invariant("DDE source proof has no exact submitted operation")
        })?;
        let (owner, generation) = continuation.host_owner_identity().ok_or_else(|| {
            invariant("DDE source proof has no exact native owner generation")
        })?;
        if !proof.has_valid_identity()
            || proof.operation != operation
            || proof.owner != owner
            || proof.worker_generation != generation
        {
            follow_up.completed_step = Some(Win16HostDdeStep::SourceRetired {
                proof: Arc::clone(&proof),
                result: result.clone(),
            });
            return Err(invariant(
                "DDE source proof changed its exact callback-owned operation identity",
            ));
        }
        if let Some(existing) = follow_up.completed_step.as_ref() {
            if !matches!(existing, Win16HostDdeStep::SourceRetired {
                proof: cached,
                result: cached_result,
            } if cached.as_ref() == proof.as_ref() && cached_result == &result)
                && !matches!(existing, Win16HostDdeStep::Complete(cached) if cached == &result)
            {
                return Err(invariant(
                    "DDE source proof changed its callback-owned cached completion",
                ));
            }
        }
        continuation.cache_native_completion(operation, result.clone())?;
        continuation.mark_normal_source_retirement_pending(operation)?;
        continuation.cache_normal_source_retirement(Arc::clone(&proof), result.clone())?;
        follow_up.completed_step = Some(Win16HostDdeStep::SourceRetired {
            proof: Arc::clone(&proof),
            result: result.clone(),
        });
        follow_up.phase = super::runtime_dde::Win16DdeFollowUpPhase::Committed {
            owner: follow_up.owner,
            carrier: super::runtime_dde::Win16DdeFollowUpCarrier::SourceRetired {
                proof,
                result,
            },
        };
        Ok(())
    }

    fn retain_follow_up_failure_from_owner(
        &mut self,
        callback_id: super::CallbackFrameId,
        error: RuntimeError,
    ) -> Result<RuntimeError, RuntimeError> {
        let error = std::sync::Arc::new(error);
        let (owner_index, owner_host_frame) = {
            let mut matching = self.dde_callbacks.iter().enumerate().filter(|(_, frame)| {
                frame.callback_id == callback_id
            });
            let Some((owner_index, owner)) = matching.next() else {
                return Err(super::super::callback_lifo::shared_runtime_error(
                    std::sync::Arc::clone(&error),
                ).with_cleanup(
                    "retain DDE callback follow-up failure",
                    invariant("DDE callback follow-up failure lost its exact owner frame"),
                ));
            };
            if matching.next().is_some() {
                return Err(super::super::callback_lifo::shared_runtime_error(
                    std::sync::Arc::clone(&error),
                ).with_cleanup(
                    "retain DDE callback follow-up failure",
                    invariant("DDE callback follow-up failure matched duplicate callback IDs"),
                ));
            }
            (owner_index, owner.host_frame)
        };
        if owner_index + 1 < self.dde_callbacks.len() {
            let exact_child = matches!(
                self.dde_callbacks[owner_index + 1].origin,
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id: parent,
                    host_frame,
                    ..
                } if parent == callback_id && host_frame == owner_host_frame
            );
            if !exact_child {
                return Err(super::super::callback_lifo::shared_runtime_error(
                    std::sync::Arc::clone(&error),
                ).with_cleanup(
                    "retain DDE callback follow-up failure",
                    invariant("DDE callback follow-up failure is blocked by a different child owner"),
                ));
            }
            let child = &mut self.dde_callbacks[owner_index + 1];
            if child.pending_callback_error.is_none() {
                child.pending_callback_error = Some(std::sync::Arc::clone(&error));
            }
        }
        let Some(frame) = self.dde_callbacks.get_mut(owner_index) else {
            return Err(super::super::callback_lifo::shared_runtime_error(
                std::sync::Arc::clone(&error),
            ).with_cleanup(
                "retain DDE callback follow-up failure",
                invariant("DDE callback follow-up owner disappeared while retaining its cause"),
            ));
        };
        if frame.pending_callback_error.is_none() {
            frame.pending_callback_error = Some(std::sync::Arc::clone(&error));
        }
        if let Some(continuation) = frame.pending_follow_up.as_mut()
            .and_then(|follow_up| follow_up.continuation.as_deref_mut())
        {
            let _ = continuation.retain_finish_failure(
                super::super::callback_lifo::shared_runtime_error(std::sync::Arc::clone(&error)),
            );
        }
        Ok(super::super::callback_lifo::shared_runtime_error(error))
    }

    /// Submit or replay a WILDCONNECT readback on the callback frame that owns
    /// it. This path never creates a second WindowOperationFrame.
    pub(in crate::win16_runtime) fn submit_dde_callback_follow_up(
        &mut self,
        callback_id: super::CallbackFrameId,
        host: &mut impl RuntimeHost,
    ) -> Result<(
        super::runtime_dde::Win16DdeFollowUpOwner,
        super::runtime_dde::Win16DdeFollowUpCarrier,
    ), RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback follow-up has no retained callback owner")
        })?;
        if frame.callback_id != callback_id
            || frame.callback_kind_active
            || frame.active_call.is_some()
            || !frame.runtime_published
            || !frame.source_step.has_valid_identity()
        {
            return Err(invariant(
                "DDE callback follow-up is not attached to its exact retained callback frame",
            ));
        }
        let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE callback owner has no prepared follow-up journal")
        })?;
        let expected_owner = super::runtime_dde::Win16DdeFollowUpOwner::Callback {
            callback_id: frame.callback_id,
            host_frame: frame.host_frame,
            parent: frame.source_step.parent,
            owner: frame.source_step.owner,
            worker_generation: frame.source_step.worker_generation,
            origin: frame.origin,
        };
        if follow_up.owner != expected_owner {
            return Err(invariant(
                "DDE callback follow-up journal changed its owner, source, or origin",
            ));
        }
        let carrier = super::runtime_dde::submit_callback_owned_dde_follow_up(
            follow_up.owner,
            &follow_up.call,
            &mut follow_up.continuation,
            &mut follow_up.phase,
            host,
        )?;
        if let super::runtime_dde::Win16DdeFollowUpCarrier::SourceRetired {
            proof,
            result,
        } = &carrier
        {
            match follow_up.completed_step.as_ref() {
                None => {
                    follow_up.completed_step = Some(Win16HostDdeStep::SourceRetired {
                        proof: std::sync::Arc::clone(proof),
                        result: result.clone(),
                    });
                }
                Some(Win16HostDdeStep::SourceRetired {
                    proof: existing,
                    result: existing_result,
                }) if existing.as_ref() == proof.as_ref() && existing_result == result => {}
                Some(_) => {
                    return Err(invariant(
                        "DDE callback follow-up source proof changed its retained completion",
                    ));
                }
            }
        } else if let super::runtime_dde::Win16DdeFollowUpCarrier::Callback(step) = &carrier {
            match follow_up.pending_child_callback.as_ref() {
                None => {
                    follow_up.pending_child_callback = Some(std::sync::Arc::clone(step));
                }
                Some(existing) if std::sync::Arc::ptr_eq(existing, step) => {}
                Some(_) => {
                    return Err(invariant(
                        "DDE callback follow-up changed its retained child callback carrier",
                    ));
                }
            }
        }
        Ok((follow_up.owner, carrier))
    }

    /// Retire the exact native operation after a nested follow-up callback has
    /// returned. The full completion is first retained on the callback owner;
    /// a lost reply can therefore be retried by proof lookup without repeating
    /// the DDE Begin, callback reply, or source pop.
    pub(in crate::win16_runtime) fn retire_callback_owned_dde_completion(
        &mut self,
        callback_id: super::CallbackFrameId,
        operation: crate::Win16HostDdeOperation,
        result: &crate::Win16HostDdeResult,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("callback-owned DDE completion has no retained callback frame")
        })?;
        if frame.callback_id != callback_id
            || frame.callback_kind_active
            || frame.active_call.is_some()
            || !frame.runtime_published
        {
            return Err(invariant(
                "callback-owned DDE completion is not attached to its exact retained callback frame",
            ));
        }
        let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE completion has no follow-up journal")
        })?;
        let super::runtime_dde::Win16DdeFollowUpOwner::Callback {
            callback_id: owner_callback,
            host_frame,
            owner,
            worker_generation,
            ..
        } = follow_up.owner
        else {
            return Err(invariant(
                "callback-owned DDE completion changed to an operation-frame owner",
            ));
        };
        if owner_callback != callback_id {
            return Err(invariant(
                "callback-owned DDE completion changed its callback identity",
            ));
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("callback-owned DDE completion lost its continuation")
        })?;
        if continuation.host_operation() != Some(operation)
            || continuation.host_owner_identity() != Some((owner, worker_generation))
            || continuation.cached_native_completion(operation) != Some(result)
        {
            return Err(invariant(
                "callback-owned DDE completion changed its exact operation, owner, or result",
            ));
        }
        match follow_up.completed_step.as_ref() {
            Some(Win16HostDdeStep::SourceRetired {
                proof,
                result: cached,
            }) if proof.operation == operation && cached == result => {
                let carrier = super::runtime_dde::Win16DdeFollowUpCarrier::SourceRetired {
                    proof: Arc::clone(proof),
                    result: cached.clone(),
                };
                follow_up.phase = super::runtime_dde::Win16DdeFollowUpPhase::Committed {
                    owner: follow_up.owner,
                    carrier,
                };
                return Ok(Win16HostDdeStep::SourceRetired {
                    proof: Arc::clone(proof),
                    result: cached.clone(),
                });
            }
            Some(Win16HostDdeStep::Complete(cached)) if cached == result => {}
            None => {
                follow_up.completed_step = Some(Win16HostDdeStep::Complete(result.clone()));
            }
            Some(_) => {
                return Err(invariant(
                    "callback-owned DDE completion retry changed its retained native step",
                ));
            }
        }
        continuation.mark_normal_source_retirement_pending(operation)?;
        let proof_step = match host.win16_dde_retire_completed_source(operation, result) {
            Ok(step) => step,
            Err(error) => {
                return Err(continuation.retain_normal_completion_failure(operation, error)?);
            }
        };
        let Win16HostDdeStep::SourceRetired {
            proof,
            result: retired_result,
        } = proof_step
        else {
            return Err(invariant(
                "DDE normal source retirement did not return its typed proof",
            ));
        };
        if !proof.has_valid_identity()
            || proof.operation != operation
            || proof.owner != owner
            || proof.worker_generation != worker_generation
            || retired_result != *result
        {
            return Err(invariant(
                "callback-owned DDE source retirement changed its exact operation result or owner",
            ));
        }
        continuation.cache_normal_source_retirement(Arc::clone(&proof), retired_result.clone())?;
        follow_up.completed_step = Some(Win16HostDdeStep::SourceRetired {
            proof: Arc::clone(&proof),
            result: retired_result.clone(),
        });
        follow_up.phase = super::runtime_dde::Win16DdeFollowUpPhase::Committed {
            owner: follow_up.owner,
            carrier: super::runtime_dde::Win16DdeFollowUpCarrier::SourceRetired {
                proof: Arc::clone(&proof),
                result: retired_result.clone(),
            },
        };
        let _exact_host_frame = host_frame;
        Ok(Win16HostDdeStep::SourceRetired {
            proof,
            result: retired_result,
        })
    }

    pub(super) fn validate_callback_follow_up_origin(
        &self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        step: &std::sync::Arc<Win16HostDdeCallbackStep>,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("nested DDE follow-up callback lost its exact callback owner")
        })?;
        let expected = super::runtime_dde::Win16DdeFollowUpOwner::Callback {
            callback_id,
            host_frame,
            parent: frame.source_step.parent,
            owner,
            worker_generation,
            origin: frame.origin,
        };
        let exact_carrier = frame.pending_follow_up.as_ref().is_some_and(|follow_up| {
            follow_up.owner == expected
                && matches!(
                    &follow_up.phase,
                    super::runtime_dde::Win16DdeFollowUpPhase::Submitted { owner: actual, .. }
                        | super::runtime_dde::Win16DdeFollowUpPhase::Committed { owner: actual, .. }
                        if *actual == expected
                )
                && follow_up.pending_child_callback.as_ref().is_some_and(|cached| {
                    std::sync::Arc::ptr_eq(cached, step)
                })
                && follow_up.continuation.as_deref().is_some_and(|continuation| {
                    continuation.host_operation() == Some(operation)
                        && continuation.host_owner_identity() == Some((owner, worker_generation))
                })
        });
        if frame.callback_id != callback_id
            || frame.host_frame != host_frame
            || frame.source_step.owner != owner
            || frame.source_step.worker_generation != worker_generation
            || frame.callback_kind_active
            || frame.active_call.is_some()
            || !frame.runtime_published
            || !exact_carrier
            || step.parent != Some(operation)
            || step.owner != owner
            || step.worker_generation != worker_generation
        {
            return Err(invariant(
                "nested DDE callback is not bound to its exact retained callback follow-up",
            ));
        }
        Ok(())
    }

    pub(super) fn reserve_callback_owned_dde_return_transfer(
        &mut self,
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback follow-up lost its return-event owner")
        })?;
        if frame.callback_id != callback_id || frame.host_frame != host_frame {
            return Err(invariant(
                "DDE callback follow-up return-event reservation changed its exact owner",
            ));
        }
        let follow_up = frame.pending_follow_up.as_mut().ok_or_else(|| {
            invariant("DDE callback follow-up lost its return-event continuation")
        })?;
        if follow_up.owner.native_owner_identity() != Some((owner, worker_generation)) {
            return Err(invariant(
                "DDE callback follow-up return-event reservation changed its worker generation",
            ));
        }
        let continuation = follow_up.continuation.as_mut().ok_or_else(|| {
            invariant("DDE callback follow-up has no continuation before guest entry")
        })?;
        if continuation.host_operation() != Some(operation) {
            return Err(invariant(
                "DDE callback follow-up return-event reservation changed its submitted operation",
            ));
        }
        continuation.reserve_guest_return_transfer()
    }

}
