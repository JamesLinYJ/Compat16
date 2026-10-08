//! Exact operation and callback-source lifecycle for the DDEML owner.

use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeCallbackReply,
    Win16DdeOperationRequestPhase, Win16DdeOperationStartedFailure,
    Win16DdeSourceRetiredProof, Win16HostDdeCallbackFrame, Win16HostDdeOperation,
    Win16HostDdeResult, Win16HostDdeResume, Win16HostDdeStep,
};

use super::{Win16DdeHost, errors};

impl Win16DdeHost {
    /// Retain the exact submitted DDE operation when a later wait/resume fails.
    /// Only the operation ledger created before command submission can produce
    /// this carrier; absent active-map membership is never interpreted as a
    /// successful terminal result.
    pub(in crate::windows) fn started_failure_after_submission(
        &self,
        operation: Win16HostDdeOperation,
        fallback: Arc<RuntimeError>,
    ) -> Option<Arc<Win16DdeOperationStartedFailure>> {
        let record = self.pending_operation_instances.get(&operation)?;
        let phase = record.request_phase?;
        if phase == Win16DdeOperationRequestPhase::NativeCompleteReturned {
            return None;
        }
        let cause = match phase {
            Win16DdeOperationRequestPhase::SubmittedPending => {
                record.failure.clone().unwrap_or(fallback)
            }
            Win16DdeOperationRequestPhase::NativeCompleteError => record.failure.clone()?,
            Win16DdeOperationRequestPhase::NativeCompleteReturned => return None,
        };
        Some(Arc::new(Win16DdeOperationStartedFailure {
            operation,
            owner: self.owner,
            worker_generation: self.worker_generation,
            request_phase: phase,
            cause,
        }))
    }

    pub(in crate::windows) fn normal_source_operation_known(
        &self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        if !proof.has_valid_identity()
            || proof.owner != self.owner
            || proof.worker_generation != self.worker_generation
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source proof names a different owner or generation",
            ));
        }
        let Some(record) = self.pending_operation_instances.get(&proof.operation) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source proof names an unknown operation",
            ));
        };
        Ok(matches!(
            record.request_phase,
            Some(
                Win16DdeOperationRequestPhase::SubmittedPending
                    | Win16DdeOperationRequestPhase::NativeCompleteReturned
            )
        ) && (record.request_phase
            != Some(Win16DdeOperationRequestPhase::NativeCompleteReturned)
            || record.completed_result.is_some()))
    }

    pub(in crate::windows) fn normal_completed_operation_matches(
        &self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<bool, RuntimeError> {
        if !proof.has_valid_identity()
            || proof.owner != self.owner
            || proof.worker_generation != self.worker_generation
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source proof names a different owner or generation",
            ));
        }
        let Some(record) = self.pending_operation_instances.get(&proof.operation) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source proof names an unknown operation",
            ));
        };
        Ok(record.request_phase == Some(Win16DdeOperationRequestPhase::NativeCompleteReturned)
            && record.completed_result.is_some()
            && !self.pending_operations.contains(&proof.operation)
            && !self.operation_has_pending_callback(proof.operation)
            && !self.pending_transfer_guards.contains_key(&proof.operation))
    }

    pub(in crate::windows) fn normal_source_retired_proof(
        &self,
        operation: Win16HostDdeOperation,
        result: &Win16HostDdeResult,
    ) -> Result<Win16DdeSourceRetiredProof, RuntimeError> {
        let record = self.pending_operation_instances.get(&operation).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal completion has no exact host operation record",
            )
        })?;
        if operation.0 == 0
            || record.request_phase != Some(Win16DdeOperationRequestPhase::NativeCompleteReturned)
            || self.pending_operations.contains(&operation)
            || record.completed_result.as_ref() != Some(result)
            || self.operation_has_pending_callback(operation)
            || self.pending_transfer_guards.contains_key(&operation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source retirement lacks an actual returned Complete record",
            ));
        }
        Ok(Win16DdeSourceRetiredProof {
            operation,
            owner: self.owner,
            worker_generation: self.worker_generation,
        })
    }

    pub(in crate::windows) fn normal_completion_result(
        &self,
        operation: Win16HostDdeOperation,
    ) -> Option<Win16HostDdeResult> {
        let record = self.pending_operation_instances.get(&operation)?;
        (record.request_phase == Some(Win16DdeOperationRequestPhase::NativeCompleteReturned))
            .then(|| record.completed_result.clone())
            .flatten()
    }

    /// Drop a normal-completion tombstone only after runtime guest projection
    /// and CPU restoration have succeeded. All checks precede the infallible
    /// map removal so this method has no post-mutation failure path.
    pub(in crate::windows) fn consume_normal_source_retirement(
        &mut self,
        proof: &Win16DdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        if !proof.has_valid_identity()
            || proof.owner != self.owner
            || proof.worker_generation != self.worker_generation
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source retirement changed its exact owner identity",
            ));
        }
        let record = self.pending_operation_instances.get(&proof.operation).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source retirement lost its exact completion record",
            )
        })?;
        if record.request_phase != Some(Win16DdeOperationRequestPhase::NativeCompleteReturned)
            || self.pending_operations.contains(&proof.operation)
            || self.operation_has_pending_callback(proof.operation)
            || self.pending_transfer_guards.contains_key(&proof.operation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE normal source retirement still has native operation or transfer ownership",
            ));
        }
        self.pending_operation_instances.remove(&proof.operation);
        Ok(())
    }

    pub fn operation_has_pending_callback(&self, operation: Win16HostDdeOperation) -> bool {
        self.pending_callbacks
            .values()
            .any(|pending| pending.parent == Some(operation))
    }

    pub fn callback_source_matches(&self, step: &runtime::Win16HostDdeCallbackStep) -> bool {
        step.has_valid_identity()
            && step.owner == self.owner
            && step.worker_generation == self.worker_generation
            && self.pending_callbacks.get(&step.frame).is_some_and(|pending| {
                pending.parent == step.parent && pending.instance == step.callback.host_instance
            })
    }

    pub fn callback_frame_retired(
        &mut self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        instance: runtime::Win16HostDdeInstance,
        owner: runtime::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        if owner != self.owner || worker_generation != self.worker_generation {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retirement changed its native owner or worker generation",
            ));
        }
        let pending = self.pending_callbacks.get(&frame).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE runtime retired a callback frame absent from the host owner ledger",
            )
        })?;
        if pending.parent != parent || pending.instance != instance || !pending.acknowledged {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retirement does not match its acknowledged parent and instance",
            ));
        }
        self.pending_callbacks.remove(&frame);
        Ok(())
    }

    /// Resume one suspended native callback. For an unsolicited callback the
    /// returned completion acknowledges only that callback frame; it does not
    /// stand in for a guest-initiated DDE API call.
    pub fn resume(&mut self, resume: Win16HostDdeResume) -> Result<Win16HostDdeStep, RuntimeError> {
        let pending = self.pending_callbacks.get(&resume.frame).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback continuation does not name a pending callback frame",
            )
        })?;
        if pending
            .resume_reply
            .as_ref()
            .is_some_and(|cached| cached != &resume.reply)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retry changed its exact guest reply",
            ));
        }
        if let Some(failure) = pending.resume_failure.as_ref() {
            return Err(super::shared_runtime_error(
                Arc::clone(failure),
                "retry cached DDE callback continuation failure",
            ));
        }
        if let Some(step) = pending.resume_step.as_ref() {
            return Ok(step.clone());
        }
        if pending.resume_reply.is_none() {
            let saved_reply = clone_callback_reply_for_retry(&resume.reply)?;
            let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback owner disappeared before reply reservation",
                )
            })?;
            pending.resume_reply = Some(saved_reply);
        }
        let (parent, reply_sent, reply_sender) = {
            let pending = self.pending_callbacks.get(&resume.frame).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback owner disappeared before reply submission",
                )
            })?;
            (pending.parent, pending.reply_sent, pending.reply.clone())
        };
        if !reply_sent {
            if reply_sender.send(resume.reply).is_err() {
                return Err(super::disconnected("resume a native DDE callback"));
            }
            if let Some(pending) = self.pending_callbacks.get_mut(&resume.frame) {
                pending.reply_sent = true;
            }
        }

        let cached_acknowledgement = self
            .pending_callbacks
            .get(&resume.frame)
            .and_then(|pending| pending.acknowledgement_result.clone());
        let acknowledgement = match cached_acknowledgement {
            Some(result) => result,
            None => match self.wait_for_callback_completion(resume.frame, parent) {
                Ok(Ok(())) => {
                    if let Some(pending) = self.pending_callbacks.get_mut(&resume.frame) {
                        pending.acknowledged = true;
                        pending.acknowledgement_result = Some(Ok(()));
                    }
                    Ok(())
                }
                Ok(Err(error)) => {
                    let failure = Arc::new(error);
                    if let Some(pending) = self.pending_callbacks.get_mut(&resume.frame) {
                        pending.acknowledged = true;
                        pending.acknowledgement_failure = Some(Arc::clone(&failure));
                        pending.acknowledgement_result = Some(Err(Arc::clone(&failure)));
                    }
                    Err(failure)
                }
                Err(error) => return Err(error),
            },
        };

        if let Some(parent) = parent {
            let step = match self.continue_operation(parent) {
                Ok(step) => {
                    let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback owner disappeared after its operation step",
                        )
                    })?;
                    match pending.resume_step.as_ref() {
                        Some(existing) if existing != &step => {
                            return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "DDE callback retry changed its cached operation step",
                            ));
                        }
                        Some(_) => {}
                        None => pending.resume_step = Some(step.clone()),
                    }
                    step
                }
                Err(operation_error) => {
                    if self.pending_operations.contains(&parent) {
                        return match acknowledgement {
                            Ok(()) => Err(operation_error),
                            Err(ack_error) => Err(errors::combine_cleanup_errors(
                                operation_error,
                                super::shared_runtime_error(
                                    Arc::clone(&ack_error),
                                    "native DDE callback acknowledgement failed",
                                ),
                                "DDE operation wait and callback ACK both failed",
                            )),
                        };
                    }
                    let reported = match acknowledgement {
                        Ok(()) => operation_error,
                        Err(ack_error) => errors::combine_cleanup_errors(
                            operation_error,
                            super::shared_runtime_error(
                                Arc::clone(&ack_error),
                                "native DDE callback acknowledgement failed",
                            ),
                            "DDE operation completion and callback ACK both failed",
                        ),
                    };
                    let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback owner disappeared after terminal operation failure",
                        )
                    })?;
                    let reported = Arc::new(reported);
                    pending.resume_failure = Some(Arc::clone(&reported));
                    return Err(super::shared_runtime_error(
                        reported,
                        "DDE callback continuation failed after terminal operation completion",
                    ));
                }
            };
            match acknowledgement {
                Ok(()) => Ok(step),
                Err(error) => {
                    let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback owner disappeared after ACK failure",
                        )
                    })?;
                    pending.resume_failure = Some(Arc::clone(&error));
                    Err(super::shared_runtime_error(
                        error,
                        "native DDE callback acknowledgement failed",
                    ))
                }
            }
        } else {
            match acknowledgement {
                Ok(()) => {
                    let step = Win16HostDdeStep::CallbackFrameComplete {
                    frame: resume.frame,
                    };
                    let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "unsolicited DDE callback owner disappeared after ACK",
                        )
                    })?;
                    pending.resume_step = Some(step.clone());
                    Ok(step)
                }
                Err(error) => {
                    let pending = self.pending_callbacks.get_mut(&resume.frame).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "unsolicited DDE callback owner disappeared after ACK failure",
                        )
                    })?;
                    pending.resume_failure = Some(Arc::clone(&error));
                    Err(super::shared_runtime_error(
                        error,
                        "native unsolicited DDE callback acknowledgement failed",
                    ))
                }
            }
        }
    }
}

fn clone_callback_reply_for_retry(
    reply: &Win16DdeCallbackReply,
) -> Result<Win16DdeCallbackReply, RuntimeError> {
    match reply {
        Win16DdeCallbackReply::WildConnect { source, pairs } => {
            let mut copied = Vec::new();
            copied.try_reserve_exact(pairs.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain native DDE WILDCONNECT callback reply before submission",
                    error,
                )
            })?;
            copied.extend_from_slice(pairs);
            Ok(Win16DdeCallbackReply::WildConnect {
                source: *source,
                pairs: copied,
            })
        }
        reply => Ok(reply.clone()),
    }
}
