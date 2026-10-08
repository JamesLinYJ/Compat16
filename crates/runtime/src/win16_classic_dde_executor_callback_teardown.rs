//! Exact teardown of entered classic-DDE guest callback frames.

use super::*;

impl Win16State {
    /// Cancel one exact entered DDE callback only after task execution ended.
    /// The captured CPU roots are aborted first; the host source stays live
    /// until the original message has passed through its exact default-proc
    /// reply and returned a matching source-retirement proof.
    pub(in crate::win16_runtime) fn cancel_classic_dde_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::ClassicDde)?;
        let retained = self.classic_dde.callbacks.last().ok_or_else(|| {
            dde_invariant("classic DDE teardown has no exact family callback frame")
        })?;
        if retained.callback_id != callback_id {
            return Err(dde_invariant(
                "classic DDE teardown callback frame changed its shared identity",
            ));
        }
        let has_prepared_document = matches!(
            &retained.continuation.completion,
            super::super::win16_ole1_server_callback::Ole1ServerCallbackCompletion::DdeExecute {
                prepared_document: Some(_),
                ..
            }
        );
        let has_server_release_completion = matches!(
            &retained.continuation.completion,
            super::super::win16_ole1_server_callback::Ole1ServerCallbackCompletion::DdeRelease { .. }
        );
        if retained.continuation.close_document_proof.is_some()
            || has_prepared_document
            || has_server_release_completion
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "classic DDE teardown is blocked by an entered OLE1 server callback with a live business proof; retaining its guest frame and exact host source",
            ));
        }
        let mut frame = self.classic_dde.callbacks.pop().ok_or_else(|| {
            dde_invariant("classic DDE teardown has no exact family callback frame")
        })?;
        if frame.callback_id != callback_id {
            self.classic_dde.callbacks.push(frame);
            return Err(dde_invariant(
                "classic DDE teardown callback frame changed its shared identity",
            ));
        }

        let result = self.cancel_classic_dde_callback_frame_after_abort(
            callback_id,
            ended,
            cpu,
            dos,
            memory,
            host,
            &mut frame,
        );
        if let Err(error) = result {
            self.classic_dde.callbacks.push(frame);
            return Err(error);
        }
        self.retire_callback_binding(CallbackKind::ClassicDde, callback_id)?;
        Ok(())
    }

    fn cancel_classic_dde_callback_frame_after_abort(
        &mut self,
        callback_id: CallbackFrameId,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frame: &mut super::super::classic_dde_dispatch::ClassicDdeGuestCallbackFrame,
    ) -> Result<(), RuntimeError> {
        let callback_step = frame.continuation.callback_step.clone().ok_or_else(|| {
            RuntimeError::new(
                Kind::HostFailure,
                "classic DDE callback teardown has no exact host callback source",
            )
        })?;
        if callback_step.owner != frame.continuation.owner
            || callback_step.endpoint != frame.continuation.endpoint
            || callback_step.event.event_id != frame.continuation.event_id
            || callback_step.event.peer != frame.continuation.peer
            || callback_step.worker_generation == 0
        {
            return Err(dde_invariant(
                "classic DDE teardown callback changed its exact source tuple",
            ));
        }
        let identity = Win16ClassicDdeOperationIdentity {
            owner: callback_step.owner,
            id: callback_step.operation_id,
            worker_generation: callback_step.worker_generation,
        };
        if frame.continuation.operation.is_some_and(|operation| operation != identity) {
            return Err(dde_invariant(
                "classic DDE teardown callback changed its source operation identity",
            ));
        }
        let Some(operation) = self.classic_dde.operations.last() else {
            return Err(dde_invariant(
                "classic DDE teardown callback lost its retained source operation",
            ));
        };
        if operation.identity != identity
            || operation.resume_parent.is_some()
            || !matches!(
                &operation.owner,
                ClassicDdeOperationOwner::PollOwner { .. }
                    | ClassicDdeOperationOwner::PollEndpoint { .. }
            )
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "classic DDE callback source is nested or business-owned and cannot be retired as a poll",
            ));
        }
        let accepted_untranslated_retry = callback_step.source
            == Win16ClassicDdeCallbackSource::ParkedUserWait
            && operation.accepted_untranslated_callbacks.iter().any(|reply| {
                reply.owner == callback_step.owner
                    && reply.endpoint == callback_step.endpoint
                    && reply.operation_id == callback_step.operation_id
                    && reply.worker_generation == callback_step.worker_generation
                    && reply.callback == callback_step.callback
                    && reply.frame == callback_step.frame
                    && reply.event_id == callback_step.event.event_id
                    && reply.peer == callback_step.event.peer
                    && reply.causal_parents == callback_step.causal_parents
                    && matches!(
                        &reply.result,
                        Win16HostClassicDdeCallbackResult::Untranslated
                    )
            });
        match &operation.step {
            Win16HostClassicDdeStep::Callback(source)
                if source.owner == callback_step.owner
                    && source.endpoint == callback_step.endpoint
                    && source.worker_generation == callback_step.worker_generation
                    && source.operation_id == callback_step.operation_id
                    && source.callback == callback_step.callback
                    && source.frame == callback_step.frame
                    && source.event.event_id == callback_step.event.event_id
                    && source.event.peer == callback_step.event.peer => {}
            Win16HostClassicDdeStep::Started(operation)
                if *operation == identity && accepted_untranslated_retry => {}
            Win16HostClassicDdeStep::Complete { .. } => {}
            _ => {
                return Err(dde_invariant(
                    "classic DDE teardown callback is not the retained exact source step",
                ));
            }
        }

        if !frame.guest_frame.is_terminal_aborted() {
            self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::ClassicDde,
                callback_id,
                cpu,
                dos,
                memory,
                &mut frame.guest_frame,
            )?;
        }

        // The callback reply may already have been accepted even when a local
        // HGLOBAL/ATOM cleanup phase failed. Complete those exact phases before
        // attempting a parked-wait retry or consuming any host terminal.
        self.retry_classic_dde_callback_event_cleanup(identity, host)?;

        let current_step = self
            .classic_dde
            .operations
            .last()
            .filter(|operation| operation.identity == identity)
            .map(|operation| operation.step.clone())
            .ok_or_else(|| dde_invariant("classic DDE teardown source operation disappeared"))?;
        let terminal = match current_step {
            Win16HostClassicDdeStep::Callback(_) => {
                let replied = self.resume_classic_dde_host_call(
                    identity,
                    Some(callback_reply(
                        &callback_step,
                        Win16HostClassicDdeCallbackResult::Untranslated,
                    )),
                    host,
                )?;
                match replied {
                    Win16HostClassicDdeStep::Started(operation)
                        if operation == identity
                            && callback_step.source == Win16ClassicDdeCallbackSource::ParkedUserWait =>
                    {
                        self.resume_classic_dde_host_call(identity, None, host)?
                    }
                    terminal => terminal,
                }
            }
            Win16HostClassicDdeStep::Started(operation)
                if operation == identity
                    && callback_step.source == Win16ClassicDdeCallbackSource::ParkedUserWait =>
            {
                self.resume_classic_dde_host_call(identity, None, host)?
            }
            terminal @ Win16HostClassicDdeStep::Complete { .. } => terminal,
            Win16HostClassicDdeStep::StartedFailure(_) => {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "classic DDE callback source failed before an exact retirement receipt",
                ));
            }
            Win16HostClassicDdeStep::Started(_) => {
                return Err(dde_invariant(
                    "classic DDE teardown source returned to Started without a parked-wait receipt",
                ));
            }
        };
        let source_retired = match &terminal {
            Win16HostClassicDdeStep::Complete {
                operation: terminal_operation,
                result: Win16HostClassicDdeResult::CallbackResumed(frame_id),
                source_retired,
            } if *terminal_operation == identity && *frame_id == callback_step.frame => source_retired,
            _ => {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "classic DDE default-procedure reply did not return its exact callback terminal",
                ));
            }
        };
        if source_retired.operation != identity
            || !source_retired.callbacks.iter().any(|retirement| {
                retirement.callback == callback_step.callback
                    && retirement.frame == callback_step.frame
                    && retirement.event_id == callback_step.event.event_id
                    && retirement.endpoint == callback_step.endpoint
                    && retirement.peer == callback_step.event.peer
                    && retirement.result == Win16HostClassicDdeCallbackResult::Untranslated
            })
        {
            return Err(dde_invariant(
                "classic DDE teardown terminal omitted its exact default-procedure source retirement",
            ));
        }

        let (owner, resume_parent) = self.consume_classic_dde_source_retirement(identity, host)?;
        if !matches!(
            owner,
            ClassicDdeOperationOwner::PollOwner { .. }
                | ClassicDdeOperationOwner::PollEndpoint { .. }
        ) || resume_parent.is_some()
        {
            return Err(dde_invariant(
                "classic DDE teardown source retirement changed its exact poll owner",
            ));
        }
        Ok(())
    }

}
