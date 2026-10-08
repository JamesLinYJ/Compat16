impl super::Win16State {

    /// Finish a guest Release triggered by an exact queued TERMINATE. Host
    /// failures preserve the release journal and this event continuation, so
    /// retries run only the unfinished native cleanup phases.
    pub(in crate::win16_runtime) fn finish_ole1_server_release_callback(
        &mut self,
        continuation: &Ole1ServerDdeContinuation,
        callback_result: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
        let Ole1ServerCallbackCompletion::DdeRelease {
            event,
            target,
            release_target,
            journal_id,
        } = &continuation.completion
        else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Release completion received a non-release server callback",
            ));
        };
        if event.owner != continuation.owner
            || event.endpoint != continuation.endpoint
            || event.event_id != continuation.event_id
            || event.peer != continuation.peer
            || !matches!(&event.message, crate::Win16ClassicDdeMessage::Terminate)
            || !callback_target_matches_release(*target, *release_target)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Release completion changed its exact TERMINATE or target",
            ));
        }
        let exact_source = match (&event.delivery, continuation.callback_step.as_ref()) {
            (Win16ClassicDdeDeliveryKind::Queued, None) => continuation.operation.is_none(),
            (
                Win16ClassicDdeDeliveryKind::Synchronous {
                    operation_id,
                    callback,
                    frame,
                },
                Some(step),
            ) => {
                continuation.operation
                    == Some(Win16ClassicDdeOperationIdentity {
                        owner: event.owner,
                        id: *operation_id,
                        worker_generation: event.worker_generation,
                    })
                    && step.owner == event.owner
                    && step.endpoint == event.endpoint
                    && step.operation_id == *operation_id
                    && step.callback == *callback
                    && step.frame == *frame
                    && step.event == *event
            }
            _ => false,
        };
        if !exact_source {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Release completion lost its exact DDE callback source",
            ));
        }
        match self
            .ole1_server_state
            .pending_release_completion(*journal_id)
        {
            Some(entry)
                if entry.owner == event.owner
                    && entry.target == *release_target
                    && entry.callback_result
                        == super::win16_ole1_server_state::Ole1ReleaseCallbackResult::Returned(
                            callback_result as u16,
                        ) => {}
            Some(_) => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 Release retry changed its exact callback journal",
                ));
            }
            None => {
                self.ole1_server_state
                    .begin_release_completion(
                        *journal_id,
                        event.owner,
                        *release_target,
                        callback_result as u16,
                    )
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot begin exact OLE1 DDE Release completion ({status})"),
                        )
                    })?;
            }
        }
        let release_outcome = if event.delivery == Win16ClassicDdeDeliveryKind::Queued {
            super::ole1::finish_server_release_completion_for_dde(
                &mut self.ole1_server_state,
                *journal_id,
                *release_target,
                host,
            )?
        } else {
            super::ole1::finish_server_release_completion(
                &mut self.ole1_server_state,
                *journal_id,
                *release_target,
                host,
            )?;
            super::ole1::Ole1ReleaseEndpointOutcome::Complete
        };
        if let super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(pending) = release_outcome {
            let chain = self
                .ole1_server_state
                .dde_release_chain_for_event(event)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("OLE1 DDE release callback lost its EventId chain ({status})"),
                    )
                })?
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "queued OLE1 Release callback has no retained EventId chain",
                    )
                })?;
            let disposition =
                self.wait_for_release_endpoint_events(event, &chain, *release_target, pending)?;
            return disposition_into_callback_finish(disposition);
        }
        let next_target = self
            .ole1_server_state
            .release_target_after_completion(event.owner, *release_target);
        if event.delivery == Win16ClassicDdeDeliveryKind::Queued {
            let chain = self
                .ole1_server_state
                .dde_release_chain_for_event(event)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("OLE1 DDE release callback lost its EventId chain ({status})"),
                    )
                })?
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "queued OLE1 Release callback has no retained EventId chain",
                    )
                })?;
            if !chain.event_acknowledged {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 queued Release retired its endpoint before the exact EventId ACK",
                ));
            }
            self.ole1_server_state
                .advance_dde_release_chain(event, *release_target, next_target)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("cannot advance completed OLE1 DDE Release ({status})"),
                    )
                })?;
            if next_target.is_some() {
                let disposition = self.resume_server_release_chain(
                    event,
                    continuation
                        .callback_step
                        .as_ref()
                        .map(|step| Arc::new(step.clone())),
                    memory,
                    host,
                )?;
                return disposition_into_callback_finish(disposition);
            }
            finish_exact_dde_release_chain(&mut self.ole1_server_state, event)?;
            return Ok(Ole1ServerGuestCallbackFinish::Complete);
        }
        if let Some(next_target) = next_target {
            let plan = self.server_release_callback_plan(event, next_target, memory)?;
            let next_continuation = self.server_dde_continuation(
                event,
                continuation
                    .callback_step
                    .as_ref()
                    .map(|step| Arc::new(step.clone())),
                plan.target,
                plan.completion.clone(),
            )?;
            return Ok(Ole1ServerGuestCallbackFinish::GuestCallback {
                plan,
                continuation: next_continuation,
            });
        }
        let Win16ClassicDdeDeliveryKind::Synchronous {
            operation_id,
            callback,
            frame,
        } = event.delivery
        else {
            unreachable!("queued DDE release returned above")
        };
        let reply = crate::Win16HostClassicDdeCallbackReply {
            owner: event.owner,
            endpoint: event.endpoint,
            operation_id,
            worker_generation: event.worker_generation,
            callback,
            frame,
            event_id: event.event_id,
            peer: event.peer,
            causal_parents: continuation
                .callback_step
                .as_ref()
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "synchronous OLE1 Release completion lost its callback parent chain",
                    )
                })?
                .causal_parents
                .clone(),
            result: crate::Win16HostClassicDdeCallbackResult::WindowProcedure(0),
        };
        Ok(Ole1ServerGuestCallbackFinish::Resume {
            resume: crate::Win16HostClassicDdeResume {
                operation: crate::Win16ClassicDdeOperationIdentity {
                    owner: event.owner,
                    id: operation_id,
                    worker_generation: event.worker_generation,
                },
                reply: Some(reply),
            },
        })
    }

    fn server_dde_continuation(
        &self,
        event: &Win16HostClassicDdeEvent,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        target: Ole1ServerCallbackTarget,
        completion: Ole1ServerCallbackCompletion,
    ) -> Result<Ole1ServerDdeContinuation, RuntimeError> {
        if let Some(step) = &callback_step {
            if step.owner != event.owner
                || step.endpoint != event.endpoint
                || step.worker_generation != event.worker_generation
                || step.event != *event
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 continuation was not derived from its exact classic-DDE callback step",
                ));
            }
        }
        let (server, server_generation, document, document_generation) = match target {
            Ole1ServerCallbackTarget::Server { handle, generation } => {
                let record = self
                    .ole1_server_state
                    .server(event.owner, handle)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 server disappeared while preparing its DDE callback",
                        )
                    })?;
                if record.generation != generation {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 server generation changed while preparing its DDE callback",
                    ));
                }
                (handle, generation, None, None)
            }
            Ole1ServerCallbackTarget::Document { handle, generation } => {
                let document = self
                    .ole1_server_state
                    .document(event.owner, handle)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 server document disappeared while preparing its DDE callback",
                        )
                    })?;
                if document.generation != generation {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 server document generation changed while preparing its DDE callback",
                    ));
                }
                let server = self
                    .ole1_server_state
                    .server(event.owner, document.server)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 document parent disappeared while preparing its DDE callback",
                        )
                    })?;
                (
                    document.server,
                    server.generation,
                    Some(handle),
                    Some(generation),
                )
            }
        };
        let operation = callback_step
            .as_ref()
            .map(|step| Win16ClassicDdeOperationIdentity {
                owner: step.owner,
                id: step.operation_id,
                worker_generation: step.worker_generation,
            });
        Ok(Ole1ServerDdeContinuation {
            owner: event.owner,
            endpoint: event.endpoint,
            event_id: event.event_id,
            callback_step: callback_step.as_ref().map(|step| step.as_ref().clone()),
            operation,
            peer: event.peer,
            server,
            server_generation,
            document,
            document_generation,
            close_document_proof: None,
            completion,
        })
    }
}
