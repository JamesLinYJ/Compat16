impl super::Win16State {
    fn route_classic_dde_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        _cpu: &mut Cpu,
        _dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        if let Some(cleanup) = self
            .ole1_server_state
            .unpublished_cleanup_for_endpoint(event.owner, event.endpoint)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("ambiguous OLE1 unpublished endpoint cleanup ({status})"),
                )
            })?
        {
            if cleanup.worker_generation != Some(event.worker_generation) {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "unpublished OLE1 DDE endpoint event changed worker generation",
                ));
            }
            let owns = match event.delivery {
                Win16ClassicDdeDeliveryKind::Queued => self
                    .ole1_server_state
                    .unpublished_cleanup_owns_event(event)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot match unpublished OLE1 EventId ({status})"),
                        )
                    })?,
                Win16ClassicDdeDeliveryKind::Synchronous { .. } => true,
            };
            if !owns {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "unpublished OLE1 endpoint delivered an EventId absent from its exact retirement receipt",
                ));
            }
            return Ok(Ole1ServerDdeDisposition::UnpublishedCleanupEvent {
                cleanup_id: cleanup.id,
                event: event.clone(),
            });
        }
        let is_server = self
            .ole1_server_state
            .server_for_endpoint(event.owner, event.endpoint)
            .is_some();
        let is_document = self
            .ole1_server_state
            .document_for_endpoint(event.owner, event.endpoint)
            .is_some();
        if !is_server && !is_document {
            return Ok(Ole1ServerDdeDisposition::NotOwned);
        }
        let registered_worker_generation = self
            .ole1_server_state
            .server_for_endpoint(event.owner, event.endpoint)
            .map(|(_, server)| server.endpoint_worker_generation)
            .or_else(|| {
                self.ole1_server_state
                    .document_for_endpoint(event.owner, event.endpoint)
                    .map(|(_, document)| document.endpoint_worker_generation)
            });
        if registered_worker_generation != Some(event.worker_generation)
            || event.worker_generation == 0
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE event belongs to a stale worker generation for its OLE endpoint",
            ));
        }
        let blocked = self
            .ole1_server_state
            .server_for_any_endpoint(event.owner, event.endpoint)
            .is_some_and(|(_, server)| server.blocked && !server.processing_deferred_message);
        if blocked {
            if let Some(step) = callback_step.clone() {
                self.ole1_server_state
                    .defer_classic_dde_event(event.owner, event, step)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::ResourceExhausted,
                            format!("cannot retain blocked OLE1 DDE message ({status})"),
                        )
                    })?;
                return Ok(Ole1ServerDdeDisposition::Deferred);
            }
            return Ok(Ole1ServerDdeDisposition::DeferredEvent(event.clone()));
        }
        let (system_topic, ole_topic) = if is_server {
            let system = host.win16_global_find_atom(Win16HostAtomName::String(b"System"))?;
            let ole = host.win16_global_find_atom(Win16HostAtomName::String(b"OLE"))?;
            let system = (system != 0).then_some(system);
            let ole = (ole != 0).then_some(ole);
            (system, ole)
        } else {
            (None, None)
        };
        if let crate::Win16ClassicDdeMessage::Initiate { application, topic } = &event.message {
            // The native USER worker supplies atom spellings, not native
            // ATOM integers. Resolve each spelling through the guest global
            // atom service before comparing Win16 atom identities.
            let application = atom_value(application, host)?;
            let topic = atom_value(topic, host)?;
            let disposition = route_server_initiate(
                &self.ole1_server_state,
                event,
                application,
                topic,
                system_topic,
                ole_topic,
            )
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("invalid OLE1 server INITIATE state ({status})"),
                )
            })?;
            let disposition =
                self.bind_server_initiate_continuation(disposition, callback_step.clone())?;
            if disposition == Ole1ServerDdeDisposition::Deferred {
                let step = callback_step.ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "blocked OLE1 server INITIATE has no exact suspended callback step",
                    )
                })?;
                self.ole1_server_state
                    .defer_classic_dde_event(event.owner, event, step)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::ResourceExhausted,
                            format!("cannot retain blocked OLE1 DDE event ({status})"),
                        )
                    })?;
            }
            return Ok(disposition);
        }
        if matches!(&event.message, crate::Win16ClassicDdeMessage::Terminate) {
            return self.route_server_terminate(event, callback_step, memory, host);
        }
        if matches!(
            &event.message,
            crate::Win16ClassicDdeMessage::Execute { .. }
        ) {
            return match self.prepare_server_execute_callback(event, memory, host)? {
                Ok(Some(plan)) => {
                    let completion = plan.completion.clone();
                    let close_document_proof = match (&completion, plan.target) {
                        (
                            Ole1ServerCallbackCompletion::DdeExecute {
                                allow_document_self_retirement: true,
                                ..
                            },
                            Ole1ServerCallbackTarget::Document { handle, generation },
                        ) => Some((event.owner, handle, generation)),
                        (
                            Ole1ServerCallbackCompletion::DdeExecute {
                                allow_document_self_retirement: true,
                                ..
                            },
                            _,
                        ) => {
                            return Err(RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "StdCloseDocument callback has no exact document target",
                            ));
                        }
                        _ => None,
                    };
                    let mut continuation = self.server_dde_continuation(
                        event,
                        callback_step,
                        plan.target,
                        completion,
                    )?;
                    if let Some((owner, handle, generation)) = close_document_proof {
                        if let Err(status) = self
                            .ole1_server_state
                            .begin_close_document_callback(owner, handle, generation)
                        {
                            return Ok(Ole1ServerDdeDisposition::ProtocolResult {
                                event: event.clone(),
                                status,
                            });
                        }
                    }
                    continuation.close_document_proof = close_document_proof;
                    Ok(Ole1ServerDdeDisposition::GuestCallback {
                        far: plan.procedure,
                        args: plan.arguments,
                        return_kind: plan.return_kind,
                        continuation,
                    })
                }
                Ok(None) => Ok(Ole1ServerDdeDisposition::ProtocolResult {
                    event: event.clone(),
                    status: super::win16_ole1_server_state::OLE_OK,
                }),
                Err(status) => Ok(Ole1ServerDdeDisposition::ProtocolResult {
                    event: event.clone(),
                    status,
                }),
            };
        }
        Ok(Ole1ServerDdeDisposition::OwnedMessage(event.clone()))
    }

    fn route_server_terminate(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        let Some(conversation) = event.conversation else {
            return event_delivery_complete(event, false, callback_step.as_ref());
        };
        // A queued EventId can be polled again after a native atom/endpoint
        // cleanup failure. The conversation was already retired before that
        // cleanup began, so route the retained release chain before ordinary
        // conversation classification. If a release journal exists, finish
        // only its outstanding host phase; never call guest Release twice.
        if event.delivery == Win16ClassicDdeDeliveryKind::Queued {
            if let Some(chain) = self
                .ole1_server_state
                .dde_release_chain_for_event(event)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("OLE1 DDE release EventId changed identity ({status})"),
                    )
                })?
            {
                if let Some(target) = chain.next_target {
                    if let Some(journal) = self
                        .ole1_server_state
                        .release_completion_for_target(event.owner, target)
                    {
                        match super::ole1::finish_server_release_completion_for_dde(
                            &mut self.ole1_server_state,
                            journal.callback_id,
                            target,
                            host,
                        )? {
                            super::ole1::Ole1ReleaseEndpointOutcome::Complete => {
                                if !chain.event_acknowledged {
                                    return Err(RuntimeError::new(
                                        crate::DiagnosticKind::InternalInvariant,
                                        "queued OLE1 release retired its endpoint before EventId acknowledgement",
                                    ));
                                }
                                let next = self
                                    .ole1_server_state
                                    .release_target_after_completion(event.owner, target);
                                self.ole1_server_state
                                    .advance_dde_release_chain(event, target, next)
                                    .map_err(|status| {
                                        RuntimeError::new(
                                            crate::DiagnosticKind::InternalInvariant,
                                            format!(
                                                "cannot advance retried OLE1 DDE release ({status})"
                                            ),
                                        )
                                    })?;
                            }
                            super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(pending) => {
                                return self.wait_for_release_endpoint_events(
                                    event, &chain, target, pending,
                                );
                            }
                        }
                    }
                }
                return self.resume_server_release_chain(event, callback_step, memory, host);
            }
        }
        match self.ole1_server_state.classify_terminate(
            event.owner,
            event.endpoint,
            conversation,
            event.peer,
        ) {
            super::win16_ole1_server_state::Ole1TerminateDisposition::Stale => {
                // Event acknowledgement only retires this copied mailbox
                // delivery. It is not a WM_DDE_ACK and cannot release a
                // conversation belonging to another peer/generation.
                event_delivery_complete(event, false, callback_step.as_ref())
            }
            super::win16_ole1_server_state::Ole1TerminateDisposition::RevocationPostInFlight(_) => {
                Ok(Ole1ServerDdeDisposition::AwaitHostOperation {
                    event: event.clone(),
                    callback_step: callback_step.as_ref().map(|step| step.as_ref().clone()),
                })
            }
            super::win16_ole1_server_state::Ole1TerminateDisposition::RevocationAck(target) => {
                let retired = self
                    .ole1_server_state
                    .retire_terminated_conversation(
                        event.owner,
                        target,
                        conversation,
                        event.peer,
                        true,
                    )
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot retire exact OLE1 revocation ACK ({status})"),
                        )
                    })?;
                if !retired {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "classified OLE1 revocation TERMINATE did not retire its exact conversation",
                    ));
                }
                self.begin_release_after_terminate(event, callback_step, target, memory, host)
            }
            super::win16_ole1_server_state::Ole1TerminateDisposition::PeerInitiated(target) => {
                Ok(Ole1ServerDdeDisposition::BeginHostCall {
                    call: Win16HostClassicDdeCall::Post {
                        owner: event.owner,
                        endpoint: event.endpoint,
                        target: event.peer,
                        conversation,
                        transaction: None,
                        message: crate::Win16ClassicDdeMessage::Terminate,
                    },
                    continuation: Ole1ServerDdeHostContinuation::TerminateResponse {
                        event: event.clone(),
                        target,
                        callback_step: callback_step.as_ref().map(|step| step.as_ref().clone()),
                    },
                })
            }
        }
    }

    pub(super) fn begin_release_after_terminate(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        completed_target: Ole1TerminationTarget,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            let Some(target) = release_target_for_termination(
                &self.ole1_server_state,
                event.owner,
                completed_target,
            ) else {
                return event_delivery_complete(event, false, callback_step.as_ref());
            };
            return self
                .server_release_callback_plan(event, target, memory)
                .and_then(|plan| {
                    let continuation = self.server_dde_continuation(
                        event,
                        callback_step,
                        plan.target,
                        plan.completion.clone(),
                    )?;
                    Ok(Ole1ServerDdeDisposition::GuestCallback {
                        far: plan.procedure,
                        args: plan.arguments,
                        return_kind: plan.return_kind,
                        continuation,
                    })
                });
        }
        if let Some(target) =
            release_target_for_termination(&self.ole1_server_state, event.owner, completed_target)
        {
            if self
                .ole1_server_state
                .release_completion_for_target(event.owner, target)
                .is_some()
            {
                // A public RevokeServer/RevokeServerDoc continuation already
                // owns this exact Release and endpoint journal. Do not create
                // a second DDE-owned Release chain; acknowledge this queued
                // delivery and let the API journal consume its exact EventId.
                return event_delivery_complete(event, false, None);
            }
        }
        if self
            .ole1_server_state
            .dde_release_chain_for_event(event)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 DDE release EventId changed identity ({status})"),
                )
            })?
            .is_none()
        {
            if let Some(first_target) = release_target_for_termination(
                &self.ole1_server_state,
                event.owner,
                completed_target,
            ) {
                self.ole1_server_state
                    .begin_dde_release_chain(event, first_target)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot retain OLE1 DDE release EventId ({status})"),
                        )
                    })?;
            } else {
                return event_delivery_complete(event, false, None);
            }
        }
        self.resume_server_release_chain(event, callback_step, memory, host)
    }

    fn resume_server_release_chain(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        let chain = self
            .ole1_server_state
            .dde_release_chain_for_event(event)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 DDE release chain changed EventId identity ({status})"),
                )
            })?
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "queued OLE1 TERMINATE release lost its exact EventId chain",
                )
            })?;
        let Some(mut next) = chain.next_target else {
            if chain.event_acknowledged {
                finish_exact_dde_release_chain(&mut self.ole1_server_state, event)?;
                return Ok(Ole1ServerDdeDisposition::ReleaseComplete);
            }
            return event_delivery_complete(event, true, callback_step.as_ref());
        };
        loop {
            let target = next;
            let release_journal = self
                .ole1_server_state
                .release_completion_for_target(event.owner, target);
            let missing_document_callback = match target {
                Ole1ReleaseTarget::Document {
                    handle, generation, ..
                } => self
                    .ole1_server_state
                    .document(event.owner, handle)
                    .filter(|document| document.generation == generation)
                    .is_some_and(|document| document.server_document_far.is_none()),
                Ole1ReleaseTarget::Server { .. } => false,
            };
            if release_journal.is_some() || missing_document_callback {
                let outcome = if let Some(journal) = release_journal {
                    super::ole1::finish_server_release_completion_for_dde(
                        &mut self.ole1_server_state,
                        journal.callback_id,
                        target,
                        host,
                    )?
                } else {
                    super::ole1::finish_release_without_guest_callback_for_dde(
                        self,
                        event.owner,
                        target,
                        host,
                    )?
                };
                match outcome {
                    super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(pending) => {
                        return self
                            .wait_for_release_endpoint_events(event, &chain, target, pending);
                    }
                    super::ole1::Ole1ReleaseEndpointOutcome::Complete => {
                        if !chain.event_acknowledged {
                            return Err(RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "queued OLE1 release retired its endpoint before EventId acknowledgement",
                            ));
                        }
                        let next_target = self
                            .ole1_server_state
                            .release_target_after_completion(event.owner, target);
                        self.ole1_server_state
                            .advance_dde_release_chain(event, target, next_target)
                            .map_err(|status| {
                                RuntimeError::new(
                                    crate::DiagnosticKind::InternalInvariant,
                                    format!("cannot advance OLE1 DDE release chain ({status})"),
                                )
                            })?;
                        let Some(target) = next_target else {
                            finish_exact_dde_release_chain(&mut self.ole1_server_state, event)?;
                            return Ok(Ole1ServerDdeDisposition::ReleaseComplete);
                        };
                        next = target;
                        continue;
                    }
                }
            }
            return self
                .server_release_callback_plan(event, target, memory)
                .and_then(|plan| {
                    let continuation = self.server_dde_continuation(
                        event,
                        callback_step.clone(),
                        plan.target,
                        plan.completion.clone(),
                    )?;
                    Ok(Ole1ServerDdeDisposition::GuestCallback {
                        far: plan.procedure,
                        args: plan.arguments,
                        return_kind: plan.return_kind,
                        continuation,
                    })
                });
        }
    }

    fn wait_for_release_endpoint_events(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        chain: &super::win16_ole1_server_state::Ole1ServerDdeReleaseChain,
        target: Ole1ReleaseTarget,
        pending_events: Vec<crate::Win16ClassicDdeEventId>,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        if pending_events.is_empty() {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "RetireEndpoint reported pending state without an EventId",
            ));
        }
        let endpoint = release_target_endpoint(target);
        if !chain.event_acknowledged {
            if endpoint != chain.event.endpoint || !pending_events.contains(&chain.event.event_id) {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "RetireEndpoint did not retain the exact unacknowledged OLE1 TERMINATE EventId",
                ));
            }
            self.ole1_server_state
                .record_dde_release_pending_events(&chain.event, target, pending_events)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("cannot retain OLE1 endpoint's pending EventIds ({status})"),
                    )
                })?;
            return event_delivery_complete(event, true, None);
        }
        if endpoint == event.endpoint && pending_events.contains(&event.event_id) {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "RetireEndpoint receipt still lists an acknowledged EventId",
            ));
        }
        self.ole1_server_state
            .record_dde_release_pending_events(&chain.event, target, pending_events.clone())
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot retain OLE1 endpoint's pending EventIds ({status})"),
                )
            })?;
        Ok(Ole1ServerDdeDisposition::ReleaseEndpointPending {
            event: chain.event.clone(),
            target,
            endpoint,
            pending_events,
        })
    }

    fn server_release_callback_plan(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        release_target: Ole1ReleaseTarget,
        memory: &mut Memory,
    ) -> Result<Ole1ServerGuestCallbackPlan, RuntimeError> {
        let (callback_target, procedure, arguments) = match release_target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => {
                let document = self
                    .ole1_server_state
                    .document(event.owner, handle)
                    .filter(|document| {
                        document.generation == generation
                            && document.server == server
                            && document.endpoint == endpoint
                            && document.endpoint_worker_generation == endpoint_worker_generation
                            && document.document_atom == document_atom
                    })
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 document Release target changed before callback preparation",
                        )
                    })?;
                if self
                    .ole1_server_state
                    .server(event.owner, server)
                    .is_none_or(|record| {
                        record.generation != server_generation
                            || record.endpoint_worker_generation != endpoint_worker_generation
                    })
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 document Release lost its parent server generation",
                    ));
                }
                let document_far = document.server_document_far.ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 document Release plan has no guest document callback",
                    )
                })?;
                let procedure = self
                    .ole1_server_document_method_address(
                        document_far,
                        ServerDocumentCallbackMethod::Release.vtable_slot(),
                        memory,
                    )
                    .map_err(|error| {
                        super::win16_ole1_server_wire::into_runtime_error(
                            error,
                            "invalid OLESERVERDOC::Release callback",
                        )
                    })?;
                (
                    Ole1ServerCallbackTarget::Document { handle, generation },
                    procedure,
                    ServerDocumentCallbackArguments::Release {
                        server_document_far: document_far,
                    }
                    .encode(),
                )
            }
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => {
                let server = self
                    .ole1_server_state
                    .server(event.owner, handle)
                    .filter(|server| {
                        server.generation == generation
                            && server.endpoint == endpoint
                            && server.endpoint_worker_generation == endpoint_worker_generation
                            && server.class_atom == class_atom
                            && server.executable_atom == executable_atom
                    })
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 server Release target changed before callback preparation",
                        )
                    })?;
                let procedure = self
                    .ole1_server_method_address(
                        server.server_far,
                        ServerCallbackMethod::Release.vtable_slot(),
                        memory,
                    )
                    .map_err(|error| {
                        super::win16_ole1_server_wire::into_runtime_error(
                            error,
                            "invalid OLESERVER::Release callback",
                        )
                    })?;
                (
                    Ole1ServerCallbackTarget::Server { handle, generation },
                    procedure,
                    ServerCallbackArguments::Release {
                        server_far: server.server_far,
                    }
                    .encode(),
                )
            }
        };
        let journal_id = self.reserve_callback_frame_id()?.0;
        Ok(Ole1ServerGuestCallbackPlan {
            owner: event.owner,
            target: callback_target,
            procedure,
            arguments,
            return_kind: Win16FarCallbackReturn::Word,
            completion: Ole1ServerCallbackCompletion::DdeRelease {
                event: event.clone(),
                target: callback_target,
                release_target,
                journal_id,
            },
        })
    }
}
