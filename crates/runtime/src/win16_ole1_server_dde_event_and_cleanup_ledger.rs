impl super::Win16State {
    /// Enumerate every unpublished registration cleanup owned by this task.
    /// The classic-DDE safe point must call this even when no DDE event has
    /// arrived so endpoint retirement and atom deletion can make progress.
    pub(in crate::win16_runtime) fn pending_ole1_unpublished_cleanups(
        &self,
        owner: OwnerId,
    ) -> Vec<Ole1UnpublishedCleanup> {
        self.ole1_server_state.pending_unpublished_cleanups(owner)
    }

    pub(in crate::win16_runtime) fn next_ole1_unpublished_cleanup_action(
        &self,
        id: Ole1UnpublishedCleanupId,
    ) -> Result<Option<Ole1UnpublishedCleanupAction>, RuntimeError> {
        self.ole1_server_state
            .next_unpublished_cleanup_action(id)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("invalid OLE1 unpublished cleanup action ({status})"),
                )
            })
    }

    /// Consume the exact host EventAcknowledged terminal before allowing a
    /// RetireEndpoint retry. This is separate from protocol-level DDE ACK.
    pub(in crate::win16_runtime) fn acknowledge_ole1_unpublished_cleanup_event(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<bool, RuntimeError> {
        self.ole1_server_state
            .acknowledge_unpublished_cleanup_event(id, event)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 unpublished cleanup EventId changed ({status})"),
                )
            })
    }

    pub(in crate::win16_runtime) fn record_ole1_unpublished_cleanup_retirement(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        expected_revision: u64,
        receipt: &Win16HostClassicDdeRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        self.ole1_server_state
            .record_unpublished_cleanup_retirement(id, owner, expected_revision, receipt)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 unpublished endpoint retirement receipt changed ({status})"),
                )
            })
    }

    pub(in crate::win16_runtime) fn record_ole1_unpublished_cleanup_atom_deleted(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        worker_generation: Option<u64>,
        expected_revision: u64,
        atom: u16,
    ) -> Result<bool, RuntimeError> {
        self.ole1_server_state
            .record_unpublished_cleanup_atom_deleted(
                id,
                owner,
                worker_generation,
                expected_revision,
                atom,
            )
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 unpublished atom retirement receipt changed ({status})"),
                )
            })
    }

    /// Return the exact API-owned release wait for an endpoint. A queued
    /// TERMINATE release chain owns its own journal and must never be
    /// consumed by the generic API release continuation.
    pub(in crate::win16_runtime) fn pending_ole1_release_for_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<Option<Ole1PendingReleaseEvents>, RuntimeError> {
        let pending = self
            .ole1_server_state
            .release_pending_events_for_endpoint(owner, endpoint)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("ambiguous OLE1 release wait for endpoint ({status})"),
                )
            })?;
        let Some(pending) = pending else {
            return Ok(None);
        };
        if self
            .ole1_server_state
            .dde_release_chain_owns_target(owner, pending.target)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("ambiguous OLE1 DDE release-chain owner ({status})"),
                )
            })?
        {
            return Ok(None);
        }
        Ok(Some(pending))
    }

    /// Record only the EventId whose exact host ACK terminal was consumed.
    /// Returning false means this was not a generic API release wait; the
    /// queued DDE route may own it instead.
    pub(in crate::win16_runtime) fn acknowledge_release_event(
        &mut self,
        callback_id: u64,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<bool, RuntimeError> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "API Release wait cannot acknowledge a synchronous classic-DDE callback",
            ));
        }
        let Some(journal) = self
            .ole1_server_state
            .pending_release_completion(callback_id)
        else {
            return Ok(false);
        };
        if journal.owner != event.owner || release_target_endpoint(journal.target) != event.endpoint
        {
            return Ok(false);
        }
        if self
            .ole1_server_state
            .dde_release_chain_owns_target(journal.owner, journal.target)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("ambiguous OLE1 DDE release-chain owner ({status})"),
                )
            })?
        {
            return Ok(false);
        }
        self.ole1_server_state
            .acknowledge_release_event(callback_id, event)
            .map(|matched| matched == Some(callback_id))
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 release EventId ACK changed identity ({status})"),
                )
            })
    }

    /// Resume the exact API callback only after every EventId in the current
    /// RetireEndpoint snapshot was acknowledged. If the host reports another
    /// snapshot, the callback and release journal remain live for the next
    /// drain pass. Release itself is never called again here.
    pub(in crate::win16_runtime) fn retry_pending_ole1_server_release(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        receipt_revision: u64,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1PendingServerReleaseRetry, RuntimeError> {
        let endpoint = release_target_endpoint(target);
        let current = self
            .pending_ole1_release_for_endpoint(owner, endpoint)?
            .filter(|wait| wait.callback_id == callback_id && wait.target == target)
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 server Release retry lost its exact pending EventId receipt",
                )
            })?;
        if current.receipt_revision != receipt_revision {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 server Release retry used a stale RetireEndpoint receipt revision",
            ));
        }
        if !current.pending_events.is_empty() {
            return Ok(Ole1PendingServerReleaseRetry::Pending(current));
        }
        let journal = self
            .ole1_server_state
            .pending_release_completion(callback_id)
            .filter(|entry| {
                entry.owner == owner
                    && entry.target == target
                    && entry.phase == Ole1ReleasePhase::RetireEndpoint
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 server Release retry journal no longer matches its endpoint wait",
                )
            })?;
        let _ = journal;
        let has_guest_callback = self
            .ole1_callbacks
            .last()
            .is_some_and(|frame| frame.identity() == CallbackFrameId(callback_id));
        if !has_guest_callback {
            // The public API already returned WAIT, so no callback frame can
            // be resumed. Continue the same durable resource journal anyway:
            // delete the exact atoms, retry RetireEndpoint, and commit the
            // registry only after its true retired receipt. This avoids
            // leaving an empty EventId wait that depends on the guest calling
            // Revoke again.
            return match super::ole1::finish_server_release_completion_for_dde(
                &mut self.ole1_server_state,
                callback_id,
                target,
                host,
            )? {
                super::ole1::Ole1ReleaseEndpointOutcome::Complete => {
                    Ok(Ole1PendingServerReleaseRetry::Completed)
                }
                super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                    let refreshed = self
                        .pending_ole1_release_for_endpoint(owner, endpoint)?
                        .filter(|wait| wait.callback_id == callback_id && wait.target == target)
                        .ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 no-callback release retry lost the new EventId receipt",
                            )
                        })?;
                    Ok(Ole1PendingServerReleaseRetry::Pending(refreshed))
                }
            };
        }
        let retry = self.retry_ole1_server_release_callback(
            CallbackFrameId(callback_id),
            target,
            cpu,
            dos,
            memory,
            host,
        );
        match retry {
            Ok(()) => Ok(Ole1PendingServerReleaseRetry::Completed),
            Err(error) => {
                let refreshed = self.pending_ole1_release_for_endpoint(owner, endpoint)?;
                if let Some(refreshed) = refreshed.filter(|wait| {
                    wait.callback_id == callback_id
                        && wait.target == target
                        && wait.receipt_revision > receipt_revision
                }) {
                    Ok(Ole1PendingServerReleaseRetry::Pending(refreshed))
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Route one exact synchronous OLE server/document callback. Endpoints
    /// without a live OLE server record remain eligible for the OLE client
    /// transaction route or the ordinary guest window procedure.
    pub(in crate::win16_runtime) fn route_classic_dde_callback(
        &mut self,
        step: &Arc<Win16HostClassicDdeCallbackStep>,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        let exact = match step.event.delivery {
            Win16ClassicDdeDeliveryKind::Synchronous {
                operation_id,
                callback,
                frame,
            } => {
                step.owner == step.event.owner
                    && step.endpoint == step.event.endpoint
                    && step.worker_generation == step.event.worker_generation
                    && step.operation_id == operation_id
                    && step.callback == callback
                    && step.frame == frame
            }
            Win16ClassicDdeDeliveryKind::Queued => false,
        };
        if !exact {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE callback step does not match its exact owner/event source",
            ));
        }
        validate_callback_causal_parents(step)?;
        self.route_classic_dde_event(&step.event, Some(Arc::clone(step)), cpu, dos, memory, host)
    }

    /// Route a queued mailbox event after the caller admitted its exact EventId
    /// in the publication journal. This path has no suspended native WndProc.
    pub(in crate::win16_runtime) fn route_classic_dde_queued_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerDdeDisposition, RuntimeError> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "synchronous classic-DDE callback entered through the queued event route",
            ));
        }
        self.route_classic_dde_event(event, None, cpu, dos, memory, host)
    }

    /// Retry one event-pinned endpoint release only after the host has
    /// confirmed an exact EventId acknowledgement. Other pending mailbox
    /// entries remain routable; the endpoint stays a live tombstone until a
    /// later receipt says `retired=true`.
    pub(in crate::win16_runtime) fn finish_pending_dde_release_after_event_ack(
        &mut self,
        acknowledged_event: &Win16HostClassicDdeEvent,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
        if acknowledged_event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "endpoint-retirement retry requires an exact queued EventId",
            ));
        }
        let Some(_) = self
            .ole1_server_state
            .dde_release_chain_for_pending_event(
                acknowledged_event.owner,
                acknowledged_event.endpoint,
                acknowledged_event.event_id,
            )
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("ambiguous OLE1 pending release EventId ({status})"),
                )
            })?
        else {
            return Ok(Ole1ServerGuestCallbackFinish::Complete);
        };
        let chain = self
            .ole1_server_state
            .acknowledge_dde_release_pending_event(acknowledged_event)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot record exact OLE1 DDE release EventId ACK ({status})"),
                )
            })?
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 pending release EventId disappeared before its ACK was recorded",
                )
            })?;
        let target = chain.next_target.ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 release EventId wait has no active release target",
            )
        })?;
        if !chain.pending_events.is_empty() {
            return Ok(Ole1ServerGuestCallbackFinish::PendingEndpointEvents {
                event: chain.event.clone(),
                target,
                endpoint: release_target_endpoint(target),
                pending_events: chain.pending_events,
            });
        }
        let Some(journal) = self
            .ole1_server_state
            .release_completion_for_target(chain.event.owner, target)
        else {
            // The checked Release callback is still in flight; it will start
            // the journal only after the guest returns.
            return Ok(Ole1ServerGuestCallbackFinish::Complete);
        };
        match super::ole1::finish_server_release_completion_for_dde(
            &mut self.ole1_server_state,
            journal.callback_id,
            target,
            host,
        )? {
            super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(pending) => {
                if pending.contains(&acknowledged_event.event_id) {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "RetireEndpoint still lists an EventId after its exact ACK receipt",
                    ));
                }
                self.ole1_server_state
                    .record_dde_release_pending_events(&chain.event, target, pending.clone())
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot retain remaining OLE1 endpoint EventIds ({status})"),
                        )
                    })?;
                Ok(Ole1ServerGuestCallbackFinish::PendingEndpointEvents {
                    event: chain.event.clone(),
                    target,
                    endpoint: release_target_endpoint(target),
                    pending_events: pending,
                })
            }
            super::ole1::Ole1ReleaseEndpointOutcome::Complete => {
                let next = self
                    .ole1_server_state
                    .release_target_after_completion(chain.event.owner, target);
                self.ole1_server_state
                    .advance_dde_release_chain(&chain.event, target, next)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("cannot advance completed OLE1 release target ({status})"),
                        )
                    })?;
                if next.is_some() {
                    let disposition =
                        self.resume_server_release_chain(&chain.event, None, memory, host)?;
                    return disposition_into_callback_finish(disposition);
                }
                finish_exact_dde_release_chain(&mut self.ole1_server_state, &chain.event)?;
                Ok(Ole1ServerGuestCallbackFinish::Complete)
            }
        }
    }
}
