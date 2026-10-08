//! Recoverable owner-scoped classic-DDE task-exit barrier.

use super::*;

impl Win16State {
    /// Retain task-exit intent before draining an existing host source. The
    /// producer barrier can begin only after that source has retired; a
    /// Started poll is not a suspended callback that can own a nested call.
    pub(super) fn begin_classic_dde_task_exit(
        &mut self,
        owner: OwnerId,
    ) -> Result<(), RuntimeError> {
        match &self.classic_dde.owner_shutdown {
            Some(state) if state.owner != owner => {
                return Err(dde_invariant(
                    "classic DDE task-exit continuation changed its owner",
                ));
            }
            Some(_) => return Ok(()),
            None => {
                self.classic_dde.owner_shutdown = Some(ClassicDdeOwnerShutdown {
                    owner,
                    barrier: None,
                    worker_generation: None,
                    server_side_drained: false,
                    server_pending: None,
                    host_quiesced: false,
                    worker_quiesced: false,
                    runtime_pending: None,
                    latest_snapshot: None,
                    last_failure: None,
                });
            }
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn classic_dde_task_exit_quiesced(
        &self,
        owner: OwnerId,
    ) -> bool {
        self.classic_dde.owner_shutdown.as_ref().is_some_and(|state|
            state.owner == owner && state.worker_quiesced)
    }

    /// While owner shutdown is pending, execute the existing DDE host-worker
    /// pump instead of another application instruction. A checked DDE guest
    /// callback is the exception: the CPU must run that exact callback frame
    /// before this cleanup continuation can advance.
    pub(in crate::win16_runtime) fn classic_dde_task_exit_needs_pump(&self) -> bool {
        self.toolhelp_task_exit_requires_classic_dde_pump()
    }

    pub(in crate::win16_runtime) fn service_classic_dde_task_exit_safe_point(
        &mut self,
        owner: OwnerId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.classic_dde.callbacks.last().is_some_and(|frame|
            frame.returned_value.is_some())
        {
            return self.retry_returned_classic_dde_guest_callback(cpu, dos, memory, host);
        }
        if !self.callback_kinds.is_empty() {
            return Ok(false);
        }

        // Retry exact owner-scoped client proxy allocation rollback before
        // installing or consuming the native DDE quiescence barrier. Failed
        // unlock/free keeps its lease in the client journal and remains
        // retryable on the next safe point.
        self.retry_ole1_dde_object_proxy_retirements(owner)?;

        self.begin_classic_dde_task_exit(owner)?;

        // The regular safe point can leave a PollOwner at Started when the
        // guest terminates. Consume that exact operation and its real source
        // retirement before submitting a top-level quiescence call. During
        // this phase, do not replay pending begins or execute app instructions.
        if let Some(operation) = self.classic_dde.operations.last() {
            if operation.identity.owner != owner {
                return Err(dde_invariant(
                    "classic DDE task-exit drain changed its exact operation owner",
                ));
            }
            return self.service_classic_dde_operation(cpu, dos, memory, host);
        }

        // Install the producer barrier before progressing any previously
        // queued begin. Once it exists, the worker accepts only exact drain
        // operations, so a pending application send cannot race teardown.
        if self.classic_dde.owner_shutdown.as_ref().is_some_and(|state|
            state.barrier.is_none())
        {
            self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::QuiesceOwner { owner, id: None },
                ClassicDdeOperationOwner::ClassicDdeOwnerShutdown { owner },
                None,
                host,
            )?;
            return Ok(false);
        }
        if !self.classic_dde.pending_begins.is_empty() {
            return self.service_classic_dde_safe_point(cpu, dos, memory, host);
        }

        let (worker_quiesced, host_quiesced, server_side_drained) = {
            let shutdown = self.classic_dde.owner_shutdown.as_ref().ok_or_else(||
                dde_invariant("classic DDE task-exit safe point has no owner continuation"))?;
            if shutdown.owner != owner {
                return Err(dde_invariant(
                    "classic DDE task-exit continuation changed its owner",
                ));
            }
            (
                shutdown.worker_quiesced,
                shutdown.host_quiesced,
                shutdown.server_side_drained,
            )
        };
        if worker_quiesced {
            return Ok(false);
        }

        if self.drive_one_unpublished_cleanup(owner, host)? {
            return Ok(false);
        }

        if host_quiesced && server_side_drained {
            let pending = self.classic_dde_owner_runtime_pending(owner)?;
            if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                state.runtime_pending = pending.clone();
                state.worker_quiesced = state.host_quiesced
                    && state.server_side_drained
                    && pending.is_none();
            }
            if pending.is_some() {
                // No native DDE endpoint or operation remains. Keep the exact
                // guest-side lease gap live and continue pumping the existing
                // runtime worker; do not synthesize retirement or task exit.
                host.pump_events()?;
            }
            return Ok(false);
        }

        if !server_side_drained {
            match self.progress_ole1_server_shutdown(owner, cpu, dos, memory, host)? {
                super::super::ole1::Ole1ServerShutdownStep::GuestCallbackEntered { .. } => {
                    if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                        state.server_pending = None;
                    }
                    // OLESVR has entered a checked far callback. The outer
                    // CPU loop must run this exact guest frame to its return.
                    return Ok(true);
                }
                super::super::ole1::Ole1ServerShutdownStep::HostAdvanced => {
                    if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                        state.server_pending = None;
                    }
                    return Ok(false);
                }
                super::super::ole1::Ole1ServerShutdownStep::HostContinuation(pending) => {
                    let endpoint = release_target_endpoint(pending.target);
                    self.retain_classic_dde_pending_endpoint_poll(
                        pending.owner,
                        endpoint,
                        &pending.pending_events,
                    )?;
                    if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                        state.server_pending = None;
                    }
                    return Ok(false);
                }
                super::super::ole1::Ole1ServerShutdownStep::Pending(pending) => {
                    let unpublished_cleanup = matches!(
                        &pending,
                        super::super::ole1::Ole1ServerShutdownPending::UnpublishedCleanup(_)
                    );
                    if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                        state.server_pending = Some(pending);
                    }
                    if unpublished_cleanup && self.drive_one_unpublished_cleanup(owner, host)? {
                        return Ok(false);
                    }
                }
                super::super::ole1::Ole1ServerShutdownStep::ServerSideDrained => {
                    if let Some(state) = self.classic_dde.owner_shutdown.as_mut() {
                        state.server_side_drained = true;
                        state.server_pending = None;
                    }
                }
            }
        }

        if self.retry_one_classic_dde_queued_event(owner, cpu, dos, memory, host)? {
            return Ok(true);
        }
        if self.drive_one_api_release_wait(owner, cpu, dos, memory, host)? {
            return Ok(true);
        }
        if let Some((endpoint, event_ids)) =
            self.pending_classic_dde_endpoint_poll_for(owner)
        {
            self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::Poll { owner, endpoint },
                ClassicDdeOperationOwner::PollEndpoint {
                    owner,
                    endpoint,
                    expected_event_ids: event_ids,
                },
                None,
                host,
            )?;
            return Ok(false);
        }

        // Drain a message that arrived after the last bounded worker
        // inventory. PollOwner is allowed by the installed barrier and only
        // publishes an exact EventId; an empty poll is not quiescence.
        if self.classic_dde.owner_shutdown.as_ref().is_some_and(|state|
            state.latest_snapshot.as_ref().is_some_and(|snapshot|
                !snapshot.endpoints.is_empty() || !snapshot.active_operations.is_empty()))
        {
            host.pump_events()?;
            self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::PollOwner { owner },
                ClassicDdeOperationOwner::PollOwner { owner },
                None,
                host,
            )?;
            return Ok(false);
        }

        // A server-side pending reason can be waiting for native peer traffic
        // (for example a TERMINATE ACK). Continue pumping the real USER worker
        // and poll its owner mailbox; never execute arbitrary app instructions
        // or infer protocol completion from an empty poll.
        if self.classic_dde.owner_shutdown.as_ref().is_some_and(|state|
            state.server_pending.is_some())
        {
            host.pump_events()?;
            self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::PollOwner { owner },
                ClassicDdeOperationOwner::PollOwner { owner },
                None,
                host,
            )?;
            return Ok(false);
        }

        let barrier = self
            .classic_dde
            .owner_shutdown
            .as_ref()
            .and_then(|state| state.barrier);
        self.begin_classic_dde_host_call(
            Win16HostClassicDdeCall::QuiesceOwner { owner, id: barrier },
            ClassicDdeOperationOwner::ClassicDdeOwnerShutdown { owner },
            None,
            host,
        )?;
        Ok(false)
    }

    pub(super) fn consume_classic_dde_owner_quiescence(
        &mut self,
        identity: crate::Win16ClassicDdeOperationIdentity,
        operation_owner: ClassicDdeOperationOwner,
        owner: OwnerId,
        step: crate::Win16HostClassicDdeStep,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if identity.owner != owner
            || operation_owner != (ClassicDdeOperationOwner::ClassicDdeOwnerShutdown { owner })
        {
            return Err(dde_invariant(
                "classic DDE quiescence terminal changed its exact task owner",
            ));
        }
        let state = self.classic_dde.owner_shutdown.as_ref().ok_or_else(||
            dde_invariant("classic DDE quiescence terminal has no retained task-exit state"))?;
        if state.owner != owner
            || state.worker_generation.is_some_and(|generation|
                generation != identity.worker_generation)
        {
            return Err(dde_invariant(
                "classic DDE quiescence terminal changed its worker generation",
            ));
        }

        if let crate::Win16HostClassicDdeStep::StartedFailure(failure) = &step {
            if failure.operation != identity
                || failure.source_retired.operation != identity
            {
                return Err(dde_invariant(
                    "classic DDE quiescence failure changed its exact host operation",
                ));
            }
            let (retired_owner, resume_parent) =
                self.consume_classic_dde_source_retirement(identity, host)?;
            if retired_owner != operation_owner || resume_parent.is_some() {
                return Err(dde_invariant(
                    "classic DDE quiescence failure changed its exact operation owner",
                ));
            }
            let state = self.classic_dde.owner_shutdown.as_mut().ok_or_else(||
                dde_invariant("classic DDE retry lost its task-exit continuation"))?;
            state.worker_generation = Some(identity.worker_generation);
            state.worker_quiesced = false;
            state.last_failure = Some(std::sync::Arc::clone(failure));
            return Ok(false);
        }

        let (retired_owner, resume_parent) =
            self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
        if retired_owner != operation_owner || resume_parent.is_some() {
            return Err(dde_invariant(
                "classic DDE quiescence terminal changed its operation owner",
            ));
        }
        let result = terminal_result(&step)?;
        match result {
            crate::Win16HostClassicDdeResult::OwnerQuiescing(snapshot) => {
                validate_owner_quiescence_snapshot(
                    &snapshot,
                    owner,
                    identity.worker_generation,
                )?;
                let state = self.classic_dde.owner_shutdown.as_ref().ok_or_else(||
                    dde_invariant("classic DDE owner snapshot lost its task-exit state"))?;
                if state.barrier.is_some_and(|barrier| barrier != snapshot.id) {
                    return Err(dde_invariant(
                        "classic DDE owner snapshot changed its stable barrier identity",
                    ));
                }
                let mut endpoint_ids = Vec::new();
                endpoint_ids.try_reserve_exact(snapshot.endpoints.len()).map_err(|error|
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "validate classic DDE owner endpoint snapshot",
                        error,
                    ))?;
                for endpoint in &snapshot.endpoints {
                    if endpoint_ids.contains(&endpoint.endpoint) {
                        return Err(dde_invariant(
                            "classic DDE owner snapshot duplicated an endpoint identity",
                        ));
                    }
                    endpoint_ids.push(endpoint.endpoint);
                    if !endpoint.pending_events.is_empty() {
                        self.retain_classic_dde_pending_endpoint_poll(
                            owner,
                            endpoint.endpoint,
                            &endpoint.pending_events,
                        )?;
                    }
                }
                let state = self.classic_dde.owner_shutdown.as_mut().ok_or_else(||
                    dde_invariant("classic DDE snapshot lost its retained continuation"))?;
                state.barrier = Some(snapshot.id);
                state.worker_generation = Some(snapshot.worker_generation);
                state.host_quiesced = false;
                state.worker_quiesced = false;
                state.runtime_pending = (!snapshot.endpoints.is_empty()
                    || !snapshot.active_operations.is_empty())
                    .then_some(ClassicDdeOwnerRuntimePending::NativeHostInventory {
                        endpoints: snapshot.endpoints.len(),
                        active_operations: snapshot.active_operations.len(),
                    });
                state.latest_snapshot = Some(snapshot.clone());
                state.last_failure = None;
                self.retire_classic_dde_terminal_operation(identity)?;
                Ok(false)
            }
            crate::Win16HostClassicDdeResult::OwnerQuiesced(proof) => {
                let state = self.classic_dde.owner_shutdown.as_ref().ok_or_else(||
                    dde_invariant("classic DDE worker proof lost its task-exit state"))?;
                if proof.owner != owner
                    || proof.operation != identity
                    || proof.worker_generation != identity.worker_generation
                    || proof.id.0 == 0
                    || state.barrier.is_some_and(|barrier| barrier != proof.id)
                {
                    return Err(dde_invariant(
                        "classic DDE worker quiescence proof changed its exact owner or barrier",
                    ));
                }
                self.retire_classic_dde_terminal_operation(identity)?;
                let runtime_pending = self.classic_dde_owner_runtime_pending(owner)?;
                let state = self.classic_dde.owner_shutdown.as_mut().ok_or_else(||
                    dde_invariant("classic DDE worker proof lost its continuation"))?;
                state.barrier = Some(proof.id);
                state.worker_generation = Some(proof.worker_generation);
                state.host_quiesced = true;
                state.runtime_pending = runtime_pending;
                state.worker_quiesced = state.server_side_drained
                    && state.runtime_pending.is_none();
                state.latest_snapshot = None;
                state.last_failure = None;
                Ok(false)
            }
            _ => Err(dde_invariant(
                "classic DDE QuiesceOwner completed with an unrelated result",
            )),
        }
    }

    fn classic_dde_owner_runtime_pending(
        &self,
        owner: OwnerId,
    ) -> Result<Option<ClassicDdeOwnerRuntimePending>, RuntimeError> {
        if let Some(pending) = self.classic_dde_owner_runtime_pending_local(owner) {
            return Ok(Some(pending));
        }
        let count = self.ole1_client_dde_owner_pending(owner)?;
        Ok((count != 0).then_some(
            ClassicDdeOwnerRuntimePending::ClientDdeOwnerPending { count },
        ))
    }

    fn classic_dde_owner_runtime_pending_local(
        &self,
        owner: OwnerId,
    ) -> Option<ClassicDdeOwnerRuntimePending> {
        let count = self.classic_dde.operations.iter().filter(|frame|
            frame.identity.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::HostOperation { count });
        }
        let count = self.classic_dde.pending_begins.iter().filter(|begin|
            super::super::classic_dde_operation::owner_id(&begin.owner) == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::PendingBegin { count });
        }
        let count = self.classic_dde.queued_events.iter().filter(|event|
            event.event.owner == owner).count()
            + self.classic_dde.event_tracker.pending().filter(|event|
                event.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::QueuedEvent { count });
        }
        let count = self.classic_dde.deferred_queued_events.iter().filter(|event|
            event.owner == owner).count()
            + self.classic_dde.deferred_sync.iter().filter(|step|
                step.event.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::DeferredEvent { count });
        }
        let count = self.classic_dde.callbacks.iter().filter(|callback|
            callback.continuation.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::GuestCallback { count });
        }
        let count = self.classic_dde.guest_globals.iter().filter(|lease|
            lease.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::GuestGlobal { count });
        }
        let count = self.classic_dde.pending_endpoint_polls.iter().filter(|poll|
            poll.owner == owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::EndpointPoll { count });
        }
        if self.classic_dde.atoms.owner_has_leases(owner) {
            return Some(ClassicDdeOwnerRuntimePending::AtomLease);
        }
        let count = self.ole1_server_state.owner_pending_close_document_proofs(owner).len();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::ServerCloseDocumentProof { count });
        }
        let count = self.ole1_server_state.owner_endpoints(owner).count();
        if count != 0 {
            return Some(ClassicDdeOwnerRuntimePending::ServerEndpoint { count });
        }
        None
    }
}

fn release_target_endpoint(
    target: super::super::win16_ole1_server_state::Ole1ReleaseTarget,
) -> crate::Win16HostClassicDdeEndpoint {
    match target {
        super::super::win16_ole1_server_state::Ole1ReleaseTarget::Document { endpoint, .. }
        | super::super::win16_ole1_server_state::Ole1ReleaseTarget::Server { endpoint, .. } => endpoint,
    }
}

fn validate_owner_quiescence_snapshot(
    snapshot: &crate::Win16HostClassicDdeOwnerQuiescence,
    owner: OwnerId,
    worker_generation: u64,
) -> Result<(), RuntimeError> {
    if snapshot.owner != owner
        || snapshot.worker_generation != worker_generation
        || snapshot.id.0 == 0
    {
        return Err(dde_invariant(
            "classic DDE owner snapshot changed owner, generation, or barrier identity",
        ));
    }

    let mut endpoint_ids = Vec::new();
    endpoint_ids
        .try_reserve_exact(snapshot.endpoints.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "validate classic DDE owner endpoint snapshot",
                error,
            )
        })?;
    let pending_event_count = snapshot.endpoints.iter().fold(0usize, |count, endpoint| {
        count.saturating_add(endpoint.pending_events.len())
    });
    let mut event_ids = Vec::new();
    event_ids
        .try_reserve_exact(pending_event_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "validate classic DDE owner event snapshot",
                error,
            )
        })?;
    let mut active_operations = Vec::new();
    active_operations
        .try_reserve_exact(snapshot.active_operations.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "validate classic DDE owner operation snapshot",
                error,
            )
        })?;

    for endpoint in &snapshot.endpoints {
        if endpoint.endpoint.0 == 0
            || endpoint.parent.is_some_and(|parent| parent.0 == 0 || parent == endpoint.endpoint)
            || endpoint_ids.contains(&endpoint.endpoint)
        {
            return Err(dde_invariant(
                "classic DDE owner snapshot has a zero, duplicate, or self-parent endpoint",
            ));
        }
        endpoint_ids.push(endpoint.endpoint);
        for event_id in &endpoint.pending_events {
            if event_id.0 == 0 || event_ids.contains(event_id) {
                return Err(dde_invariant(
                    "classic DDE owner snapshot has a zero or duplicate EventId",
                ));
            }
            event_ids.push(*event_id);
        }
        for callback in &endpoint.callbacks {
            if callback.operation.owner != owner
                || callback.operation.worker_generation != worker_generation
                || callback.operation.id.0 == 0
                || callback.callback.0 == 0
                || callback.frame.0 == 0
                || callback.event_id.0 == 0
            {
                return Err(dde_invariant(
                    "classic DDE owner snapshot changed a pending callback identity",
                ));
            }
        }
        for transfer in &endpoint.transfers {
            if transfer.id.0 == 0 {
                return Err(dde_invariant(
                    "classic DDE owner snapshot has a zero transfer identity",
                ));
            }
        }
        for conversation in &endpoint.conversations {
            if conversation.id.0 == 0 {
                return Err(dde_invariant(
                    "classic DDE owner snapshot has a zero conversation identity",
                ));
            }
        }
        for transaction in &endpoint.transactions {
            if transaction.id.0 == 0
                || !endpoint.conversations.iter().any(|conversation|
                    conversation.id == transaction.conversation
                        && conversation.peer == transaction.peer)
                || transaction.transfer.is_some_and(|transfer_id|
                    !endpoint.transfers.iter().any(|transfer|
                        transfer.id == transfer_id
                            && transfer.peer == transaction.peer
                            && transfer.conversation == Some(transaction.conversation)))
            {
                return Err(dde_invariant(
                    "classic DDE owner snapshot has an unbound transaction or transfer",
                ));
            }
        }
    }
    for operation in &snapshot.active_operations {
        if operation.owner != owner
            || operation.worker_generation != worker_generation
            || operation.id.0 == 0
            || active_operations.contains(operation)
        {
            return Err(dde_invariant(
                "classic DDE owner snapshot has a zero, duplicate, or foreign operation",
            ));
        }
        active_operations.push(*operation);
    }
    Ok(())
}
