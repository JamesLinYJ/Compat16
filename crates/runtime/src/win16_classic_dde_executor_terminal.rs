//! Classic DDE executor support for terminal receipts and continuations.

use super::*;

impl Win16State {
    pub(super) fn consume_classic_dde_terminal(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        owner: ClassicDdeOperationOwner,
        step: Win16HostClassicDdeStep,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        // An EventId ACK is a delivery operation with its own exact retry
        // path. A started failure retires only this operation/source; it must
        // put the same call back in the begin journal and return the event to
        // Published so the safe point can retry without republishing its
        // guest callback or confusing delivery ACK with WM_DDE_ACK.
        if let Win16HostClassicDdeStep::StartedFailure(failure) = &step {
            let protocol_retry = self.classic_dde.operations.last().and_then(|frame| {
                if frame.identity != identity {
                    return None;
                }
                matches!(
                    &frame.owner,
                    ClassicDdeOperationOwner::ServerProtocolResultPost { .. }
                )
                .then(|| {
                    (
                        frame.call.clone(),
                        frame.owner.clone(),
                        frame.resume_parent.clone(),
                    )
                })
            });
            if let Some((call, operation_owner, resume_parent)) = protocol_retry {
                if failure.operation != identity
                    || failure.source_retired.operation != identity
                {
                    return Err(dde_invariant(
                        "failed server protocol Post changed its exact source operation",
                    ));
                }
                let pending = super::super::classic_dde_dispatch::ClassicDdePendingBegin {
                    call,
                    owner: operation_owner.clone(),
                    resume_parent: resume_parent.clone(),
                };
                if !self.classic_dde.pending_begins.contains(&pending) {
                    self.classic_dde
                        .pending_begins
                        .try_reserve(1)
                        .map_err(|error| {
                            RuntimeError::with_source(
                                Kind::ResourceExhausted,
                                "retain retryable server protocol-result Post",
                                error,
                            )
                        })?;
                    self.classic_dde.pending_begins.push(pending.clone());
                }
                let (retired_owner, retired_resume) =
                    self.consume_classic_dde_source_retirement(identity, host)?;
                if retired_owner != operation_owner || retired_resume != resume_parent {
                    return Err(dde_invariant(
                        "failed server protocol Post changed its owner or callback continuation",
                    ));
                }
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "server protocol-result Post failed and its exact action was retained for retry",
                    Arc::clone(&failure.cause),
                ));
            }

            let retry = self.classic_dde.operations.last().and_then(|frame| {
                if frame.identity != identity {
                    return None;
                }
                match &frame.call {
                    Win16HostClassicDdeCall::AcknowledgeEvent {
                        owner,
                        endpoint,
                        event_id,
                    } => Some((
                        frame.call.clone(),
                        frame.owner.clone(),
                        frame.resume_parent.clone(),
                        *owner,
                        *endpoint,
                        *event_id,
                    )),
                    _ => None,
                }
            });
            if let Some((call, operation_owner, resume_parent, event_owner, endpoint, event_id)) =
                retry
            {
                let event = self
                    .classic_dde
                    .queued_events
                    .iter()
                    .find(|record| {
                        record.event.owner == event_owner
                            && record.event.endpoint == endpoint
                            && record.event.event_id == event_id
                    })
                    .ok_or_else(|| {
                        dde_invariant("failed classic DDE delivery ACK lost its exact queued event")
                    })?;
                let pending = super::super::classic_dde_dispatch::ClassicDdePendingBegin {
                    call,
                    owner: operation_owner,
                    resume_parent,
                };
                if !self.classic_dde.pending_begins.contains(&pending) {
                    self.classic_dde
                        .pending_begins
                        .try_reserve(1)
                        .map_err(|error| {
                            RuntimeError::with_source(
                                Kind::ResourceExhausted,
                                "retain retryable classic DDE EventId acknowledgement",
                                error,
                            )
                        })?;
                }
                self.classic_dde.event_tracker.acknowledgement_failed(
                    event_owner,
                    endpoint,
                    event.event.worker_generation,
                    event_id,
                )?;
                if !self.classic_dde.pending_begins.contains(&pending) {
                    self.classic_dde.pending_begins.push(pending);
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement(identity, host)?;
                if retired_owner != owner || resume_parent.is_some() {
                    return Err(dde_invariant(
                        "failed classic DDE delivery ACK changed its exact owner",
                    ));
                }
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "classic DDE EventId acknowledgement failed and was retained for retry",
                    Arc::clone(&failure.cause),
                ));
            }
        }
        match owner {
            poll_owner @ (ClassicDdeOperationOwner::PollOwner { .. }
            | ClassicDdeOperationOwner::PollEndpoint { .. }) => {
                if let Win16HostClassicDdeStep::StartedFailure(failure) = &step {
                    let (retired_owner, resume_parent) =
                        self.consume_classic_dde_source_retirement(identity, host)?;
                    if retired_owner != poll_owner || resume_parent.is_some() {
                        return Err(dde_invariant(
                            "failed classic DDE poll changed its exact operation owner",
                        ));
                    }
                    return Err(RuntimeError::with_source(
                        Kind::HostFailure,
                        "classic DDE event poll failed after the worker accepted it",
                        Arc::clone(&failure.cause),
                    ));
                }
                let result = terminal_result(&step)?;
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement(identity, host)?;
                if resume_parent.is_some() {
                    return Err(dde_invariant(
                        "classic-DDE poll operation unexpectedly nested",
                    ));
                }
                if retired_owner != poll_owner {
                    return Err(dde_invariant(
                        "classic-DDE poll owner changed before retirement",
                    ));
                }
                let Win16HostClassicDdeResult::Event(event) = result else {
                    return Err(dde_invariant(
                        "classic-DDE poll completed without an Event result",
                    ));
                };
                if let Some(event) = event {
                    if let ClassicDdeOperationOwner::PollEndpoint {
                        owner: expected_owner,
                        endpoint: expected_endpoint,
                        expected_event_ids,
                    } = &poll_owner
                    {
                        if event.owner != *expected_owner
                            || event.endpoint != *expected_endpoint
                            || !expected_event_ids.contains(&event.event_id)
                        {
                            return Err(dde_invariant(
                                "endpoint release poll returned an event outside its exact pending set",
                            ));
                        }
                    }
                    self.publish_classic_dde_queued_event(event.clone(), cpu, dos, memory, host)?;
                    Ok(true)
                } else {
                    if matches!(poll_owner, ClassicDdeOperationOwner::PollOwner { .. }) {
                        if let Some(shutdown) = self.classic_dde.owner_shutdown.as_mut()
                            .filter(|shutdown| shutdown.owner == identity.owner)
                        {
                            // An empty bounded poll is not an owner proof.
                            // Drop its stale inventory so the next safe point
                            // re-queries the exact installed barrier.
                            shutdown.latest_snapshot = None;
                        }
                    }
                    Ok(false)
                }
            }
            client_owner @ ClassicDdeOperationOwner::Client { operation, .. } => {
                let cached_disposition = self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .and_then(|frame| frame.client_terminal_disposition.clone());
                let disposition = if let Some(disposition) = cached_disposition {
                    disposition
                } else {
                    let terminal = Win16HostClassicDdeTerminal::from_step(step.clone())?;
                    let disposition =
                        self.route_ole1_client_dde_host_terminal(identity, terminal)?;
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("client terminal lost its exact operation frame")
                        })?
                        .client_terminal_disposition = Some(disposition.clone());
                    disposition
                };
                if !self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .is_some_and(|frame| frame.client_receipt_committed)
                {
                    if let Win16HostClassicDdeStep::Complete { result, .. } = &step {
                        self.commit_client_classic_dde_receipt(
                            identity,
                            operation,
                            result,
                            &disposition,
                            host,
                        )?;
                    }
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("client receipt lost its exact operation frame")
                        })?
                        .client_receipt_committed = true;
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if retired_owner != client_owner {
                    return Err(dde_invariant("classic-DDE client operation owner changed"));
                }
                if let Some(event) = self.acknowledged_classic_dde_event(identity, &step)? {
                    self.finish_classic_dde_event_ack_local(&event, host)?;
                }
                self.retire_classic_dde_terminal_operation(identity)?;
                self.apply_client_terminal_disposition(
                    identity.owner,
                    operation,
                    resume_parent,
                    disposition,
                    cpu,
                    dos,
                    memory,
                    host,
                )
            }
            ClassicDdeOperationOwner::ClientEventAcknowledgement {
                owner: client_owner,
                operation: client_operation,
            } => {
                let event = self.acknowledged_classic_dde_event(identity, &step)?
                    .ok_or_else(|| dde_invariant(
                        "client EventId acknowledgement completed without its exact host receipt"))?;
                if event.owner != client_owner {
                    return Err(dde_invariant(
                        "client EventId acknowledgement receipt changed its owner",
                    ));
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if retired_owner
                    != (ClassicDdeOperationOwner::ClientEventAcknowledgement {
                        owner: client_owner,
                        operation: client_operation,
                    })
                {
                    return Err(dde_invariant(
                        "client EventId acknowledgement changed its exact owner",
                    ));
                }
                self.finish_classic_dde_event_ack_local(&event, host)?;
                let release_finish =
                    self.finish_pending_dde_release_after_event_ack(&event, memory, host)?;
                self.retire_classic_dde_terminal_operation(identity)?;
                let release_active =
                    self.apply_server_finish(release_finish, cpu, dos, memory, host)?;
                if release_active {
                    return Err(dde_invariant(
                        "client EventId ACK produced a competing server release operation",
                    ));
                }
                if let Some(next) = self.advance_ole1_client_dde_event_ack(
                    client_owner,
                    client_operation,
                    event.event_id,
                    cpu,
                    dos,
                    memory,
                    host,
                )? {
                    self.apply_client_terminal_disposition_ready(
                        client_owner,
                        client_operation,
                        resume_parent,
                        next,
                        host,
                    )
                } else if let Some(reply) = resume_parent {
                    self.resume_classic_dde_host_call(
                        Win16ClassicDdeOperationIdentity {
                            owner: reply.owner,
                            id: reply.operation_id,
                            worker_generation: reply.worker_generation,
                        },
                        Some(reply),
                        host,
                    )?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClassicDdeOperationOwner::ServerInitiate { ref continuation } => {
                let cached_resume = self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .and_then(|frame| frame.server_initiate_resume.clone());
                let resume = if let Some(resume) = cached_resume {
                    resume
                } else {
                    let resume =
                        self.finish_server_initiate_host_call(continuation, identity, &step)?;
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("server INITIATE lost its exact operation frame")
                        })?
                        .server_initiate_resume = Some(resume.clone());
                    resume
                };
                if !self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .is_some_and(|frame| frame.server_initiate_receipt_committed)
                {
                    if let Win16HostClassicDdeStep::Complete { result, .. } = &step {
                        if let Win16HostClassicDdeResult::InitiateReplied(receipt) = result {
                            if receipt.accepted {
                                let conversation = receipt.conversation.ok_or_else(|| dde_invariant(
                                    "accepted server INITIATE omitted its conversation identity"))?;
                                let (event, peer, endpoint, generation) = match continuation {
                                    Ole1ServerInitiateContinuation::Reply { step, .. } => (
                                        &step.event,
                                        step.event.peer,
                                        step.endpoint,
                                        step.worker_generation,
                                    ),
                                    Ole1ServerInitiateContinuation::Forward { .. } => {
                                        return Err(dde_invariant(
                                            "forwarded INITIATE returned a parent-side conversation",
                                        ));
                                    }
                                };
                                self.bind_classic_dde_initiate_atoms(
                                    event.owner,
                                    endpoint,
                                    generation,
                                    event.event_id,
                                    peer,
                                    conversation,
                                    result,
                                )?;
                            }
                        }
                    }
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("server INITIATE receipt lost its exact operation frame")
                        })?
                        .server_initiate_receipt_committed = true;
                }
                let (retired_owner, _resume_parent) =
                    self.consume_classic_dde_source_retirement(identity, host)?;
                if !matches!(
                    retired_owner,
                    ClassicDdeOperationOwner::ServerInitiate { continuation: retired }
                        if &retired == continuation,
                ) {
                    return Err(dde_invariant("classic-DDE INITIATE owner changed"));
                }
                self.resume_classic_dde_host_call(resume.operation, resume.reply, host)?;
                Ok(true)
            }
            ClassicDdeOperationOwner::ServerDde { ref continuation } => {
                let acknowledged_event = server_dde_acknowledged_event(continuation, &step)?;
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if !matches!(
                    retired_owner,
                    ClassicDdeOperationOwner::ServerDde { continuation: retired }
                        if &retired == continuation,
                ) {
                    return Err(dde_invariant("classic-DDE server operation owner changed"));
                }
                if resume_parent.is_some() {
                    return Err(dde_invariant(
                        "server DDE host call unexpectedly owns a client reply",
                    ));
                }
                if let Some(event) = &acknowledged_event {
                    self.finish_classic_dde_event_ack_local(event, host)?;
                }
                let cached_finish = self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .and_then(|frame| frame.server_dde_finish.clone());
                let follow_up = if let Some(finish) = cached_finish {
                    finish
                } else {
                    let finish = finish_ole1_server_dde_host_call(
                        self,
                        continuation,
                        identity,
                        &step,
                        memory,
                        host,
                    )?;
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("server DDE terminal lost its exact operation frame")
                        })?
                        .server_dde_finish = Some(finish.clone());
                    finish
                };
                if let Some((owner, endpoint, worker_generation, event_id)) =
                    server_execute_guest_global_key(&continuation)
                {
                    if matches!(
                        &step,
                        Win16HostClassicDdeStep::Complete {
                            result: Win16HostClassicDdeResult::Posted(_),
                            ..
                        }
                    ) {
                        self.retire_classic_dde_guest_global_key(
                            owner,
                            endpoint,
                            worker_generation,
                            event_id,
                        )?;
                    }
                }
                self.retire_classic_dde_terminal_operation(identity)?;
                self.apply_server_finish(follow_up, cpu, dos, memory, host)
            }
            ClassicDdeOperationOwner::ServerProtocolResultPost {
                ref event,
                status,
                ref callback_step,
            } => {
                if identity.owner != event.owner
                    || identity.worker_generation != event.worker_generation
                {
                    return Err(dde_invariant(
                        "server protocol ACK/result changed its exact task or worker generation",
                    ));
                }
                let expected_call = server_protocol_result_post_call(event, status)?;
                let frame_call = self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .map(|frame| frame.call.clone())
                    .ok_or_else(|| dde_invariant(
                        "server protocol ACK/result lost its exact posted call"))?;
                if frame_call != expected_call {
                    return Err(dde_invariant(
                        "server protocol ACK/result host call changed its exact DDEACK/transfer",
                    ));
                }
                let Win16HostClassicDdeResult::Posted(receipt) = terminal_result(&step)? else {
                    return Err(dde_invariant(
                        "server protocol ACK/result completed without a Post receipt",
                    ));
                };
                if receipt.owner != event.owner
                    || receipt.endpoint != event.endpoint
                    || receipt.peer != event.peer
                    || receipt.conversation != event.conversation
                    || receipt.message != crate::WM_DDE_ACK
                    || !receipt.queued
                    || receipt.transaction != event.transaction
                    || receipt.transfer.is_some()
                {
                    return Err(dde_invariant(
                        "server protocol ACK/result Post receipt changed its exact target or transaction",
                    ));
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if !matches!(
                    retired_owner,
                    ClassicDdeOperationOwner::ServerProtocolResultPost {
                        event: retired_event,
                        status: retired_status,
                        callback_step: retired_step,
                    } if &retired_event == event
                        && retired_status == status
                        && &retired_step == callback_step,
                ) {
                    return Err(dde_invariant(
                        "server protocol ACK/result operation owner changed",
                    ));
                }
                if let Some(callback_step) = callback_step {
                    let expected_reply = callback_reply(
                        callback_step,
                        Win16HostClassicDdeCallbackResult::WindowProcedure(0),
                    );
                    if resume_parent.as_ref() != Some(&expected_reply) {
                        return Err(dde_invariant(
                            "server protocol ACK/result lost its exact suspended callback reply",
                        ));
                    }
                } else if resume_parent.is_some()
                    || event.delivery != Win16ClassicDdeDeliveryKind::Queued
                {
                    return Err(dde_invariant(
                        "queued server protocol ACK/result acquired a synchronous callback parent",
                    ));
                }
                let global_retired = self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .is_some_and(|frame| frame.server_protocol_result_global_retired);
                if !global_retired {
                    let guest_global = match &event.message {
                        Win16ClassicDdeMessage::Execute { global } => global.guest_global,
                        _ => None,
                    }
                    .ok_or_else(|| dde_invariant(
                        "server protocol ACK/result lost its runtime Execute HGLOBAL lease"))?;
                    self.retire_classic_dde_guest_global_for_event(event, guest_global)?;
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| dde_invariant(
                            "server protocol ACK/result lost its cleanup operation frame"))?
                        .server_protocol_result_global_retired = true;
                }
                self.retire_classic_dde_terminal_operation(identity)?;
                if let Some(reply) = resume_parent {
                    let parent = Win16ClassicDdeOperationIdentity {
                        owner: reply.owner,
                        id: reply.operation_id,
                        worker_generation: reply.worker_generation,
                    };
                    self.resume_classic_dde_host_call(parent, Some(reply), host)?;
                    Ok(true)
                } else {
                    self.begin_classic_dde_host_call(
                        Win16HostClassicDdeCall::AcknowledgeEvent {
                            owner: event.owner,
                            endpoint: event.endpoint,
                            event_id: event.event_id,
                        },
                        ClassicDdeOperationOwner::ServerProtocolResultEventAcknowledgement {
                            event: event.clone(),
                        },
                        None,
                        host,
                    )?;
                    Ok(false)
                }
            }
            ClassicDdeOperationOwner::ServerProtocolResultEventAcknowledgement {
                ref event,
            } => {
                let Win16HostClassicDdeResult::EventAcknowledged(event_id) = terminal_result(&step)?
                else {
                    return Err(dde_invariant(
                        "server protocol ACK/result EventId call completed without exact acknowledgement",
                    ));
                };
                if *event_id != event.event_id {
                    return Err(dde_invariant(
                        "server protocol ACK/result acknowledged a different EventId",
                    ));
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if !matches!(
                    retired_owner,
                    ClassicDdeOperationOwner::ServerProtocolResultEventAcknowledgement {
                        event: retired_event,
                    } if &retired_event == event,
                ) || resume_parent.is_some() {
                    return Err(dde_invariant(
                        "server protocol ACK/result EventId acknowledgement changed owner",
                    ));
                }
                self.finish_classic_dde_event_ack_local(event, host)?;
                let release_finish =
                    self.finish_pending_dde_release_after_event_ack(event, memory, host)?;
                self.retire_classic_dde_terminal_operation(identity)?;
                self.apply_server_finish(release_finish, cpu, dos, memory, host)
            }
            cleanup_owner @ ClassicDdeOperationOwner::UnpublishedCleanupRetire {
                cleanup_id,
                owner,
                expected_revision,
            } => {
                if let Win16HostClassicDdeStep::StartedFailure(failure) = &step {
                    let (retired_owner, resume_parent) =
                        self.consume_classic_dde_source_retirement(identity, host)?;
                    if retired_owner != cleanup_owner || resume_parent.is_some() {
                        return Err(dde_invariant(
                            "failed unpublished cleanup changed its exact owner",
                        ));
                    }
                    let _ = (cleanup_id, expected_revision);
                    return Err(RuntimeError::with_source(
                        Kind::HostFailure,
                        "classic DDE endpoint retirement failed; cleanup journal remains live",
                        Arc::clone(&failure.cause),
                    ));
                }
                let Win16HostClassicDdeResult::Retired(receipt) = terminal_result(&step)? else {
                    return Err(dde_invariant(
                        "unpublished endpoint cleanup completed without a retirement receipt",
                    ));
                };
                if !self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .is_some_and(|frame| frame.unpublished_retirement_recorded)
                {
                    self.record_ole1_unpublished_cleanup_retirement(
                        cleanup_id,
                        owner,
                        expected_revision,
                        receipt,
                    )?;
                    self.classic_dde
                        .operations
                        .last_mut()
                        .filter(|frame| frame.identity == identity)
                        .ok_or_else(|| {
                            dde_invariant("unpublished cleanup lost its exact operation frame")
                        })?
                        .unpublished_retirement_recorded = true;
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement(identity, host)?;
                if retired_owner != cleanup_owner || resume_parent.is_some() {
                    return Err(dde_invariant(
                        "unpublished cleanup retirement changed owner",
                    ));
                }
                let _ = self.drive_one_unpublished_cleanup(owner, host)?;
                Ok(false)
            }
            ClassicDdeOperationOwner::UnpublishedCleanupEvent {
                cleanup_id,
                ref event,
            } => {
                let Win16HostClassicDdeResult::EventAcknowledged(event_id) =
                    terminal_result(&step)?
                else {
                    return Err(dde_invariant(
                        "unpublished cleanup event completed without EventAcknowledged",
                    ));
                };
                if *event_id != event.event_id {
                    return Err(dde_invariant(
                        "unpublished cleanup acknowledged a different exact EventId",
                    ));
                }
                if !self.acknowledge_ole1_unpublished_cleanup_event(cleanup_id, event)? {
                    return Err(dde_invariant(
                        "unpublished cleanup journal rejected its exact EventId ACK",
                    ));
                }
                let (retired_owner, resume_parent) =
                    self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
                if !matches!(
                    retired_owner,
                    ClassicDdeOperationOwner::UnpublishedCleanupEvent {
                        cleanup_id: retired_cleanup_id,
                        event: retired_event,
                    } if retired_cleanup_id == cleanup_id && &retired_event == event,
                ) || resume_parent.is_some() {
                    return Err(dde_invariant(
                        "unpublished cleanup Event ACK changed its exact owner",
                    ));
                }
                self.finish_classic_dde_event_ack_local(event, host)?;
                self.retire_classic_dde_terminal_operation(identity)?;
                let _ = self.drive_one_unpublished_cleanup(event.owner, host)?;
                Ok(false)
            }
            shutdown_owner @ ClassicDdeOperationOwner::ClassicDdeOwnerShutdown { owner } => {
                self.consume_classic_dde_owner_quiescence(
                    identity,
                    shutdown_owner,
                    owner,
                    step,
                    host,
                )
            }
        }
    }
}
