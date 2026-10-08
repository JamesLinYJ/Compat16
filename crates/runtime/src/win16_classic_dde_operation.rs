//! Exact begin/resume/source-retirement handling for classic WM_DDE calls.

use super::{
    Win16State,
    classic_dde_dispatch::{
        ClassicDdeCallbackEventCleanup, ClassicDdeOperationFrame, ClassicDdeOperationOwner,
        ClassicDdePendingBegin,
    },
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ClassicDdeOperationIdentity,
    Win16HostClassicDdeCall, Win16HostClassicDdeCallbackReply, Win16HostClassicDdeResume,
    Win16HostClassicDdeStep,
};

impl Win16State {
    /// Begin one host call and retain its exact operation before any caller
    /// can process a callback or terminal result. The returned identity is
    /// the only key the OLE business journal may bind to.
    pub(in crate::win16_runtime) fn begin_classic_dde_host_call(
        &mut self,
        call: Win16HostClassicDdeCall,
        owner: ClassicDdeOperationOwner,
        resume_parent: Option<Win16HostClassicDdeCallbackReply>,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16ClassicDdeOperationIdentity, RuntimeError> {
        let call_owner = call_owner(&call);
        let operation_owner = owner;
        if call_owner != owner_id(&operation_owner) {
            return Err(dde_invariant(
                "classic DDE operation owner does not match the exact host call owner",
            ));
        }
        if let Win16HostClassicDdeCall::AcknowledgeEvent {
            owner: event_owner,
            endpoint,
            event_id,
        } = &call
        {
            let event = self
                .classic_dde
                .queued_events
                .iter()
                .find(|record| {
                    record.event.owner == *event_owner
                        && record.event.endpoint == *endpoint
                        && record.event.event_id == *event_id
                })
                .ok_or_else(|| {
                    dde_invariant("classic DDE delivery ACK has no exact retained queued event")
                })?;
            if self.classic_dde.event_tracker.pending().all(|progress| {
                progress.owner != *event_owner
                    || progress.endpoint != *endpoint
                    || progress.event_id != *event_id
                    || progress.worker_generation != event.event.worker_generation
                    || progress.phase != crate::Win16ClassicDdeEventPhase::Published
            }) {
                return Err(dde_invariant(
                    "classic DDE delivery ACK was requested outside its exact published phase",
                ));
            }
        }
        if let Some(parent) = &resume_parent {
            let top = self.classic_dde.operations.last().ok_or_else(|| {
                dde_invariant("nested classic DDE host call has no retained parent operation")
            })?;
            if top.identity.owner != parent.owner
                || top.identity.id != parent.operation_id
                || top.identity.worker_generation != parent.worker_generation
                || !matches!(&top.step, Win16HostClassicDdeStep::Callback(step)
                    if step.callback == parent.callback && step.frame == parent.frame
                        && step.endpoint == parent.endpoint && step.event.event_id == parent.event_id
                        && step.event.peer == parent.peer && step.causal_parents == parent.causal_parents)
            {
                return Err(dde_invariant(
                    "nested classic DDE call does not own the exact suspended parent callback",
                ));
            }
        }
        self.classic_dde
            .operations
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve classic DDE host operation owner",
                    error,
                )
            })?;
        if let ClassicDdeOperationOwner::Client {
            owner: client_owner,
            operation,
            bind_initiate: true,
        } = &operation_owner
        {
            if *client_owner != call_owner {
                return Err(dde_invariant(
                    "client INITIATE operation owner changed before host begin",
                ));
            }
            let Win16HostClassicDdeCall::Send {
                owner: send_owner,
                endpoint,
                target: crate::Win16HostClassicDdeTarget::BroadcastInitiate,
                message:
                    crate::Win16ClassicDdeMessage::Initiate {
                        application: Some(application),
                        topic: Some(topic),
                    },
                ..
            } = &call
            else {
                return Err(dde_invariant(
                    "client INITIATE bind action is not an exact BroadcastInitiate message",
                ));
            };
            if send_owner != &call_owner {
                return Err(dde_invariant("client INITIATE changed its task owner"));
            }
            self.retain_classic_dde_initiate_atoms(
                *send_owner,
                *endpoint,
                *operation,
                application,
                topic,
                host,
            )?;
        }
        let pending = ClassicDdePendingBegin {
            call: call.clone(),
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
                        "retain retryable classic DDE operation begin",
                        error,
                    )
                })?;
            self.classic_dde.pending_begins.push(pending.clone());
        }
        let step = match host.win16_classic_dde_begin(call.clone()) {
            Ok(step) => step,
            Err(error) => return Err(error),
        };
        let Win16HostClassicDdeStep::Started(identity) = step else {
            return Err(dde_invariant(
                "classic DDE host begin returned a step before publishing Started",
            ));
        };
        if identity.owner != call_owner || identity.id.0 == 0 || identity.worker_generation == 0 {
            return Err(dde_invariant(
                "classic DDE host begin returned a mismatched operation identity",
            ));
        }
        let client_binding_pending =
            matches!(operation_owner, ClassicDdeOperationOwner::Client { .. });
        let acknowledge_event = match &call {
            Win16HostClassicDdeCall::AcknowledgeEvent { owner, endpoint, event_id } =>
                Some((*owner, *endpoint, *event_id)),
            _ => None,
        };
        self.classic_dde.operations.push(ClassicDdeOperationFrame {
            identity,
            call,
            step: Win16HostClassicDdeStep::Started(identity),
            owner: operation_owner.clone(),
            resume_parent,
            source_retirement_consumed: false,
            client_binding_pending,
            client_terminal_disposition: None,
            client_receipt_committed: false,
            server_initiate_resume: None,
            server_initiate_receipt_committed: false,
            server_dde_finish: None,
            server_protocol_result_global_retired: false,
            unpublished_retirement_recorded: false,
            pending_callback_resume: None,
            accepted_untranslated_callbacks: Vec::new(),
            pending_callback_event_cleanup: None,
        });
        if let Some((event_owner, endpoint, event_id)) = acknowledge_event {
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
                    dde_invariant("classic DDE delivery ACK has no exact retained queued event")
                })?;
            if event.event.worker_generation != identity.worker_generation {
                return Err(dde_invariant(
                    "classic DDE delivery ACK operation changed worker generation",
                ));
            }
            self.classic_dde.event_tracker.acknowledgement_started(
                event_owner,
                endpoint,
                identity.worker_generation,
                event_id,
            )?;
        }
        let pending_index = self
            .classic_dde
            .pending_begins
            .iter()
            .position(|existing| existing == &pending)
            .ok_or_else(|| {
                dde_invariant("classic DDE started operation lost its retryable begin record")
            })?;
        self.classic_dde.pending_begins.remove(pending_index);
        self.retry_exact_classic_dde_client_bind(identity)?;
        Ok(identity)
    }

    /// Resume only the exact top host operation. `reply` must correspond to
    /// its saved synchronous callback; `None` is valid only after a Started
    /// progress step or after an exact callback reply was already queued for
    /// a parked USER wait.
    pub(in crate::win16_runtime) fn resume_classic_dde_host_call(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        reply: Option<Win16HostClassicDdeCallbackReply>,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostClassicDdeStep, RuntimeError> {
        let Some(top) = self.classic_dde.operations.last() else {
            return Err(dde_invariant("classic DDE resume has no live operation"));
        };
        if top.identity != identity {
            return Err(dde_invariant(
                "classic DDE resume is not the exact LIFO operation",
            ));
        }
        if reply.is_some() && top.pending_callback_event_cleanup.is_some() {
            return Err(dde_invariant(
                "classic DDE callback cleanup is still pending before another reply",
            ));
        }
        match (&top.step, &reply) {
            (Win16HostClassicDdeStep::Started(_), None) => {}
            (Win16HostClassicDdeStep::Callback(step), Some(reply)) => {
                validate_classic_callback_reply(identity, step, reply)?;
            }
            (Win16HostClassicDdeStep::Started(_), Some(_)) => {
                return Err(dde_invariant(
                    "classic DDE reply has no exact awaiting callback",
                ));
            }
            (Win16HostClassicDdeStep::Callback(_), None) => {
                return Err(dde_invariant(
                    "classic DDE callback continuation omitted its exact reply",
                ));
            }
            (
                Win16HostClassicDdeStep::Complete { .. }
                | Win16HostClassicDdeStep::StartedFailure(_),
                _,
            ) => {
                return Err(dde_invariant(
                    "terminal classic DDE operation was resumed before source retirement",
                ));
            }
        }
        let pending_reply = top.pending_callback_resume.clone();
        let callback_untranslated = reply.as_ref().is_some_and(|reply| {
            matches!(
                &reply.result,
                crate::Win16HostClassicDdeCallbackResult::Untranslated
            )
        });
        let accepted_untranslated = if callback_untranslated {
            reply.clone()
        } else {
            None
        };
        let callback_event = match (&top.step, &reply) {
            (Win16HostClassicDdeStep::Callback(step), Some(_)) => Some(step.event.clone()),
            _ => None,
        };
        if callback_untranslated {
            let top = self.classic_dde.operations.last_mut().ok_or_else(|| {
                dde_invariant("classic DDE operation disappeared before retaining Untranslated")
            })?;
            top.accepted_untranslated_callbacks.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain accepted classic DDE Untranslated callback proof",
                    error,
                )
            })?;
        }
        if let Some(reply) = &reply {
            if let Some(pending) = &pending_reply {
                if pending != reply {
                    return Err(dde_invariant(
                        "classic DDE callback retry changed its exact pending reply",
                    ));
                }
            } else {
                self.classic_dde
                    .operations
                    .last_mut()
                    .ok_or_else(|| {
                        dde_invariant("classic DDE operation disappeared before callback resume")
                    })?
                    .pending_callback_resume = Some(reply.clone());
            }
        }
        let next = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
            operation: identity,
            reply,
        })?;
        validate_step(identity, &next)?;
        let pending_event_cleanup = {
            let top = self.classic_dde.operations.last_mut().ok_or_else(|| {
                dde_invariant("classic DDE operation disappeared after host resume")
            })?;
            top.step = next.clone();
            top.pending_callback_resume = None;
            if let Some(reply) = accepted_untranslated {
                top.accepted_untranslated_callbacks.push(reply);
            }
            if let Some(event) = callback_event {
                top.pending_callback_event_cleanup = Some(ClassicDdeCallbackEventCleanup {
                    event,
                    accepted_untranslated: callback_untranslated,
                    guest_global_pending: callback_untranslated,
                    atoms_pending: true,
                });
            }
            top.pending_callback_event_cleanup.clone()
        };
        if pending_event_cleanup.is_some() {
            self.retry_classic_dde_callback_event_cleanup(identity, host)?;
        }
        Ok(next)
    }

    /// Retry the exact accepted callback cleanup phases. An accepted
    /// Untranslated reply first releases its event-scoped guest HGLOBAL, then
    /// deletes any remaining event ATOM refs. Each completed phase is recorded
    /// before the next fallible action so Started/Complete retries never infer
    /// cleanup state from a reply that was already consumed.
    pub(in crate::win16_runtime) fn retry_classic_dde_callback_event_cleanup(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(top) = self.classic_dde.operations.last() else {
            return Err(dde_invariant("classic DDE callback cleanup has no operation"));
        };
        if top.identity != identity {
            return Err(dde_invariant(
                "classic DDE callback cleanup is not for the exact top operation",
            ));
        }
        let Some(mut cleanup) = top.pending_callback_event_cleanup.clone() else {
            return Ok(());
        };
        if cleanup.event.owner != identity.owner
            || cleanup.event.worker_generation != identity.worker_generation
        {
            return Err(dde_invariant(
                "classic DDE callback cleanup changed its exact owner or worker generation",
            ));
        }
        if cleanup.guest_global_pending && !cleanup.accepted_untranslated {
            return Err(dde_invariant(
                "classic DDE global cleanup lacks an accepted Untranslated reply",
            ));
        }
        if cleanup.accepted_untranslated
            && !top.accepted_untranslated_callbacks.iter().any(|reply| {
                reply.owner == identity.owner
                    && reply.operation_id == identity.id
                    && reply.worker_generation == identity.worker_generation
                    && reply.endpoint == cleanup.event.endpoint
                    && reply.event_id == cleanup.event.event_id
                    && reply.peer == cleanup.event.peer
                    && matches!(
                        &reply.result,
                        crate::Win16HostClassicDdeCallbackResult::Untranslated
                    )
                    && matches!(
                        cleanup.event.delivery,
                        crate::Win16ClassicDdeDeliveryKind::Synchronous {
                            operation_id,
                            callback,
                            frame,
                        } if operation_id == reply.operation_id
                            && callback == reply.callback
                            && frame == reply.frame
                    )
            })
        {
            return Err(dde_invariant(
                "classic DDE cleanup phase lost its accepted Untranslated proof",
            ));
        }

        if cleanup.guest_global_pending {
            self.retire_classic_dde_guest_global_key(
                cleanup.event.owner,
                cleanup.event.endpoint,
                cleanup.event.worker_generation,
                cleanup.event.event_id,
            )?;
            let top = self.classic_dde.operations.last_mut().ok_or_else(|| {
                dde_invariant("classic DDE operation disappeared after guest HGLOBAL cleanup")
            })?;
            let retained_identity = top.identity;
            let retained = top.pending_callback_event_cleanup.as_mut().filter(|pending| {
                retained_identity == identity && pending.event == cleanup.event
            }).ok_or_else(|| dde_invariant(
                "classic DDE HGLOBAL cleanup lost its exact retained phase journal"))?;
            retained.guest_global_pending = false;
            cleanup.guest_global_pending = false;
        }
        if cleanup.atoms_pending {
            self.retire_classic_dde_event_atoms(&cleanup.event, host)?;
            let top = self.classic_dde.operations.last_mut().ok_or_else(|| {
                dde_invariant("classic DDE operation disappeared after event atom cleanup")
            })?;
            let retained_identity = top.identity;
            let retained = top.pending_callback_event_cleanup.as_mut().filter(|pending| {
                retained_identity == identity && pending.event == cleanup.event
            }).ok_or_else(|| dde_invariant(
                "classic DDE atom cleanup lost its exact retained phase journal"))?;
            retained.atoms_pending = false;
            cleanup.atoms_pending = false;
        }
        if !cleanup.guest_global_pending && !cleanup.atoms_pending {
            let top = self.classic_dde.operations.last_mut().ok_or_else(|| {
                dde_invariant("classic DDE operation disappeared after callback cleanup")
            })?;
            if top.identity != identity
                || top.pending_callback_event_cleanup.as_ref() != Some(&cleanup)
            {
                return Err(dde_invariant(
                    "classic DDE completed callback cleanup changed its exact phase journal",
                ));
            }
            top.pending_callback_event_cleanup = None;
        }
        Ok(())
    }

    /// Keep a terminal proof until the client/server journal has consumed
    /// the exact typed result. This method only acknowledges the host source
    /// after that caller has committed it.
    pub(in crate::win16_runtime) fn consume_classic_dde_source_retirement(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<
        (
            ClassicDdeOperationOwner,
            Option<Win16HostClassicDdeCallbackReply>,
        ),
        RuntimeError,
    > {
        let owner = self.consume_classic_dde_source_retirement_without_pop(identity, host)?;
        self.retire_classic_dde_terminal_operation(identity)?;
        Ok(owner)
    }

    /// Consume the host source proof and exact callback cleanup while keeping
    /// the terminal operation frame available for retryable local EventId
    /// cleanup. The caller must pop it with
    /// `retire_classic_dde_terminal_operation` only after all owner ledgers
    /// have accepted their terminal.
    pub(in crate::win16_runtime) fn consume_classic_dde_source_retirement_without_pop(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<
        (
            ClassicDdeOperationOwner,
            Option<Win16HostClassicDdeCallbackReply>,
        ),
        RuntimeError,
    > {
        self.retry_classic_dde_callback_event_cleanup(identity, host)?;
        let Some(top) = self.classic_dde.operations.last() else {
            return Err(dde_invariant("classic DDE terminal has no live operation"));
        };
        if top.identity != identity {
            return Err(dde_invariant(
                "classic DDE terminal is not the exact LIFO operation",
            ));
        }
        let proof = match &top.step {
            Win16HostClassicDdeStep::Complete {
                operation,
                source_retired,
                ..
            } if *operation == identity => source_retired,
            Win16HostClassicDdeStep::StartedFailure(failure) if failure.operation == identity => {
                &failure.source_retired
            }
            _ => {
                return Err(dde_invariant(
                    "classic DDE source retirement lacks an exact host terminal",
                ));
            }
        };
        let owner = top.owner.clone();
        let resume_parent = top.resume_parent.clone();
        let callbacks = proof.callbacks.clone();
        for reply in &top.accepted_untranslated_callbacks {
            let exact_untranslated_retirement = proof.callbacks.iter().any(|callback| {
                callback.callback == reply.callback
                    && callback.frame == reply.frame
                    && callback.event_id == reply.event_id
                    && callback.endpoint == reply.endpoint
                    && callback.peer == reply.peer
                    && callback.result
                        == crate::Win16HostClassicDdeCallbackResult::Untranslated
            });
            if !exact_untranslated_retirement {
                return Err(dde_invariant(
                    "classic DDE terminal omitted an accepted exact Untranslated callback receipt",
                ));
            }
        }
        if !top.source_retirement_consumed {
            host.win16_classic_dde_source_retirement_consumed(proof)?;
            let top = self.classic_dde
                .operations
                .last_mut()
                .ok_or_else(|| {
                    dde_invariant(
                        "classic DDE operation disappeared while consuming source retirement",
                    )
                })?;
            if top.identity != identity {
                return Err(dde_invariant(
                    "classic DDE operation changed while consuming source retirement",
                ));
            }
            top.source_retirement_consumed = true;
            top.accepted_untranslated_callbacks.clear();
        }
        // Guest ATOM/HGLOBAL staging copies are independent of the native
        // transfer lease. Retire them only after the host confirmed exact
        // callback/source retirement, and keep the terminal frame for retry
        // if one of these local cleanup operations fails.
        for callback in callbacks {
            self.retire_classic_dde_event_atoms_by_key(
                identity.owner,
                callback.endpoint,
                identity.worker_generation,
                callback.event_id,
                host,
            )?;
        }
        Ok((owner, resume_parent))
    }

    pub(in crate::win16_runtime) fn retire_classic_dde_terminal_operation(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), RuntimeError> {
        let Some(top) = self.classic_dde.operations.last() else {
            return Err(dde_invariant("classic DDE terminal operation disappeared"));
        };
        if top.identity != identity
            || !top.source_retirement_consumed
            || !top.accepted_untranslated_callbacks.is_empty()
            || top.pending_callback_event_cleanup.is_some()
            || !matches!(
                &top.step,
                Win16HostClassicDdeStep::Complete { .. }
                    | Win16HostClassicDdeStep::StartedFailure(_)
            )
        {
            return Err(dde_invariant(
                "classic DDE operation cannot retire before its exact source proof",
            ));
        }
        self.classic_dde.operations.pop();
        Ok(())
    }

    pub(in crate::win16_runtime) fn classic_dde_top_operation(
        &self,
    ) -> Option<(Win16ClassicDdeOperationIdentity, Win16HostClassicDdeStep)> {
        self.classic_dde
            .operations
            .last()
            .map(|frame| (frame.identity, frame.step.clone()))
    }

    pub(super) fn retry_exact_classic_dde_client_bind(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), RuntimeError> {
        let pending = self.classic_dde.operations.last().and_then(|frame| {
            if frame.identity != identity || !frame.client_binding_pending {
                return None;
            }
            match &frame.owner {
                ClassicDdeOperationOwner::Client {
                    operation,
                    bind_initiate,
                    ..
                } => Some((*operation, *bind_initiate)),
                _ => None,
            }
        });
        let Some((operation, bind_initiate)) = pending else {
            return Ok(());
        };
        let result = if bind_initiate {
            self.bind_ole1_client_dde_initiate_operation(operation, identity)
        } else {
            self.bind_ole1_client_dde_host_operation(operation, identity)
        };
        result.map_err(|message| RuntimeError::new(Kind::ResourceExhausted, message))?;
        let frame = self.classic_dde.operations.last_mut().ok_or_else(|| {
            dde_invariant("classic DDE client operation disappeared after exact journal bind")
        })?;
        if frame.identity != identity {
            return Err(dde_invariant(
                "classic DDE client identity changed during exact journal bind",
            ));
        }
        frame.client_binding_pending = false;
        Ok(())
    }

    pub(in crate::win16_runtime) fn classic_dde_top_operation_detail(
        &self,
    ) -> Option<(
        Win16ClassicDdeOperationIdentity,
        Win16HostClassicDdeStep,
        ClassicDdeOperationOwner,
        Option<Win16HostClassicDdeCallbackReply>,
    )> {
        self.classic_dde.operations.last().map(|frame| {
            (
                frame.identity,
                frame.step.clone(),
                frame.owner.clone(),
                frame.resume_parent.clone(),
            )
        })
    }
}

pub(in crate::win16_runtime) fn owner_id(
    owner: &ClassicDdeOperationOwner,
) -> guest_core::OwnerId {
    match owner {
        ClassicDdeOperationOwner::PollOwner { owner }
        | ClassicDdeOperationOwner::PollEndpoint { owner, .. }
        | ClassicDdeOperationOwner::Client { owner, .. }
        | ClassicDdeOperationOwner::ClientEventAcknowledgement { owner, .. }
        | ClassicDdeOperationOwner::UnpublishedCleanupRetire { owner, .. }
        | ClassicDdeOperationOwner::ClassicDdeOwnerShutdown { owner } => *owner,
        ClassicDdeOperationOwner::ServerInitiate { continuation } => match continuation {
            super::win16_ole1_server_dde::Ole1ServerInitiateContinuation::Reply { step, .. }
            | super::win16_ole1_server_dde::Ole1ServerInitiateContinuation::Forward { step, .. } => step.owner,
        },
        ClassicDdeOperationOwner::ServerDde { continuation } => match continuation {
            super::win16_ole1_server_callback::Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(
                after,
            ) => match after {
                super::win16_ole1_server_callback::Ole1ServerDdeAfterPost::ResumeSynchronousWindow {
                    reply, ..
                } => reply.owner,
                super::win16_ole1_server_callback::Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
                    event, ..
                } => event.owner,
            },
            super::win16_ole1_server_callback::Ole1ServerDdeHostContinuation::QueuedEventAcknowledgement {
                event,
            }
            | super::win16_ole1_server_callback::Ole1ServerDdeHostContinuation::TerminateResponse {
                event, ..
            }
            | super::win16_ole1_server_callback::Ole1ServerDdeHostContinuation::EventAcknowledgement {
                event, ..
            } => event.owner,
        },
        ClassicDdeOperationOwner::ServerProtocolResultPost { event, .. }
        | ClassicDdeOperationOwner::ServerProtocolResultEventAcknowledgement { event } => event.owner,
        ClassicDdeOperationOwner::UnpublishedCleanupEvent { event, .. } => event.owner,
    }
}

pub(super) fn validate_step(
    identity: Win16ClassicDdeOperationIdentity,
    step: &Win16HostClassicDdeStep,
) -> Result<(), RuntimeError> {
    let valid = match step {
        Win16HostClassicDdeStep::Started(candidate) => *candidate == identity,
        Win16HostClassicDdeStep::Callback(callback) => {
            callback.owner == identity.owner
                && callback.event.owner == identity.owner
                && callback.endpoint == callback.event.endpoint
                && callback.worker_generation == identity.worker_generation
                && callback.event.worker_generation == identity.worker_generation
                && callback.operation_id == identity.id
                && callback.event.event_id.0 != 0
                && matches!(callback.event.delivery,
                    crate::Win16ClassicDdeDeliveryKind::Synchronous {
                        operation_id, callback: source, frame,
                    } if operation_id == identity.id && source == callback.callback
                        && frame == callback.frame)
                && callback.causal_parents.iter().all(|parent| {
                    parent.owner == identity.owner
                        && parent.worker_generation == identity.worker_generation
                        && parent.id != identity.id
                        && parent.id.0 != 0
                })
        }
        Win16HostClassicDdeStep::Complete {
            operation,
            source_retired,
            ..
        } => *operation == identity && source_retired.operation == identity,
        Win16HostClassicDdeStep::StartedFailure(failure) => {
            failure.operation == identity && failure.source_retired.operation == identity
        }
    };
    if !valid {
        return Err(dde_invariant(
            "classic DDE host step changed its exact operation/source",
        ));
    }
    Ok(())
}

fn validate_classic_callback_reply(
    identity: Win16ClassicDdeOperationIdentity,
    step: &crate::Win16HostClassicDdeCallbackStep,
    reply: &Win16HostClassicDdeCallbackReply,
) -> Result<(), RuntimeError> {
    if reply.owner != identity.owner
        || reply.endpoint != step.endpoint
        || reply.operation_id != identity.id
        || reply.worker_generation != identity.worker_generation
        || reply.callback != step.callback
        || reply.frame != step.frame
        || reply.event_id != step.event.event_id
        || reply.peer != step.event.peer
        || reply.causal_parents != step.causal_parents
    {
        return Err(dde_invariant(
            "classic DDE callback answer changed its exact source tuple",
        ));
    }
    Ok(())
}

fn call_owner(call: &Win16HostClassicDdeCall) -> guest_core::OwnerId {
    use Win16HostClassicDdeCall as Call;
    match call {
        Call::QuiesceOwner { owner, .. }
        | Call::CreateEndpoint { owner, .. }
        | Call::RetireEndpoint { owner, .. }
        | Call::Send { owner, .. }
        | Call::Post { owner, .. }
        | Call::Poll { owner, .. }
        | Call::PollOwner { owner }
        | Call::AcknowledgeEvent { owner, .. }
        | Call::ReplyInitiate { owner, .. }
        | Call::BindConversation { owner, .. }
        | Call::RetireConversation { owner, .. }
        | Call::ForwardInitiateToChild { owner, .. } => *owner,
    }
}

fn dde_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
