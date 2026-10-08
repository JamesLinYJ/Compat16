//! Independent classic WM_DDE operation owners layered on the shared USER
//! worker. This ledger never consumes a GetMessage/WaitMessage USER proof.

use std::sync::mpsc::{self, Receiver};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ClassicDdeOperationIdentity,
    Win16HostClassicDdeCall, Win16HostClassicDdeCallbackReply,
    Win16HostClassicDdeCallbackRetirement,
    Win16HostClassicDdeResume, Win16HostClassicDdeSourceRetiredProof,
    Win16HostClassicDdeStep,
};

use super::{Win16Windows, WorkerCommand, allocate_shared_identity, worker_stopped};

pub(super) struct PendingClassicDdeOperation {
    identity: Win16ClassicDdeOperationIdentity,
    response: Receiver<Result<Win16HostClassicDdeStep, RuntimeError>>,
    awaiting: Option<std::sync::Arc<runtime::Win16HostClassicDdeCallbackStep>>,
    callback_receipts: Vec<Win16HostClassicDdeCallbackRetirement>,
    source_retired: Option<std::sync::Arc<Win16HostClassicDdeSourceRetiredProof>>,
}

impl Win16Windows {
    pub(in crate::windows) fn classic_dde_begin(
        &mut self,
        call: Win16HostClassicDdeCall,
    ) -> Result<Win16HostClassicDdeStep, RuntimeError> {
        if self.aborted {
            return Err(RuntimeError::new(Kind::HostFailure,
                "classic WM_DDE host is unavailable after USER worker abort"));
        }
        let owner = call_owner(&call);
        let worker_generation = self.worker()?.worker_generation();
        let identity = Win16ClassicDdeOperationIdentity {
            owner,
            id: runtime::Win16ClassicDdeOperationId(
                allocate_shared_identity(&self.identity_source)?,
            ),
            worker_generation,
        };
        if identity.worker_generation == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE worker generation is zero"));
        }
        self.classic_dde_sources.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic WM_DDE operation owner", error)
        })?;
        if let Some(parent) = self.classic_dde_sources.last()
            && parent.awaiting.is_none()
            && parent.source_retired.is_none()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE nested operation has no exact suspended callback owner"));
        }
        let (sender, response) = mpsc::channel();
        self.send(WorkerCommand::ClassicDdeBegin {
            operation: identity,
            call,
            response: sender,
        }).map_err(|_| worker_stopped("submit classic WM_DDE operation"))?;
        self.classic_dde_sources.push(PendingClassicDdeOperation {
            identity,
            response,
            awaiting: None,
            callback_receipts: Vec::new(),
            source_retired: None,
        });
        Ok(Win16HostClassicDdeStep::Started(identity))
    }

    pub(in crate::windows) fn classic_dde_resume(
        &mut self,
        resume: Win16HostClassicDdeResume,
    ) -> Result<Win16HostClassicDdeStep, RuntimeError> {
        let Some(pending_index) = self.classic_dde_sources.len().checked_sub(1) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE continuation has no pending operation owner"));
        };
        let (identity, awaiting, source_retired) = {
            let pending = &self.classic_dde_sources[pending_index];
            (pending.identity, pending.awaiting.clone(), pending.source_retired.is_some())
        };
        if identity != resume.operation || source_retired {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE continuation does not match the exact live top operation"));
        }
        // A parked USER wait owns the outer native message pump. Its endpoint
        // callback must return before the worker can retire this classic-DDE
        // source. Return a progress step after queuing the exact reply so the
        // runtime can continue the USER wait; the terminal proof is collected
        // by a later classic-DDE resume after that wait has unwound.
        let retire_after_parked_wait = awaiting.as_ref().is_some_and(|step|
            step.source == runtime::Win16ClassicDdeCallbackSource::ParkedUserWait);
        match (&awaiting, &resume.reply) {
            (Some(step), Some(reply)) => validate_callback_reply(&identity, step, reply)?,
            (None, None) => {}
            (Some(_), None) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE callback continuation omitted its exact callback reply")),
            (None, Some(_)) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE callback reply has no exact awaiting callback")),
        }

        if let Some(reply) = resume.reply.as_ref() {
            self.classic_dde_sources[pending_index].callback_receipts.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve exact classic WM_DDE callback retirement", error)
            })?;
            self.send(WorkerCommand::ClassicDdeResume {
                operation: identity,
                reply: reply.clone(),
            }).map_err(|_| worker_stopped("resume classic WM_DDE endpoint callback"))?;
            let pending = &mut self.classic_dde_sources[pending_index];
            pending.callback_receipts.push(callback_retirement(reply));
            pending.awaiting = None;
        }
        if retire_after_parked_wait {
            return Ok(Win16HostClassicDdeStep::Started(identity));
        }
        receive_exact_step(&mut self.classic_dde_sources[pending_index])
    }

    pub(in crate::windows) fn classic_dde_source_retirement_consumed(
        &mut self,
        proof: &Win16HostClassicDdeSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        let Some(pending) = self.classic_dde_sources.last() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE source-retirement acknowledgement has no owner"));
        };
        if pending.identity != proof.operation
            || pending.source_retired.as_deref() != Some(proof)
            || pending.awaiting.is_some()
            || pending.callback_receipts != proof.callbacks
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "classic WM_DDE source-retirement proof changed before exact consumption"));
        }
        self.classic_dde_sources.pop();
        Ok(())
    }
}

fn receive_exact_step(
    pending: &mut PendingClassicDdeOperation,
) -> Result<Win16HostClassicDdeStep, RuntimeError> {
    let received = pending.response.recv().map_err(|error| RuntimeError::with_source(
        Kind::HostFailure, "receive classic WM_DDE worker step", error,
    ))??;
    match &received {
        Win16HostClassicDdeStep::Started(identity) => {
            if *identity != pending.identity || pending.awaiting.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "classic WM_DDE worker replayed a conflicting Started step"));
            }
        }
        Win16HostClassicDdeStep::Callback(step) => {
            validate_callback_step(&pending.identity, step)?;
            if pending.awaiting.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "classic WM_DDE worker emitted a second callback before resume"));
            }
            pending.awaiting = Some(std::sync::Arc::clone(step));
        }
        Win16HostClassicDdeStep::Complete { operation, source_retired, .. } => {
            if *operation != pending.identity
                || source_retired.operation != pending.identity
                || pending.awaiting.is_some()
                || source_retired.callbacks != pending.callback_receipts
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "classic WM_DDE completion has a conflicting source-retirement proof"));
            }
            pending.source_retired = Some(std::sync::Arc::clone(source_retired));
        }
        Win16HostClassicDdeStep::StartedFailure(failure) => {
            if failure.operation != pending.identity
                || failure.source_retired.operation != pending.identity
                || failure.source_retired.callbacks != pending.callback_receipts
                || pending.awaiting.is_some()
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "classic WM_DDE started failure has conflicting source-retirement evidence"));
            }
            pending.source_retired = Some(std::sync::Arc::clone(&failure.source_retired));
        }
    }
    Ok(received)
}

fn validate_callback_step(
    operation: &Win16ClassicDdeOperationIdentity,
    step: &runtime::Win16HostClassicDdeCallbackStep,
) -> Result<(), RuntimeError> {
    let runtime::Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id, callback, frame,
    } = step.event.delivery else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "classic WM_DDE callback step contains a queued event"));
    };
    if step.owner != operation.owner
        || step.event.owner != operation.owner
        || step.operation_id != operation.id
        || operation_id != operation.id
        || step.worker_generation != operation.worker_generation
        || step.event.worker_generation != operation.worker_generation
        || step.endpoint != step.event.endpoint
        || step.callback != callback
        || step.frame != frame
        || step.event.event_id.0 == 0
        || step.causal_parents.iter().any(|parent|
            parent.owner != operation.owner
                || parent.worker_generation != operation.worker_generation
                || parent.id == operation.id || parent.id.0 == 0)
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "classic WM_DDE callback step does not match its exact operation/event tuple"));
    }
    Ok(())
}

pub(super) fn validate_callback_reply(
    operation: &Win16ClassicDdeOperationIdentity,
    step: &runtime::Win16HostClassicDdeCallbackStep,
    reply: &Win16HostClassicDdeCallbackReply,
) -> Result<(), RuntimeError> {
    if reply.owner != operation.owner
        || reply.endpoint != step.endpoint
        || reply.operation_id != operation.id
        || reply.worker_generation != operation.worker_generation
        || reply.callback != step.callback
        || reply.frame != step.frame
        || reply.event_id != step.event.event_id
        || reply.peer != step.event.peer
        || reply.causal_parents != step.causal_parents
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "classic WM_DDE callback reply does not match the exact live endpoint frame"));
    }
    Ok(())
}

pub(super) fn callback_retirement(
    reply: &Win16HostClassicDdeCallbackReply,
) -> Win16HostClassicDdeCallbackRetirement {
    Win16HostClassicDdeCallbackRetirement {
        callback: reply.callback,
        frame: reply.frame,
        event_id: reply.event_id,
        endpoint: reply.endpoint,
        peer: reply.peer,
        result: reply.result.clone(),
    }
}

fn call_owner(call: &Win16HostClassicDdeCall) -> guest_core::OwnerId {
    match call {
        Win16HostClassicDdeCall::QuiesceOwner { owner, .. }
        | Win16HostClassicDdeCall::CreateEndpoint { owner, .. }
        | Win16HostClassicDdeCall::RetireEndpoint { owner, .. }
        | Win16HostClassicDdeCall::BindConversation { owner, .. }
        | Win16HostClassicDdeCall::RetireConversation { owner, .. }
        | Win16HostClassicDdeCall::Send { owner, .. }
        | Win16HostClassicDdeCall::Post { owner, .. }
        | Win16HostClassicDdeCall::Poll { owner, .. }
        | Win16HostClassicDdeCall::PollOwner { owner }
        | Win16HostClassicDdeCall::AcknowledgeEvent { owner, .. }
        | Win16HostClassicDdeCall::ReplyInitiate { owner, .. }
        | Win16HostClassicDdeCall::ForwardInitiateToChild { owner, .. } => *owner,
    }
}
