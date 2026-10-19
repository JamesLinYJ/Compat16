//! Runtime dispatch for classic WM_DDE callbacks and queued mailbox events.
//!
//! The USER worker owns native windows, ATOMs and HGLOBAL transfers. This
//! module only routes typed snapshots through the OLE1 journals and checked
//! guest-memory/callback helpers; transport receipts never stand in for a
//! protocol acknowledgement.

use std::sync::Arc;

use dos_kernel::DosKernel;
use guest_core::{OwnerId, memory::Memory};
use x86_cpu::Cpu;

use super::{
    CallbackFrameId, CallbackKind, Win16State,
    classic_dde_dispatch::{
        ClassicDdeOperationOwner, ClassicDdeOwnerRuntimePending, ClassicDdeOwnerShutdown,
        ClassicDdeQueuedEvent,
    },
    far_callback::{Win16FarCallbackConvention, Win16FarCallbackReturn},
    ole1::{Win16Ole1ClientDdeDisposition, Win16Ole1ClientDdeEventCommit},
    win16_ole1_server_callback::{
        Ole1ServerDdeHostContinuation, Ole1ServerGuestCallbackFinish,
        finish_ole1_server_dde_host_call,
    },
    win16_ole1_server_dde::{Ole1ServerDdeDisposition, Ole1ServerInitiateContinuation},
    win16_ole1_server_state::Ole1UnpublishedCleanupAction,
};

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ClassicDdeAckStatus,
    Win16ClassicDdeAckValue, Win16ClassicDdeCallbackSource, Win16ClassicDdeDeliveryKind,
    Win16ClassicDdeEventId, Win16ClassicDdeMessage, Win16ClassicDdeOperationIdentity,
    Win16HostClassicDdeCall,
    Win16HostClassicDdeCallbackReply, Win16HostClassicDdeCallbackResult,
    Win16HostClassicDdeCallbackStep, Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
    Win16HostClassicDdeResult, Win16HostClassicDdeStep,
    Win16HostClassicDdeTerminal,
};

#[path = "win16_classic_dde_executor_client_terminal.rs"]
mod client_terminal;
#[path = "win16_classic_dde_executor_events.rs"]
mod events;
#[path = "win16_classic_dde_executor_release.rs"]
mod release;
#[path = "win16_classic_dde_executor_terminal.rs"]
mod terminal;
#[path = "win16_classic_dde_executor_shutdown.rs"]
mod shutdown;
#[path = "win16_classic_dde_executor_callback_teardown.rs"]
mod callback_teardown;
#[path = "win16_classic_dde_executor_guest_finish.rs"]
mod guest_finish;

impl Win16State {
    /// A Started source is still a synchronous owner, even before it yields
    /// a callback. Drain its exact terminal and source ACK before ordinary
    /// guest execution can enter an unrelated USER/OLESVR call. Checked guest
    /// callbacks remain runnable while their enclosing source is suspended.
    pub(super) fn service_pending_classic_dde_work(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let returned_callback = self.classic_dde.callbacks.last().is_some_and(|frame|
            frame.returned_value.is_some());
        if !returned_callback
            && (self.classic_dde.operations.is_empty() || !self.callback_kinds.is_empty())
        {
            return Ok(false);
        }
        self.service_classic_dde_safe_point(cpu, dos, memory, host)?;
        // This was a pump turn, including Started -> Complete and source
        // retirement. Do not charge or execute a guest instruction for it.
        Ok(true)
    }

    /// Run one bounded classic-DDE safe-point action. A true result means a
    /// checked guest callback or an exact synchronous DDE source now owns the
    /// runtime; callers must not start an unrelated guest callback this turn.
    pub(in crate::win16_runtime) fn service_classic_dde_safe_point(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.classic_dde.callbacks.last().is_some_and(|frame|
            frame.returned_value.is_some())
        {
            let owned = self.retry_returned_classic_dde_guest_callback(cpu, dos, memory, host)?;
            return Ok(owned || !self.classic_dde.operations.is_empty());
        }
        // Classic WM_DDE has its own USER worker and ownership ledger. The
        // DDEML `dde_runtime_quiesced` bit must not strand its callbacks or
        // exact EventId cleanup.
        if !self.callback_kinds.is_empty() {
            return Ok(false);
        }
        let owned = self.service_classic_dde_sources(cpu, dos, memory, host)?;
        Ok(owned || !self.classic_dde.operations.is_empty())
    }

    fn service_classic_dde_sources(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.classic_dde_top_operation_detail().is_some() {
            return self.service_classic_dde_operation(cpu, dos, memory, host);
        }

        if let Some(pending) = self.classic_dde.pending_begins.first().cloned() {
            let _ = self.begin_classic_dde_host_call(
                pending.call,
                pending.owner,
                pending.resume_parent,
                host,
            )?;
            return Ok(false);
        }

        let owner = self.tasks.current().ok_or_else(|| {
            dde_invariant("classic DDE safe point has no current Win16 task owner")
        })?;

        if self.retry_one_classic_dde_queued_event(owner, cpu, dos, memory, host)? {
            return Ok(true);
        }
        if self.drive_one_unpublished_cleanup(owner, host)? {
            return Ok(false);
        }
        if self.drive_one_api_release_wait(owner, cpu, dos, memory, host)? {
            return Ok(true);
        }
        if let Some((owner, endpoint, _event_ids)) = self.pending_classic_dde_endpoint_poll() {
            self.begin_classic_dde_host_call(
                Win16HostClassicDdeCall::Poll { owner, endpoint },
                ClassicDdeOperationOwner::PollEndpoint {
                    owner,
                    endpoint,
                    expected_event_ids: _event_ids,
                },
                None,
                host,
            )?;
            return Ok(false);
        }
        self.begin_classic_dde_host_call(
            Win16HostClassicDdeCall::PollOwner { owner },
            ClassicDdeOperationOwner::PollOwner { owner },
            None,
            host,
        )?;
        Ok(false)
    }

    fn service_classic_dde_operation(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if let Some((identity, pending_reply)) =
            self.classic_dde.operations.last().and_then(|frame| {
                frame
                    .pending_callback_resume
                    .clone()
                    .map(|reply| (frame.identity, reply))
            })
        {
            self.resume_classic_dde_host_call(identity, Some(pending_reply), host)?;
            return Ok(true);
        }
        if let Some(identity) = self.classic_dde.operations.last().and_then(|frame| {
            frame.pending_callback_event_cleanup.as_ref().map(|_| frame.identity)
        }) {
            self.retry_classic_dde_callback_event_cleanup(identity, host)?;
        }
        if let Some(identity) = self
            .classic_dde_top_operation()
            .map(|(identity, _)| identity)
        {
            self.retry_exact_classic_dde_client_bind(identity)?;
        }
        let (identity, step, owner, _resume_parent) = self
            .classic_dde_top_operation_detail()
            .ok_or_else(|| dde_invariant("classic DDE operation disappeared at its safe point"))?;
        self.service_classic_dde_operation_with_owner(identity, step, owner, cpu, dos, memory, host)
    }

    fn service_classic_dde_operation_with_owner(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        step: Win16HostClassicDdeStep,
        owner: ClassicDdeOperationOwner,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        match step {
            Win16HostClassicDdeStep::Started(_) => {
                let _ = self.resume_classic_dde_host_call(identity, None, host)?;
                Ok(false)
            }
            Win16HostClassicDdeStep::Callback(step) => {
                self.route_classic_dde_callback_step(identity, owner, step, cpu, dos, memory, host)
            }
            Win16HostClassicDdeStep::Complete { .. }
            | Win16HostClassicDdeStep::StartedFailure(_) => {
                self.consume_classic_dde_terminal(identity, owner, step, cpu, dos, memory, host)
            }
        }
    }

    fn route_classic_dde_callback_step(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        operation_owner: ClassicDdeOperationOwner,
        step: Arc<Win16HostClassicDdeCallbackStep>,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if super::classic_dde_operation::owner_id(&operation_owner) != identity.owner
            || step.owner != identity.owner
            || step.operation_id != identity.id
            || step.worker_generation != identity.worker_generation
        {
            return Err(dde_invariant(
                "classic DDE callback source changed its operation identity",
            ));
        }
        let mut event = self.materialize_classic_dde_event_atoms(&step.event, host)?;
        self.materialize_classic_dde_event_global(&mut event, memory, host)?;
        let mut routed_step = (*step).clone();
        routed_step.event = event.clone();
        let routed_step = Arc::new(routed_step);

        let disposition = self.route_classic_dde_callback(&routed_step, cpu, dos, memory, host)?;
        match disposition {
            Ole1ServerDdeDisposition::NotOwned => {
                let client = self.route_ole1_client_dde_callback_step(&routed_step)?;
                self.apply_client_sync_disposition(identity, &routed_step, client, host)
            }
            Ole1ServerDdeDisposition::HostCall {
                call, continuation, ..
            } => {
                let continuation = continuation.ok_or_else(|| {
                    dde_invariant(
                        "OLE1 server INITIATE host call lost its exact callback continuation",
                    )
                })?;
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::ServerInitiate { continuation },
                    None,
                    host,
                )?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::ResumeCallback { resume } => {
                self.resume_classic_dde_host_call(resume.operation, resume.reply, host)?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::UnpublishedCleanupEvent { .. } => {
                let reply = callback_reply(
                    &routed_step,
                    Win16HostClassicDdeCallbackResult::Untranslated,
                );
                self.resume_classic_dde_host_call(identity, Some(reply), host)?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::GuestCallback {
                far,
                args,
                return_kind,
                continuation,
            } => {
                self.enter_classic_dde_guest_callback(
                    cpu,
                    dos,
                    memory,
                    far,
                    &args,
                    return_kind,
                    continuation,
                    host,
                )?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::Deferred => {
                // Keep the exact synchronous callback at the top of the host
                // operation stack. UnblockServer will make it routable again.
                Ok(true)
            }
            Ole1ServerDdeDisposition::ProtocolResult { event, status } => {
                if event != routed_step.event {
                    return Err(dde_invariant(
                        "OLE1 protocol result changed the exact synchronous DDE event",
                    ));
                }
                self.begin_server_protocol_result(event, status, Some(routed_step), host)?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::OwnedMessage(_)
            | Ole1ServerDdeDisposition::DeferredEvent(_) => {
                // These owned cases have no completed protocol action yet.
                // Retain the source and report no success/default result.
                Ok(true)
            }
            Ole1ServerDdeDisposition::BeginHostCall { call, continuation } => {
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::ServerDde { continuation },
                    None,
                    host,
                )?;
                Ok(true)
            }
            Ole1ServerDdeDisposition::AwaitHostOperation { .. }
            | Ole1ServerDdeDisposition::ReleaseEndpointPending { .. }
            | Ole1ServerDdeDisposition::ReleaseComplete => Err(dde_invariant(
                "queued-only OLE1 release action was returned for a synchronous callback",
            )),
        }
    }

    fn apply_client_sync_disposition(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        step: &Win16HostClassicDdeCallbackStep,
        disposition: Win16Ole1ClientDdeDisposition,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        match disposition {
            Win16Ole1ClientDdeDisposition::NotOwned => {
                let reply = callback_reply(step, Win16HostClassicDdeCallbackResult::Untranslated);
                self.resume_classic_dde_host_call(identity, Some(reply), host)?;
                Ok(true)
            }
            Win16Ole1ClientDdeDisposition::Deferred => Ok(true),
            Win16Ole1ClientDdeDisposition::CallbackReply(result) => {
                self.resume_classic_dde_host_call(
                    identity,
                    Some(callback_reply(step, result)),
                    host,
                )?;
                Ok(true)
            }
            Win16Ole1ClientDdeDisposition::ResumeCallback(reply) => {
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
            }
            Win16Ole1ClientDdeDisposition::HostCall {
                operation,
                call,
                resume_callback,
            } => {
                if resume_callback.is_none() {
                    return Err(dde_invariant(
                        "nested classic-DDE client host action lost its exact callback reply",
                    ));
                }
                let bind_initiate = matches!(
                    &call,
                    Win16HostClassicDdeCall::Send {
                        target: crate::Win16HostClassicDdeTarget::BroadcastInitiate,
                        ..
                    }
                );
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::Client {
                        owner: identity.owner,
                        operation,
                        bind_initiate,
                    },
                    resume_callback,
                    host,
                )?;
                Ok(true)
            }
            _ => Err(dde_invariant(
                "OLE1 client returned a non-callback disposition for a synchronous DDE source",
            )),
        }
    }

    pub(super) fn enter_classic_dde_guest_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        far: u32,
        args: &[super::far_callback::Win16FarCallbackArgument],
        return_kind: Win16FarCallbackReturn,
        continuation: super::win16_ole1_server_callback::Ole1ServerDdeContinuation,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let close_document_proof = continuation.close_document_proof;
        let prepared_document_proof = match &continuation.completion {
            super::win16_ole1_server_callback::Ole1ServerCallbackCompletion::DdeExecute {
                prepared_document: Some(proof),
                ..
            } => Some(proof.clone()),
            _ => None,
        };
        let entry = (|| {
            let callback_id = self.reserve_callback_frame_id()?;
            self.classic_dde.callbacks.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain classic DDE guest callback frame",
                    error,
                )
            })?;
            let guest_frame = self.enter_guest_far_callback_checked(
                cpu,
                dos,
                memory,
                far,
                args,
                Win16FarCallbackConvention::Pascal,
                return_kind,
            )?;
            if let Err(error) = self.push_callback_kind(CallbackKind::ClassicDde, callback_id) {
                let mut guest_frame = guest_frame;
                let cleanup = self.release_guest_far_callback_owner(&mut guest_frame, dos, memory);
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => error.with_cleanup(
                        "release classic DDE callback CPU owner after stack failure",
                        cleanup,
                    ),
                });
            }
            Ok((callback_id, guest_frame))
        })();
        let (callback_id, guest_frame) = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let mut failure = error;
                if let Some(proof) = prepared_document_proof {
                    if let Err(cleanup) = self.cancel_prepared_server_document_callback(
                        proof,
                        memory,
                        host,
                    ) {
                        failure = failure.with_cleanup(
                            "cancel exact prepared OLE1 document after checked-entry failure",
                            cleanup,
                        );
                    }
                }
                if let Err(cleanup) = cancel_classic_dde_close_document_proof(
                    &mut self.ole1_server_state,
                    close_document_proof,
                ) {
                    failure = failure.with_cleanup(
                        "cancel exact OLE1 CloseDocument proof after checked-entry failure",
                        cleanup,
                    );
                }
                return Err(failure);
            }
        };
        self.classic_dde.callbacks.push(
            super::classic_dde_dispatch::ClassicDdeGuestCallbackFrame {
                callback_id,
                guest_frame,
                continuation,
                returned_value: None,
                binding_retired: false,
                server_finish: None,
                cleanup_poll: None,
            },
        );
        Ok(())
    }

    pub(super) fn begin_server_protocol_result(
        &mut self,
        event: Win16HostClassicDdeEvent,
        status: u16,
        callback_step: Option<Arc<Win16HostClassicDdeCallbackStep>>,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let reply = if let Some(step) = callback_step.as_ref() {
            if step.event != event
                || step.owner != event.owner
                || step.endpoint != event.endpoint
                || step.worker_generation != event.worker_generation
                || !matches!(
                    event.delivery,
                    Win16ClassicDdeDeliveryKind::Synchronous { .. }
                )
            {
                return Err(dde_invariant(
                    "synchronous protocol result lost its exact callback/event identity",
                ));
            }
            Some(callback_reply(
                step,
                Win16HostClassicDdeCallbackResult::WindowProcedure(0),
            ))
        } else {
            if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
                return Err(dde_invariant(
                    "protocol result without a callback step is not a queued event",
                ));
            }
            None
        };
        let call = server_protocol_result_post_call(&event, status)?;
        self.begin_classic_dde_host_call(
            call,
            ClassicDdeOperationOwner::ServerProtocolResultPost {
                event,
                status,
                callback_step,
            },
            reply,
            host,
        )?;
        Ok(())
    }

    fn apply_server_finish(
        &mut self,
        finish: Ole1ServerGuestCallbackFinish,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        match finish {
            Ole1ServerGuestCallbackFinish::BeginHostCall { call, continuation } => {
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::ServerDde { continuation },
                    None,
                    host,
                )?;
                Ok(true)
            }
            Ole1ServerGuestCallbackFinish::Resume { resume } => {
                self.resume_classic_dde_host_call(resume.operation, resume.reply, host)?;
                Ok(true)
            }
            Ole1ServerGuestCallbackFinish::Complete => Ok(false),
            Ole1ServerGuestCallbackFinish::GuestCallback { plan, continuation } => {
                self.enter_classic_dde_guest_callback(
                    cpu,
                    dos,
                    memory,
                    plan.procedure,
                    &plan.arguments,
                    plan.return_kind,
                    continuation,
                    host,
                )?;
                Ok(true)
            }
            Ole1ServerGuestCallbackFinish::PendingEndpointEvents {
                event,
                endpoint,
                pending_events,
                ..
            } => {
                self.retain_classic_dde_pending_endpoint_poll(
                    event.owner,
                    endpoint,
                    &pending_events,
                )?;
                Ok(true)
            }
            Ole1ServerGuestCallbackFinish::DeferredQueuedEvent { .. } => Ok(true),
        }
    }
}

// Windows 3.1 OLESTATUS values and DDEACK bits, confirmed by the local
// OLE.H/DDE.H headers. XP's SET_MSG_STATUS sets only fAck for OLE_OK and
// fBusy for OLE_BUSY; other OLE failures produce a zero-status negative ACK.
const OLE1_STATUS_OK: u16 = 0;
const OLE1_STATUS_BUSY: u16 = 2;
const DDEACK_ACKNOWLEDGED_BIT: u16 = 0x8000;
const DDEACK_BUSY_BIT: u16 = 0x4000;

fn server_protocol_result_post_call(
    event: &Win16HostClassicDdeEvent,
    status: u16,
) -> Result<Win16HostClassicDdeCall, RuntimeError> {
    let Win16ClassicDdeMessage::Execute { global } = &event.message else {
        return Err(dde_invariant(
            "OLE1 protocol-result route does not own a DDE Execute",
        ));
    };
    let transfer = global
        .transfer
        .filter(|transfer| transfer.0 != 0)
        .ok_or_else(|| dde_invariant("DDE Execute result has no exact native transfer lease"))?;
    if global.guest_global.is_none() {
        return Err(dde_invariant(
            "DDE Execute result has no exact runtime HGLOBAL copy lease",
        ));
    }
    let conversation = event
        .conversation
        .ok_or_else(|| dde_invariant("DDE Execute result has no exact conversation"))?;
    let acknowledged = status == OLE1_STATUS_OK;
    let busy = status == OLE1_STATUS_BUSY;
    let raw = if acknowledged {
        DDEACK_ACKNOWLEDGED_BIT
    } else if busy {
        DDEACK_BUSY_BIT
    } else {
        0
    };
    Ok(Win16HostClassicDdeCall::Post {
        owner: event.owner,
        endpoint: event.endpoint,
        target: event.peer,
        conversation,
        transaction: event.transaction,
        message: Win16ClassicDdeMessage::Ack {
            status: Win16ClassicDdeAckStatus {
                raw,
                application_return_code: 0,
                reserved: 0,
                busy,
                acknowledged,
            },
            value: Win16ClassicDdeAckValue::ExecuteTransfer(Some(transfer)),
        },
    })
}

fn callback_reply(
    step: &Win16HostClassicDdeCallbackStep,
    result: Win16HostClassicDdeCallbackResult,
) -> Win16HostClassicDdeCallbackReply {
    Win16HostClassicDdeCallbackReply {
        owner: step.owner,
        endpoint: step.endpoint,
        operation_id: step.operation_id,
        worker_generation: step.worker_generation,
        callback: step.callback,
        frame: step.frame,
        event_id: step.event.event_id,
        peer: step.event.peer,
        causal_parents: step.causal_parents.clone(),
        result,
    }
}

fn terminal_result(
    step: &Win16HostClassicDdeStep,
) -> Result<&Win16HostClassicDdeResult, RuntimeError> {
    match step {
        Win16HostClassicDdeStep::Complete { result, .. } => Ok(result),
        Win16HostClassicDdeStep::StartedFailure(failure) => Err(RuntimeError::with_source(
            Kind::HostFailure,
            "classic DDE host operation started and then failed",
            Arc::clone(&failure.cause),
        )),
        _ => Err(dde_invariant(
            "classic DDE result requested from a nonterminal step",
        )),
    }
}

fn server_execute_guest_global_key(
    continuation: &Ole1ServerDdeHostContinuation,
) -> Option<(
    OwnerId,
    Win16HostClassicDdeEndpoint,
    u64,
    Win16ClassicDdeEventId,
)> {
    match continuation {
        Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(
            super::win16_ole1_server_callback::Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
                event,
                ..
            },
        ) => Some((
            event.owner,
            event.endpoint,
            event.worker_generation,
            event.event_id,
        )),
        Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(
            super::win16_ole1_server_callback::Ole1ServerDdeAfterPost::ResumeSynchronousWindow {
                reply,
                ..
            },
        ) => Some((
            reply.owner,
            reply.endpoint,
            reply.worker_generation,
            reply.event_id,
        )),
        _ => None,
    }
}

fn server_dde_acknowledged_event(
    continuation: &Ole1ServerDdeHostContinuation,
    step: &Win16HostClassicDdeStep,
) -> Result<Option<Win16HostClassicDdeEvent>, RuntimeError> {
    let Win16HostClassicDdeStep::Complete { result, .. } = step else {
        return Ok(None);
    };
    let Win16HostClassicDdeResult::EventAcknowledged(event_id) = result else {
        return Ok(None);
    };
    let event = match continuation {
        Ole1ServerDdeHostContinuation::QueuedEventAcknowledgement { event }
        | Ole1ServerDdeHostContinuation::EventAcknowledgement { event, .. } => event,
        Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(
            super::win16_ole1_server_callback::Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
                event,
                ..
            },
        ) => event,
        Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(_)
        | Ole1ServerDdeHostContinuation::TerminateResponse { .. } => return Ok(None),
    };
    if event.event_id != *event_id {
        return Err(dde_invariant(
            "classic DDE server EventAcknowledged receipt changed EventId",
        ));
    }
    Ok(Some(event.clone()))
}

fn cancel_classic_dde_close_document_proof(
    state: &mut super::win16_ole1_server_state::Ole1ServerState,
    proof: Option<(
        guest_core::OwnerId,
        super::win16_ole1_server_state::Ole1ServerDocumentHandle,
        u64,
    )>,
) -> Result<(), RuntimeError> {
    let Some((owner, handle, generation)) = proof else {
        return Ok(());
    };
    state
        .cancel_close_document_callback(owner, handle, generation)
        .map_err(|status| {
            RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "exact OLE1 CloseDocument proof cancellation failed with status 0x{status:04x}"
                ),
            )
        })
}

fn dde_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
