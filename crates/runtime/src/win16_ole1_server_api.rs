//! Synchronous Win16 OLESVR API entry points whose effects do not require a
//! guest callback. Endpoint creation still uses the independent classic-DDE
//! operation owner and validates the exact terminal/source-retirement proof.
//!
//! Revocation is a resumable release cascade. Exact host receipts and checked
//! guest callback frames retain ownership until each document and server
//! endpoint has completed cleanup.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, SegmentedPointer, Win16Ole1Request, Win16ReturnKind};
use x86_cpu::Cpu;

use crate::{
    RuntimeError, RuntimeHost, Win16ClassicDdeEventId, Win16ClassicDdeMessage,
    Win16HostClassicDdeCall, Win16HostClassicDdeEndpoint, Win16HostClassicDdeResult,
    Win16HostClassicDdeResume, Win16HostClassicDdeRetirementReceipt, Win16HostClassicDdeStep,
};

use super::super::win16_ole1_server_registration::validate_server_registration;
use super::super::win16_ole1_server_state::{
    OLE_ERROR_ADDRESS, OLE_ERROR_CLASS, OLE_ERROR_COMMAND, OLE_ERROR_HANDLE, OLE_ERROR_MEMORY,
    OLE_ERROR_NAME, OLE_ERROR_OBJECT, OLE_ERROR_PROTOCOL, OLE_ERROR_TERMINATE, OLE_OK,
    OLE_WAIT_FOR_RELEASE, Ole1ReleasePhase, Ole1ReleaseTarget, Ole1ServerHandle, Ole1ServerUse,
};
use super::super::win16_ole1_server_wire::{Ole1ServerWireError, selector_error};
use super::Win16State;

fn wire_status_or_runtime(error: Ole1ServerWireError) -> Result<u16, RuntimeError> {
    match error {
        Ole1ServerWireError::GuestStatus(status) => Ok(status),
        Ole1ServerWireError::Runtime(error) => Err(error),
    }
}

fn complete_wire_failure(
    state: &mut Win16State,
    cpu: &mut Cpu,
    return_to: (u16, u16, u32),
    error: Ole1ServerWireError,
) -> Result<Option<u8>, RuntimeError> {
    match error {
        Ole1ServerWireError::GuestStatus(status) => {
            complete_ole1_api_status(state, cpu, return_to, status)
        }
        Ole1ServerWireError::Runtime(error) => Err(error),
    }
}

fn journal_unpublished_cleanup(
    state: &mut Win16State,
    owner: guest_core::OwnerId,
    endpoint: Option<Win16HostClassicDdeEndpoint>,
    worker_generation: Option<u64>,
    atoms: Vec<u16>,
) -> Result<(), RuntimeError> {
    state
        .ole1_server_state
        .begin_unpublished_cleanup(owner, endpoint, worker_generation, atoms)
        .map(|_| ())
        .map_err(|status| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                format!("cannot retain OLE1 unpublished registration resources ({status})"),
            )
        })
}

// The API fragments share this module's exact private server registry and
// callback helpers; splitting them keeps the hand-written files bounded.
include!("win16_ole1_server_api_dispatch_and_register.rs");
include!("win16_ole1_server_api_server_release_cascade.rs");
include!("win16_ole1_server_api_unblock_and_deferred.rs");

impl Win16State {
    pub(in crate::win16_runtime) fn create_server_document_endpoint_checked(
        &mut self,
        owner: guest_core::OwnerId,
        parent: Option<Win16HostClassicDdeEndpoint>,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<(Win16HostClassicDdeEndpoint, u64), u16>, RuntimeError> {
        create_endpoint_checked(owner, parent, host)
    }
}

fn complete_ole1_api_status(
    state: &mut Win16State,
    cpu: &mut Cpu,
    return_to: (u16, u16, u32),
    status: u16,
) -> Result<Option<u8>, RuntimeError> {
    state.complete_return(
        &mut cpu.regs,
        return_to.0,
        return_to.1,
        return_to.2,
        u32::from(status),
        Win16ReturnKind::Word,
    )
}

pub(super) fn post_termination_exact(
    state: &mut super::super::win16_ole1_server_state::Ole1ServerState,
    owner: guest_core::OwnerId,
    post: super::super::win16_ole1_server_state::Ole1TerminationPost,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    state
        .begin_termination_post(owner, post.target, post.binding)
        .map_err(|status| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                format!("cannot claim exact OLE1 TERMINATE post ({status})"),
            )
        })?;
    let result = post_termination_host_call(owner, post.target, post.binding, host);
    match result {
        Ok(()) => state
            .mark_termination_posted(owner, post.target, post.binding)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot commit exact OLE1 TERMINATE receipt ({status})"),
                )
            }),
        Err(primary) => {
            if let Err(status) = state.fail_termination_post(owner, post.target, post.binding) {
                return Err(primary.with_cleanup(
                    "restore OLE1 TERMINATE journal after host post failure",
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("termination journal rollback failed ({status})"),
                    ),
                ));
            }
            Err(primary)
        }
    }
}

fn post_termination_host_call(
    owner: guest_core::OwnerId,
    target: super::super::win16_ole1_server_state::Ole1TerminationTarget,
    binding: super::super::win16_ole1_server_state::Ole1ConversationBinding,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    use super::super::win16_ole1_server_state::Ole1TerminationTarget;
    let (endpoint, worker_generation) = match target {
        Ole1TerminationTarget::Server {
            endpoint,
            worker_generation,
            ..
        }
        | Ole1TerminationTarget::Document {
            endpoint,
            worker_generation,
            ..
        } => (endpoint, worker_generation),
    };
    let call = Win16HostClassicDdeCall::Post {
        owner,
        endpoint,
        target: binding.peer,
        conversation: binding.id,
        transaction: None,
        message: Win16ClassicDdeMessage::Terminate,
    };
    let started = host.win16_classic_dde_begin(call)?;
    let operation = match started {
        Win16HostClassicDdeStep::Started(operation)
            if operation.owner == owner && operation.worker_generation == worker_generation =>
        {
            operation
        }
        Win16HostClassicDdeStep::StartedFailure(failure)
            if failure.operation.owner == owner
                && failure.source_retired.operation == failure.operation
                && failure.source_retired.callbacks.is_empty() =>
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::HostFailure,
                "host failed to start the exact OLE1 TERMINATE post",
            ));
        }
        _ => {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE TERMINATE post did not start an owner-bound host operation",
            ));
        }
    };
    loop {
        let step = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
            operation,
            reply: None,
        })?;
        match step {
            Win16HostClassicDdeStep::Started(actual) if actual == operation => continue,
            Win16HostClassicDdeStep::Complete {
                operation: actual,
                result: Win16HostClassicDdeResult::Posted(receipt),
                source_retired,
            } if actual == operation
                && source_retired.operation == operation
                && source_retired.callbacks.is_empty()
                && receipt.owner == owner
                && receipt.endpoint == endpoint
                && receipt.peer == binding.peer
                && receipt.conversation == Some(binding.id)
                && receipt.message == crate::WM_DDE_TERMINATE
                && receipt.queued
                && receipt.transfer.is_none()
                && receipt.transaction.is_none() =>
            {
                return Ok(());
            }
            Win16HostClassicDdeStep::StartedFailure(failure)
                if failure.operation == operation
                    && failure.source_retired.operation == operation
                    && failure.source_retired.callbacks.is_empty() =>
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::HostFailure,
                    "host could not post the exact OLE1 TERMINATE message",
                ));
            }
            Win16HostClassicDdeStep::Callback(_) => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "asynchronous DDE TERMINATE post yielded a guest callback",
                ));
            }
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "classic-DDE TERMINATE post lost its exact operation receipt",
                ));
            }
        }
    }
}

pub(super) fn finish_release_without_guest_callback(
    state: &mut Win16State,
    owner: guest_core::OwnerId,
    target: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<Ole1ReleaseEndpointOutcome, RuntimeError> {
    if let Ole1ReleaseTarget::Document {
        handle, generation, ..
    } = target
    {
        state.release_server_document_callback_scratch(owner, handle, generation)?;
    }
    let callback_id = match state
        .ole1_server_state
        .release_completion_for_target(owner, target)
    {
        Some(entry) => entry.callback_id,
        None => state.reserve_callback_frame_id()?.0,
    };
    if state
        .ole1_server_state
        .pending_release_completion(callback_id)
        .is_none()
    {
        state
            .ole1_server_state
            .begin_release_completion_without_guest_callback(callback_id, owner, target)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot journal OLE1 release without guest callback ({status})"),
                )
            })?;
    }
    finish_server_release_completion_for_dde(
        &mut state.ole1_server_state,
        callback_id,
        target,
        host,
    )
}

pub(in crate::win16_runtime) fn finish_release_without_guest_callback_for_dde(
    state: &mut Win16State,
    owner: guest_core::OwnerId,
    target: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<Ole1ReleaseEndpointOutcome, RuntimeError> {
    if let Ole1ReleaseTarget::Document {
        handle, generation, ..
    } = target
    {
        state.release_server_document_callback_scratch(owner, handle, generation)?;
    }
    let callback_id = match state
        .ole1_server_state
        .release_completion_for_target(owner, target)
    {
        Some(entry) => entry.callback_id,
        None => state.reserve_callback_frame_id()?.0,
    };
    if state
        .ole1_server_state
        .pending_release_completion(callback_id)
        .is_none()
    {
        state
            .ole1_server_state
            .begin_release_completion_without_guest_callback(callback_id, owner, target)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot journal OLE1 DDE release without guest callback ({status})"),
                )
            })?;
    }
    finish_server_release_completion_for_dde(
        &mut state.ole1_server_state,
        callback_id,
        target,
        host,
    )
}

pub(in crate::win16_runtime) fn finish_server_release_completion(
    state: &mut super::super::win16_ole1_server_state::Ole1ServerState,
    callback_id: u64,
    target: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    match finish_server_release_completion_core(state, callback_id, target, host)? {
        Ole1ReleaseEndpointOutcome::Complete => Ok(()),
        Ole1ReleaseEndpointOutcome::PendingEvents(_) => Err(RuntimeError::new(
            crate::DiagnosticKind::HostFailure,
            "OLE1 endpoint retirement is waiting for queued classic-DDE EventIds",
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Ole1ReleaseEndpointOutcome {
    Complete,
    /// The endpoint remains a live tombstone until these exact queued
    /// deliveries have been consumed and acknowledged.
    PendingEvents(Vec<Win16ClassicDdeEventId>),
}

pub(in crate::win16_runtime) fn finish_server_release_completion_for_dde(
    state: &mut super::super::win16_ole1_server_state::Ole1ServerState,
    callback_id: u64,
    target: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<Ole1ReleaseEndpointOutcome, RuntimeError> {
    let outcome = finish_server_release_completion_core(state, callback_id, target, host)?;
    if outcome == Ole1ReleaseEndpointOutcome::Complete {
        state
            .finalize_release_completion(callback_id, target)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 completed release journal could not be finalized ({status})"),
                )
            })?;
    }
    Ok(outcome)
}

fn finish_server_release_completion_core(
    state: &mut super::super::win16_ole1_server_state::Ole1ServerState,
    callback_id: u64,
    target: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<Ole1ReleaseEndpointOutcome, RuntimeError> {
    loop {
        let entry = state
            .pending_release_completion(callback_id)
            .filter(|entry| entry.target == target)
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 release completion lost its exact callback/target journal",
                )
            })?;
        match entry.phase {
            Ole1ReleasePhase::DeleteFirstAtom | Ole1ReleasePhase::DeleteSecondAtom => {
                let atom = state
                    .release_atom_delete_pending(callback_id, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 release atom phase changed ({status})"),
                        )
                    })?
                    .ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 release atom journal has no atom for its delete phase",
                        )
                    })?;
                host.win16_global_delete_atom(atom)?;
                state
                    .mark_release_atom_deleted(callback_id, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 release atom receipt lost its phase ({status})"),
                        )
                    })?;
            }
            Ole1ReleasePhase::RetireEndpoint => {
                let (endpoint, endpoint_worker_generation) = match target {
                    Ole1ReleaseTarget::Document {
                        endpoint,
                        endpoint_worker_generation,
                        ..
                    }
                    | Ole1ReleaseTarget::Server {
                        endpoint,
                        endpoint_worker_generation,
                        ..
                    } => (endpoint, endpoint_worker_generation),
                };
                let receipt = retire_endpoint_receipt(
                    entry.owner,
                    endpoint,
                    endpoint_worker_generation,
                    host,
                )?;
                if !receipt.retired {
                    if receipt.pending_events.is_empty()
                        || !receipt.retained_callbacks.is_empty()
                        || !receipt.retained_transfers.is_empty()
                    {
                        return Err(RuntimeError::new(
                            crate::DiagnosticKind::HostFailure,
                            "OLE1 endpoint retirement is blocked without a routable EventId set",
                        ));
                    }
                    let mut unique = std::collections::BTreeSet::new();
                    if receipt
                        .pending_events
                        .iter()
                        .any(|event| !unique.insert(*event))
                    {
                        return Err(RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 RetireEndpoint receipt duplicated a pending EventId",
                        ));
                    }
                    state
                        .record_release_pending_events(
                            callback_id,
                            entry.owner,
                            target,
                            receipt.worker_generation,
                            receipt.pending_events.clone(),
                        )
                        .map_err(|status| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                format!("OLE1 release EventId journal changed ({status})"),
                            )
                        })?;
                    return Ok(Ole1ReleaseEndpointOutcome::PendingEvents(
                        receipt.pending_events,
                    ));
                }
                if !retired_exact(entry.owner, endpoint, endpoint_worker_generation, &receipt) {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 RetireEndpoint success did not retire its exact endpoint",
                    ));
                }
                if state
                    .release_pending_events_for_endpoint(entry.owner, endpoint)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 release EventId retirement journal changed ({status})"),
                        )
                    })?
                    .is_some_and(|pending| !pending.pending_events.is_empty())
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 endpoint retired while EventIds remain unacknowledged",
                    ));
                }
                state
                    .mark_release_endpoint_retired(callback_id, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 endpoint retirement receipt lost its phase ({status})"),
                        )
                    })?;
            }
            Ole1ReleasePhase::CommitRegistry => {
                state
                    .finish_release_completion(callback_id, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!("OLE1 release registry commit failed ({status})"),
                        )
                    })?;
                return Ok(Ole1ReleaseEndpointOutcome::Complete);
            }
            Ole1ReleasePhase::Committed => {
                return Ok(Ole1ReleaseEndpointOutcome::Complete);
            }
        }
    }
}

/// Select the next checked Release in XP's public RevokeServer cascade after
/// a document callback has retired. Documents with no registered guest
/// callback are cleaned inline before the next guest callback is selected.
pub(super) fn next_server_revoke_release_target(
    state: &mut Win16State,
    owner: guest_core::OwnerId,
    completed: Ole1ReleaseTarget,
    host: &mut impl RuntimeHost,
) -> Result<Option<Ole1ReleaseTarget>, RuntimeError> {
    let mut completed = completed;
    loop {
        let Some(next) = state
            .ole1_server_state
            .release_target_after_completion(owner, completed)
        else {
            return Ok(None);
        };
        match next {
            Ole1ReleaseTarget::Document { handle, .. }
                if state
                    .ole1_server_state
                    .document(owner, handle)
                    .is_some_and(|document| document.server_document_far.is_none()) =>
            {
                match finish_release_without_guest_callback(state, owner, next, host)? {
                    Ole1ReleaseEndpointOutcome::Complete => completed = next,
                    Ole1ReleaseEndpointOutcome::PendingEvents(_) => return Ok(None),
                }
            }
            _ => return Ok(Some(next)),
        }
    }
}

fn create_endpoint_checked(
    owner: guest_core::OwnerId,
    parent: Option<Win16HostClassicDdeEndpoint>,
    host: &mut impl RuntimeHost,
) -> Result<Result<(Win16HostClassicDdeEndpoint, u64), u16>, RuntimeError> {
    let started =
        host.win16_classic_dde_begin(Win16HostClassicDdeCall::CreateEndpoint { owner, parent })?;
    let operation = match started {
        Win16HostClassicDdeStep::Started(operation)
            if operation.owner == owner && operation.worker_generation != 0 =>
        {
            operation
        }
        Win16HostClassicDdeStep::Started(_) => {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "CreateEndpoint started under another owner or zero worker generation",
            ));
        }
        _ => {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE CreateEndpoint did not start a distinct operation",
            ));
        }
    };
    loop {
        let step = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
            operation,
            reply: None,
        })?;
        match step {
            Win16HostClassicDdeStep::Started(actual) if actual == operation => continue,
            Win16HostClassicDdeStep::Complete {
                operation: actual,
                result,
                source_retired,
            } if actual == operation && source_retired.operation == operation => {
                if !source_retired.callbacks.is_empty() {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "CreateEndpoint unexpectedly retired a guest-facing DDE callback",
                    ));
                }
                return match result {
                    Win16HostClassicDdeResult::Endpoint(endpoint) if endpoint.0 != 0 => {
                        Ok(Ok((endpoint, operation.worker_generation)))
                    }
                    _ => Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "CreateEndpoint completed without a nonzero endpoint token",
                    )),
                };
            }
            Win16HostClassicDdeStep::StartedFailure(failure)
                if failure.operation == operation
                    && failure.source_retired.operation == operation
                    && failure.source_retired.callbacks.is_empty() =>
            {
                // `source_retired` proves the initiating host call unwound; it
                // is not proof that native resource cleanup completed. Keep
                // every failure typed until the host supplies such evidence,
                // including ResourceExhausted with a retained cleanup cause.
                return Err(RuntimeError::with_source(
                    failure.cause.kind(),
                    "classic-DDE CreateEndpoint failed",
                    std::sync::Arc::clone(&failure.cause),
                ));
            }
            Win16HostClassicDdeStep::Callback(_) => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "CreateEndpoint yielded a guest callback before endpoint publication",
                ));
            }
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "CreateEndpoint terminal step lost its exact operation identity",
                ));
            }
        }
    }
}

fn retire_endpoint_receipt(
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    host: &mut impl RuntimeHost,
) -> Result<Win16HostClassicDdeRetirementReceipt, RuntimeError> {
    if worker_generation == 0 {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "OLE1 endpoint retirement has no owner worker generation",
        ));
    }
    let started =
        host.win16_classic_dde_begin(Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint })?;
    let operation = match started {
        Win16HostClassicDdeStep::Started(operation)
            if operation.owner == owner && operation.worker_generation == worker_generation =>
        {
            operation
        }
        Win16HostClassicDdeStep::Started(_) => {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "RetireEndpoint started under a different owner or worker generation",
            ));
        }
        _ => {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "classic-DDE RetireEndpoint did not start a distinct operation",
            ));
        }
    };
    loop {
        let step = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
            operation,
            reply: None,
        })?;
        match step {
            Win16HostClassicDdeStep::Started(actual) if actual == operation => continue,
            Win16HostClassicDdeStep::Complete {
                operation: actual,
                result: Win16HostClassicDdeResult::Retired(receipt),
                source_retired,
            } if actual == operation
                && source_retired.operation == operation
                && source_retired.callbacks.is_empty()
                && receipt.owner == owner
                && receipt.endpoint == endpoint
                && receipt.worker_generation == worker_generation =>
            {
                return Ok(receipt);
            }
            Win16HostClassicDdeStep::StartedFailure(failure)
                if failure.operation == operation
                    && failure.source_retired.operation == operation =>
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::HostFailure,
                    "host could not retire an unpublished OLE1 DDE endpoint",
                ));
            }
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "RetireEndpoint did not produce its exact retirement receipt",
                ));
            }
        }
    }
}

fn retired_exact(
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    receipt: &Win16HostClassicDdeRetirementReceipt,
) -> bool {
    receipt.owner == owner
        && receipt.endpoint == endpoint
        && receipt.worker_generation == worker_generation
        && receipt.retired
        && receipt.pending_events.is_empty()
        && receipt.retained_callbacks.is_empty()
        && receipt.retained_transfers.is_empty()
}
