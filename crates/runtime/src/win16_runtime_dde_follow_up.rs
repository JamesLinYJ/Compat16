//! Exact-owner DDE follow-up submission and retry state.

use std::sync::Arc;

use crate::{
    RuntimeError, RuntimeHost, Win16HostDdeCallbackStep, Win16WindowOperation,
    Win16WindowResult, Win16WindowStep,
};

use super::{
    Win16DdeContinuation, Win16DdeFinish, Win16DdeFollowUpCarrier,
    Win16DdeFollowUpOwner, Win16DdeFollowUpPhase, invariant,
};

use super::super::Win16DdeCallbackOrigin;

/// Submit a completed DDE operation's compensation on its existing exact
/// window-operation frame. The caller keeps that frame and this outcome alive
/// across errors; once submitted, this method returns the cached carrier and
/// never issues the same native Begin twice.
pub(in crate::win16_runtime) fn submit_dde_follow_up_in_place(
    continuation: &mut Win16DdeContinuation,
    finish: &mut Win16DdeFinish,
    window_frame_id: u64,
    host: &mut impl RuntimeHost,
) -> Result<Win16DdeFollowUpCarrier, RuntimeError> {
    if let Win16DdeFinish::FollowUp {
        phase: Win16DdeFollowUpPhase::Committed { owner, carrier },
        ..
    } = finish
    {
        if owner.window_frame_id() != Some(window_frame_id)
            || owner.native_owner_identity() != continuation.host_owner_identity()
            || !carrier_matches_continuation(carrier, continuation)
        {
            return Err(invariant(
                "committed DDE follow-up no longer matches its exact window-frame owner",
            ));
        }
        return Ok(carrier.clone());
    }
    let Win16DdeFinish::FollowUp {
        call,
        continuation: next_continuation,
        phase,
    } = finish
    else {
        return Err(invariant(
            "DDE operation follow-up dispatcher received a non-follow-up outcome",
        ));
    };
    let operation = continuation.host_operation().ok_or_else(|| {
        invariant("DDE operation follow-up has no exact completed source identity")
    })?;
    let (native_owner, worker_generation) = continuation.host_owner_identity().ok_or_else(|| {
        invariant("DDE operation follow-up has no exact native owner generation")
    })?;
    if window_frame_id == 0 || operation.0 == 0 {
        return Err(invariant(
            "DDE operation follow-up has an invalid runtime or native frame identity",
        ));
    }
    let expected_owner = Win16DdeFollowUpOwner::Operation {
        window_frame_id,
        operation,
        owner: native_owner,
        worker_generation,
    };

    match phase {
        Win16DdeFollowUpPhase::UnboundPrepared => {
            *phase = Win16DdeFollowUpPhase::Prepared(expected_owner);
        }
        Win16DdeFollowUpPhase::Prepared(actual) if *actual != expected_owner => {
            return Err(invariant(
                "DDE operation follow-up changed its exact runtime/native owner",
            ));
        }
        Win16DdeFollowUpPhase::Submitted { owner, carrier: _ }
        | Win16DdeFollowUpPhase::Committed { owner, carrier: _ }
            if *owner != expected_owner =>
        {
            return Err(invariant(
                "cached DDE operation follow-up belongs to a different exact owner",
            ));
        }
        Win16DdeFollowUpPhase::Rejected { owner, step, cause } => {
            if *owner != expected_owner {
                return Err(invariant(
                    "rejected DDE follow-up step belongs to a different exact owner",
                ));
            }
            return Err(retained_rejected_follow_up_error(step, cause));
        }
        Win16DdeFollowUpPhase::Submitted { .. }
        | Win16DdeFollowUpPhase::Committed { .. } => {}
        Win16DdeFollowUpPhase::Prepared(_) => {}
    }

    if let Win16DdeFollowUpPhase::Committed { carrier, .. } = phase {
        return Ok(carrier.clone());
    }

    if matches!(phase, Win16DdeFollowUpPhase::Prepared(_)) {
        let next = next_continuation.as_mut().ok_or_else(|| {
            invariant("prepared DDE follow-up lost its next continuation owner")
        })?;
        // Reserve the exact source-proof slot before the native call can
        // publish a completion carrier.
        next.reserve_source_retirement_record()?;
        let step = host.win16_window_begin(Win16WindowOperation::Dde(call.clone()))?;
        let carrier = match carrier_from_step(&step, native_owner, worker_generation) {
            Ok(carrier) => carrier,
            Err(cause) => {
                let cause = Arc::new(cause);
                *phase = Win16DdeFollowUpPhase::Rejected {
                    owner: expected_owner,
                    step: Box::new(step),
                    cause: Arc::clone(&cause),
                };
                return Err(super::super::callback_lifo::shared_runtime_error(cause));
            }
        };
        *phase = Win16DdeFollowUpPhase::Submitted {
            owner: expected_owner,
            carrier,
        };
    }

    let (owner, carrier) = match phase {
        Win16DdeFollowUpPhase::Submitted { owner, carrier } => (*owner, carrier.clone()),
        _ => {
            return Err(invariant(
                "DDE operation follow-up did not reach a submitted state",
            ));
        }
    };
    if owner != expected_owner {
        return Err(invariant(
            "submitted DDE follow-up changed its exact operation owner",
        ));
    }
    let next = next_continuation.as_mut().ok_or_else(|| {
        invariant("submitted DDE follow-up lost its next continuation before commit")
    })?;
    bind_follow_up_carrier(next, &carrier)?;
    let next = next_continuation.take().ok_or_else(|| {
        invariant("DDE follow-up continuation disappeared during in-place commit")
    })?;
    *continuation = *next;
    if !matches!(phase, Win16DdeFollowUpPhase::Submitted { .. }) {
        return Err(invariant(
            "DDE follow-up phase changed during in-place owner commit",
        ));
    }
    *phase = Win16DdeFollowUpPhase::Committed {
        owner,
        carrier: carrier.clone(),
    };
    Ok(carrier)
}

fn retained_rejected_follow_up_error(
    step: &Win16WindowStep,
    cause: &Arc<RuntimeError>,
) -> RuntimeError {
    let context = match step {
        Win16WindowStep::DdeSourceRetired { proof, .. } => format!(
            "DDE follow-up retains a rejected source result for operation {}, worker {}",
            proof.operation.0, proof.worker_generation,
        ),
        Win16WindowStep::DdeStartedFailure(failure) => format!(
            "DDE follow-up retains a rejected start receipt for operation {}, worker {}",
            failure.operation.0, failure.worker_generation,
        ),
        Win16WindowStep::DdeCallback(_) =>
            "DDE follow-up retains a callback with an invalid owner identity".to_owned(),
        Win16WindowStep::Started { operation_id, worker_generation, .. } => format!(
            "DDE follow-up retains a USER start receipt for operation {}, worker {}",
            operation_id.0, worker_generation,
        ),
        _ => "DDE follow-up retains a non-DDE native result".to_owned(),
    };
    RuntimeError::with_source(cause.kind(), context, Arc::clone(cause))
}

fn carrier_from_step(
    step: &Win16WindowStep,
    expected_owner: crate::Win16HostDdeOwner,
    expected_generation: u64,
) -> Result<Win16DdeFollowUpCarrier, RuntimeError> {
    let carrier = match step {
        Win16WindowStep::DdeCallback(callback) => {
            if !callback.has_valid_identity()
                || callback.owner != expected_owner
                || callback.worker_generation != expected_generation
            {
                return Err(invariant(
                    "DDE follow-up callback changed its native owner generation",
                ));
            }
            Win16DdeFollowUpCarrier::Callback(Arc::clone(callback))
        }
        Win16WindowStep::DdeStartedFailure(failure) => {
            if failure.operation.0 == 0
                || failure.owner != expected_owner
                || failure.worker_generation != expected_generation
            {
                return Err(invariant(
                    "DDE follow-up failure changed its exact native owner generation",
                ));
            }
            Win16DdeFollowUpCarrier::StartedFailure(Arc::clone(failure))
        }
        Win16WindowStep::DdeSourceRetired { proof, result } => {
            let Win16WindowStep::Complete(Win16WindowResult::Dde(result)) = result.as_ref() else {
                return Err(invariant(
                    "DDE source-retirement carrier omitted its exact copied completion",
                ));
            };
            if !proof.has_valid_identity()
                || proof.owner != expected_owner
                || proof.worker_generation != expected_generation
            {
                return Err(invariant(
                    "DDE follow-up source proof changed its exact owner generation",
                ));
            }
            Win16DdeFollowUpCarrier::SourceRetired {
                proof: Arc::clone(proof),
                result: result.clone(),
            }
        }
        _ => {
            return Err(invariant(
                "DDE follow-up returned a non-DDE host step",
            ));
        }
    };
    Ok(carrier)
}

/// Submit or replay a follow-up owned by an exact DDE callback frame. Unlike
/// the operation helper, this leaves the callback-frame continuation resident
/// in its owner journal and never creates a window-operation frame.
pub(in crate::win16_runtime) fn submit_callback_owned_dde_follow_up(
    owner: Win16DdeFollowUpOwner,
    call: &crate::Win16HostDdeCall,
    next_continuation: &mut Option<Box<Win16DdeContinuation>>,
    phase: &mut Win16DdeFollowUpPhase,
    host: &mut impl RuntimeHost,
) -> Result<Win16DdeFollowUpCarrier, RuntimeError> {
    let Win16DdeFollowUpOwner::Callback {
        callback_id,
        host_frame,
        parent,
        owner: native_owner,
        worker_generation,
        origin,
    } = owner
    else {
        return Err(invariant(
            "callback-owned DDE follow-up received an operation-frame owner",
        ));
    };
    let expected_parent = match origin {
        Win16DdeCallbackOrigin::Foreground(operation)
        | Win16DdeCallbackOrigin::CallbackFollowUp {
            operation,
            ..
        } => Some(operation),
        Win16DdeCallbackOrigin::WindowWait { .. }
        | Win16DdeCallbackOrigin::GuestExecution { .. } => None,
    };
    if callback_id.0 == 0
        || host_frame.0 == 0
        || native_owner.0 == 0
        || worker_generation == 0
        || parent.is_some_and(|operation| operation.0 == 0)
        || parent != expected_parent
    {
        return Err(invariant(
            "callback-owned DDE follow-up has an invalid exact owner identity",
        ));
    }

    match phase {
        Win16DdeFollowUpPhase::Prepared(actual) if *actual != owner => {
            return Err(invariant(
                "DDE callback follow-up changed its exact callback owner",
            ));
        }
        Win16DdeFollowUpPhase::Submitted { owner: actual, .. }
        | Win16DdeFollowUpPhase::Committed { owner: actual, .. }
            if *actual != owner =>
        {
            return Err(invariant(
                "cached DDE callback follow-up belongs to another callback owner",
            ));
        }
        Win16DdeFollowUpPhase::Rejected { owner: actual, step, cause } => {
            if *actual != owner {
                return Err(invariant(
                    "rejected DDE callback follow-up belongs to another owner",
                ));
            }
            return Err(retained_rejected_follow_up_error(step, cause));
        }
        Win16DdeFollowUpPhase::UnboundPrepared => {
            return Err(invariant(
                "callback-owned DDE follow-up omitted its exact callback identity",
            ));
        }
        Win16DdeFollowUpPhase::Prepared(_)
        | Win16DdeFollowUpPhase::Submitted { .. }
        | Win16DdeFollowUpPhase::Committed { .. } => {}
    }

    if let Win16DdeFollowUpPhase::Committed { carrier, .. } = phase {
        return Ok(carrier.clone());
    }
    if matches!(phase, Win16DdeFollowUpPhase::Prepared(_)) {
        let next = next_continuation.as_mut().ok_or_else(|| {
            invariant("prepared callback follow-up lost its continuation owner")
        })?;
        next.reserve_source_retirement_record()?;
        let step = host.win16_window_begin(Win16WindowOperation::Dde(call.clone()))?;
        let carrier = match carrier_from_step(&step, native_owner, worker_generation) {
            Ok(carrier) => carrier,
            Err(cause) => {
                let cause = Arc::new(cause);
                *phase = Win16DdeFollowUpPhase::Rejected {
                    owner,
                    step: Box::new(step),
                    cause: Arc::clone(&cause),
                };
                return Err(super::super::callback_lifo::shared_runtime_error(cause));
            }
        };
        *phase = Win16DdeFollowUpPhase::Submitted { owner, carrier };
    }

    let carrier = match phase {
        Win16DdeFollowUpPhase::Submitted { owner: actual, carrier }
            if *actual == owner => carrier.clone(),
        _ => {
            return Err(invariant(
                "callback-owned DDE follow-up did not retain its submitted carrier",
            ));
        }
    };
    let next = next_continuation.as_mut().ok_or_else(|| {
        invariant("submitted callback follow-up lost its continuation before binding")
    })?;
    bind_follow_up_carrier(next, &carrier)?;
    *phase = Win16DdeFollowUpPhase::Committed {
        owner,
        carrier: carrier.clone(),
    };
    Ok(carrier)
}

fn bind_follow_up_carrier(
    continuation: &mut Win16DdeContinuation,
    carrier: &Win16DdeFollowUpCarrier,
) -> Result<(), RuntimeError> {
    match carrier {
        Win16DdeFollowUpCarrier::Callback(callback) => {
            if let Some(operation) = callback.parent {
                continuation.bind_host_operation_identity(
                    operation,
                    callback.owner,
                    callback.worker_generation,
                )
            } else {
                continuation.bind_host_owner_identity(
                    callback.owner,
                    callback.worker_generation,
                )
            }
        }
        Win16DdeFollowUpCarrier::StartedFailure(failure) => {
            continuation.bind_started_failure(Arc::clone(failure))
        }
        Win16DdeFollowUpCarrier::SourceRetired { proof, result } => {
            continuation.cache_normal_source_retirement(Arc::clone(proof), result.clone())
        }
    }
}

fn carrier_matches_continuation(
    carrier: &Win16DdeFollowUpCarrier,
    continuation: &Win16DdeContinuation,
) -> bool {
    match carrier {
        Win16DdeFollowUpCarrier::Callback(callback) => {
            continuation.host_owner_identity()
                == Some((callback.owner, callback.worker_generation))
                && callback.parent.is_none_or(|operation| {
                    continuation.host_operation() == Some(operation)
                })
        }
        Win16DdeFollowUpCarrier::StartedFailure(failure) => {
            continuation.host_operation() == Some(failure.operation)
                && continuation.host_owner_identity()
                    == Some((failure.owner, failure.worker_generation))
        }
        Win16DdeFollowUpCarrier::SourceRetired { proof, .. } => {
            continuation.host_operation() == Some(proof.operation)
                && continuation.host_owner_identity()
                    == Some((proof.owner, proof.worker_generation))
        }
    }
}

pub(in crate::win16_runtime) fn follow_up_carrier_step(
    carrier: &Win16DdeFollowUpCarrier,
) -> Win16WindowStep {
    match carrier {
        Win16DdeFollowUpCarrier::Callback(callback) => {
            Win16WindowStep::DdeCallback(Arc::clone(callback))
        }
        Win16DdeFollowUpCarrier::StartedFailure(failure) => {
            Win16WindowStep::DdeStartedFailure(Arc::clone(failure))
        }
        Win16DdeFollowUpCarrier::SourceRetired { proof, result } => {
            Win16WindowStep::DdeSourceRetired {
                proof: Arc::clone(proof),
                result: Box::new(Win16WindowStep::Complete(Win16WindowResult::Dde(
                    result.clone(),
                ))),
            }
        }
    }
}

/// Resolve a callback carrier into its exact runtime callback origin. A
/// callback returned by the follow-up call must name that call's operation;
/// parentless callbacks cannot be attached to this owner without inventing an
/// operation identity.
pub(in crate::win16_runtime) fn callback_owned_follow_up_origin(
    owner: Win16DdeFollowUpOwner,
    carrier: &Win16DdeFollowUpCarrier,
) -> Result<(Win16DdeCallbackOrigin, Arc<Win16HostDdeCallbackStep>), RuntimeError> {
    let Win16DdeFollowUpOwner::Callback {
        callback_id,
        host_frame,
        owner: native_owner,
        worker_generation,
        ..
    } = owner
    else {
        return Err(invariant(
            "callback follow-up dispatcher received an operation-frame owner",
        ));
    };
    match carrier {
        Win16DdeFollowUpCarrier::Callback(step) => {
            let Some(operation) = step.parent else {
                return Err(invariant(
                    "callback-owned DDE follow-up returned a parentless callback without an exact submitted operation identity",
                ));
            };
            if callback_id.0 == 0
                || host_frame.0 == 0
                || operation.0 == 0
                || !step.has_valid_identity()
                || step.owner != native_owner
                || step.worker_generation != worker_generation
            {
                return Err(invariant(
                    "DDE follow-up callback changed its exact callback owner or submitted operation",
                ));
            }
            Ok((
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    operation,
                    owner: native_owner,
                    worker_generation,
                },
                Arc::clone(step),
            ))
        }
        Win16DdeFollowUpCarrier::StartedFailure(_)
        | Win16DdeFollowUpCarrier::SourceRetired { .. } => Err(invariant(
            "non-callback DDE follow-up carrier was used as a callback origin",
        )),
    }
}
