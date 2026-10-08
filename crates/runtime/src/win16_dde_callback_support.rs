//! Shared validation and typed error composition for DDE callback phases.

use compat_services::win16_dde::callback_class as class;

use super::Win16DdeCallbackOrigin;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeCallbackReply,
    Win16HostDdeCallbackFrame, Win16HostDdeStep,
};

pub(in crate::win16_runtime) fn validate_resumed_step(
    origin: Win16DdeCallbackOrigin,
    frame: Win16HostDdeCallbackFrame,
    step: Win16HostDdeStep,
) -> Result<(), RuntimeError> {
    match (origin, step) {
        // A foreground native operation may yield an unrelated unsolicited
        // callback while continuing to wait. The root scheduler will route
        // parent=None against the exact WindowWait runtime-frame identity.
        (Win16DdeCallbackOrigin::Foreground(_), Win16HostDdeStep::Callback(next))
            if next.parent.is_none() =>
        {
            Ok(())
        }
        (Win16DdeCallbackOrigin::Foreground(expected), Win16HostDdeStep::Callback(next))
            if next.parent == Some(expected) =>
        {
            Ok(())
        }
        // This Complete is an internal callback reply result. It remains on
        // the original DDE continuation until it is cached, guest callback
        // cleanup and the exact host callback-retired ACK complete, and the
        // parent source-retirement API produces a SourceRetired carrier.
        (Win16DdeCallbackOrigin::Foreground(_), Win16HostDdeStep::Complete(_)) => Ok(()),
        (
            Win16DdeCallbackOrigin::Foreground(expected),
            Win16HostDdeStep::SourceRetired { proof, .. },
        ) if proof.operation == expected && proof.has_valid_identity() => Ok(()),
        (Win16DdeCallbackOrigin::Foreground(_), Win16HostDdeStep::SourceRetired { .. }) => {
            Err(invariant(
                "resumed DDE callback returned a foreign or invalid source-retirement proof",
            ))
        }
        (Win16DdeCallbackOrigin::Foreground(_), _) => Err(invariant(
            "resumed foreground DDE operation returned an invalid callback step",
        )),
        (
            Win16DdeCallbackOrigin::CallbackFollowUp { operation, owner, worker_generation, .. },
            Win16HostDdeStep::Callback(next),
        ) if next.parent == Some(operation)
            && next.owner == owner
            && next.worker_generation == worker_generation
            && next.has_valid_identity() => Ok(()),
        (
            Win16DdeCallbackOrigin::CallbackFollowUp { .. },
            Win16HostDdeStep::Callback(_),
        ) => Err(invariant(
            "callback-owned DDE follow-up yielded a callback for another operation owner",
        )),
        (
            Win16DdeCallbackOrigin::CallbackFollowUp { operation, owner, worker_generation, .. },
            Win16HostDdeStep::Complete(_),
        ) => {
            if operation.0 != 0 && owner.0 != 0 && worker_generation != 0 {
                Ok(())
            } else {
                Err(invariant(
                    "callback-owned DDE follow-up completion has an invalid exact operation owner",
                ))
            }
        }
        (
            Win16DdeCallbackOrigin::CallbackFollowUp { operation, owner, worker_generation, .. },
            Win16HostDdeStep::SourceRetired { proof, .. },
        ) if proof.has_valid_identity()
            && proof.operation == operation
            && proof.owner == owner
            && proof.worker_generation == worker_generation => Ok(()),
        (
            Win16DdeCallbackOrigin::CallbackFollowUp { .. },
            Win16HostDdeStep::SourceRetired { .. },
        ) => Err(invariant(
            "callback-owned DDE follow-up returned a foreign source-retirement proof",
        )),
        (Win16DdeCallbackOrigin::CallbackFollowUp { .. }, _) => Err(invariant(
            "callback-owned DDE follow-up returned an unsupported native step",
        )),
        (
            Win16DdeCallbackOrigin::WindowWait { .. },
            Win16HostDdeStep::CallbackFrameComplete { frame: completed },
        ) if frame == completed => Ok(()),
        (
            Win16DdeCallbackOrigin::GuestExecution { frame: expected },
            Win16HostDdeStep::CallbackFrameComplete { frame: completed },
        ) if expected == frame && frame == completed => Ok(()),
        (
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. },
            _,
        ) => Err(invariant(
            "unsolicited DDE callback reply did not complete its exact native frame",
        )),
    }
}

pub(in crate::win16_runtime) fn callback_projection_fallback_for_type(
    transaction_type_value: u32,
) -> Option<Win16DdeCallbackReply> {
    match class::from_transaction_type(transaction_type_value)? {
        class::BOOL | class::FLAGS | class::NOTIFICATION => Some(Win16DdeCallbackReply::Scalar(0)),
        class::DATA => Some(Win16DdeCallbackReply::NoData),
        _ => None,
    }
}

pub(in crate::win16_runtime) fn dde_callback_failure(
    primary: Option<RuntimeError>,
    cleanup: RuntimeError,
) -> RuntimeError {
    match primary {
        Some(operation) => combine_dde_errors(
            operation,
            cleanup,
            "Win16 DDE callback failed and its native acknowledgement or cleanup also failed",
        ),
        None => cleanup,
    }
}

/// Make a retry copy of a prepared guest reply with fallible capacity
/// reservation. The original reply must already be stored on its callback
/// owner before callers attempt this copy or submit any native effect.
pub(in crate::win16_runtime) fn clone_dde_callback_reply(
    reply: &Win16DdeCallbackReply,
) -> Result<Win16DdeCallbackReply, RuntimeError> {
    match reply {
        Win16DdeCallbackReply::WildConnect { source, pairs } => {
            let mut copied = Vec::new();
            copied.try_reserve_exact(pairs.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "copy Win16 WILDCONNECT reply before native submission",
                    error,
                )
            })?;
            copied.extend_from_slice(pairs);
            Ok(Win16DdeCallbackReply::WildConnect {
                source: *source,
                pairs: copied,
            })
        }
        reply => Ok(reply.clone()),
    }
}

pub(in crate::win16_runtime) fn combine_dde_errors(
    first: RuntimeError,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    first.with_cleanup(context, additional)
}

pub(in crate::win16_runtime) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
