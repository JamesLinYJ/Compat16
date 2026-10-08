//! Finish an entered MCI yield while its exact callback-LIFO owner stays live.

use guest_core::memory::Memory;

use super::{CallbackKind, Win16MciFinishPhase, Win16MciPendingCleanup, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMciActiveYield,
    Win16HostMciResume, Win16HostMciResumeReceipt, Win16HostMciStep,
    Win16HostMciYieldReturn,
};

pub(super) fn progress(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let phase = state
        .mci
        .active
        .last()
        .map(|continuation| continuation.finish_phase)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI active finish lost its exact continuation owner",
            )
        })?;

    if phase == Win16MciFinishPhase::RestoreCaller {
        restore_caller(state, cpu)?;
    }

    match active_phase(state)? {
        Win16MciFinishPhase::ResumeNative => {
            resume_native(state, host)?;
            transfer_acknowledged_owner(state)?;
        }
        Win16MciFinishPhase::EnterNextCallback
        | Win16MciFinishPhase::CompleteGuestCall => transfer_acknowledged_owner(state)?,
        Win16MciFinishPhase::UnexpectedHostStep => {
            return Err(retained_active_error(state));
        }
        phase => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                format!("MCI active finish cannot advance phase {phase:?}"),
            ));
        }
    }

    super::retry::retry_pending(state, cpu, memory, host)
}

fn restore_caller(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
) -> Result<(), RuntimeError> {
    let (callback_id, context) = state
        .mci
        .active
        .last()
        .filter(|continuation| continuation.finish_phase == Win16MciFinishPhase::RestoreCaller)
        .map(|continuation| (continuation.callback_id, continuation.cpu_context.clone()))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI caller restore has no exact retained context",
            )
        })?;
    ensure_callback_top(state, callback_id)?;
    if let Err(error) = cpu.restore_context(&context) {
        return Err(super::retry::record_active_failure(
            state,
            crate::runtime_error(error),
        ));
    }
    ensure_callback_top(state, callback_id)?;
    let continuation = state
        .mci
        .active
        .last_mut()
        .expect("exact MCI callback owner was checked after context restore");
    continuation.finish_phase = Win16MciFinishPhase::ResumeNative;
    Ok(())
}

fn resume_native(
    state: &mut Win16State,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let (callback_id, operation, event, guest_return, next_callback_id, has_failure, returned_len) = {
        let continuation = state
            .mci
            .active
            .last()
            .filter(|continuation| continuation.finish_phase == Win16MciFinishPhase::ResumeNative)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI native resume has no exact active owner",
                )
            })?;
        (
            continuation.callback_id,
            continuation.operation,
            continuation.event,
            continuation.guest_return.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI native resume has no cached guest WORD",
                )
            })?,
            continuation.next_callback_id,
            continuation.finish_failure.is_some(),
            continuation.returned_yields.len(),
        )
    };
    ensure_callback_top(state, callback_id)?;

    // Every runtime owner and history allocation is reserved before the
    // native resume can consume the checked guest WORD.
    if let Err(error) = state.mci.pending_cleanup.try_reserve(1) {
        return Err(record_reserve_failure(
            state,
            "reserve acknowledged MCI continuation before native resume",
            error,
        ));
    }
    if let Err(error) = state
        .mci
        .completed_yields
        .try_reserve(returned_len.saturating_add(1))
    {
        return Err(record_reserve_failure(
            state,
            "reserve exact MCI returned-yield history before native resume",
            error,
        ));
    }
    if let Err(error) = state.mci.completed_operations.try_reserve(1) {
        return Err(record_reserve_failure(
            state,
            "reserve exact MCI completion history before native resume",
            error,
        ));
    }
    let returned_reserve = state
        .mci
        .active
        .last_mut()
        .expect("MCI active owner was checked")
        .returned_yields
        .try_reserve(1);
    if let Err(error) = returned_reserve {
        return Err(record_reserve_failure(
            state,
            "reserve exact MCI yield ACK in its active continuation",
            error,
        ));
    }
    if has_failure {
        if let Err(error) = state.mci.resolved_finish_causes.try_reserve(1) {
            return Err(record_reserve_failure(
                state,
                "reserve resolved MCI failure evidence before retrying native resume",
                error,
            ));
        }
    }
    if next_callback_id.is_none() {
        let id = match state.reserve_callback_frame_id() {
            Ok(id) => id,
            Err(error) => return Err(super::retry::record_active_failure(state, error)),
        };
        state
            .mci
            .active
            .last_mut()
            .expect("MCI active owner remains retained")
            .next_callback_id = Some(id);
    }

    let receipt = match host.win16_mci_resume(Win16HostMciResume {
        operation,
        frame: event.frame,
        return_value: guest_return,
    }) {
        Ok(receipt) => receipt,
        Err(cause) => return Err(super::retry::record_active_failure(state, cause)),
    };
    let Win16HostMciResumeReceipt { returned_yield, step } = receipt;
    let expected_return = Win16HostMciYieldReturn {
        owner: Win16HostMciActiveYield {
            operation,
            frame: event.frame,
            device: event.device,
        },
        guest_return,
    };
    if returned_yield != expected_return {
        let continuation = state
            .mci
            .active
            .last_mut()
            .expect("MCI active owner remains retained");
        continuation.unexpected_step = Some(Win16HostMciResumeReceipt {
            returned_yield,
            step,
        });
        continuation.finish_phase = Win16MciFinishPhase::UnexpectedHostStep;
        return Err(super::retry::record_active_failure(
            state,
            RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI resume did not ACK the exact operation/frame/device/guest WORD",
            ),
        ));
    }

    state
        .mci
        .active
        .last_mut()
        .expect("MCI active owner remains retained")
        .returned_yields
        .push(returned_yield);
    if let Some(cause) = state
        .mci
        .active
        .last_mut()
        .and_then(|continuation| continuation.finish_failure.take())
    {
        state.mci.resolved_finish_causes.push(cause);
    }

    match step {
        Win16HostMciStep::Yield(next_event) => {
            if next_event.operation != operation || next_event.frame.0 == 0 {
                let continuation = state
                    .mci
                    .active
                    .last_mut()
                    .expect("MCI active owner remains retained");
                continuation.unexpected_step = Some(Win16HostMciResumeReceipt {
                    returned_yield,
                    step: Win16HostMciStep::Yield(next_event),
                });
                continuation.finish_phase = Win16MciFinishPhase::UnexpectedHostStep;
                return Err(super::retry::record_active_failure(
                    state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "native MCI returned a yield for another operation or a zero frame",
                    ),
                ));
            }
            let continuation = state
                .mci
                .active
                .last_mut()
                .expect("MCI active owner remains retained");
            continuation.next_event = Some(next_event);
            continuation.finish_phase = Win16MciFinishPhase::EnterNextCallback;
        }
        Win16HostMciStep::Complete(result) => {
            let continuation = state
                .mci
                .active
                .last_mut()
                .expect("MCI active owner remains retained");
            for returned in &continuation.returned_yields {
                if !state.mci.completed_yields.contains(returned) {
                    state.mci.completed_yields.push(*returned);
                }
            }
            let proof = crate::Win16HostMciOperationCompletion {
                operation,
                native_return_value: result.return_value,
            };
            if !state.mci.completed_operations.contains(&proof) {
                state.mci.completed_operations.push(proof);
            }
            continuation.next_event = None;
            continuation.completed_result = Some(result);
            continuation.finish_phase = Win16MciFinishPhase::CompleteGuestCall;
        }
    }
    Ok(())
}

fn transfer_acknowledged_owner(state: &mut Win16State) -> Result<(), RuntimeError> {
    let (callback_id, phase) = state
        .mci
        .active
        .last()
        .map(|continuation| (continuation.callback_id, continuation.finish_phase))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "acknowledged MCI callback lost its active continuation",
            )
        })?;
    if !matches!(phase, Win16MciFinishPhase::EnterNextCallback | Win16MciFinishPhase::CompleteGuestCall) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MCI callback LIFO retirement was attempted before an exact native ACK",
        ));
    }
    let continuation = state
        .mci
        .active
        .last()
        .expect("MCI active continuation was read above");
    match phase {
        Win16MciFinishPhase::EnterNextCallback
            if continuation.next_event.is_none() || continuation.next_callback_id.is_none() =>
        {
            return Err(super::retry::record_active_failure(
                state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "acknowledged MCI next-yield phase lost its exact event or reserved callback identity",
                ),
            ));
        }
        Win16MciFinishPhase::CompleteGuestCall if continuation.completed_result.is_none() => {
            return Err(super::retry::record_active_failure(
                state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "acknowledged MCI callback phase lost its exact native completion result",
                ),
            ));
        }
        _ => {}
    }
    ensure_callback_top(state, callback_id)?;
    if let Err(error) = state.mci.pending_cleanup.try_reserve(1) {
        return Err(record_reserve_failure(
            state,
            "reserve acknowledged MCI continuation before callback-LIFO retirement",
            error,
        ));
    }

    let mut continuation = state
        .mci
        .active
        .pop()
        .expect("exact MCI callback owner was checked before retirement");
    let callback = state.callback_kinds.pop();
    if callback != Some(CallbackKind::Mci) {
        state.mci.active.push(continuation);
        if let Some(callback) = callback {
            state.callback_kinds.push(callback);
        }
        return Err(super::retry::record_active_failure(
            state,
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI central callback LIFO changed while retiring its acknowledged frame",
            ),
        ));
    }

    if phase == Win16MciFinishPhase::EnterNextCallback {
        continuation.event = continuation
            .next_event
            .take()
            .expect("exact next-yield event was checked before retiring old callback");
        continuation.callback_id = continuation
            .next_callback_id
            .take()
            .expect("reserved next callback ID was checked before retiring old callback");
        continuation.guest_return = None;
    }
    continuation.active_call = None;
    continuation.next_event = None;
    continuation.finish_phase = phase;
    let unexpected_step = continuation.unexpected_step.take();
    state.mci.pending_cleanup.push(Win16MciPendingCleanup {
        continuation,
        unexpected_step,
    });
    Ok(())
}

fn ensure_callback_top(
    state: &mut Win16State,
    callback_id: super::super::CallbackFrameId,
) -> Result<(), RuntimeError> {
    if matches!(state.callback_kinds.last(), Some(CallbackKind::Mci))
        && state.mci.callback_top_matches(callback_id)
    {
        Ok(())
    } else {
        Err(super::retry::record_active_failure(
            state,
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI finish no longer owns the exact central callback-LIFO top",
            ),
        ))
    }
}

fn active_phase(state: &Win16State) -> Result<Win16MciFinishPhase, RuntimeError> {
    state
        .mci
        .active
        .last()
        .map(|continuation| continuation.finish_phase)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "MCI active finish owner disappeared",
            )
        })
}

fn retained_active_error(state: &Win16State) -> RuntimeError {
    let continuation = state
        .mci
        .active
        .last()
        .expect("retained MCI active error has an owner");
    let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
        std::sync::Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            "unexpected MCI native step remains retained with its exact receipt",
        ))
    });
    super::retry::finish_error(
        continuation.callback_id,
        continuation.event,
        continuation.finish_phase,
        continuation.guest_return,
        continuation.unexpected_step.clone(),
        continuation.invalid_return_snapshot,
        cause,
    )
}

fn record_reserve_failure(
    state: &mut Win16State,
    context: &'static str,
    error: std::collections::TryReserveError,
) -> RuntimeError {
    super::retry::record_active_failure(
        state,
        RuntimeError::with_source(Kind::ResourceExhausted, context, error),
    )
}
