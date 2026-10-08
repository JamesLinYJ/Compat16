//! Retryable MCI guest-return, CPU-restore, and native-resume phases.

use guest_core::memory::Memory;
use std::sync::Arc;

use super::{
    CallbackKind, Win16MciFinishPhase, Win16State,
};
use crate::{RuntimeError, RuntimeHost, Win16HostMciResume, Win16HostMciStep};

pub(super) fn finish_callback(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let callback_id = state.mci.active.last().map(|continuation| continuation.callback_id);
    if !matches!(state.callback_kinds.last(), Some(CallbackKind::Mci))
        || callback_id.is_none_or(|id| !state.mci.callback_top_matches(id))
    {
        return Err(record_active_failure(
            state,
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "MCI callback nesting order or exact callback identity is damaged; its continuation remains retained",
            ),
        ));
    }
    if state.mci.active.last().is_some_and(|continuation| {
        continuation.finish_phase == Win16MciFinishPhase::GuestReturnValidation
    }) {
        return retry_guest_return_if_changed(state, cpu, memory, host);
    }
    if state.mci.active.last().is_some_and(|continuation| {
        matches!(
            continuation.finish_phase,
            Win16MciFinishPhase::RestoreCaller
                | Win16MciFinishPhase::ResumeNative
                | Win16MciFinishPhase::EnterNextCallback
                | Win16MciFinishPhase::CompleteGuestCall
                | Win16MciFinishPhase::UnexpectedHostStep
        )
    }) {
        return super::active_finish::progress(state, cpu, memory, host);
    }
    state.mci.pending_cleanup.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve retryable MCI callback continuation before reading its return",
            error,
        )
    })?;
    let frame = match state
        .mci
        .active
        .last()
        .filter(|continuation| continuation.finish_phase == Win16MciFinishPhase::GuestCallback)
        .and_then(|continuation| continuation.active_call.clone())
    {
        Some(frame) => frame,
        None => {
            return Err(record_active_failure(
                state,
                RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                    "MCI callback return has no exact entered guest FAR frame; its pre-entry phase remains retained",
                ),
            ));
        }
    };
    let guest_return = match state.finish_guest_far_callback(&mut cpu.regs, frame) {
        Ok(value) => value as u16,
        Err(primary) => {
            let snapshot = super::Win16MciGuestReturnSnapshot::capture(&cpu.regs);
            if let Some(continuation) = state.mci.active.last_mut() {
                continuation.finish_phase = Win16MciFinishPhase::GuestReturnValidation;
                continuation.invalid_return_snapshot = Some(snapshot);
            }
            return Err(record_active_failure(state, primary));
        }
    };
    let continuation = state
        .mci
        .active
        .last_mut()
        .expect("prechecked MCI continuation remains active");
    continuation.active_call = None;
    continuation.guest_return = Some(guest_return);
    continuation.invalid_return_snapshot = None;
    continuation.finish_phase = Win16MciFinishPhase::RestoreCaller;
    super::active_finish::progress(state, cpu, memory, host)
}

pub(super) fn retry_on_run_entry(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    if state.mci.pending_begin.is_some() {
        super::begin_retry::retry_pending_begin(state, cpu, memory, host)?;
        return Ok(true);
    }
    if state.mci.active.last().is_some_and(|continuation| {
        matches!(
            continuation.finish_phase,
            Win16MciFinishPhase::PreEntryPending | Win16MciFinishPhase::PreEntryAborted
        )
    }) {
        let continuation = state.mci.active.last().expect("phase owner remains retained");
        let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
            Arc::new(RuntimeError::new(
                crate::DiagnosticKind::CompatibilityGap,
                "MCI yield callback was not entered and has no native abort receipt",
            ))
        });
        return Err(finish_error(
            continuation.callback_id,
            continuation.event,
            continuation.finish_phase,
            continuation.guest_return,
            None,
            continuation.invalid_return_snapshot,
            cause,
        ));
    }
    if state.mci.pending_cleanup.last().is_some_and(|pending| {
        matches!(
            pending.continuation.finish_phase,
            Win16MciFinishPhase::PreEntryPending | Win16MciFinishPhase::PreEntryAborted
        )
    }) {
        let continuation = &state
            .mci
            .pending_cleanup
            .last()
            .expect("pre-entry owner remains retained")
            .continuation;
        let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
            Arc::new(RuntimeError::new(
                crate::DiagnosticKind::CompatibilityGap,
                "MCI yield callback pre-entry owner remains retained without a native abort receipt",
            ))
        });
        return Err(finish_error(
            continuation.callback_id,
            continuation.event,
            continuation.finish_phase,
            continuation.guest_return,
            state
                .mci
                .pending_cleanup
                .last()
                .and_then(|pending| pending.unexpected_step.clone()),
            continuation.invalid_return_snapshot,
            cause,
        ));
    }
    if state.mci.active.last().is_some_and(|continuation| {
        continuation.finish_phase == Win16MciFinishPhase::GuestReturnValidation
    }) {
        retry_guest_return_if_changed(state, cpu, memory, host)?;
        return Ok(true);
    }
    if state.mci.active.last().is_some_and(|continuation| {
        matches!(
            continuation.finish_phase,
            Win16MciFinishPhase::RestoreCaller
                | Win16MciFinishPhase::ResumeNative
                | Win16MciFinishPhase::EnterNextCallback
                | Win16MciFinishPhase::CompleteGuestCall
                | Win16MciFinishPhase::UnexpectedHostStep
        )
    }) {
        super::active_finish::progress(state, cpu, memory, host)?;
        return Ok(true);
    }
    if state.mci.pending_cleanup.last().is_some_and(|pending| {
        matches!(
            pending.continuation.finish_phase,
            Win16MciFinishPhase::ResumeNative
                | Win16MciFinishPhase::EnterNextCallback
                | Win16MciFinishPhase::CompleteGuestCall
        )
    }) {
        retry_pending(state, cpu, memory, host)?;
        return Ok(true);
    }
    if state.mci.pending_cleanup.last().is_some_and(|pending| {
        pending.continuation.finish_phase == Win16MciFinishPhase::UnexpectedHostStep
    }) {
        let continuation = &state
            .mci
            .pending_cleanup
            .last()
            .expect("unexpected native step owner remains retained")
            .continuation;
        let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
            Arc::new(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "unexpected native MCI step remains retained with its full receipt",
            ))
        });
        return Err(finish_error(
            continuation.callback_id,
            continuation.event,
            continuation.finish_phase,
            continuation.guest_return,
            state
                .mci
                .pending_cleanup
                .last()
                .and_then(|pending| pending.unexpected_step.clone()),
            continuation.invalid_return_snapshot,
            cause,
        ));
    }
    Ok(false)
}

fn retry_guest_return_if_changed(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let current = super::Win16MciGuestReturnSnapshot::capture(&cpu.regs);
    let continuation = state
        .mci
        .active
        .last()
        .filter(|continuation| {
            continuation.finish_phase == Win16MciFinishPhase::GuestReturnValidation
        })
        .ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "MCI return-validation retry lost its exact active continuation",
            )
        })?;
    if continuation.invalid_return_snapshot == Some(current) {
        let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
            Arc::new(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "invalid MCI guest-return state remains retained without its original typed cause",
            ))
        });
        return Err(finish_error(
            continuation.callback_id,
            continuation.event,
            continuation.finish_phase,
            continuation.guest_return,
            None,
            continuation.invalid_return_snapshot,
            cause,
        ));
    }
    retry_guest_return(state, cpu, memory, host)
}

fn retry_guest_return(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let callback_id = state
        .mci
        .active
        .last()
        .filter(|continuation| {
            continuation.finish_phase == Win16MciFinishPhase::GuestReturnValidation
        })
        .map(|continuation| continuation.callback_id)
        .ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "MCI return-validation retry has no exact callback identity",
            )
        })?;
    if !matches!(state.callback_kinds.last(), Some(CallbackKind::Mci))
        || !state.mci.callback_top_matches(callback_id)
    {
        return Err(record_active_failure(
            state,
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "MCI return-validation retry no longer owns the exact callback LIFO top",
            ),
        ));
    }
    let frame = state
        .mci
        .active
        .last()
        .and_then(|continuation| continuation.active_call.clone());
    let Some(frame) = frame else {
        return Err(record_active_failure(
            state,
            RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "MCI return-validation retry lost its original FAR frame",
            ),
        ));
    };
    match state.finish_guest_far_callback(&mut cpu.regs, frame) {
        Err(cause) => {
            let snapshot = super::Win16MciGuestReturnSnapshot::capture(&cpu.regs);
            if let Some(continuation) = state.mci.active.last_mut() {
                continuation.invalid_return_snapshot = Some(snapshot);
            }
            Err(record_active_failure(state, cause))
        }
        Ok(value) => {
            let continuation = state
                .mci
                .active
                .last_mut()
                .expect("validated MCI return owner remains active");
            continuation.active_call = None;
            continuation.guest_return = Some(value as u16);
            continuation.invalid_return_snapshot = None;
            continuation.finish_phase = Win16MciFinishPhase::RestoreCaller;
            super::active_finish::progress(state, cpu, memory, host)
        }
    }
}

pub(super) fn retry_pending(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    loop {
        let Some(phase) = state
            .mci
            .pending_cleanup
            .last()
            .map(|pending| pending.continuation.finish_phase)
        else {
            return Ok(());
        };
        match phase {
            Win16MciFinishPhase::ResumeNative => {
                state.mci.active.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        crate::DiagnosticKind::ResourceExhausted,
                        "reserve MCI nested-yield owner before native resume",
                        error,
                    )
                })?;
                if state
                    .mci
                    .pending_cleanup
                    .last()
                    .is_some_and(|pending| pending.continuation.next_callback_id.is_none())
                {
                    let next_callback_id = state.reserve_callback_frame_id()?;
                    state
                        .mci
                        .pending_cleanup
                        .last_mut()
                        .expect("native resume continuation remains retained")
                        .continuation
                        .next_callback_id = Some(next_callback_id);
                }
                let has_prior_failure = state
                    .mci
                    .pending_cleanup
                    .last()
                    .is_some_and(|pending| pending.continuation.finish_failure.is_some());
                if has_prior_failure {
                    state.mci.resolved_finish_causes.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            crate::DiagnosticKind::ResourceExhausted,
                            "reserve resolved MCI resume evidence before retrying native owner",
                            error,
                        )
                    })?;
                }
                state
                    .mci
                    .pending_cleanup
                    .last_mut()
                    .expect("native resume continuation remains retained")
                    .continuation
                    .returned_yields
                    .try_reserve(1)
                    .map_err(|error| {
                        RuntimeError::with_source(
                            crate::DiagnosticKind::ResourceExhausted,
                            "reserve exact native MCI yield-return proof before resume",
                            error,
                        )
                    })?;
                let completed_yield_capacity = state
                    .mci
                    .pending_cleanup
                    .last()
                    .map(|pending| pending.continuation.returned_yields.len().saturating_add(1))
                    .unwrap_or(1);
                state.mci.completed_yields.try_reserve(completed_yield_capacity).map_err(|error| {
                    RuntimeError::with_source(
                        crate::DiagnosticKind::ResourceExhausted,
                        "reserve exact returned-yield proof history before native resume",
                        error,
                    )
                })?;
                state.mci.completed_operations.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        crate::DiagnosticKind::ResourceExhausted,
                        "reserve exact native operation completion history before resume",
                        error,
                    )
                })?;
                let (operation, event, guest_return) = {
                    let continuation = &state
                        .mci
                        .pending_cleanup
                        .last()
                        .expect("phase owner remains retained")
                        .continuation;
                    (
                        continuation.operation,
                        continuation.event,
                        continuation.guest_return.ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "MCI native resume retry has no cached guest WORD",
                            )
                        })?,
                    )
                };
                let resume_receipt = match host.win16_mci_resume(Win16HostMciResume {
                    operation,
                    frame: event.frame,
                    return_value: guest_return,
                }) {
                    Ok(receipt) => receipt,
                    Err(cause) => return Err(record_pending_failure(state, cause)),
                };
                let expected_return = crate::Win16HostMciYieldReturn {
                    owner: crate::Win16HostMciActiveYield {
                        operation,
                        frame: event.frame,
                        device: event.device,
                    },
                    guest_return,
                };
                if resume_receipt.returned_yield != expected_return {
                    let pending = state
                        .mci
                        .pending_cleanup
                        .last_mut()
                        .expect("native resume continuation remains retained");
                    pending.unexpected_step = Some(resume_receipt.clone());
                    pending.continuation.finish_phase =
                        Win16MciFinishPhase::UnexpectedHostStep;
                    return Err(record_pending_failure(
                        state,
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "native MCI resume receipt does not ACK the exact operation/frame/device/WORD submitted",
                        ),
                    ));
                }
                state
                    .mci
                    .pending_cleanup
                    .last_mut()
                    .expect("native resume continuation remains retained")
                    .continuation
                    .returned_yields
                    .push(resume_receipt.returned_yield);
                if let Some(cause) = state
                    .mci
                    .pending_cleanup
                    .last_mut()
                    .and_then(|pending| pending.continuation.finish_failure.take())
                {
                    state.mci.resolved_finish_causes.push(cause);
                }
                match resume_receipt.step.clone() {
                    Win16HostMciStep::Yield(next_event) => {
                        if next_event.operation != operation || next_event.frame.0 == 0 {
                            let pending = state
                                .mci
                                .pending_cleanup
                                .last_mut()
                                .expect("phase owner remains retained");
                            pending.unexpected_step = Some(resume_receipt.clone());
                            pending.continuation.finish_phase =
                                Win16MciFinishPhase::UnexpectedHostStep;
                            return Err(record_pending_failure(
                                state,
                                RuntimeError::new(
                                    crate::DiagnosticKind::InternalInvariant,
                                    "native MCI resume returned a different operation identity or a zero yield-frame identity",
                                ),
                            ));
                        }
                        let continuation = &mut state
                            .mci
                            .pending_cleanup
                            .last_mut()
                            .expect("phase owner remains retained")
                            .continuation;
                        continuation.event = next_event;
                        continuation.next_event = None;
                        continuation.callback_id = continuation
                            .next_callback_id
                            .take()
                            .expect("next-yield callback identity was reserved before native resume");
                        continuation.guest_return = None;
                        continuation.finish_phase = Win16MciFinishPhase::EnterNextCallback;
                    }
                    Win16HostMciStep::Complete(result) => {
                        for index in 0..state
                            .mci
                            .pending_cleanup
                            .last()
                            .expect("phase owner remains retained")
                            .continuation
                            .returned_yields
                            .len()
                        {
                            let returned = state
                                .mci
                                .pending_cleanup
                                .last()
                                .expect("phase owner remains retained")
                                .continuation
                                .returned_yields[index];
                            if !state.mci.completed_yields.contains(&returned) {
                                state.mci.completed_yields.push(returned);
                            }
                        }
                        let proof = crate::Win16HostMciOperationCompletion {
                            operation,
                            native_return_value: result.return_value,
                        };
                        if !state.mci.completed_operations.contains(&proof) {
                            state.mci.completed_operations.push(proof);
                        }
                        let continuation = &mut state
                            .mci
                            .pending_cleanup
                            .last_mut()
                            .expect("phase owner remains retained")
                            .continuation;
                        continuation.next_callback_id = None;
                        continuation.completed_result = Some(result);
                        continuation.finish_phase = Win16MciFinishPhase::CompleteGuestCall;
                    }
                }
            }
            Win16MciFinishPhase::EnterNextCallback => {
                let mut pending = state.mci.pending_cleanup.pop().ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "MCI next-yield callback owner disappeared before entry",
                    )
                })?;
                pending.continuation.active_call = None;
                pending.continuation.finish_phase = Win16MciFinishPhase::PreEntryPending;
                state.publish_mci_yield_callback(
                    pending.continuation,
                    &mut cpu.regs,
                    memory,
                )?;
                return Ok(());
            }
            Win16MciFinishPhase::CompleteGuestCall => {
                state.mci.resolved_finish_causes.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        crate::DiagnosticKind::ResourceExhausted,
                        "reserve resolved MCI callback causes before guest completion",
                        error,
                    )
                })?;
                let (request, result, return_to, return_kind) = {
                    let continuation = &state
                        .mci
                        .pending_cleanup
                        .last()
                        .expect("phase owner remains retained")
                        .continuation;
                    (
                        continuation.request.clone(),
                        continuation.completed_result.clone().ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "MCI completion retry has no exact native result",
                            )
                        })?,
                        continuation.return_to,
                        continuation.return_kind,
                    )
                };
                if let Err(cause) = super::completion::complete(
                    state,
                    request,
                    result,
                    &mut cpu.regs,
                    memory,
                    host,
                    return_to,
                    return_kind,
                ) {
                    return Err(record_pending_failure(state, cause));
                }
                let pending = state
                    .mci
                    .pending_cleanup
                    .pop()
                    .expect("completed MCI continuation remains retained");
                if let Some(cause) = pending.continuation.finish_failure {
                    state.mci.resolved_finish_causes.push(cause);
                }
                return Ok(());
            }
            Win16MciFinishPhase::PreEntryPending
            | Win16MciFinishPhase::PreEntryAborted
            | Win16MciFinishPhase::GuestReturnValidation => {
                let continuation = &state
                    .mci
                    .pending_cleanup
                    .last()
                    .expect("pre-entry owner remains retained")
                    .continuation;
                let cause = continuation.finish_failure.clone().unwrap_or_else(|| {
                    Arc::new(RuntimeError::new(
                        crate::DiagnosticKind::CompatibilityGap,
                        "MCI yield callback pre-entry owner remains retained without a native abort receipt",
                    ))
                });
                return Err(finish_error(
                    continuation.callback_id,
                    continuation.event,
                    continuation.finish_phase,
                    continuation.guest_return,
                    state
                        .mci
                        .pending_cleanup
                        .last()
                        .and_then(|pending| pending.unexpected_step.clone()),
                    continuation.invalid_return_snapshot,
                    cause,
                ));
            }
            Win16MciFinishPhase::GuestCallback
            | Win16MciFinishPhase::RestoreCaller
            | Win16MciFinishPhase::UnexpectedHostStep => return Ok(()),
        }
    }
}

pub(super) fn record_active_failure(state: &mut Win16State, cause: RuntimeError) -> RuntimeError {
    let Some(continuation) = state.mci.active.last_mut() else {
        return cause;
    };
    let retained = super::errors::retain_finish_failure(
        &mut continuation.finish_failure,
        cause,
    );
    finish_error(
        continuation.callback_id,
        continuation.event,
        continuation.finish_phase,
        continuation.guest_return,
        continuation.unexpected_step.clone(),
        continuation.invalid_return_snapshot,
        retained,
    )
}

fn record_pending_failure(state: &mut Win16State, cause: RuntimeError) -> RuntimeError {
    let Some(pending) = state.mci.pending_cleanup.last_mut() else {
        return cause;
    };
    let retained = super::errors::retain_finish_failure(
        &mut pending.continuation.finish_failure,
        cause,
    );
    finish_error(
        pending.continuation.callback_id,
        pending.continuation.event,
        pending.continuation.finish_phase,
        pending.continuation.guest_return,
        pending.unexpected_step.clone(),
        pending.continuation.invalid_return_snapshot,
        retained,
    )
}

pub(super) fn finish_error(
    callback_id: super::super::CallbackFrameId,
    event: crate::Win16HostMciYieldEvent,
    phase: Win16MciFinishPhase,
    guest_return: Option<u16>,
    unexpected_step: Option<crate::Win16HostMciResumeReceipt>,
    guest_return_snapshot: Option<super::Win16MciGuestReturnSnapshot>,
    cause: std::sync::Arc<RuntimeError>,
) -> RuntimeError {
    RuntimeError::with_source(
        cause.kind(),
        "MCI callback finish retains its exact phase for a retry",
        super::errors::MciFinishFailure {
            callback_id,
            event,
            phase,
            guest_return,
            cancellation_gap: super::errors::cancellation_gap(phase),
            unexpected_step,
            guest_return_snapshot,
            cause,
        },
    )
}
