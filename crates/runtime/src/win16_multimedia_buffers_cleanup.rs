//! Ordered, retryable teardown for the WAVE child subsystem.

use super::*;
use super::super::window_post::{window_post_attempt_consumed, window_post_attempt_result};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WaveCallbackCancellationReason {
    TargetRetired,
    UserPostRejected,
    OwnerTerminatedAfterProducerQuiescence(super::WaveProducerQuiescenceReceipt),
    UserNotificationRetired(super::proof::WaveUserSourceRetirementReceipt),
    CallbackAbortedAfterProducerQuiescence {
        proof: super::WaveProducerQuiescenceReceipt,
        retirement: super::super::callback_scheduler::AsynchronousCallbackRetirement,
    },
}

impl Win16State {
    /// Stop WAVE production and consume native Close/Quiescent before USER
    /// callback/source retirement. Runtime header and callback rows remain
    /// owned until their later exact source retirement.
    pub(in crate::win16_runtime) fn quiesce_wave_producers(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.wave_audio.producers_quiesced {
            return Ok(());
        }
        let mut devices = Vec::new();
        devices
            .try_reserve_exact(self.wave_audio.devices.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve WAVE cleanup snapshot",
                    error,
                )
            })?;
        devices.extend(self.wave_audio.devices.iter().copied());

        for device in devices {
            if !self
                .wave_audio
                .devices
                .iter()
                .any(|record| {
                    record.host == device.host && record.generation == device.generation
                })
            {
                continue;
            }
            if device.closing {
                if device.close_result != Some(MMSYSERR_NOERROR) {
                    return Err(wave_invariant(
                        "closed WAVE device has no exact successful native Close result",
                    ));
                }
                continue;
            }
            if device.reset_result != Some(MMSYSERR_NOERROR) {
                let reset = host.win16_wave(Win16HostWaveOperation::Control {
                    device: device.host,
                    command: Win16HostWaveControl::Reset,
                })?;
                let Win16HostWaveResult::Scalar(reset) = reset else {
                    return Err(wave_invariant("WAVE reset returned the wrong result"));
                };
                if let Some(current) = self.wave_audio.devices.iter_mut().find(|current| {
                    current.host == device.host && current.generation == device.generation
                }) {
                    if reset == MMSYSERR_NOERROR {
                        current.reset_result = Some(MMSYSERR_NOERROR);
                    } else {
                        current.reset_result = None;
                        let first = *current.reset_failure_result.get_or_insert(reset);
                        if first != reset {
                            let primary = wave_cleanup_error("first reset", first);
                            let retry = wave_cleanup_error("reset retry", reset);
                            return Err(primary.with_cleanup(
                                "Win16 WAVE Reset retry also failed",
                                retry,
                            ));
                        }
                    }
                } else {
                    return Err(wave_invariant(
                        "WAVE device generation disappeared after native reset",
                    ));
                }
                if reset != MMSYSERR_NOERROR {
                    return Err(wave_cleanup_error("reset", reset));
                }
            }
        }
        self.poll_wave_events(memory, host, true)?;
        // Native production must be stopped before USER closes or the central
        // LIFO cancellation path runs. The real host Close/Quiescent events
        // stop its callback producer; guest callback/source rows stay pinned.
        super::native_shutdown::close_quiesced_wave_devices(self, memory, host)?;
        if self.wave_audio.devices.iter().any(|device| {
            !device.closing
                || device.close_result != Some(MMSYSERR_NOERROR)
                || device.close_event_sequence.is_none()
                || device.producer_quiescence_sequence.is_none()
        }) {
            return Err(wave_invariant(
                "WAVE producer barrier lacks exact Close and Quiescent events",
            ));
        }
        if self.wave_audio.owner_barrier_required {
            host.win16_wave_retired_owner_barrier()?;
        }
        self.wave_audio.producers_quiesced = true;
        Ok(())
    }

    /// Finish source-owner cleanup after the central callback stack has had
    /// the chance to cancel entered frames in LIFO order.
    pub(in crate::win16_runtime) fn close_wave_runtime(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.wave_audio.cleanup_complete {
            return Ok(());
        }
        if self.window_teardown_state != super::super::WindowTeardownState::Closed {
            return Err(wave_invariant(
                "WAVE logical source retirement began before exact USER teardown completed",
            ));
        }
        let receipt = self.window_abort_receipt.clone().ok_or_else(|| {
            wave_invariant("WAVE logical source retirement has no cached USER abort receipt")
        })?;
        if !self.wave_audio.producers_quiesced {
            return Err(wave_invariant(
                "WAVE native source retirement began before producer quiescence",
            ));
        }
        super::native_shutdown::close_quiesced_wave_devices(self, memory, host)?;
        super::native_shutdown::validate_quiescent_wave_sources(self)?;
        drain_wave_notifications_for_shutdown(self, &receipt, host)?;
        if self.wave_audio.pending_callbacks.iter().any(|pending| {
            matches!(pending.route, WaveCallbackRoute::Function { .. })
        }) {
            return Err(wave_invariant(
                "WAVE function sources remain after central callback retirement",
            ));
        }
        if !self.wave_audio.pending_callbacks.is_empty()
            || !self.wave_audio.devices.is_empty()
            || !self.wave_audio.headers.is_empty()
            || !self.wave_audio.pending_host_events.is_empty()
        {
            return Err(wave_cleanup_pending("exact WAVE source and header retirement"));
        }
        host.win16_wave_cleanup()?;
        self.wave_audio.cleanup_complete = true;
        Ok(())
    }

    /// Consume one exact source receipt only after its target is known to have
    /// ended. This is separate from successful USER sidecar transfer.
    pub(in crate::win16_runtime) fn cancel_pending_wave_notification(
        &mut self,
        notification_id: u64,
        reason: WaveCallbackCancellationReason,
    ) -> Result<(), RuntimeError> {
        let index = self
            .wave_audio
            .pending_callbacks
            .iter()
            .position(|pending| pending.notification_id == notification_id)
            .ok_or_else(|| wave_invariant("WAVE cancellation names no pending source receipt"))?;
        let pending = self
            .wave_audio
            .pending_callbacks
            .get(index)
            .ok_or_else(|| wave_invariant("WAVE cancellation index disappeared"))?;
        match reason {
            WaveCallbackCancellationReason::OwnerTerminatedAfterProducerQuiescence(proof)
                if proof.callback_id.is_none()
                    && matches!(pending.dispatch,
                        WaveCallbackDispatchState::Available
                            | WaveCallbackDispatchState::CallbackUnavailable
                            | WaveCallbackDispatchState::CallbackRetired(_))
                    && self.wave_producer_quiescence_matches(pending, proof) => {}
            WaveCallbackCancellationReason::OwnerTerminatedAfterProducerQuiescence(_) => {
                return Err(wave_invariant(
                    "WAVE owner cancellation lacks an exact post-quiescence source receipt",
                ));
            }
            WaveCallbackCancellationReason::UserNotificationRetired(proof)
                if self.wave_user_source_retirement_matches(pending, proof) => {}
            WaveCallbackCancellationReason::UserNotificationRetired(_) => {
                return Err(wave_invariant(
                    "WAVE USER source cancellation lacks an exact native and terminal receipt",
                ));
            }
            WaveCallbackCancellationReason::TargetRetired
                if matches!(
                    pending.route,
                    WaveCallbackRoute::Window { .. } | WaveCallbackRoute::Task { .. }
                ) && pending.dispatch == WaveCallbackDispatchState::Available
                    && pending.post_attempt.is_none()
                    && self.wave_user_target_is_retired(pending) => {}
            WaveCallbackCancellationReason::TargetRetired => {
                return Err(wave_invariant(
                    "WAVE target-retirement cancellation names a non-USER callback",
                ));
            }
            WaveCallbackCancellationReason::UserPostRejected
                if matches!(pending.route,
                    WaveCallbackRoute::Window { .. } | WaveCallbackRoute::Task { .. })
                    && pending.post_attempt.as_ref().is_some_and(|attempt| {
                        window_post_attempt_consumed(attempt)
                            && window_post_attempt_result(attempt) == Some(false)
                    }) => {}
            WaveCallbackCancellationReason::UserPostRejected => {
                return Err(wave_invariant(
                    "WAVE USER rejection lacks its exact consumed normal POST result",
                ));
            }
            WaveCallbackCancellationReason::CallbackAbortedAfterProducerQuiescence {
                proof,
                retirement,
            } if proof.callback_id == Some(retirement.callback_id)
                && retirement.source_bound
                && retirement.callback_token == proof.callback.callback
                && pending.dispatch == WaveCallbackDispatchState::CallbackRunning(retirement.callback_id)
                && self.wave_producer_quiescence_matches(pending, proof) => {}
            WaveCallbackCancellationReason::CallbackAbortedAfterProducerQuiescence { .. } => {
                return Err(wave_invariant(
                    "WAVE callback abort lacks an exact source, frame, or producer-close proof",
                ));
            }
        }
        if let WaveCallbackCancellationReason::CallbackAbortedAfterProducerQuiescence {
            retirement,
            ..
        } = reason
        {
            // The source owner can acknowledge an aborted callback only after
            // the central scheduler has retained and matched its exact
            // terminal identity. Leave the WAVE row live if that check fails.
            self.complete_asynchronous_source_retirement(
                retirement.callback_id,
                retirement.callback_token,
            )?;
        }
        let pending = self
            .wave_audio
            .pending_callbacks
            .remove(index)
            .ok_or_else(|| wave_invariant("WAVE source receipt disappeared during cancellation"))?;
        if let Some(device) = self.wave_audio.devices.iter().find(|device| {
            device.host.0 == pending.source.id
                && device.generation == pending.source.generation
        }).map(|device| device.host) {
            self.retire_unprepared_wave_header_if_idle(
                device,
                pending.source.generation,
                pending.guest_handle,
                pending.header_far,
            );
        }
        let mut retire_device = pending.closed_device;
        match reason {
            WaveCallbackCancellationReason::OwnerTerminatedAfterProducerQuiescence(proof) => {
                retire_device = Some(proof.device);
            }
            WaveCallbackCancellationReason::UserNotificationRetired(proof) => {
                retire_device = Some(proof.device());
            }
            WaveCallbackCancellationReason::CallbackAbortedAfterProducerQuiescence {
                proof,
                ..
            } => {
                retire_device = Some(proof.device);
            }
            WaveCallbackCancellationReason::UserPostRejected => {}
            WaveCallbackCancellationReason::TargetRetired => {}
        }
        if let Some(device) = retire_device {
            self.retire_quiescent_wave_device_if_idle(device);
        }
        Ok(())
    }

    /// A successfully unprepared WAVEHDR remains pinned while any native
    /// callback source still names its FAR. Drop that lease only after the
    /// exact source row has been retired.
    pub(super) fn retire_unprepared_wave_header_if_idle(
        &mut self,
        device: Win16HostWaveDevice,
        device_generation: u64,
        guest_handle: u16,
        header_far: u32,
    ) {
        if header_far == 0 {
            return;
        }
        let mut matching = self.wave_audio.headers.iter().enumerate().filter(|(_, record)| {
            record.guest_handle == guest_handle && record.header_far == header_far
        });
        let Some((index, record)) = matching.next() else {
            return;
        };
        if matching.next().is_some()
            || record.host_device != device
            || !self.wave_audio.devices.iter().any(|device| {
                device.host == record.host_device && device.generation == device_generation
            })
            || record.native_prepared
            || record.guest_prepared
            || record.submission.is_some()
            || self.wave_audio.pending_callbacks.iter().any(|pending| {
                pending.source.id == device.0
                    && pending.source.generation == device_generation
                    && pending.guest_handle == guest_handle
                    && pending.header_far == header_far
            })
        {
            return;
        }
        self.wave_audio.headers.remove(index);
        }
    }

/// FUNCTION source rows remain owned until the native reaper receipt proves
/// this device generation quiescent. An entered guest callback is left for
/// the exact asynchronous scheduler retirement path.
fn drain_wave_notifications_for_shutdown(
    state: &mut Win16State,
    abort: &crate::Win16WindowAbortReceipt,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let current_owner = state.tasks.current();
    let pending_count = state.wave_audio.pending_callbacks.len();
    for _ in 0..pending_count {
        let Some(mut pending) = state.wave_audio.pending_callbacks.front().cloned() else {
            break;
        };
        match pending.dispatch {
            WaveCallbackDispatchState::RollbackRetained(id)
            | WaveCallbackDispatchState::SourceReleasePending(id) => {
                state.retry_wave_pre_entry_cleanup(id)?;
                let Some(updated) = state.wave_audio.pending_callbacks.front().cloned() else {
                    return Err(wave_invariant("WAVE rollback source disappeared during retry"));
                };
                pending = updated;
            }
            WaveCallbackDispatchState::CallbackRunning(_) => {
                rotate_pending_wave_notification(state, pending.notification_id)?;
                continue;
            }
            WaveCallbackDispatchState::Reserved => return Err(wave_invariant(
                "WAVE callback reservation escaped its pre-entry transaction",
            )),
            WaveCallbackDispatchState::Available
            | WaveCallbackDispatchState::CallbackUnavailable
            | WaveCallbackDispatchState::CallbackRetired(_) => {}
        }
        if pending.post_attempt.is_some() {
            if pending.dispatch != WaveCallbackDispatchState::Available {
                return Err(wave_invariant(
                    "WAVE cached normal POST proof is attached to a non-available source",
                ));
            }
            let posted = {
                let front = state.wave_audio.pending_callbacks.front_mut().ok_or_else(|| {
                    wave_invariant("WAVE normal POST source disappeared during shutdown")
                })?;
                if front.notification_id != pending.notification_id
                    || front.source != pending.source
                {
                    return Err(wave_invariant(
                        "WAVE shutdown changed the exact cached POST source",
                    ));
                }
                let attempt = front.post_attempt.as_mut().ok_or_else(|| {
                    wave_invariant("WAVE shutdown lost the cached normal POST attempt")
                })?;
                super::super::window_post::consume_window_post_attempt(host, attempt)?
            };
            if posted {
                let retired = state.wave_audio.pending_callbacks.pop_front().ok_or_else(|| {
                    wave_invariant("WAVE posted source disappeared after proof consumption")
                })?;
                if retired.notification_id != pending.notification_id
                    || retired.source != pending.source
                {
                    state.wave_audio.pending_callbacks.push_front(retired);
                    return Err(wave_invariant(
                        "WAVE shutdown retired a different cached POST source",
                    ));
                }
                super::user_posts::retire_posted_close(state, retired);
            } else {
                state.cancel_pending_wave_notification(
                    pending.notification_id,
                    WaveCallbackCancellationReason::UserPostRejected,
                )?;
            }
            continue;
        }
        match pending.route {
            WaveCallbackRoute::Function { callback, task } => {
                let source_receipt = WaveCallbackReceipt {
                    notification_id: pending.notification_id,
                    source: pending.source,
                    callback,
                    task,
                };
                let quiescent = state.wave_audio.devices.iter().any(|device| {
                    device.host.0 == pending.source.id
                        && device.generation == pending.source.generation
                        && device.producer_quiescence_sequence.is_some()
                });
                if quiescent {
                    if let Some(proof) = state.wave_producer_quiescence_receipt(
                        source_receipt,
                        None,
                    )? {
                        state.cancel_pending_wave_notification(
                            pending.notification_id,
                            WaveCallbackCancellationReason::OwnerTerminatedAfterProducerQuiescence(proof),
                        )?;
                        continue;
                    }
                }
                if current_owner != Some(task.owner)
                    || state.current_task_handle().ok() != Some(task.guest_htask)
                    || !state.wave_task_identity_is_live(task)
                {
                    rotate_pending_wave_notification(state, pending.notification_id)?;
                    continue;
                }
                // Teardown does not enter a fresh guest callback. Close the
                // host source first; a later exact Quiescent receipt will
                // authorize cancellation of this still-available row.
                rotate_pending_wave_notification(state, pending.notification_id)?;
            }
            WaveCallbackRoute::Task { .. } | WaveCallbackRoute::Window { .. } => {
                let proof = state
                    .wave_user_source_retirement_receipt(&pending, abort)?
                    .ok_or_else(|| {
                        wave_cleanup_pending(
                            "exact USER abort, WAVE quiescence, and terminal POST ACK proof",
                        )
                    })?;
                state.cancel_pending_wave_notification(
                    pending.notification_id,
                    WaveCallbackCancellationReason::UserNotificationRetired(proof),
                )?;
            }
        }
    }
    Ok(())
}

fn rotate_pending_wave_notification(
    state: &mut Win16State,
    notification_id: u64,
) -> Result<(), RuntimeError> {
    let pending = state
        .wave_audio
        .pending_callbacks
        .pop_front()
        .ok_or_else(|| wave_invariant("WAVE notification disappeared during teardown"))?;
    if pending.notification_id != notification_id {
        state.wave_audio.pending_callbacks.push_front(pending);
        return Err(wave_invariant(
            "WAVE notification order changed during teardown rotation",
        ));
    }
    state.wave_audio.pending_callbacks.push_back(pending);
    Ok(())
}

pub(super) fn unprepare_for_cleanup(
    state: &mut Win16State,
    record: &WaveHeaderRecord,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    let result = host.win16_wave(Win16HostWaveOperation::Unprepare {
        device: record.host_device,
        buffer: record.host_buffer,
    })?;
    let Win16HostWaveResult::Header {
        result,
        buffer,
        submission,
        completion_pending,
        state: header_state,
        input_bytes,
    } = result
    else {
        return Err(wave_invariant("WAVE unprepare returned the wrong result"));
    };
    if buffer != Some(record.host_buffer) {
        return Err(wave_invariant(
            "WAVE cleanup unprepare changed its native header identity",
        ));
    }
    if result != MMSYSERR_NOERROR {
        if completion_pending || input_bytes.is_some() {
            return Err(wave_invariant(
                "failed WAVE cleanup unprepare returned completion output",
            ));
        }
        return Ok(result);
    }
    if header_state.is_none() {
        return Err(wave_invariant(
            "successful WAVE cleanup unprepare omitted native header state",
        ));
    }
    if record.submission.is_some() {
        if submission != record.submission || submission.is_none() || !completion_pending {
            return Err(wave_invariant(
                "WAVE cleanup unprepare lost its pending completion",
            ));
        }
        let Some(header_state) = header_state else {
            return Err(wave_invariant(
                "WAVE cleanup unprepare omitted native header state",
            ));
        };
        if header_state.flags & WHDR_DONE == 0
            || header_state.bytes_recorded > record.queued_length
            || (record.direction == Win16WaveDirection::Input
                && input_bytes
                    .as_ref()
                    .is_none_or(|bytes| bytes.len() != header_state.bytes_recorded as usize))
            || (record.direction == Win16WaveDirection::Output && input_bytes.is_some())
        {
            return Err(wave_invariant(
                "WAVE cleanup unprepare returned invalid completed state",
            ));
        }
        if let Some(current) = state
            .wave_audio
            .headers
            .iter_mut()
            .find(|current| current.host_buffer == record.host_buffer)
        {
            current.native_prepared = false;
            current.guest_prepared = false;
            current.native_queued = false;
            current.unprepare_state = Some(header_state);
            current.completion_projection = WaveCompletionProjection::Suppressed;
        }
        state.poll_wave_events(memory, host, true)?;
    } else {
        if submission.is_some() || completion_pending || input_bytes.is_some() {
            return Err(wave_invariant(
                "idle WAVE cleanup unprepare returned completion state",
            ));
        }
        let current = state.wave_audio.headers.iter_mut()
            .find(|current| current.host_buffer == record.host_buffer)
            .ok_or_else(|| wave_invariant(
                "WAVE header disappeared after successful native unprepare",
            ))?;
        current.native_prepared = false;
        current.guest_prepared = false;
        current.native_queued = false;
        current.unprepare_state = header_state;
        current.completion_projection = WaveCompletionProjection::Suppressed;
    }
    Ok(MMSYSERR_NOERROR)
}

#[derive(Debug)]
struct WaveCleanupMmResult(u32);

impl fmt::Display for WaveCleanupMmResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WinMM returned MMRESULT {}", self.0)
    }
}

impl Error for WaveCleanupMmResult {}

#[derive(Debug)]
struct WaveCleanupPending(&'static str);

impl fmt::Display for WaveCleanupPending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "waiting for {}", self.0)
    }
}

impl Error for WaveCleanupPending {}

pub(super) fn wave_cleanup_error(operation: &'static str, result: u32) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        format!("Win16 WAVE {operation} cleanup failed"),
        WaveCleanupMmResult(result),
    )
}

fn wave_cleanup_pending(source: &'static str) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        "Win16 WAVE native ownership has not reached its completion boundary",
        WaveCleanupPending(source),
    )
}
