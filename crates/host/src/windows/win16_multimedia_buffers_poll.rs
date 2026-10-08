//! Poll native callback signals and actual WAVEHDR completion state.

use super::*;

#[derive(Clone, Copy)]
enum SignalKind {
    Open,
    Close,
    Completed(usize),
}

pub(super) fn poll_callback_signal(
    host: &mut Win16WaveHost,
) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
    let mut selected: Option<(
        u64,
        usize,
        SignalKind,
        Option<Win16HostWaveSubmission>,
        Win16HostWaveHeaderState,
    )> = None;
    for (device_index, device) in host.devices.iter().enumerate() {
        let Some(callback) = device.callback.as_ref() else {
            continue;
        };
        if let Some((sequence, submission, state)) = callback.open_signal().peek() {
            select_signal(
                &mut selected,
                sequence,
                device_index,
                SignalKind::Open,
                submission,
                state,
            );
        }
        if let Some((sequence, submission, state)) = callback.close_signal().peek() {
            select_signal(
                &mut selected,
                sequence,
                device_index,
                SignalKind::Close,
                submission,
                state,
            );
        }
        for (buffer_index, buffer) in device.buffers.iter().enumerate() {
            if let Some((sequence, submission, state)) = buffer.signal.peek() {
                select_signal(
                    &mut selected,
                    sequence,
                    device_index,
                    SignalKind::Completed(buffer_index),
                    submission,
                    state,
                );
            }
        }
    }
    let Some((sequence, device_index, kind, submission, _signal_state)) = selected else {
        return Ok(None);
    };
    if host.devices[device_index]
        .callback
        .as_ref()
        .is_some_and(|callback| callback.active_callbacks() != 0)
    {
        return Ok(None);
    }
    let event =
        {
            let device = &mut host.devices[device_index];
            match kind {
                SignalKind::Open => {
                    if submission.is_some() {
                        return Err(wave_invariant("WAVE open signal carried a submission"));
                    }
                    let context = device.callback.as_ref().ok_or_else(|| {
                        wave_invariant("WAVE open signal lost its callback owner")
                    })?;
                    if !context.open_signal().consume(sequence) {
                        return Ok(None);
                    }
                    wave_event(device, sequence, Win16HostWaveEventKind::Open)
                }
                SignalKind::Close => {
                    if submission.is_some() {
                        return Err(wave_invariant("WAVE close signal carried a submission"));
                    }
                    // WOM_CLOSE is consumed only after its exact event has
                    // queue capacity, because the callback signal cannot be
                    // replayed after this point.
                    host.pending_wave_events.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "retain native WAVE Close before consuming its callback signal",
                            error,
                        )
                    })?;
                    let context = device.callback.as_ref().ok_or_else(|| {
                        wave_invariant("WAVE close signal lost its callback owner")
                    })?;
                    if !context.close_signal().consume(sequence) {
                        return Ok(None);
                    }
                    device.close_event_delivered = true;
                    device.close_event_sequence = Some(sequence);
                    wave_event(device, sequence, Win16HostWaveEventKind::Close)
                }
                SignalKind::Completed(buffer_index) => {
                    let direction = device.direction;
                    let submission = submission.ok_or_else(|| {
                        wave_invariant("WAVE completion signal omitted its submission")
                    })?;
                    let (buffer_token, state, input_bytes) = {
                        let Some(buffer) = device.buffers.get_mut(buffer_index) else {
                            return Err(wave_invariant("WAVE completion signal lost its buffer"));
                        };
                        if buffer.active_submission != Some(submission) {
                            return Err(wave_invariant(
                                "WAVE completion belongs to a retired submission",
                            ));
                        }
                        // Unprepare may succeed after WinMM has signalled WOM_DONE
                        // but before this mailbox is drained. Read the stable
                        // header on the owner thread after the callback has returned,
                        // so completion reflects post-unprepare flags without a
                        // callback-thread read racing the native API.
                        let state =
                            unsafe { callback::header_state(ptr::addr_of!(buffer.storage.header)) };
                        let input_bytes = native::completed_input_bytes(direction, buffer, state)?;
                        if !buffer.signal.consume(sequence) {
                            return Ok(None);
                        }
                        buffer.in_flight = false;
                        buffer.active_submission = None;
                        buffer.signal.disarm_submission();
                        (buffer.token, state, input_bytes)
                    };
                    wave_event(
                        device,
                        sequence,
                        Win16HostWaveEventKind::Completed(runtime::Win16HostWaveCompletion {
                            buffer: buffer_token,
                            submission,
                            header: state,
                            input_bytes,
                        }),
                    )
                }
            }
        };
    if matches!(kind, SignalKind::Close) {
        // The queue now owns the exact Close event. If reaping cannot publish
        // Quiescent, the committed Close remains available for normal polling.
        super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
        reap_closed_devices(host)?;
        reap_retired_buffers(host);
        return Ok(None);
    }
    reap_retired_buffers(host);
    Ok(Some(event))
}

pub(super) fn poll_native_completion(
    host: &mut Win16WaveHost,
) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
    let event_sequences = Arc::clone(&host.event_sequences);
    for device in &mut host.devices {
        let direction = device.direction;
        let completed = if device.callback_function {
            None
        } else {
            let mut completed = None;
            for buffer in &mut device.buffers {
                let Some(submission) = buffer.active_submission else {
                    continue;
                };
                // SAFETY: the native owner retains the stable header allocation
                // while this exact submission is active, including after a
                // successful UnprepareHeader until its completion source is read.
                let state = unsafe { callback::header_state(ptr::addr_of!(buffer.storage.header)) };
                if state.flags & WHDR_INQUEUE != 0 || state.flags & WHDR_DONE == 0 {
                    continue;
                }
                let input_bytes = native::completed_input_bytes(direction, buffer, state)?;
                let sequence = allocate_event_sequence(&event_sequences)?;
                buffer.in_flight = false;
                buffer.active_submission = None;
                buffer.signal.disarm_submission();
                completed = Some((sequence, buffer.token, submission, state, input_bytes));
                break;
            }
            completed
        };
        if let Some((sequence, buffer, submission, state, input_bytes)) = completed {
            return Ok(Some(wave_event(
                device,
                sequence,
                Win16HostWaveEventKind::Completed(runtime::Win16HostWaveCompletion {
                    buffer,
                    submission,
                    header: state,
                    input_bytes,
                }),
            )));
        }
        // CALLBACK_NULL has no driver callback to signal WOM_CLOSE. Synthesize
        // that guest-facing source only after every accepted header completion
        // has been observed from the actual native WHDR state.
        let native_headers_pending = device.buffers.iter().any(|buffer| {
            buffer.in_flight || buffer.active_submission.is_some() || buffer.signal.peek().is_some()
        });
        if device.closing
            && !device.close_event_delivered
            && !device.callback_function
            && !native_headers_pending
        {
            let sequence = allocate_event_sequence(&event_sequences)?;
            device.close_event_delivered = true;
            device.close_event_sequence = Some(sequence);
            return Ok(Some(wave_event(
                device,
                sequence,
                Win16HostWaveEventKind::Close,
            )));
        }
    }
    reap_closed_devices(host)?;
    Ok(None)
}

pub(super) fn reap_closed_devices(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    let event_sequences = Arc::clone(&host.event_sequences);
    let mut index = 0;
    while index < host.devices.len() {
        let ready = {
            let device = &host.devices[index];
            let callback = device.callback.as_ref();
            let callbacks_active = callback.is_some_and(|context| context.active_callbacks() != 0);
            let callback_signals_pending = callback.is_some_and(|context| {
                context.open_signal().peek().is_some()
                    || context.close_signal().peek().is_some()
            });
            device.closing
                && device.native_closed
                && device.close_event_delivered
                && device.close_event_sequence.is_some()
                && !callbacks_active
                && !callback_signals_pending
                && !device.buffers.iter().any(|buffer| {
                    buffer.prepared
                        || buffer.in_flight
                        || buffer.active_submission.is_some()
                        || buffer.signal.peek().is_some()
                })
        };
        if !ready {
            index += 1;
            continue;
        }
        let close_sequence = host.devices[index]
            .close_event_sequence
            .ok_or_else(|| wave_invariant("reaped WAVE device lost its Close event sequence"))?;
        // The receipt survives the native-owner removal. Reserve it before
        // releasing the handle so failed storage keeps the entire device
        // owner live for a later exact retry.
        host.pending_wave_events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain exact WAVE producer-quiescence receipt",
                error,
            )
        })?;
        let receipt_sequence = allocate_event_sequence(&event_sequences)?;
        let receipt = wave_event(
            &host.devices[index],
            receipt_sequence,
            Win16HostWaveEventKind::Quiescent { close_sequence },
        );
        retired::release_device_reservation(&mut host.devices[index])?;
        super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, receipt);
        host.devices.swap_remove(index);
    }
    Ok(())
}

pub(super) fn reap_retired_buffers(host: &mut Win16WaveHost) {
    for device in &mut host.devices {
        let callback = device.callback.as_ref();
        let callback_active = callback.is_some_and(|context| context.active_callbacks() != 0);
        device.buffers.retain(|buffer| {
            if buffer.prepared
                || buffer.in_flight
                || buffer.active_submission.is_some()
                || buffer.signal.peek().is_some()
                || callback_active
            {
                return true;
            }
            if let Some(callback) = callback {
                callback.unregister_header(ptr::addr_of!(buffer.storage.header) as usize);
            }
            false
        });
    }
}

fn select_signal(
    selected: &mut Option<(
        u64,
        usize,
        SignalKind,
        Option<Win16HostWaveSubmission>,
        Win16HostWaveHeaderState,
    )>,
    sequence: u64,
    device: usize,
    kind: SignalKind,
    submission: Option<Win16HostWaveSubmission>,
    state: Win16HostWaveHeaderState,
) {
    if selected.is_none_or(|current| sequence < current.0) {
        *selected = Some((sequence, device, kind, submission, state));
    }
}

fn wave_event(
    device: &WaveDevice,
    sequence: u64,
    kind: Win16HostWaveEventKind,
) -> Win16HostWaveEvent {
    Win16HostWaveEvent {
        device: device.token,
        sequence,
        kind,
    }
}

fn allocate_event_sequence(source: &AtomicU64) -> Result<u64, RuntimeError> {
    source
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |next| {
            (next != 0 && next != u64::MAX).then_some(next + 1)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "WinMM callback sequence space is exhausted",
            )
        })
}
