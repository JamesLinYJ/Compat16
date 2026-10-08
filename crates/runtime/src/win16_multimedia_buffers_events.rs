//! Consume exact native WAVE events into guest state and notification receipts.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn poll_wave_events(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        deliver_callbacks: bool,
    ) -> Result<(), RuntimeError> {
        for _ in 0..MAX_WAVE_EVENTS_PER_POLL {
            if let Some(mut event) = self.wave_audio.pending_host_events.pop_front() {
                if let Err(error) = self.consume_wave_event(&mut event, memory, deliver_callbacks) {
                    self.wave_audio.pending_host_events.push_front(event);
                    return Err(error);
                }
                continue;
            }
            self.wave_audio
                .pending_host_events
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve WAVE host event queue",
                        error,
                    )
                })?;
            let Some(event) = host.win16_wave_poll()? else {
                return Ok(());
            };
            self.wave_audio.pending_host_events.push_back(event);
        }
        // Revisit a busy producer at the next safe point so one poll never
        // monopolizes guest execution while native completions arrive.
        Ok(())
    }

    fn consume_wave_event(
        &mut self,
        event: &mut Win16HostWaveEvent,
        memory: &mut Memory,
        deliver_callbacks: bool,
    ) -> Result<(), RuntimeError> {
        let event_sequence = event.sequence;
        let is_close_event = matches!(&event.kind, Win16HostWaveEventKind::Close);
        let quiescence_close_sequence = match &event.kind {
            Win16HostWaveEventKind::Quiescent { close_sequence } => Some(*close_sequence),
            _ => None,
        };
        let device_index = self
            .wave_audio
            .devices
            .iter()
            .position(|record| record.host == event.device);
        let Some(device_index) = device_index else {
            // Only a retained device generation can consume its event; an
            // absent table entry cannot stand in for a reaper receipt.
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "WAVE host event has no retained device generation",
            ));
        };
        let device = self.wave_audio.devices[device_index];
        match &mut event.kind {
            Win16HostWaveEventKind::Open => {
                if let Some(callback) = device.callback.filter(|_| deliver_callbacks) {
                    self.queue_wave_callback(
                        callback,
                        device.guest_handle,
                        device.instance,
                        wave_message(device.direction, true),
                        0,
                        None,
                        None,
                        device.host,
                        event_sequence,
                    )?;
                }
            }
            Win16HostWaveEventKind::Close => {
                if let Some(callback) = device.callback.filter(|_| deliver_callbacks) {
                    self.queue_wave_callback(
                        callback,
                        device.guest_handle,
                        device.instance,
                        wave_message(device.direction, false),
                        0,
                        None,
                        Some(device.host),
                        device.host,
                        event_sequence,
                    )?;
                } else {
                    // Native Close does not prove producer quiescence. Retain
                    // this exact generation until the later host receipt.
                }
            }
            Win16HostWaveEventKind::Quiescent { close_sequence } => {
                let current = &self.wave_audio.devices[device_index];
                if !current.closing
                    || current.close_event_sequence != Some(*close_sequence)
                    || current.last_received_sequence != *close_sequence
                    || event_sequence <= *close_sequence
                {
                    return Err(wave_invariant(
                        "WAVE quiescence receipt does not follow this device generation's Close event",
                    ));
                }
            }
            Win16HostWaveEventKind::Completed(completion) => {
                let (buffer, submission, header) =
                    (completion.buffer, completion.submission, completion.header);
                let input_bytes = &completion.input_bytes;
                let Some(index) = self.wave_audio.headers.iter().position(|record| {
                    record.host_device == event.device && record.host_buffer == buffer
                }) else {
                    return Err(wave_invariant("WAVE completion has no prepared header"));
                };
                let record = self.wave_audio.headers[index].clone();
                if record.submission != Some(submission) {
                    return Err(wave_invariant(
                        "WAVE completion does not match the active header submission",
                    ));
                }
                if header.bytes_recorded > record.queued_length
                    || input_bytes.len() > record.capacity as usize
                    || (record.direction == Win16WaveDirection::Input
                        && input_bytes.len() != header.bytes_recorded as usize)
                    || (record.direction == Win16WaveDirection::Output && !input_bytes.is_empty())
                {
                    return Err(wave_invariant(
                        "native WAVE completion exceeded its prepared buffer",
                    ));
                }
                let projection = record.completion_projection;
                if let WaveCompletionProjection::Committed(projected) = projection {
                    if projected != header {
                        return Err(wave_invariant(
                            "WAVE completion changed state after successful unprepare",
                        ));
                    }
                }
                if deliver_callbacks && projection == WaveCompletionProjection::Pending {
                    self.validate_header_record_ranges(&record, memory)?;
                    let current = record.header_range.read(self, memory)?;
                    let current = Win16WaveHeader16::decode(&current).ok_or_else(|| {
                        wave_invariant("WAVE completion header changed fixed size")
                    })?;
                    if current.data != record.data_far
                        || current.buffer_length != record.queued_length
                    {
                        return Err(RuntimeError::new(
                            Kind::GuestFault,
                            "Win16 WAVE header address or length changed while queued",
                        ));
                    }
                    self.commit_header_state(
                        memory,
                        buffer,
                        header,
                        (record.direction == Win16WaveDirection::Input)
                            .then_some(input_bytes.as_slice()),
                    )?;
                }
                if deliver_callbacks {
                    if let Some(callback) = device.callback {
                        self.queue_wave_callback(
                            callback,
                            device.guest_handle,
                            device.instance,
                            wave_completion_message(device.direction),
                            record.header_far,
                            Some(record.header_range.start().selector().generation()),
                            None,
                            device.host,
                            event_sequence,
                        )?;
                    }
                }
                if let Some(current) = self.wave_audio.headers.get_mut(index) {
                    current.native_queued = false;
                    current.submission = None;
                    current.unprepare_state = None;
                    current.unprepare_input_bytes = None;
                    current.completion_projection = if deliver_callbacks {
                        match projection {
                            WaveCompletionProjection::Pending => {
                                WaveCompletionProjection::Committed(header)
                            }
                            other => other,
                        }
                    } else {
                        WaveCompletionProjection::Suppressed
                    };
                }
                let callback_source_retained = self.wave_audio.pending_callbacks.iter().any(|pending| {
                    pending.source.id == device.host.0
                        && pending.source.generation == device.generation
                        && pending.source.sequence == event_sequence
                        && pending.guest_handle == record.guest_handle
                        && pending.header_far == record.header_far
                });
                if !record.guest_prepared && !callback_source_retained {
                    self.wave_audio.headers.remove(index);
                }
            }
        }
        if let Some(record) = self
            .wave_audio
            .devices
            .iter_mut()
            .find(|record| record.host == event.device)
        {
            if event_sequence <= record.last_received_sequence {
                return Err(wave_invariant(
                    "WAVE host event sequence moved backwards for one device generation",
                ));
            }
            record.last_received_sequence = event_sequence;
            if is_close_event {
                record.close_event_sequence = Some(event_sequence);
            }
            if quiescence_close_sequence.is_some() {
                record.producer_quiescence_sequence = Some(event_sequence);
            }
        }
        if quiescence_close_sequence.is_some() {
            self.retire_quiescent_wave_device_if_idle(event.device);
        }
        Ok(())
    }

    fn queue_wave_callback(
        &mut self,
        route: WaveCallbackRoute,
        guest_handle: u16,
        instance: u32,
        message: u16,
        header_far: u32,
        header_selector_generation: Option<u64>,
        closed_device: Option<Win16HostWaveDevice>,
        source_device: Win16HostWaveDevice,
        source_sequence: u64,
    ) -> Result<(), RuntimeError> {
        let notification_id = self.wave_audio.allocate_notification_id()?;
        let device_generation = self
            .wave_audio
            .devices
            .iter()
            .find(|device| device.host == source_device)
            .map(|device| device.generation)
            .ok_or_else(|| wave_invariant(
                "WAVE notification source device lost its generation",
            ))?;
        self.wave_audio
            .pending_callbacks
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 WAVE callback queue",
                    error,
                )
            })?;
        self.wave_audio
            .pending_callbacks
            .push_back(PendingWaveCallback {
                notification_id,
                // Device tokens are never reused; the native sequence stays
                // stable if callback or USER delivery needs to be retried.
                source: Win16GuestNotificationSource {
                    id: source_device.0,
                    generation: device_generation,
                    sequence: source_sequence,
                },
                route,
                guest_handle,
                instance,
                message,
                header_far,
                header_selector_generation,
                closed_device,
                dispatch: WaveCallbackDispatchState::Available,
                post_failure: None,
                post_attempt: None,
                terminal_producer_proof: None,
                terminal_ack: None,
                terminal_acknowledged: false,
            });
        Ok(())
    }
}
