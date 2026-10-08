//! MIDI owner teardown with exact native close and callback receipts.

use guest_core::memory::Memory;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMidiCancellationReason, Win16HostMidiDirection,
    Win16HostMidiNotificationDisposition as Disposition,
    Win16HostMidiProducerOwner as ProducerOwner};

use super::{MidiHeaderRecord, Win16State};

const CLOSE_DRAIN_LIMIT: Duration = Duration::from_millis(250);
const MM_MIM_LONGDATA: u32 = 0x03c4;
const MM_MIM_LONGERROR: u32 = 0x03c6;
const MM_MOM_CLOSE: u32 = 0x03c8;
const MM_MOM_DONE: u32 = 0x03c9;
const MM_MIM_CLOSE: u32 = 0x03c2;

impl Win16State {
    /// Cache real Reset results for every host registry owner before USER
    /// teardown. This stops producers while retaining all handles, callback
    /// registrations, prepared headers, and runtime selector leases.
    pub(in crate::win16_runtime) fn quiesce_midi_producers(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.midi.producers_quiesced {
            return Ok(());
        }
        let snapshot = host.win16_midi_quiesce_all()?;
        let reported = snapshot.devices.len().checked_add(snapshot.failures.len())
            .ok_or_else(|| midi_invariant("MIDI producer owner count overflowed"))?;
        if snapshot.observed_owner_count != reported {
            return Err(midi_invariant(
                "MIDI producer snapshot omitted or duplicated a native registry owner",
            ));
        }

        let mut owners = BTreeSet::new();
        let mut failures = None;
        for receipt in &snapshot.devices {
            let device = receipt.device;
            if device.token == 0 || device.generation == 0 || !owners.insert(device) {
                return Err(midi_invariant(
                    "MIDI producer receipt changed or duplicated its exact device generation",
                ));
            }
            match receipt.owner {
                ProducerOwner::GuestPublished { direction, callback_instance } => {
                    let matches = self.midi.devices.iter().filter(|record| {
                        record.host == device && record.direction == direction
                            && record.instance == callback_instance
                    }).count();
                    if matches != 1 {
                        return Err(midi_invariant(
                            "published MIDI producer receipt has no unique runtime owner",
                        ));
                    }
                    let record = self.midi.devices.iter_mut().find(|record| record.host == device)
                        .ok_or_else(|| midi_invariant(
                            "published MIDI producer owner disappeared after exact match",
                        ))?;
                    match (receipt.reset_result, receipt.close_result) {
                        (Some(0), None) if !record.closing && record.close_result.is_none() => {
                            record.reset_result = Some(0);
                        }
                        (Some(0), Some(0))
                            if record.closing && record.close_result == Some(0) =>
                        {
                            record.reset_result = Some(0);
                        }
                        (None, Some(0)) if record.closing && record.close_result == Some(0) => {}
                        _ => return Err(midi_invariant(
                            "MIDI producer receipt lacks exact successful Reset or Close stages",
                        )),
                    }
                }
                ProducerOwner::Unpublished { direction: _, callback_instance: _ } => {
                    if self.midi.devices.iter().any(|record| record.host == device)
                        || self.midi.headers.iter().any(|header| header.host_device == device)
                        || self.midi.dispatching.as_ref().is_some_and(|dispatch|
                            dispatch.identity.device == device)
                        || self.midi.pending_cleanup.contains(&device)
                    {
                        return Err(midi_invariant(
                            "unpublished MIDI producer identity collides with a guest runtime owner",
                        ));
                    }
                    if !matches!(receipt.reset_result, Some(0))
                        && receipt.close_result != Some(0)
                    {
                        return Err(midi_invariant(
                            "unpublished MIDI owner has no successful producer barrier",
                        ));
                    }
                }
            }
        }

        for failure in &snapshot.failures {
            let device = failure.device;
            if device.token == 0 || device.generation == 0 || !owners.insert(device)
                || failure.reset_result == 0
            {
                return Err(midi_invariant(
                    "MIDI producer failure changed its exact generation or native result",
                ));
            }
            match failure.owner {
                ProducerOwner::GuestPublished { direction, callback_instance } => {
                    let matches = self.midi.devices.iter().filter(|record| {
                        record.host == device && record.direction == direction
                            && record.instance == callback_instance
                    }).count();
                    if matches != 1 {
                        return Err(midi_invariant(
                            "failed published MIDI Reset has no unique runtime owner",
                        ));
                    }
                    if let Some(record) = self.midi.devices.iter_mut()
                        .find(|record| record.host == device)
                    {
                        let _ = record.reset_failure_result
                            .get_or_insert(failure.reset_result);
                    }
                }
                ProducerOwner::Unpublished { .. } => {
                    if self.midi.devices.iter().any(|record| record.host == device)
                        || self.midi.headers.iter().any(|header| header.host_device == device)
                        || self.midi.dispatching.as_ref().is_some_and(|dispatch|
                            dispatch.identity.device == device)
                        || self.midi.pending_cleanup.contains(&device)
                    {
                        return Err(midi_invariant(
                            "unpublished MIDI Reset failure collides with a guest runtime owner",
                        ));
                    }
                }
            }
            remember_failure(&mut failures, midi_producer_reset_failure(failure));
        }

        if self.midi.devices.iter().any(|record| !owners.contains(&record.host)) {
            return Err(midi_invariant(
                "MIDI host producer snapshot omitted a published runtime device",
            ));
        }
        if self.midi.dispatching.as_ref().is_some_and(|dispatch| {
            !owners.contains(&dispatch.identity.device)
                || !self.midi.devices.iter().any(|device|
                    device.host == dispatch.identity.device
                        && device.guest == dispatch.guest_device)
        }) || self.midi.headers.iter().any(|header| {
            !owners.contains(&header.host_device)
                || !self.midi.devices.iter().any(|device|
                    device.host == header.host_device
                        && device.guest == header.guest_device)
        }) || self.midi.pending_cleanup.iter().any(|device| !owners.contains(device)) {
            return Err(midi_invariant(
                "MIDI producer snapshot omitted a retained dispatch, header, or close owner",
            ));
        }
        if let Some(error) = failures {
            self.midi.producers_quiesced = false;
            return Err(error);
        }
        if self.midi.devices.iter().any(|record| {
            record.close_result != Some(0) && record.reset_result != Some(0)
        }) {
            return Err(midi_invariant(
                "MIDI task producer barrier lacks a cached successful native stage",
            ));
        }
        self.midi.producers_quiesced = true;
        Ok(())
    }

    /// Close host devices, cancel queued guest notifications as owner teardown,
    /// and release mappings only after each exact native close event is ACKed.
    /// A bounded wait timeout preserves all unresolved mappings so cleanup can
    /// be entered again against the same token/generation receipts.
    pub(crate) fn close_all_midi(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.midi.cleanup_complete {
            return Ok(());
        }
        if !self.midi.producers_quiesced
            || self.window_teardown_state != super::super::WindowTeardownState::Closed
            || self.window_abort_receipt.is_none()
        {
            return Err(midi_invariant(
                "MIDI final source cleanup began before producer and USER terminal receipts",
            ));
        }
        self.retry_pending_midi_close_projections(memory, host)?;
        self.retry_midi_callback_start_cleanup()?;
        if self.callback_scheduler.has_active_midi_frame() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "MIDI owner teardown is waiting for an active guest callback frame"));
        }
        if let Some(pending) = self.midi.dispatching.clone() {
            if pending.post_accepted {
                // USER already accepted this exact source. Retry its delivery
                // ACK instead of reporting cancellation or posting it again.
                self.finish_midi_notification_target(host, pending.identity)?;
            } else if pending.post_attempt.is_some() {
                // A normal POST may already have returned while its exact USER
                // proof readback/consume or family ACK failed. Resume that same
                // receipt before considering terminal owner cancellation.
                self.resume_midi_user_post(host, pending.identity)?;
            } else {
                self.cancel_midi_notification_source(host, pending.identity,
                    Win16HostMidiCancellationReason::OwnerTerminated)?;
            }
        }

        let mut receipts = Vec::new();
        receipts.try_reserve_exact(self.midi.devices.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact MIDI close receipts before native shutdown", error)
        })?;
        let mut closed = host.win16_midi_close_all()?;
        let mut failures = None;
        let mut failure_devices = BTreeSet::new();
        for failure in &mut closed.failures {
            if failure.device.token == 0 || failure.device.generation == 0
                || !failure_devices.insert(failure.device)
            {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close failure duplicated or zeroed an exact device generation"));
                continue;
            }
            let known = self.midi.devices.iter().any(|device| device.host == failure.device);
            if let Some(record) = self.midi.devices.iter_mut()
                .find(|device| device.host == failure.device)
            {
                if let Some(result) = failure.reset_result {
                    if result == 0 {
                        record.reset_result = Some(0);
                    } else {
                        let _ = record.reset_failure_result.get_or_insert(result);
                    }
                }
                if failure.close_result == Some(0) {
                    record.close_result = Some(0);
                    record.closing = true;
                }
            }
            if known == failure.unpublished_owner {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close failure origin did not match its exact runtime owner"));
            }
            let has_native_failure = failure.reset_result.is_some_and(|result| result != 0)
                || failure.unprepare_result.is_some_and(|result| result != 0)
                || failure.close_result.is_some_and(|result| result != 0);
            let has_unpublished_cause = failure.unpublished_owner_error.is_some();
            let header_pair_valid = failure.unprepare_header.is_some()
                == failure.unprepare_result.is_some()
                && failure.unprepare_result != Some(0);
            let (stage_valid, receipts_valid) = if failure.unpublished_owner {
                let reset_failed = failure.reset_result.is_some_and(|result| result != 0);
                let close_failed = failure.close_result.is_some_and(|result| result != 0);
                let stage_sequence = if reset_failed {
                    failure.close_result.is_none()
                } else if close_failed {
                    failure.reset_result == Some(0)
                } else {
                    has_unpublished_cause
                        && (failure.reset_result.is_none() || failure.reset_result == Some(0))
                        && failure.close_result == Some(0)
                };
                let stage_valid = failure.unprepared_headers.is_empty()
                    && failure.unprepare_header.is_none()
                    && failure.unprepare_result.is_none()
                    && stage_sequence;
                (stage_valid, failure.unprepared_headers.is_empty())
            } else if known {
                let subset = prepared_headers_match(&failure.unprepared_headers,
                    &self.midi.headers, failure.device);
                let failed_header = failure.unprepare_header.is_none_or(|header|
                    !failure.unprepared_headers.contains(&header)
                        && self.midi.headers.iter().any(|record|
                            record.host_device == failure.device
                                && record.host_header == header && record.prepared));
                let reset_failed = failure.reset_result.is_some_and(|result| result != 0);
                let unprepare_failed = failure.unprepare_result.is_some_and(|result| result != 0);
                let close_failed = failure.close_result.is_some_and(|result| result != 0);
                let shape = if reset_failed {
                    failure.unprepare_header.is_none()
                        && failure.unprepare_result.is_none()
                        && failure.close_result.is_none()
                        && failure.unprepared_headers.is_empty()
                } else if unprepare_failed {
                    failure.reset_result == Some(0)
                        && failure.close_result.is_none()
                        && failure.unprepare_header.is_some()
                        && failed_header
                } else if close_failed {
                    failure.reset_result == Some(0)
                        && failure.unprepare_header.is_none()
                        && failure.unprepare_result.is_none()
                        && prepared_headers_exact(&failure.unprepared_headers,
                            &self.midi.headers, failure.device)
                } else {
                    !has_native_failure && failure.reset_result.is_none()
                        && failure.close_result.is_none()
                        && failure.unprepare_header.is_none()
                        && failure.unprepare_result.is_none()
                        && failure.unprepared_headers.is_empty()
                        && has_unpublished_cause
                };
                (shape, subset && header_pair_valid && failed_header)
            } else {
                (false, false)
            };
            if !header_pair_valid || !stage_valid || !receipts_valid {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close failure carried inconsistent native stages or header receipts"));
            } else if !failure.unpublished_owner {
                mark_unprepared_headers(&mut self.midi.headers,
                    &failure.unprepared_headers, failure.device);
            }
            if has_native_failure {
                remember_failure(&mut failures, native_close_failure(failure));
            }
            if let Some(error) = failure.unpublished_owner_error.take() {
                if !failure.unpublished_owner {
                    remember_failure(&mut failures, midi_invariant(
                        "guest MIDI owner returned an unpublished-owner cleanup error"));
                }
                remember_failure(&mut failures, error);
            }
            if !has_native_failure && !has_unpublished_cause {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close failure omitted its typed cause"));
            }
        }
        for receipt in closed.devices {
            if receipt.device.token == 0 || receipt.device.generation == 0
                || receipts.contains(&receipt.device)
            {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close owner returned a duplicate or zeroed device receipt"));
                continue;
            }
            if receipt.close_result != Some(0)
                || receipt.reset_result.is_some_and(|result| result != 0)
            {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close receipt omitted its actual successful native stages"));
                continue;
            }
            let Some(device_index) = self.midi.devices.iter().position(|record|
                record.host == receipt.device) else {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close receipt referenced an unknown host generation"));
                continue;
            };
            if closed.failures.iter().any(|failure| failure.device == receipt.device) {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close owner returned both success and failure for one generation"));
                continue;
            }
            if !prepared_headers_exact(&receipt.unprepared_headers,
                &self.midi.headers, receipt.device)
            {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close receipt did not name every actually prepared header"));
                continue;
            }
            if let Some(reset_result) = receipt.reset_result {
                self.midi.devices[device_index].reset_result = Some(reset_result);
            }
            self.midi.devices[device_index].close_result = Some(0);
            mark_unprepared_headers(&mut self.midi.headers,
                &receipt.unprepared_headers, receipt.device);
            if self.midi.headers.iter().any(|header|
                header.host_device == receipt.device && header.prepared)
            {
                remember_failure(&mut failures, midi_invariant(
                    "successful MIDI close left a prepared runtime header"));
                continue;
            }
            self.midi.devices[device_index].closing = true;
            receipts.push(receipt.device);
        }
        for device in &self.midi.devices {
            if !receipts.contains(&device.host)
                && !closed.failures.iter().any(|failure| failure.device == device.host)
            {
                remember_failure(&mut failures, midi_invariant(
                    "MIDI close owner omitted an open device without a failure receipt"));
            }
        }

        let deadline = Instant::now() + CLOSE_DRAIN_LIMIT;
        loop {
            loop {
                let notification = match host.win16_midi_peek_notification() {
                    Ok(notification) => notification,
                    Err(error) => return Err(with_prior_failures(failures, error)),
                };
                let Some(notification) = notification else { break; };
                let Some(device_index) = self.midi.devices.iter().position(|record|
                    record.host == notification.device) else {
                    return Err(with_prior_failures(failures, midi_invariant(
                        "MIDI close drain found a callback for an unknown owner generation")));
                };
                let device = self.midi.devices[device_index];
                if notification.callback_instance != device.instance {
                    return Err(with_prior_failures(failures, midi_invariant(
                        "MIDI close drain callback instance changed after open")));
                }
                let header_update = match validate_completion(&notification, &self.midi.headers) {
                    Ok(update) => update,
                    Err(error) => return Err(with_prior_failures(failures, error)),
                };
                if let Err(error) = host.win16_midi_ack_notification(
                    notification.device,
                    notification.sequence,
                    Disposition::Cancelled(Win16HostMidiCancellationReason::OwnerTerminated),
                ) {
                    return Err(with_prior_failures(failures, error));
                }
                if let Some((index, completion, flags)) = header_update {
                    let record = &mut self.midi.headers[index];
                    if record.submission == Some(completion) {
                        record.submission = None;
                    }
                    if record.completed_pending == Some(completion) {
                        record.completed_pending = None;
                    }
                    record.guest_flags = flags;
                }
                if matches!(notification.message, MM_MOM_CLOSE | MM_MIM_CLOSE) {
                    self.midi.devices[device_index].close_seen = true;
                }
            }

            let mut blocked_by_header = false;
            for token in receipts.iter().copied() {
                let Some(index) = self.midi.devices.iter().position(|device|
                    device.host == token) else { continue; };
                let device = self.midi.devices[index];
                if !device.close_seen { continue; }
                if self.midi.headers.iter().any(|header| header.host_device == token
                    && (header.submission.is_some() || header.completed_pending.is_some()))
                {
                    remember_failure(&mut failures, RuntimeError::new(Kind::HostFailure,
                        "MIDI close drain still owns an unacknowledged header submission"));
                    blocked_by_header = true;
                    continue;
                }
                match host.win16_midi_finalize_closed_device(token) {
                    Ok(true) => self.retire_midi_device(device.guest, token),
                    Ok(false) => {}
                    Err(error) => return Err(with_prior_failures(failures, error)),
                }
            }

            let pending_close = receipts.iter().any(|token|
                self.midi.devices.iter().any(|device| device.host == *token));
            if !pending_close { break; }
            if blocked_by_header { break; }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                remember_failure(&mut failures, pending_close_error());
                break;
            }
            match host.win16_midi_wait_notification(remaining) {
                Ok(true) => continue,
                Ok(false) => {
                    remember_failure(&mut failures, pending_close_error());
                    break;
                }
                Err(error) => {
                    remember_failure(&mut failures, error);
                    break;
                }
            }
        }

        if let Some(failure) = failures {
            return Err(failure);
        }
        if self.midi.dispatching.is_some()
            || self.midi.pending_callback_cleanup.is_some()
            || !self.midi.pending_cleanup.is_empty()
            || !self.midi.devices.is_empty()
            || !self.midi.headers.is_empty()
        {
            return Err(midi_invariant(
                "MIDI shutdown ACKed native owners but runtime notification, callback, device, or header owners remain",
            ));
        }
        self.midi.cleanup_complete = true;
        Ok(())
    }
}

fn prepared_headers_match(
    receipt: &[crate::Win16HostMidiHeader],
    records: &[MidiHeaderRecord],
    device: crate::Win16HostMidiDevice,
) -> bool {
    receipt.iter().enumerate().all(|(index, header)|
        records.iter().filter(|record| record.host_device == device
            && record.host_header == *header && record.prepared).count() == 1
            && !receipt[index + 1..].contains(header))
}

fn prepared_headers_exact(
    receipt: &[crate::Win16HostMidiHeader],
    records: &[MidiHeaderRecord],
    device: crate::Win16HostMidiDevice,
) -> bool {
    receipt.len() == records.iter().filter(|record|
        record.host_device == device && record.prepared).count()
        && prepared_headers_match(receipt, records, device)
}

fn mark_unprepared_headers(
    records: &mut [MidiHeaderRecord],
    receipt: &[crate::Win16HostMidiHeader],
    device: crate::Win16HostMidiDevice,
) {
    for record in records.iter_mut().filter(|record|
        record.host_device == device && receipt.contains(&record.host_header))
    {
        record.prepared = false;
        record.retired = true;
    }
}

fn validate_completion(
    notification: &crate::Win16HostMidiNotification,
    headers: &[MidiHeaderRecord],
) -> Result<Option<(usize, crate::Win16HostMidiSubmission, u32)>, RuntimeError> {
    let header_message = matches!(notification.message,
        MM_MOM_DONE | MM_MIM_LONGDATA | MM_MIM_LONGERROR);
    let Some(state) = notification.header.as_ref() else {
        if header_message {
            return Err(midi_invariant("MIDI completion callback omitted its header snapshot"));
        }
        return Ok(None);
    };
    if !header_message || state.submission.is_some() || state.callback_pending
        || state.bytes_recorded > state.capacity
    {
        return Err(midi_invariant("MIDI shutdown callback carried an invalid header snapshot"));
    }
    let completion = state.completed_submission.ok_or_else(|| midi_invariant(
        "MIDI shutdown header callback omitted its submission generation"))?;
    let Some(index) = headers.iter().position(|record|
        record.host_device == notification.device && record.host_header == state.header)
    else {
        return Err(midi_invariant("MIDI shutdown callback named an unknown guest header"));
    };
    let record = &headers[index];
    if record.submission != Some(completion)
        && record.completed_pending != Some(completion)
    {
        return Err(midi_invariant("MIDI shutdown callback changed its submission identity"));
    }
    match (record.direction, state.input_data.as_deref()) {
        (Win16HostMidiDirection::Input, Some(bytes))
            if bytes.len() == state.bytes_recorded as usize => {}
        (Win16HostMidiDirection::Output, None) => {}
        _ => return Err(midi_invariant("MIDI shutdown callback data did not match device direction")),
    }
    Ok(Some((index, completion, state.flags)))
}

fn native_close_failure(failure: &crate::Win16HostMidiCloseFailure) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure,
        "WinMM MIDI close-all returned native failure codes",
        MidiNativeCloseCodes {
            device: failure.device,
            reset_result: failure.reset_result,
            unprepared_headers: failure.unprepared_headers.len(),
            unprepare_header: failure.unprepare_header,
            unprepare_result: failure.unprepare_result,
            close_result: failure.close_result,
        })
}

#[derive(Debug)]
struct MidiNativeCloseCodes {
    device: crate::Win16HostMidiDevice,
    reset_result: Option<u32>,
    unprepared_headers: usize,
    unprepare_header: Option<crate::Win16HostMidiHeader>,
    unprepare_result: Option<u32>,
    close_result: Option<u32>,
}

impl std::fmt::Display for MidiNativeCloseCodes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "MIDI owner {}:{}",
            self.device.token, self.device.generation)?;
        write_native_stage(formatter, "reset", self.reset_result)?;
        match self.unprepare_header {
            Some(header) => {
                write!(formatter, " unprepare_failed_header={}:{}",
                    header.token, header.generation)?;
                if self.unprepared_headers != 0 {
                    write!(formatter, " prior_unprepare_successes={}",
                        self.unprepared_headers)?;
                }
            }
            None if self.unprepared_headers != 0 => write!(formatter,
                " unprepare=MMRESULT 0 for {} native header(s)", self.unprepared_headers)?,
            None => formatter.write_str(" unprepare=not attempted")?,
        }
        if let Some(code) = self.unprepare_result {
            write!(formatter, " unprepare=MMRESULT {code} (0x{code:08X})")?;
        }
        write_native_stage(formatter, "close", self.close_result)?;
        Ok(())
    }
}

fn write_native_stage(
    formatter: &mut std::fmt::Formatter<'_>,
    name: &str,
    result: Option<u32>,
) -> std::fmt::Result {
    match result {
        Some(code) => write!(formatter, " {name}=MMRESULT {code} (0x{code:08X})"),
        None => write!(formatter, " {name}=not attempted"),
    }
}

impl std::error::Error for MidiNativeCloseCodes {}

fn pending_close_error() -> RuntimeError {
    RuntimeError::new(Kind::HostFailure,
        "MIDI native close awaits its exact callback receipt; owner mappings remain retryable")
}

fn remember_failure(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => primary.with_cleanup(
            "multiple MIDI close and callback retirement failures",
            error,
        ),
    });
}

fn with_prior_failures(
    failures: Option<RuntimeError>,
    error: RuntimeError,
) -> RuntimeError {
    match failures {
        Some(primary) => primary.with_cleanup(
            "MIDI close failed before callback drain completed",
            error,
        ),
        None => error,
    }
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn midi_producer_reset_failure(
    failure: &crate::Win16HostMidiProducerFailure,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        "native MIDI producer Reset did not succeed; owner and headers remain retained",
        MidiProducerResetResult {
            device: failure.device,
            owner: failure.owner,
            result: failure.reset_result,
        },
    )
}

#[derive(Debug)]
struct MidiProducerResetResult {
    device: crate::Win16HostMidiDevice,
    owner: ProducerOwner,
    result: u32,
}

impl std::fmt::Display for MidiProducerResetResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (owner, direction, instance) = match self.owner {
            ProducerOwner::GuestPublished { direction, callback_instance } =>
                ("published", direction, callback_instance),
            ProducerOwner::Unpublished { direction, callback_instance } =>
                ("unpublished", direction, callback_instance),
        };
        let direction = match direction {
            Win16HostMidiDirection::Input => "input",
            Win16HostMidiDirection::Output => "output",
        };
        write!(formatter,
            "device {}:{} {} {} owner, callback instance {}, Reset MMRESULT {} (0x{:08X})",
            self.device.token, self.device.generation, owner, direction, instance,
            self.result, self.result)
    }
}

impl std::error::Error for MidiProducerResetResult {}
