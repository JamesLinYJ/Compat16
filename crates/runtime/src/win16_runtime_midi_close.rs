//! Exact native stage receipts for ordinary MIDI device close.

use guest_core::memory::Memory;
use win16_abi::{Win16MidiDirection as GuestDirection, Win16MidiHeader16};

use super::{MidiHeaderRecord, Win16State, MHDR_DONE, MHDR_INQUEUE, MHDR_PREPARED,
    MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR};
use super::calls::NativeMidiResult;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMidiCall as HostCall, Win16HostMidiDirection as HostDirection,
    Win16HostMidiHeaderState, Win16HostMidiResult as HostResult};

impl Win16State {
    pub(super) fn close_midi_device(
        &mut self,
        direction: GuestDirection,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let direction = HostDirection::from(direction);
        let Some(device) = self.midi.device(guest, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        for record in self.midi.headers.iter().filter(|record|
            record.host_device == device.host && record.prepared)
        {
            match self.validate_prepared_header(record, memory) {
                Ok(_) => {}
                Err(error) if super::calls::is_guest_pointer_error(&error) => {
                    return Ok(MMSYSERR_INVALPARAM);
                }
                Err(error) => return Err(error),
            }
        }
        let response = host.win16_midi(HostCall::Close { device: device.host })?;
        let HostResult::Closed {
            result,
            retired_headers,
            reset_result,
            unprepare_header,
            unprepare_result,
            close_result,
        } = response else {
            return Err(midi_invariant("MIDI close returned the wrong result shape"));
        };

        if reset_result.is_some()
            || unprepare_header.is_some() != unprepare_result.is_some()
            || unprepare_result == Some(MMSYSERR_NOERROR)
            || unprepare_result.is_some() && close_result.is_some()
        {
            return Err(midi_invariant("MIDI close returned inconsistent unprepare and close stages"));
        }
        if !is_exact_prepared_subset(&retired_headers, &self.midi.headers, device.host) {
            return Err(midi_invariant(
                "MIDI close unprepare receipts do not identify prepared headers owned by this device"));
        }
        if unprepare_header.is_some_and(|token|
            retired_headers.iter().any(|receipt| receipt.header == token)
                || !self.midi.headers.iter().any(|record|
                    record.host_device == device.host
                        && record.host_header == token
                        && record.prepared))
        {
            return Err(midi_invariant(
                "MIDI close failure did not name an outstanding opaque header token"));
        }

        let native_stage_result = unprepare_result.or(close_result);
        if native_stage_result != Some(result) {
            return Err(midi_invariant("MIDI close result does not match its last attempted native stage"));
        }
        if close_result == Some(MMSYSERR_NOERROR)
            && (unprepare_header.is_some()
                || !is_exact_prepared_set(&retired_headers, &self.midi.headers, device.host))
        {
            return Err(midi_invariant(
                "successful MIDI close lacks actual unprepare receipts for every prepared header"));
        }

        if close_result == Some(MMSYSERR_NOERROR) {
            if self.midi.headers.iter().any(|record|
                record.host_device == device.host && record.prepared
                    && !retired_headers.iter().any(|receipt|
                        receipt.header == record.host_header))
            {
                return Err(midi_invariant("successful MIDI close left a prepared runtime header"));
            }
            let Some(record) = self.midi.devices.iter_mut()
                .find(|record| record.host == device.host) else {
                return Err(midi_invariant("MIDI close lost its exact runtime device generation"));
            };
            record.closing = true;
            record.close_result = Some(MMSYSERR_NOERROR);
        } else if result == MMSYSERR_NOERROR {
            return Err(midi_invariant("MIDI close reported success without a successful close stage"));
        }

        // Publish every successful native unprepare receipt before touching
        // guest memory. A failed projection must not discard later native
        // effects from the same close attempt.
        let pending_native_result = (result != MMSYSERR_NOERROR).then_some(result);
        for receipt in &retired_headers {
            let Some(index) = self.midi.headers.iter().position(|record|
                record.host_device == device.host && record.host_header == receipt.header
                    && record.prepared)
            else {
                return Err(midi_invariant("MIDI close receipt lost its exact prepared guest header"));
            };
            {
                let live = &mut self.midi.headers[index];
                live.prepared = false;
                live.retired = true;
                live.pending_close_projection = Some(receipt.clone());
                live.pending_close_native_result = pending_native_result;
                live.close_projection_committed = false;
            }
        }

        let mut failures = None;
        for receipt in &retired_headers {
            let Some(index) = self.midi.headers.iter().position(|record|
                record.host_device == device.host && record.host_header == receipt.header
                    && record.retired && record.pending_close_projection.is_some())
            else {
                remember_midi_failure(&mut failures, midi_invariant(
                    "retained MIDI unprepare receipt lost its exact runtime owner"));
                continue;
            };
            let record = self.midi.headers[index].clone();
            match self.commit_unprepared_header_flags(&record, receipt, memory) {
                Ok(()) => {
                    let closing = self.midi.devices.iter().any(|device|
                        device.host == record.host_device && device.closing);
                    let live = &mut self.midi.headers[index];
                    live.close_projection_committed = true;
                    live.pending_close_native_result = None;
                    live.guest_flags =
                        (record.guest_flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
                            | (receipt.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
                    if closing {
                        // The closed device owns final native-header retirement.
                        live.pending_close_projection = None;
                        live.close_projection_committed = false;
                    }
                }
                Err(error) => {
                    let error = error.with_context(
                        "project successful MIDI close-stage unprepare to Win16 MIDIHDR");
                    let error = with_native_close_result(
                        error, self.midi.headers[index].pending_close_native_result,
                    );
                    remember_midi_failure(&mut failures, error);
                }
            }
        }

        if close_result != Some(MMSYSERR_NOERROR) {
            for receipt in &retired_headers {
                let Some(index) = self.midi.headers.iter().position(|record|
                    record.host_device == device.host && record.host_header == receipt.header
                        && record.retired && record.pending_close_projection.is_some())
                else {
                    continue;
                };
                let record = self.midi.headers[index].clone();
                if !record.close_projection_committed || receipt.callback_pending
                    || self.has_runtime_header_callback(&record)
                {
                    continue;
                }
                if let Err(error) = self.release_retired_header_owner(index, &record, host) {
                    remember_midi_failure(&mut failures,
                        with_native_close_result(error, pending_native_result));
                }
            }
        }

        if let Some(error) = failures { return Err(error); }
        Ok(result)
    }

    pub(super) fn retry_pending_midi_close_projections(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failures = None;
        let mut index = 0;
        while index < self.midi.headers.len() {
            let close_receipt = self.midi.headers[index].pending_close_projection.clone();
            let unprepare_receipt = self.midi.headers[index].pending_unprepare_projection.clone();
            if close_receipt.is_some() && unprepare_receipt.is_some() {
                return Err(midi_invariant(
                    "MIDI header retained both ordinary and Close-stage unprepare projections",
                ));
            }
            let Some(receipt) = close_receipt.clone().or(unprepare_receipt.clone()) else {
                index += 1;
                continue;
            };
            if close_receipt.is_some() && self.midi.headers[index].close_projection_committed {
                index += 1;
                continue;
            }
            let record = self.midi.headers[index].clone();
            let projection = if let Some(unprepare) = unprepare_receipt.as_ref() {
                if record.pending_unprepare_native_result != Some(MMSYSERR_NOERROR) {
                    return Err(midi_invariant(
                        "retained ordinary MIDI unprepare lost successful native MMRESULT",
                    ));
                }
                self.commit_pending_unprepare(&record, unprepare, memory)
            } else {
                self.commit_unprepared_header_flags(&record, &receipt, memory)
            };
            match projection {
                Ok(()) => {
                    let live = &mut self.midi.headers[index];
                    live.guest_flags =
                        (live.guest_flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
                            | (receipt.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
                    if unprepare_receipt.is_some() {
                        live.pending_unprepare_projection = None;
                        live.pending_unprepare_native_result = None;
                    } else {
                        live.close_projection_committed = true;
                        live.pending_close_native_result = None;
                        let closing = self.midi.devices.iter().any(|device|
                            device.host == record.host_device && device.closing);
                        if closing {
                            live.pending_close_projection = None;
                            live.close_projection_committed = false;
                        }
                    }
                }
                Err(error) => {
                    let error = if unprepare_receipt.is_some() {
                        error
                    } else {
                        let error = error.with_context(
                            "retry Win16 MIDIHDR projection after native unprepare",
                        );
                        with_native_close_result(error, record.pending_close_native_result)
                    };
                    remember_midi_failure(&mut failures, error);
                }
            }
            index += 1;
        }
        if let Err(error) = self.release_quiescent_close_headers(host) {
            remember_midi_failure(&mut failures, error);
        }
        failures.map_or(Ok(()), Err)
    }

    /// A guest FAR may be reused only after both callback sides and the exact
    /// native storage owner confirm quiescence for the old opaque header token.
    pub(super) fn recycle_retired_midi_header(
        &mut self,
        guest_device: u16,
        header_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(index) = self.midi.headers.iter().position(|record|
            record.guest_device == guest_device && record.header_far == header_far)
        else {
            return Ok(true);
        };
        let record = self.midi.headers[index].clone();
        if record.prepared || !record.retired {
            return Err(midi_invariant("MIDI header recycle did not target an unprepared retired owner"));
        }
        if let Some(receipt) = &record.pending_unprepare_projection {
            if record.pending_unprepare_native_result != Some(MMSYSERR_NOERROR) {
                return Err(midi_invariant(
                    "retained MIDI unprepare projection lost successful native MMRESULT",
                ));
            }
            self.commit_pending_unprepare(&record, receipt, memory)?;
            let live = &mut self.midi.headers[index];
            live.guest_flags = (live.guest_flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
                | (receipt.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
            live.pending_unprepare_projection = None;
            live.pending_unprepare_native_result = None;
        }
        if let Some(receipt) = &record.pending_close_projection {
            if !record.close_projection_committed {
                self.commit_unprepared_header_flags(&record, receipt, memory)
                    .map_err(|error| error.with_context(
                        "project retained MIDI close-stage unprepare before header reuse"))?;
                self.midi.headers[index].close_projection_committed = true;
                self.midi.headers[index].pending_close_native_result = None;
                self.midi.headers[index].guest_flags =
                    (record.guest_flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
                        | (receipt.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
            }
        }
        let record = self.midi.headers[index].clone();
        if self.has_runtime_header_callback(&record) {
            return Ok(false);
        }
        let response = host.win16_midi(HostCall::ReleaseRetiredHeader {
            device: record.host_device,
            header: record.host_header,
        })?;
        match response {
            HostResult::RetiredHeaderReleased { header, released }
                if header == record.host_header =>
            {
                if released {
                    self.midi.headers.remove(index);
                }
                Ok(released)
            }
            _ => Err(midi_invariant(
                "retired MIDI header release returned the wrong owner or result shape")),
        }
    }

    pub(super) fn commit_unprepared_header_flags(
        &self,
        record: &MidiHeaderRecord,
        receipt: &Win16HostMidiHeaderState,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if !valid_unprepare_receipt(receipt, record) {
            return Err(midi_invariant("successful MIDI unprepare returned invalid header state"));
        }
        let mut raw = record.header_range.read(self, memory)?;
        let mut header = Win16MidiHeader16::decode(&raw).ok_or_else(||
            midi_invariant("captured MIDIHDR16 changed size during close"))?;
        if header.data != record.data_far || header.buffer_length != record.capacity {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDIHDR data identity changed during close"));
        }
        header.flags = (header.flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
            | (receipt.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
        raw.copy_from_slice(&header.encode());
        record.header_range.commit(self, memory, &raw)
    }

    pub(super) fn has_runtime_header_callback(&self, record: &MidiHeaderRecord) -> bool {
        record.submission.is_some()
            || record.completed_pending.is_some()
            || self.midi.dispatching.as_ref().is_some_and(|pending|
                pending.identity.device == record.host_device
                    && pending.host_header == Some(record.host_header))
    }

    fn release_retired_header_owner(
        &mut self,
        index: usize,
        record: &MidiHeaderRecord,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let response = host.win16_midi(HostCall::ReleaseRetiredHeader {
            device: record.host_device,
            header: record.host_header,
        })?;
        match response {
            HostResult::RetiredHeaderReleased { header, released }
                if header == record.host_header =>
            {
                if released {
                    self.midi.headers.remove(index);
                }
                Ok(())
            }
            _ => Err(midi_invariant(
                "retired MIDI header release returned the wrong owner or result shape")),
        }
    }
}

fn is_exact_prepared_subset(
    receipts: &[Win16HostMidiHeaderState],
    records: &[MidiHeaderRecord],
    device: crate::Win16HostMidiDevice,
) -> bool {
    receipts.iter().enumerate().all(|(index, receipt)| {
        records.iter().filter(|record| record.host_device == device
            && record.host_header == receipt.header && record.prepared).count() == 1
            && !receipts[index + 1..].iter().any(|other| other.header == receipt.header)
            && records.iter().find(|record| record.host_device == device
                && record.host_header == receipt.header && record.prepared)
                .is_some_and(|record| valid_unprepare_receipt(receipt, record))
    })
}

fn is_exact_prepared_set(
    receipts: &[Win16HostMidiHeaderState],
    records: &[MidiHeaderRecord],
    device: crate::Win16HostMidiDevice,
) -> bool {
    let prepared_count = records.iter().filter(|record|
        record.host_device == device && record.prepared).count();
    receipts.len() == prepared_count && is_exact_prepared_subset(receipts, records, device)
}

fn valid_unprepare_receipt(
    receipt: &Win16HostMidiHeaderState,
    record: &MidiHeaderRecord,
) -> bool {
    // Native Unprepare may retire WinMM ownership after driver completion but
    // before the queued source is peeked or ACKed; retain that exact identity.
    let submission_matches_owner = match (
        record.submission,
        record.completed_pending,
        receipt.submission,
    ) {
        (Some(active), None, Some(receipt_submission)) => active == receipt_submission,
        (Some(_), None, None) => receipt.callback_pending,
        (None, Some(_), None) => receipt.callback_pending,
        (None, None, None) => true,
        _ => false,
    };
    receipt.header == record.host_header
        && submission_matches_owner
        && receipt.capacity == record.capacity
        && receipt.user == record.user
        && receipt.bytes_recorded <= record.capacity
        && receipt.completed_submission.is_none()
        && receipt.input_data.is_none()
        && receipt.flags & (MHDR_PREPARED | MHDR_INQUEUE) == 0
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn remember_midi_failure(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => primary.with_cleanup(
            "multiple MIDI header projection or retirement operations failed",
            error,
        ),
    });
}

fn with_native_close_result(error: RuntimeError, result: Option<u32>) -> RuntimeError {
    let Some(result) = result.filter(|result| *result != MMSYSERR_NOERROR) else {
        return error;
    };
    let native_result = RuntimeError::with_source(
        Kind::HostFailure,
        "native MIDI close stage returned a nonzero MMRESULT",
        NativeMidiResult(result),
    );
    error.with_cleanup("guest MIDIHDR publication followed a failed native close stage", native_result)
}
