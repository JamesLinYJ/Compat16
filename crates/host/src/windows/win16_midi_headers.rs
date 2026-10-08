//! Stable native MIDIHDR storage and async submission ownership.

use std::mem::size_of;

use runtime::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostMidiDevice as DeviceToken, Win16HostMidiHeader as HeaderToken,
    Win16HostMidiHeaderState as HeaderState, Win16HostMidiResult as ResultValue,
};
use windows_sys::Win32::Media::Audio::{
    MIDIHDR, midiInAddBuffer, midiInPrepareHeader, midiInUnprepareHeader,
    midiOutLongMsg, midiOutPrepareHeader, midiOutUnprepareHeader,
};

use super::{MidiDirection, MidiHeader, NativeMidiBuffer, NativeMidiHandle, Win16MidiHost,
    allocate_samples, invalid_device, invalid_header, invalid_parameter_header};
use super::callback;

const MMSYSERR_NOERROR: u32 = 0;
const MIDIERR_STILLPLAYING: u32 = 65;

impl Win16MidiHost {
    pub(super) fn prepare_header(
        &mut self,
        token: DeviceToken,
        capacity: u32,
        user: u32,
        initial_data: Vec<u8>,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(device_index) = self.device_index(token) else {
            return Ok(ResultValue::Header { result: 5, state: None });
        };
        let device_direction = self.devices[device_index].direction;
        let native_device = self.devices[device_index].native;
        if self.devices[device_index].closing {
            return Ok(invalid_device());
        }
        let length = usize::try_from(capacity).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "native MIDI buffer length exceeds host address width", error))?;
        if (device_direction == MidiDirection::Output && initial_data.len() != length)
            || (device_direction == MidiDirection::Input && !initial_data.is_empty())
        {
            return Ok(invalid_parameter_header());
        }
        self.headers.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native MIDI header ledger", error))?;
        let header_token = self.allocate_pair(|token, generation| HeaderToken { token, generation })?;
        let mut samples = allocate_samples(length)?;
        if device_direction == MidiDirection::Output {
            samples.copy_from_slice(&initial_data);
        }
        let mut storage_vec = Vec::new();
        storage_vec.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve stable MIDIHDR allocation", error))?;
        let mut native_header = MIDIHDR::default();
        native_header.lpData = samples.as_mut_ptr();
        native_header.dwBufferLength = capacity;
        native_header.dwBytesRecorded = 0;
        native_header.dwUser = user as usize;
        native_header.dwFlags = 0;
        native_header.lpNext = std::ptr::null_mut();
        native_header.reserved = 0;
        storage_vec.push(NativeMidiBuffer { header: native_header, samples });
        let mut storage = storage_vec.into_boxed_slice();
        let pointer = &mut storage[0].header as *mut MIDIHDR;
        let result = unsafe { match native_device {
            NativeMidiHandle::Input(handle) => midiInPrepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
            NativeMidiHandle::Output(handle) => midiOutPrepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
        }};
        if result != MMSYSERR_NOERROR {
            return Ok(ResultValue::Header { result, state: None });
        }
        let record = MidiHeader {
            token: header_token,
            device: token,
            direction: device_direction,
            storage,
            capacity,
            user,
            prepared: true,
            active_submission: None,
            completed_submissions: Vec::new(),
            submission_generation: 0,
            defer_release: false,
            retired: false,
        };
        let state = header_state(&record, None, None)?;
        self.headers.push(record);
        Ok(ResultValue::Header { result, state: Some(state) })
    }

    pub(super) fn unprepare_header(
        &mut self,
        token: DeviceToken,
        header: HeaderToken,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(index) = self.header_index(token, header) else { return Ok(invalid_header()); };
        let Some(device_index) = self.device_index(token) else {
            return Ok(ResultValue::Header { result: 5, state: None });
        };
        if !self.headers[index].prepared { return Ok(invalid_header()); }
        if self.headers[index].active_submission.is_some() {
            return Ok(ResultValue::Header { result: MIDIERR_STILLPLAYING, state: None });
        }
        let native_device = self.devices[device_index].native;
        let record = &mut self.headers[index];
        let pointer = &mut record.storage[0].header as *mut MIDIHDR;
        let result = unsafe { match native_device {
            NativeMidiHandle::Input(handle) => midiInUnprepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
            NativeMidiHandle::Output(handle) => midiOutUnprepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
        }};
        if result != MMSYSERR_NOERROR {
            let state = header_state(record, record.active_submission, None)?;
            return Ok(ResultValue::Header { result, state: Some(state) });
        }
        record.prepared = false;
        record.retired = true;
        let mut state = header_state(record, None, None)?;
        let record_token = record.token;
        let keep_for_callback = self.header_has_queued_callback(token, header);
        state.callback_pending = keep_for_callback;
        if !keep_for_callback {
            if self.headers.get(index).is_some_and(|entry| entry.token == record_token) {
                self.headers.remove(index);
            }
        }
        Ok(ResultValue::Header { result, state: Some(state) })
    }

    /// Drop only a header whose actual WinMM unprepare has already succeeded.
    /// The runtime has also checked guest callback/source ownership; recheck
    /// every host-side queue before releasing its stable MIDIHDR/sample storage.
    pub(super) fn release_retired_header(
        &mut self,
        device: DeviceToken,
        header: HeaderToken,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(device_index) = self.device_index(device) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "retired MIDI header release lost its exact native device owner"));
        };
        let Some(index) = self.header_index(device, header) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "retired MIDI header release lost its exact native header owner"));
        };
        if self.headers[index].prepared || !self.headers[index].retired {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "retired MIDI header release did not follow successful native unprepare"));
        }
        let expected_direction = self.devices[device_index].direction;
        if self.headers[index].direction != expected_direction
            || self.headers[index].storage.len() != 1
            || self.headers[index].storage[0].samples.as_ptr()
                != self.headers[index].storage[0].header.lpData.cast::<u8>()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "retired MIDI header release lost its exact native storage"));
        }
        let released = !self.devices[device_index].closing
            && self.devices[device_index].callback.in_flight() == 0
            && self.headers[index].active_submission.is_none()
            && self.headers[index].completed_submissions.is_empty()
            && !self.header_has_queued_callback(device, header);
        if released {
            self.headers.remove(index);
        }
        Ok(ResultValue::RetiredHeaderReleased { header, released })
    }

    pub(super) fn output_long(
        &mut self,
        token: DeviceToken,
        header: HeaderToken,
        data: Vec<u8>,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(device_index) = self.device_index(token) else {
            return Ok(ResultValue::Header { result: 5, state: None });
        };
        let Some(header_index) = self.header_index(token, header) else { return Ok(invalid_header()); };
        if self.devices[device_index].direction != MidiDirection::Output
            || !self.headers[header_index].prepared
            || self.headers[header_index].direction != MidiDirection::Output
        {
            return Ok(invalid_header());
        }
        if self.headers[header_index].active_submission.is_some() {
            return Ok(ResultValue::Header { result: MIDIERR_STILLPLAYING, state: None });
        }
        let capacity = usize::try_from(self.headers[header_index].capacity).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "MIDI output buffer length exceeds host address width", error))?;
        if data.len() != capacity { return Ok(invalid_parameter_header()); }
        let submission = self.allocate_pair(|token, generation|
            runtime::Win16HostMidiSubmission { token, generation })?;
        let native_device = self.devices[device_index].native;
        let record = &mut self.headers[header_index];
        record.storage[0].samples.copy_from_slice(&data);
        record.storage[0].header.dwBytesRecorded = 0;
        let pointer = &record.storage[0].header as *const MIDIHDR;
        let NativeMidiHandle::Output(handle_native) = native_device else { return Ok(invalid_device()); };
        let result = unsafe { midiOutLongMsg(handle_native, pointer, size_of::<MIDIHDR>() as u32) };
        if result != MMSYSERR_NOERROR {
            return Ok(ResultValue::Header { result, state: None });
        }
        record.submission_generation = submission.generation;
        record.active_submission = Some(submission);
        let state = header_state(record, Some(submission), None)?;
        Ok(ResultValue::Header { result, state: Some(state) })
    }

    pub(super) fn input_add_buffer(
        &mut self,
        token: DeviceToken,
        header: HeaderToken,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(device_index) = self.device_index(token) else {
            return Ok(ResultValue::Header { result: 5, state: None });
        };
        let Some(header_index) = self.header_index(token, header) else { return Ok(invalid_header()); };
        if self.devices[device_index].direction != MidiDirection::Input
            || self.headers[header_index].direction != MidiDirection::Input
            || !self.headers[header_index].prepared
        { return Ok(invalid_header()); }
        if self.headers[header_index].active_submission.is_some() {
            return Ok(ResultValue::Header { result: MIDIERR_STILLPLAYING, state: None });
        }
        let submission = self.allocate_pair(|token, generation|
            runtime::Win16HostMidiSubmission { token, generation })?;
        let native_device = self.devices[device_index].native;
        let record = &mut self.headers[header_index];
        record.storage[0].header.dwBytesRecorded = 0;
        let pointer = &mut record.storage[0].header as *mut MIDIHDR;
        let NativeMidiHandle::Input(handle_native) = native_device else { return Ok(invalid_device()); };
        let result = unsafe { midiInAddBuffer(handle_native, pointer, size_of::<MIDIHDR>() as u32) };
        if result != MMSYSERR_NOERROR {
            return Ok(ResultValue::Header { result, state: None });
        }
        record.submission_generation = submission.generation;
        record.active_submission = Some(submission);
        let state = header_state(record, Some(submission), None)?;
        Ok(ResultValue::Header { result, state: Some(state) })
    }

    pub(super) fn header_snapshot_for_callback(
        &mut self,
        device: DeviceToken,
        native_pointer: usize,
        input: bool,
    ) -> Result<Option<HeaderState>, RuntimeError> {
        let Some(index) = self.headers.iter().position(|record| record.device == device
            && record.storage[0].header_address() == native_pointer) else { return Ok(None); };
        let record = &self.headers[index];
        let completed = record.active_submission.ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "native MIDI completion has no active owned submission")
        })?;
        let input_data = if input {
            let recorded = record.storage[0].header.dwBytesRecorded;
            if recorded > record.capacity {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native MIDI input callback reported bytes beyond its owned buffer"));
            }
            let mut bytes = allocate_samples(recorded as usize)?;
            bytes.copy_from_slice(&record.storage[0].samples[..recorded as usize]);
            Some(std::sync::Arc::<[u8]>::from(bytes))
        } else { None };
        // Finish every fallible projection before changing the active native
        // submission. A failed peek can then be retried against the same raw
        // callback without losing the identity needed for exact ACK.
        let mut state = header_state(record, Some(completed), input_data)?;
        state.submission = None;
        state.completed_submission = Some(completed);
        self.headers[index].completed_submissions.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve completed MIDI submission identity", error)
        })?;
        self.headers[index].active_submission = None;
        self.headers[index].completed_submissions.push(completed);
        Ok(Some(state))
    }

    pub(super) fn complete_submission(
        &mut self,
        device: DeviceToken,
        header: HeaderToken,
        submission: Option<runtime::Win16HostMidiSubmission>,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.header_index(device, header) else { return Ok(()); };
        let retired = {
            let record = &mut self.headers[index];
            let Some(submission) = submission else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "MIDI completion ACK did not match the active header submission"));
            };
            let Some(position) = record.completed_submissions.iter()
                .position(|entry| *entry == submission) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "MIDI completion ACK did not match a completed owned submission"));
            };
            record.completed_submissions.remove(position);
            record.retired
        };
        if retired && !self.headers[index].defer_release
            && self.headers[index].completed_submissions.is_empty()
            && self.headers[index].active_submission.is_none()
            && !self.header_has_queued_callback(device, header)
        {
            self.headers.remove(index);
        }
        Ok(())
    }

    pub(super) fn validate_completion_ack(
        &self,
        device: DeviceToken,
        header: HeaderToken,
        submission: Option<runtime::Win16HostMidiSubmission>,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.header_index(device, header) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI completion ACK lost its stable native header"));
        };
        let Some(submission) = submission else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI completion ACK omitted its submission identity"));
        };
        if !self.headers[index].completed_submissions.contains(&submission) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI completion ACK did not match a completed owned submission"));
        }
        Ok(())
    }

    pub(super) fn retire_closed_device(
        &mut self,
        device_token: DeviceToken,
    ) -> Result<bool, RuntimeError> {
        let Some(device) = self.devices.iter().find(|device| device.token == device_token) else {
            return Ok(true);
        };
        if !device.closing || !device.close_seen || device.projected.is_some()
            || device.callback.peek().is_some() || device.callback.in_flight() != 0
        {
            return Ok(false);
        }
        if let Some(error) = device.callback.take_failure() {
            return Err(error);
        }
        if !callback::unregister_if_idle(device.context_id, &device.callback) {
            return Ok(false);
        }
        self.headers.retain(|header| header.device != device_token);
        self.devices.retain(|device| device.token != device_token);
        Ok(true)
    }

    pub(super) fn header_has_queued_callback(&self, device: DeviceToken, header: HeaderToken) -> bool {
        let Some(device) = self.devices.iter().find(|entry| entry.token == device) else { return false; };
        let Some(record) = self.headers.iter().find(|entry| entry.token == header) else { return false; };
        device.callback.contains_header(record.storage[0].header_address())
    }
}

fn header_state(
    record: &MidiHeader,
    submission: Option<runtime::Win16HostMidiSubmission>,
    input_data: Option<std::sync::Arc<[u8]>>,
) -> Result<HeaderState, RuntimeError> {
    let native = &record.storage[0].header;
    let bytes_recorded = native.dwBytesRecorded;
    let user = u32::try_from(native.dwUser).map_err(|error| RuntimeError::with_source(
        Kind::CompatibilityGap, "native MIDIHDR dwUser does not fit Win16 DWORD", error))?;
    Ok(HeaderState {
        header: record.token,
        submission: submission.or(record.active_submission),
        completed_submission: None,
        capacity: record.capacity,
        bytes_recorded,
        user,
        flags: native.dwFlags,
        callback_pending: false,
        input_data,
    })
}

#[allow(dead_code)]
fn _native_header_size_is_pointer_sized() -> usize { size_of::<MIDIHDR>() }

pub(super) fn _copy_result(value: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(value.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve MIDI completion copy", error))?;
    copied.extend_from_slice(value);
    Ok(copied)
}
