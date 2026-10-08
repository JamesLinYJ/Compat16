//! WAVE open, header registration, submit, and device-control operations.

use super::*;

impl Win16State {
    pub(super) fn wave_get_parameter(
        &self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        parameter: Win16WaveParameter,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(parameter) = host_wave_parameter(parameter) else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let output = match self.capture_wave_output(memory, output_far, 4) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_wave(Win16HostWaveOperation::GetParameter {
            device: device.host,
            parameter,
        })?;
        let Win16HostWaveResult::Parameter { result, value } = reply else {
            return Err(wave_invariant(
                "WAVE parameter getter returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if value.is_some() {
                return Err(wave_invariant(
                    "failed WAVE parameter getter returned a value",
                ));
            }
            return Ok(result);
        }
        let value = value
            .ok_or_else(|| wave_invariant("successful WAVE parameter getter omitted its value"))?;
        commit_one_wave_output(self, memory, output, wave_bytes(value.to_le_bytes())?)?;
        Ok(result)
    }

    pub(super) fn wave_set_parameter(
        &self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        parameter: Win16WaveParameter,
        value: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(parameter) = host_wave_parameter(parameter) else {
            return Ok(MMSYSERR_INVALPARAM);
        };
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        match host.win16_wave(Win16HostWaveOperation::SetParameter {
            device: device.host,
            parameter,
            value,
        })? {
            Win16HostWaveResult::Scalar(result) => Ok(result),
            _ => Err(wave_invariant(
                "WAVE parameter setter returned the wrong result shape",
            )),
        }
    }

    pub(super) fn wave_get_device_id(
        &self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let output = match self.capture_wave_output(memory, output_far, 2) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_wave(Win16HostWaveOperation::GetDeviceId {
            device: device.host,
        })?;
        let Win16HostWaveResult::DeviceId { result, device_id } = reply else {
            return Err(wave_invariant("WAVE GetID returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if device_id.is_some() {
                return Err(wave_invariant(
                    "failed WAVE GetID returned a device identifier",
                ));
            }
            return Ok(result);
        }
        let device_id = device_id
            .ok_or_else(|| wave_invariant("successful WAVE GetID omitted the device identifier"))?;
        let device_id = u16::try_from(device_id).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "native WAVE device ID cannot be represented by Win16 UINT",
            )
        })?;
        commit_one_wave_output(self, memory, output, wave_bytes(device_id.to_le_bytes())?)?;
        Ok(result)
    }

    pub(super) fn wave_message(
        &mut self,
        direction: Win16WaveDirection,
        device_or_handle: u16,
        message: u16,
        parameter1: u32,
        parameter2: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if message == DRV_QUERYMAPPABLE {
            if parameter1 != 0 || parameter2 != 0 {
                return Ok(MMSYSERR_INVALPARAM);
            }
            return match host.win16_wave(Win16HostWaveOperation::QueryMappable {
                direction: host_direction(direction),
                device_id: device_or_handle,
            })? {
                Win16HostWaveResult::Scalar(result) => Ok(result),
                _ => Err(wave_invariant(
                    "WAVE mapper query returned the wrong result shape",
                )),
            };
        }
        self.warn_wave_unsupported(
            host,
            "Win16 wave*Message driver-specific pointer contracts are not translated",
        );
        Ok(MMSYSERR_NOTSUPPORTED)
    }

    pub(super) fn wave_error_text(
        &self,
        direction: Win16WaveDirection,
        error_code: u16,
        output_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = if size == 0 {
            None
        } else {
            match self.capture_wave_output(memory, output_far, usize::from(size)) {
                Ok(output) => Some(output),
                Err(error) if is_guest_api_failure(&error) => {
                    return Ok(MMSYSERR_INVALPARAM);
                }
                Err(error) => return Err(error),
            }
        };
        let reply = host.win16_wave(Win16HostWaveOperation::ErrorText {
            direction: host_direction(direction),
            error: error_code,
            capacity: size,
        })?;
        let Win16HostWaveResult::ErrorText { result, bytes } = reply else {
            return Err(wave_invariant(
                "WAVE error-text call returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if bytes.is_some() {
                return Err(wave_invariant(
                    "failed WAVE error-text call returned output",
                ));
            }
            return Ok(result);
        }
        let mut bytes = bytes.ok_or_else(|| {
            wave_invariant("successful WAVE error-text call omitted its output buffer")
        })?;
        if bytes.len() > usize::from(size) {
            return Err(wave_invariant("WAVE error text exceeded guest capacity"));
        }
        let written = bytes
            .iter()
            .position(|byte| *byte == 0)
            .map_or(bytes.len(), |index| index + 1);
        bytes.truncate(written);
        if let Some(output) = output {
            if !bytes.is_empty() {
                commit_one_wave_output(self, memory, output, bytes)?;
            }
        } else if !bytes.is_empty() {
            return Err(wave_invariant(
                "zero-capacity WAVE error text returned output bytes",
            ));
        }
        Ok(result)
    }

    pub(super) fn wave_prepare(
        &mut self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if size as usize != WAVEHDR16_SIZE {
            return Ok(MMSYSERR_INVALPARAM);
        }
        if let Some(record) = self.wave_audio.header(guest_handle, header_far).cloned() {
            let current = self.validate_header_record_ranges(&record, memory)?;
            if current.data != record.data_far {
                return Ok(MMSYSERR_INVALPARAM);
            }
            return Ok(if record.guest_prepared {
                MMSYSERR_NOERROR
            } else if record.submission.is_some() {
                WAVERR_STILLPLAYING
            } else {
                WAVERR_UNPREPARED
            });
        }
        if self.wave_audio.headers.try_reserve(1).is_err() {
            return Ok(MMSYSERR_NOMEM);
        }
        let capture = match self.capture_wave_header(memory, header_far) {
            Ok(capture) => capture,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        if capture.header.flags != 0 {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let length = capture.header.buffer_length;
        if capture.header.data == 0 && length != 0 {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let initial = match direction {
            Win16WaveDirection::Output => {
                if capture.header.data == 0 {
                    Win16HostWaveInitialBuffer::Null
                } else {
                    let bytes = match read_wave_data(self, memory, capture.header.data, length) {
                        Ok(bytes) => bytes,
                        Err(error) if is_guest_api_failure(&error) => {
                            return Ok(MMSYSERR_INVALPARAM);
                        }
                        Err(error) => return Err(error),
                    };
                    Win16HostWaveInitialBuffer::Playback { bytes }
                }
            }
            Win16WaveDirection::Input => Win16HostWaveInitialBuffer::Capture {
                capacity: length,
                data_present: capture.header.data != 0,
            },
        };
        let data_range =
            if direction == Win16WaveDirection::Input && capture.header.data != 0 && length != 0 {
                match self.capture_wave_output(memory, capture.header.data, length as usize) {
                    Ok(range) => Some(range),
                    Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
        let data_input_range =
            if direction == Win16WaveDirection::Output && capture.header.data != 0 && length != 0 {
                let pointer = self
                    .selectors
                    .pointer_from_far(capture.header.data)
                    .map_err(crate::runtime_error)?;
                match GuestInputRange::capture(self, memory, pointer, length as usize) {
                    Ok(range) => Some(range),
                    Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
        let result = host.win16_wave(Win16HostWaveOperation::Prepare {
            device: device.host,
            initial,
            length,
            loops: capture.header.loops,
        })?;
        let Win16HostWaveResult::Header {
            result,
            buffer,
            state,
            ..
        } = result
        else {
            return Err(wave_invariant("WAVE prepare returned the wrong result"));
        };
        if result != MMSYSERR_NOERROR {
            return Ok(result);
        }
        let Some(host_buffer) = buffer else {
            return Err(wave_invariant(
                "successful WAVE prepare returned no header token",
            ));
        };
        let Some(header_state) = state else {
            return Err(wave_invariant(
                "successful WAVE prepare omitted native header state",
            ));
        };
        let record = WaveHeaderRecord {
            guest_handle,
            direction,
            host_device: device.host,
            host_buffer,
            header_far,
            data_far: capture.header.data,
            capacity: length,
            queued_length: 0,
            submission: None,
            header_range: capture.header_range,
            flags_range: capture.flags_range,
            bytes_recorded_range: capture.bytes_recorded_range,
            data_range,
            data_input_range,
            native_prepared: true,
            guest_prepared: true,
            native_queued: false,
            unprepare_state: None,
            unprepare_input_bytes: None,
            completion_projection: WaveCompletionProjection::Pending,
        };
        self.wave_audio.headers.push(record);
        self.commit_header_state(memory, host_buffer, header_state, None)?;
        Ok(result)
    }

    pub(super) fn wave_unprepare(
        &mut self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if size as usize != WAVEHDR16_SIZE {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let capture = match self.capture_wave_header(memory, header_far) {
            Ok(capture) => capture,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let Some(index) = self.wave_audio.headers.iter().position(|record| {
            record.guest_handle == guest_handle
                && record.header_far == header_far
                && record.direction == direction
        }) else {
            // Current WinMM treats UnprepareHeader on an already unprepared
            // valid header as a no-op. SDK 3.1's local header gives the ABI
            // shape but no contrary repeated-call rule, so follow that host
            // contract while keeping handle, size, and FAR validation above.
            return Ok(MMSYSERR_NOERROR);
        };
        let record = self.wave_audio.headers[index].clone();
        self.validate_header_record_ranges(&record, memory)?;
        if capture.header.data != record.data_far || capture.header.buffer_length > record.capacity
        {
            return Ok(MMSYSERR_INVALPARAM);
        }
        if !record.guest_prepared {
            if let Some(state) = record.unprepare_state {
                self.commit_header_state_for_record(
                    &record,
                    memory,
                    state,
                    record.unprepare_input_bytes.as_deref(),
                )?;
                if let Some(current) = self.wave_audio.headers.get_mut(index) {
                    current.unprepare_state = None;
                    current.unprepare_input_bytes = None;
                }
                if record.submission.is_none() {
                    self.retire_unprepared_wave_header_if_idle(
                        device.host,
                        device.generation,
                        guest_handle,
                        header_far,
                    );
                }
            }
            return Ok(MMSYSERR_NOERROR);
        }
        if record.submission.is_some() && capture.header.buffer_length != record.queued_length {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let result = if record.native_prepared {
            host.win16_wave(Win16HostWaveOperation::Unprepare {
                device: device.host,
                buffer: record.host_buffer,
            })?
        } else {
            return Err(wave_invariant(
                "guest-prepared WAVE header lost native prepared ownership",
            ));
        };
        let Win16HostWaveResult::Header {
            result,
            buffer,
            submission,
            completion_pending,
            state,
            input_bytes,
        } = result
        else {
            return Err(wave_invariant("WAVE unprepare returned the wrong result"));
        };
        if buffer != Some(record.host_buffer) {
            return Err(wave_invariant(
                "WAVE unprepare changed its native header identity",
            ));
        }
        if result != MMSYSERR_NOERROR {
            if completion_pending || input_bytes.is_some() {
                return Err(wave_invariant(
                    "failed WAVE unprepare returned completion output",
                ));
            }
            if record.submission.is_some() {
                if submission != record.submission {
                    return Err(wave_invariant(
                        "failed WAVE unprepare changed the active submission",
                    ));
                }
            } else if submission.is_some() {
                return Err(wave_invariant(
                    "idle WAVE unprepare returned a submission identity",
                ));
            }
            return Ok(result);
        }

        let Some(state) = state else {
            return Err(wave_invariant(
                "successful WAVE unprepare omitted native header state",
            ));
        };
        if record.submission.is_some() {
            if submission != record.submission || submission.is_none() {
                return Err(wave_invariant(
                    "successful WAVE unprepare changed its submission identity",
                ));
            }
            if !completion_pending
                || state.flags & WHDR_DONE == 0
                || state.bytes_recorded > record.queued_length
                || (direction == Win16WaveDirection::Input
                    && input_bytes
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() != state.bytes_recorded as usize))
                || (direction == Win16WaveDirection::Output && input_bytes.is_some())
            {
                return Err(wave_invariant(
                    "successful WAVE unprepare returned invalid completion projection",
                ));
            }
        } else {
            if submission.is_some() || completion_pending || input_bytes.is_some() {
                return Err(wave_invariant(
                    "idle WAVE unprepare returned completion state",
                ));
            }
        };
        {
            let current = self.wave_audio.headers.get_mut(index).ok_or_else(|| {
                wave_invariant("unprepared WAVE header disappeared from runtime table")
            })?;
            current.native_prepared = false;
            current.guest_prepared = false;
            current.native_queued = false;
            current.unprepare_state = Some(state);
            current.unprepare_input_bytes = input_bytes;
            if record.submission.is_some() {
                current.completion_projection = WaveCompletionProjection::Pending;
            }
        }
        self.commit_header_state_for_record(
            &record,
            memory,
            state,
            self.wave_audio.headers[index]
                .unprepare_input_bytes
                .as_deref(),
        )?;
        {
            let current = self
                .wave_audio
                .headers
                .get_mut(index)
                .ok_or_else(|| wave_invariant("successfully unprepared WAVE header disappeared"))?;
            current.unprepare_state = None;
            current.unprepare_input_bytes = None;
            if record.submission.is_some() {
                current.completion_projection = WaveCompletionProjection::Committed(state);
            }
        }
        if record.submission.is_none() {
            self.retire_unprepared_wave_header_if_idle(
                device.host,
                device.generation,
                guest_handle,
                header_far,
            );
        }
        Ok(result)
    }

    pub(super) fn wave_submit(
        &mut self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if size as usize != WAVEHDR16_SIZE {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let capture = match self.capture_wave_header(memory, header_far) {
            Ok(capture) => capture,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let Some(index) = self.wave_audio.headers.iter().position(|record| {
            record.guest_handle == guest_handle
                && record.header_far == header_far
                && record.direction == direction
        }) else {
            return Ok(WAVERR_UNPREPARED);
        };
        let record = self.wave_audio.headers[index].clone();
        self.validate_header_record_ranges(&record, memory)?;
        if capture.header.data != record.data_far || capture.header.buffer_length > record.capacity
        {
            return Ok(MMSYSERR_INVALPARAM);
        }
        if !record.guest_prepared {
            return Ok(WAVERR_UNPREPARED);
        }
        if record.native_queued || record.submission.is_some() {
            return Ok(WAVERR_STILLPLAYING);
        }
        let length = capture.header.buffer_length;
        let operation = match direction {
            Win16WaveDirection::Output => {
                let bytes = if capture.header.data == 0 {
                    Vec::new()
                } else {
                    match read_wave_data(self, memory, capture.header.data, length) {
                        Ok(bytes) => bytes,
                        Err(error) if is_guest_api_failure(&error) => {
                            return Ok(MMSYSERR_INVALPARAM);
                        }
                        Err(error) => return Err(error),
                    }
                };
                Win16HostWaveSubmit::Playback {
                    bytes,
                    length,
                    flags: capture.header.flags,
                    loops: capture.header.loops,
                }
            }
            Win16WaveDirection::Input => Win16HostWaveSubmit::Capture {
                length,
                flags: capture.header.flags,
            },
        };
        let result = host.win16_wave(Win16HostWaveOperation::Submit {
            device: device.host,
            buffer: record.host_buffer,
            operation,
        })?;
        let Win16HostWaveResult::Header {
            result,
            buffer,
            submission,
            completion_pending,
            state,
            input_bytes,
        } = result
        else {
            return Err(wave_invariant("WAVE submit returned the wrong result"));
        };
        if buffer != Some(record.host_buffer) {
            return Err(wave_invariant(
                "WAVE submit changed its native header identity",
            ));
        }
        let submission = match (result == MMSYSERR_NOERROR, submission) {
            (true, Some(submission)) => Some(submission),
            (true, None) => {
                return Err(wave_invariant(
                    "successful WAVE submit omitted its submission identity",
                ));
            }
            (false, None) => None,
            (false, Some(_)) => {
                return Err(wave_invariant(
                    "failed WAVE submit returned a live submission identity",
                ));
            }
        };
        if result == MMSYSERR_NOERROR {
            let current = self.wave_audio.headers.get_mut(index).ok_or_else(|| {
                wave_invariant("submitted WAVE header disappeared from runtime table")
            })?;
            // Commit native acceptance before any guest projection can fail;
            // cleanup and callback polling must retain this exact generation.
            current.native_queued = state.is_none_or(|state| state.flags & WHDR_INQUEUE != 0);
            current.queued_length = length;
            current.submission = submission;
            current.completion_projection = WaveCompletionProjection::Pending;
        }
        if (result == MMSYSERR_NOERROR && !completion_pending)
            || input_bytes.is_some()
            || (result != MMSYSERR_NOERROR && completion_pending)
        {
            return Err(wave_invariant(
                "WAVE submit returned invalid completion ownership",
            ));
        }
        if let Some(state) = state {
            let completion_already_visible =
                result == MMSYSERR_NOERROR && state.flags & WHDR_DONE != 0;
            if !completion_already_visible {
                self.commit_header_state(memory, record.host_buffer, state, None)?;
            }
        } else if result == MMSYSERR_NOERROR {
            return Err(wave_invariant(
                "successful WAVE submit omitted native header state",
            ));
        }
        Ok(result)
    }

    pub(super) fn wave_get_position(
        &self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        time_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if usize::from(size) < MMTIME16_SIZE {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let Some(device) = self.wave_audio.device(guest_handle, direction) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let output = match self.capture_wave_output(memory, time_far, MMTIME16_SIZE) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let initial = output.read(self, memory)?;
        let requested_time = u32::from(u16::from_le_bytes([initial[0], initial[1]]));
        let reply = host.win16_wave(Win16HostWaveOperation::GetPosition {
            device: device.host,
            requested_time,
        })?;
        let Win16HostWaveResult::Position { result, position } = reply else {
            return Err(wave_invariant(
                "WAVE GetPosition returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if position.is_some() {
                return Err(wave_invariant("failed WAVE GetPosition returned time data"));
            }
            return Ok(result);
        }
        let Some(position) = position else {
            return Err(wave_invariant(
                "successful WAVE GetPosition omitted time data",
            ));
        };
        let time_type = u16::try_from(position.time_type).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "native WAVE position type does not fit Win16 MMTIME",
            )
        })?;
        let mut value = [0_u8; 6];
        value.copy_from_slice(&position.value[..6]);
        let encoded = Win16Mmtime16 {
            kind: time_type,
            value,
        }
        .encode();
        let mut writes = Vec::new();
        writes.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE position output",
                error,
            )
        })?;
        writes.push((output, wave_bytes(encoded)?));
        commit_guest_writes(self, memory, writes)?;
        Ok(result)
    }
}

pub(super) fn commit_one_wave_output(
    state: &Win16State,
    memory: &mut Memory,
    output: super::super::guest_ranges::GuestOutputRange,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let mut writes = Vec::new();
    writes.try_reserve_exact(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve single WAVE output transaction",
            error,
        )
    })?;
    writes.push((output, bytes));
    super::super::guest_ranges::commit_guest_writes(state, memory, writes)
}

fn host_wave_parameter(parameter: Win16WaveParameter) -> Option<Win16HostWaveParameter> {
    match parameter {
        Win16WaveParameter::Pitch => Some(Win16HostWaveParameter::Pitch),
        Win16WaveParameter::Volume => None,
        Win16WaveParameter::PlaybackRate => Some(Win16HostWaveParameter::PlaybackRate),
    }
}
