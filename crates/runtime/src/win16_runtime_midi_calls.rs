//! Synchronous MIDI ordinal projection and native WinMM result validation.

use guest_core::memory::Memory;
use win16_abi::{Win16MidiDirection as GuestDirection, Win16MidiHeader16,
    Win16MidiRequest as Request, MIDIHDR16_SIZE, MIDIINCAPS16_SIZE, MIDIOUTCAPS16_SIZE};

use super::{MidiCallbackRoute, MidiDeviceRecord, MidiHeaderRecord,
    CALLBACK_FUNCTION, CALLBACK_NULL, CALLBACK_TASK, CALLBACK_TYPEMASK, CALLBACK_WINDOW,
    MHDR_DONE, MHDR_INQUEUE, MHDR_PREPARED, MIDIERR_STILLPLAYING, MIDIERR_UNPREPARED,
    MMSYSERR_INVALFLAG, MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOMEM,
    MMSYSERR_NOERROR, MMSYSERR_NOTSUPPORTED};
use super::ranges::{self, MidiGuestRange};
use super::Win16State;
use crate::win16_runtime::far_callback;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMidiCall as HostCall, Win16HostMidiCaps as HostCaps,
    Win16HostMidiDirection as HostDirection, Win16HostMidiHeaderState as HostHeaderState,
    Win16HostMidiResult as HostResult};

impl Win16State {
    pub(in crate::win16_runtime) fn midi_api(
        &mut self,
        request: Request,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.retry_pending_midi_close_projections(memory, host)?;
        match request {
            Request::DeviceCount { direction } => {
                let result = host.win16_midi(HostCall::DeviceCount { direction: direction.into() })?;
                match result {
                    HostResult::Scalar(count) => u16::try_from(count).map(u32::from).map_err(|_| {
                        RuntimeError::new(Kind::CompatibilityGap,
                            "native MIDI device count does not fit the Win16 return word")
                    }),
                    _ => Err(midi_invariant("MIDI device count returned the wrong result shape")),
                }
            }
            Request::GetDeviceCaps { direction, device_id, output_far, size } =>
                self.midi_get_caps(direction, device_id, output_far, size, memory, host),
            Request::GetErrorText { direction, error, output_far, size } =>
                self.midi_get_error_text(direction, error, output_far, size, memory, host),
            Request::Open { direction, output_far, device_id, callback, instance, flags } =>
                self.midi_open(direction, output_far, device_id, callback, instance, flags, memory, host),
            Request::Close { direction, device } =>
                self.midi_close(direction, device, memory, host),
            Request::PrepareHeader { direction, device, header_far, size } =>
                self.midi_prepare(direction, device, header_far, size, memory, host),
            Request::UnprepareHeader { direction, device, header_far, size } =>
                self.midi_unprepare(direction, device, header_far, size, memory, host),
            Request::OutputShortMessage { device, message } => {
                let Some(device) = self.midi_host(HostDirection::Output, device) else {
                    return Ok(MMSYSERR_INVALHANDLE);
                };
                self.midi_scalar(HostCall::OutputShort {
                    device, message,
                }, host)
            }
            Request::OutputLongMessage { device, header_far, size } =>
                self.midi_output_long(device, header_far, size, memory, host),
            Request::OutputReset { device } => {
                let Some(device) = self.midi_host(HostDirection::Output, device) else {
                    return Ok(MMSYSERR_INVALHANDLE);
                };
                self.midi_scalar(HostCall::OutputReset { device }, host)
            }
            Request::OutputGetVolume { device, output_far } =>
                self.midi_get_volume(device, output_far, memory, host),
            Request::OutputSetVolume { device, volume } => self.midi_scalar(
                HostCall::OutputSetVolumeById { device_id: device, volume }, host),
            Request::OutputCachePatches { device, bank, patches_far, flags } =>
                self.midi_cache_patches(device, bank, patches_far, flags, false, memory, host),
            Request::OutputCacheDrumPatches { device, patch, keys_far, flags } =>
                self.midi_cache_drum_patches(device, patch, keys_far, flags, memory, host),
            Request::GetId { direction, device, output_far } =>
                self.midi_get_id(direction, device, output_far, memory, host),
            Request::DriverMessage { direction, device, message: _, parameter1: _, parameter2: _ } => {
                if self.midi.device(device, direction.into()).is_none() {
                    return Ok(MMSYSERR_INVALHANDLE);
                }
                self.warn_midi_gap(host, 216 + u16::from(direction == GuestDirection::Input) * 97,
                    "Win16 MIDI driver-message pointer semantics are not forwarded");
                Ok(MMSYSERR_NOTSUPPORTED)
            }
            Request::InputAddBuffer { device, header_far, size } =>
                self.midi_input_add_buffer(device, header_far, size, memory, host),
            Request::InputStart { device } => {
                let Some(device) = self.midi_host(HostDirection::Input, device) else {
                    return Ok(MMSYSERR_INVALHANDLE);
                };
                self.midi_scalar(HostCall::InputStart { device }, host)
            }
            Request::InputStop { device } => {
                let Some(device) = self.midi_host(HostDirection::Input, device) else {
                    return Ok(MMSYSERR_INVALHANDLE);
                };
                self.midi_scalar(HostCall::InputStop { device }, host)
            }
            Request::InputReset { device } => {
                let Some(device) = self.midi_host(HostDirection::Input, device) else {
                    return Ok(MMSYSERR_INVALHANDLE);
                };
                self.midi_scalar(HostCall::InputReset { device }, host)
            }
            Request::StreamUnsupported { ordinal, arguments: _ } => {
                self.warn_midi_gap(host, ordinal,
                    "Win16 MIDI stream wire structures are absent from the Windows 3.1 SDK");
                Ok(MMSYSERR_NOTSUPPORTED)
            }
        }
    }

    pub(super) fn midi_host(&self, direction: HostDirection, guest: u16)
        -> Option<crate::Win16HostMidiDevice>
    {
        self.midi.device(guest, direction).map(|record| record.host)
    }

    fn midi_scalar(
        &mut self,
        call: HostCall,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match host.win16_midi(call)? {
            HostResult::Scalar(result) => Ok(result),
            _ => Err(midi_invariant("MIDI scalar operation returned the wrong result shape")),
        }
    }

    fn midi_get_caps(
        &mut self,
        direction: GuestDirection,
        device_id: u16,
        output_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let expected = if direction == GuestDirection::Input {
            MIDIINCAPS16_SIZE
        } else {
            MIDIOUTCAPS16_SIZE
        };
        let output_length = usize::from(size).min(expected);
        let output = match self.capture_midi_range(memory, output_far, output_length, false, true) {
            Ok(output) => output,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let response = host.win16_midi(HostCall::GetCaps {
            direction: direction.into(), device_id, size,
        })?;
        let HostResult::Caps { result, caps } = response else {
            return Err(midi_invariant("MIDI capabilities returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if caps.is_some() { return Err(midi_invariant("failed MIDI caps query returned data")); }
            return Ok(result);
        }
        let Some(caps) = caps else {
            return Err(midi_invariant("successful MIDI caps query returned no record"));
        };
        let bytes = match (direction, caps) {
            (GuestDirection::Input, HostCaps::Input { manufacturer, product,
                driver_version, product_name }) => win16_abi::Win16MidiInCaps16 {
                    manufacturer, product, driver_version, product_name,
                }.encode().to_vec(),
            (GuestDirection::Output, HostCaps::Output { manufacturer, product,
                driver_version, product_name, technology, voices, notes,
                channel_mask, support }) => win16_abi::Win16MidiOutCaps16 {
                    manufacturer, product, driver_version, product_name,
                    technology, voices, notes, channel_mask, support,
                }.encode().to_vec(),
            _ => return Err(midi_invariant("MIDI caps direction did not match request")),
        };
        output.commit(self, memory, &bytes[..output_length])?;
        Ok(result)
    }

    fn midi_get_error_text(
        &mut self,
        direction: GuestDirection,
        error: u16,
        output_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match self.capture_midi_range(memory, output_far, usize::from(size), false, true) {
            Ok(output) => output,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let response = host.win16_midi(HostCall::GetErrorText {
            direction: direction.into(), error, capacity: size,
        })?;
        let HostResult::ErrorText { result, bytes } = response else {
            return Err(midi_invariant("MIDI error-text query returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if !bytes.is_empty() { return Err(midi_invariant("failed MIDI error-text query returned bytes")); }
            return Ok(result);
        }
        if bytes.len() > usize::from(size) {
            return Err(midi_invariant("MIDI error text exceeded guest capacity"));
        }
        output.commit(self, memory, &bytes)?;
        Ok(result)
    }

    fn midi_open(
        &mut self,
        direction: GuestDirection,
        output_far: u32,
        device_id: u16,
        callback_far: u32,
        instance: u32,
        flags: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if output_far == 0 { return Ok(MMSYSERR_INVALPARAM); }
        let output = match self.capture_midi_range(memory, output_far, 2, false, true) {
            Ok(output) => output,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let guest_direction = HostDirection::from(direction);
        let callback_mode = flags & CALLBACK_TYPEMASK;
        let callback_route = match callback_mode {
            CALLBACK_NULL => MidiCallbackRoute::None,
            CALLBACK_FUNCTION => {
                if callback_far == 0 { return Ok(MMSYSERR_INVALPARAM); }
                match self.register_guest_callback(memory, callback_far,
                    far_callback::Win16FarCallbackConvention::Pascal,
                    far_callback::Win16FarCallbackReturn::Void)
                {
                    Ok(callback) => MidiCallbackRoute::Function(callback),
                    Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
                    Err(error) => return Err(error),
                }
            }
            CALLBACK_WINDOW => {
                let Ok(window) = u16::try_from(callback_far) else { return Ok(MMSYSERR_INVALPARAM); };
                let Some(host_window) = self.window_handles.get(&window).copied() else {
                    return Ok(MMSYSERR_INVALPARAM);
                };
                MidiCallbackRoute::Window { host: host_window, guest: window }
            }
            CALLBACK_TASK => {
                let Ok(task) = u16::try_from(callback_far) else { return Ok(MMSYSERR_INVALPARAM); };
                let Some(identity) = self.midi_task_identity(task) else {
                    return Ok(MMSYSERR_INVALPARAM);
                };
                MidiCallbackRoute::Task(identity)
            }
            _ => return Ok(MMSYSERR_INVALFLAG),
        };
        if self.midi.devices.try_reserve(1).is_err() {
            unregister_route(self, callback_route);
            return Ok(MMSYSERR_NOMEM);
        }
        let Some(guest_handle) = self.midi.reserve_guest_device() else {
            unregister_route(self, callback_route);
            return Ok(MMSYSERR_NOMEM);
        };
        if self.current_midi_task_identity().is_none() {
            unregister_route(self, callback_route);
            return Err(midi_invariant(
                "current Win16 MIDI owner task has no live selector identity",
            ));
        }
        let response = host.win16_midi(HostCall::Open {
            direction: guest_direction, device_id, instance, flags,
        });
        let (result, native_device) = match response {
            Ok(HostResult::Opened { result, device }) => (result, device),
            Ok(_) => {
                unregister_route(self, callback_route);
                return Err(midi_invariant("MIDI open returned the wrong result shape"));
            }
            Err(error) => {
                unregister_route(self, callback_route);
                return Err(error);
            }
        };
        if result != MMSYSERR_NOERROR {
            if native_device.is_some() {
                return Err(midi_invariant("failed MIDI open returned a live device"));
            }
            unregister_route(self, callback_route);
            return Ok(result);
        }
        let Some(native_device) = native_device else {
            unregister_route(self, callback_route);
            return Err(midi_invariant("successful MIDI open returned no device token"));
        };
        let device = MidiDeviceRecord {
            guest: guest_handle, direction: guest_direction, host: native_device,
            callback: callback_route, instance, closing: false,
            reset_result: None, close_result: None,
            reset_failure_result: None,
            close_seen: false,
        };
        self.midi.devices.push(device);
        if let Err(primary) = output.commit(self, memory, &guest_handle.to_le_bytes()) {
            let pointer_invalid = is_guest_pointer_error(&primary);
            let rollback = host.win16_midi(HostCall::CloseUnpublished { device: native_device });
            self.midi.devices.retain(|record| record.host != native_device);
            unregister_route(self, callback_route);
            match rollback {
                Ok(HostResult::Closed {
                    result: MMSYSERR_NOERROR,
                    retired_headers,
                    reset_result: None,
                    unprepare_header: None,
                    unprepare_result: None,
                    close_result: Some(MMSYSERR_NOERROR),
                }) => {
                    if !retired_headers.is_empty() {
                        return Err(midi_cleanup_failure(primary, midi_invariant(
                            "unpublished MIDI open rollback retired unexpected headers")));
                    }
                    if pointer_invalid { return Ok(MMSYSERR_INVALPARAM); }
                    return Err(primary);
                }
                Ok(HostResult::Closed {
                    result,
                    retired_headers,
                    reset_result,
                    unprepare_header,
                    unprepare_result,
                    close_result,
                }) => {
                    let cleanup = RuntimeError::with_source(Kind::HostFailure,
                        "midiOpen unpublished-owner rollback returned a native failure",
                        NativeMidiResult(result));
                    let cleanup = if retired_headers.is_empty()
                        && unprepare_header.is_none()
                        && unprepare_result.is_none()
                        && reset_result.is_none()
                        && close_result == Some(result)
                        && result != MMSYSERR_NOERROR
                    { cleanup } else {
                        midi_cleanup_failure(cleanup, midi_invariant(
                            "failed unpublished MIDI rollback retired headers"))
                    };
                    return Err(midi_cleanup_failure(primary, cleanup));
                }
                Ok(_) => return Err(midi_cleanup_failure(primary,
                    midi_invariant("MIDI open rollback returned the wrong result shape"))),
                Err(cleanup) => return Err(midi_cleanup_failure(primary, cleanup)),
            }
        }
        Ok(MMSYSERR_NOERROR)
    }

    fn midi_close(
        &mut self,
        direction: GuestDirection,
        guest: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.close_midi_device(direction, guest, memory, host)
    }

    fn midi_prepare(
        &mut self,
        direction: GuestDirection,
        guest_device: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let direction = HostDirection::from(direction);
        let Some(device) = self.midi.device(guest_device, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if usize::from(size) != MIDIHDR16_SIZE { return Ok(MMSYSERR_INVALPARAM); }
        if let Some(record) = self.midi.header(guest_device, header_far).cloned() {
            if record.host_device != device.host || record.direction != direction {
                return Ok(MIDIERR_UNPREPARED);
            }
            match (record.prepared, record.retired) {
                (true, false) => {
                    match self.validate_prepared_header(&record, memory) {
                        Ok(_) => return Ok(MMSYSERR_NOERROR),
                        Err(error) if is_guest_pointer_error(&error) => {
                            return Ok(MMSYSERR_INVALPARAM);
                        }
                        Err(error) => return Err(error),
                    }
                }
                (false, true) => {
                    if !self.recycle_retired_midi_header(
                        guest_device, header_far, memory, host,
                    )? {
                        return Ok(MIDIERR_STILLPLAYING);
                    }
                }
                (false, false) => return Ok(MIDIERR_UNPREPARED),
                (true, true) => return Err(midi_invariant(
                    "Win16 MIDI header is both prepared and retired")),
            }
        }
        let (header, header_range, data_range) =
            match self.capture_header(header_far, memory, direction) {
                Ok(value) => value,
                Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
                Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(MMSYSERR_NOMEM),
                Err(error) => return Err(error),
            };
        if direction == HostDirection::Output && header.buffer_length > 0
            && header.data == 0 { return Ok(MMSYSERR_INVALPARAM); }
        let initial_data = if direction == HostDirection::Output {
            match data_range.read(self, memory) {
                Ok(bytes) => bytes,
                Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
                Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(MMSYSERR_NOMEM),
                Err(error) => return Err(error),
            }
        } else {
            Vec::new()
        };
        self.midi.headers.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 MIDI header ledger", error))?;
        let response = host.win16_midi(HostCall::PrepareHeader {
            device: device.host, capacity: header.buffer_length, user: header.user, initial_data,
        })?;
        let HostResult::Header { result, state } = response else {
            return Err(midi_invariant("MIDI prepare-header returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if state.is_some() { return Err(midi_invariant("failed MIDI prepare returned a header token")); }
            return Ok(result);
        }
        let Some(state) = state else {
            return Err(midi_invariant("successful MIDI prepare returned no header token"));
        };
        verify_header_state(&state, header.buffer_length)?;
        let record = MidiHeaderRecord {
            guest_device, direction, host_device: device.host, host_header: state.header,
            header_far, data_far: header.data, capacity: header.buffer_length, user: header.user,
            guest_flags: header.flags, submission: state.submission,
            completed_pending: None, header_range,
            data_range, prepared: true, retired: false, pending_close_projection: None,
            pending_close_native_result: None, close_projection_committed: false,
            pending_unprepare_projection: None, pending_unprepare_native_result: None,
            pending_unprepare_failure: None,
        };
        self.midi.headers.push(record.clone());
        self.commit_midi_header_state(&record, &state, None, memory)?;
        Ok(result)
    }

    fn midi_output_long(
        &mut self,
        guest_device: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.midi.device(guest_device, HostDirection::Output).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if usize::from(size) != MIDIHDR16_SIZE { return Ok(MMSYSERR_INVALPARAM); }
        let Some(record) = self.midi.header(guest_device, header_far).cloned() else {
            return Ok(MIDIERR_UNPREPARED);
        };
        if record.direction != HostDirection::Output || record.host_device != device.host
            || !record.prepared { return Ok(MIDIERR_UNPREPARED); }
        if record.submission.is_some() || record.completed_pending.is_some() {
            return Ok(MIDIERR_STILLPLAYING);
        }
        match self.validate_prepared_header(&record, memory) {
            Ok(_) => {}
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        }
        let data = match record.data_range.read(self, memory) {
            Ok(bytes) => bytes,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(MMSYSERR_NOMEM),
            Err(error) => return Err(error),
        };
        let response = host.win16_midi(HostCall::OutputLong {
            device: device.host, header: record.host_header, data,
        })?;
        let HostResult::Header { result, state } = response else {
            return Err(midi_invariant("MIDI long-output returned the wrong result shape"));
        };
        if result == MMSYSERR_NOERROR {
            let Some(state) = state else { return Err(midi_invariant(
                "successful MIDI long-output returned no header state")); };
            verify_header_state(&state, record.capacity)?;
            if state.submission.is_none() {
                return Err(midi_invariant("successful MIDI long-output has no submission identity"));
            }
            if let Some(header) = self.midi.header_mut(guest_device, header_far) {
                header.submission = state.submission;
                header.guest_flags = state.flags;
            }
            self.commit_midi_header_state(&record, &state, None, memory)?;
        } else if state.is_some() {
            return Err(midi_invariant("failed MIDI long-output returned a changed header"));
        }
        Ok(result)
    }

    fn midi_input_add_buffer(
        &mut self,
        guest_device: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.midi.device(guest_device, HostDirection::Input).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if usize::from(size) != MIDIHDR16_SIZE { return Ok(MMSYSERR_INVALPARAM); }
        let Some(record) = self.midi.header(guest_device, header_far).cloned() else {
            return Ok(MIDIERR_UNPREPARED);
        };
        if record.direction != HostDirection::Input || record.host_device != device.host
            || !record.prepared { return Ok(MIDIERR_UNPREPARED); }
        if record.submission.is_some() || record.completed_pending.is_some() {
            return Ok(MIDIERR_STILLPLAYING);
        }
        if record.capacity != 0 && record.data_far == 0 { return Ok(MMSYSERR_INVALPARAM); }
        match self.validate_prepared_header(&record, memory) {
            Ok(_) => {}
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        }
        let response = host.win16_midi(HostCall::InputAddBuffer {
            device: device.host, header: record.host_header,
        })?;
        let HostResult::Header { result, state } = response else {
            return Err(midi_invariant("MIDI input add-buffer returned the wrong result shape"));
        };
        if result == MMSYSERR_NOERROR {
            let Some(state) = state else { return Err(midi_invariant(
                "successful MIDI input add-buffer returned no header state")); };
            verify_header_state(&state, record.capacity)?;
            if state.submission.is_none() {
                return Err(midi_invariant("successful MIDI input add-buffer has no submission identity"));
            }
            if let Some(header) = self.midi.header_mut(guest_device, header_far) {
                header.submission = state.submission;
                header.guest_flags = state.flags;
            }
            self.commit_midi_header_state(&record, &state, None, memory)?;
        } else if state.is_some() {
            return Err(midi_invariant("failed MIDI input add-buffer returned a changed header"));
        }
        Ok(result)
    }

    fn capture_header(
        &self,
        header_far: u32,
        memory: &Memory,
        direction: HostDirection,
    ) -> Result<(Win16MidiHeader16, MidiGuestRange, MidiGuestRange), RuntimeError> {
        if header_far == 0 { return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 MIDIHDR pointer is NULL")); }
        let header_range = self.capture_midi_range(memory, header_far, MIDIHDR16_SIZE, true, true)?;
        let bytes = header_range.read(self, memory)?;
        let header = Win16MidiHeader16::decode(&bytes).ok_or_else(|| midi_invariant(
            "MIDIHDR16 fixed wire decoder rejected its captured size"))?;
        let data_length = usize::try_from(header.buffer_length).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "Win16 MIDI buffer length exceeds host address width", error))?;
        let data_range = MidiGuestRange::capture(self, memory, header.data, data_length,
            direction == HostDirection::Output, direction == HostDirection::Input)?;
        Ok((header, header_range, data_range))
    }

    pub(super) fn commit_midi_header_state(
        &self,
        record: &MidiHeaderRecord,
        state: &HostHeaderState,
        input_bytes: Option<&[u8]>,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if state.header != record.host_header || state.capacity != record.capacity {
            return Err(midi_invariant("MIDI header state changed identity or capacity"));
        }
        if let Some(bytes) = input_bytes {
            if bytes.len() != state.bytes_recorded as usize || bytes.len() > record.capacity as usize {
                return Err(midi_invariant("MIDI input completion bytes do not match its header"));
            }
        }
        let mut raw = record.header_range.read(self, memory)?;
        let mut header = Win16MidiHeader16::decode(&raw)
            .ok_or_else(|| midi_invariant("captured guest MIDIHDR changed size"))?;
        if header.data != record.data_far || header.buffer_length != record.capacity {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDIHDR data identity changed while prepared"));
        }
        // dwUser belongs to the guest application; keep the freshly read value
        // and project only host-owned count/flag fields below.
        header.bytes_recorded = state.bytes_recorded;
        header.flags = (header.flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
            | (state.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
        raw.copy_from_slice(&header.encode());
        match input_bytes {
            Some(bytes) => ranges::commit_ranges(self, memory, &[
                (&record.data_range, bytes),
                (&record.header_range, raw.as_slice()),
            ]),
            None => record.header_range.commit(self, memory, &raw),
        }
    }

    pub(super) fn validate_prepared_header(
        &self,
        record: &MidiHeaderRecord,
        memory: &Memory,
    ) -> Result<Win16MidiHeader16, RuntimeError> {
        if !record.prepared || record.retired {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDI header is no longer prepared"));
        }
        record.header_range.is_live(self, memory)?;
        record.data_range.is_live(self, memory)?;
        let bytes = record.header_range.read(self, memory)?;
        let header = Win16MidiHeader16::decode(&bytes).ok_or_else(|| midi_invariant(
            "captured Win16 MIDIHDR no longer has its fixed ABI size"))?;
        if header.data != record.data_far || header.buffer_length != record.capacity {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDIHDR data pointer or capacity changed after prepare"));
        }
        Ok(header)
    }

    pub(super) fn capture_midi_range(
        &self,
        memory: &Memory,
        far: u32,
        size: usize,
        read: bool,
        write: bool,
    ) -> Result<MidiGuestRange, RuntimeError> {
        MidiGuestRange::capture(self, memory, far, size, read, write)
    }

    pub(super) fn warn_midi_gap(&mut self, host: &mut impl RuntimeHost, ordinal: u16, message: &str) {
        if self.midi.warned_gap(ordinal) {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message.to_owned()));
        }
    }
}

fn verify_header_state(state: &HostHeaderState, capacity: u32) -> Result<(), RuntimeError> {
    if state.capacity != capacity || state.bytes_recorded > capacity
        || state.completed_submission.is_some() || state.callback_pending
    {
        return Err(midi_invariant("native MIDI header returned an invalid extent"));
    }
    if state.submission.is_some() && state.flags & (MHDR_INQUEUE | MHDR_DONE) == 0 {
        return Err(midi_invariant("successful MIDI submission is neither queued nor already complete"));
    }
    Ok(())
}

fn unregister_route(state: &mut Win16State, route: MidiCallbackRoute) {
    if let MidiCallbackRoute::Function(token) = route {
        state.unregister_guest_callback(token);
    }
}

pub(super) fn is_guest_pointer_error(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

pub(super) fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn midi_cleanup_failure(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup("MIDI operation and cleanup both failed", cleanup)
}

#[derive(Debug)]
pub(super) struct NativeMidiResult(pub(super) u32);

impl std::fmt::Display for NativeMidiResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "WinMM returned MMRESULT {}", self.0)
    }
}

impl std::error::Error for NativeMidiResult {}

impl From<GuestDirection> for HostDirection {
    fn from(value: GuestDirection) -> Self {
        match value { GuestDirection::Input => Self::Input, GuestDirection::Output => Self::Output }
    }
}
