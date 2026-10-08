//! Synchronous WinMM calls with exact opaque MIDI identities.

use std::mem::size_of;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use runtime::{
    DiagnosticKind as Kind, RuntimeError,
    Win16HostMidiCaps as Caps, Win16HostMidiCloseAll, Win16HostMidiCloseFailure,
    Win16HostMidiClosedDevice,
    Win16HostMidiCancellationReason,
    Win16HostMidiDevice as DeviceToken,
    Win16HostMidiDirection as Direction, Win16HostMidiHeader as HeaderToken,
    Win16HostMidiHeaderState as HeaderState,
    Win16HostMidiMixerId, Win16HostMidiNotificationDisposition as Disposition,
    Win16HostMidiResult as ResultValue,
};
use windows_sys::Win32::Media::Audio::{
    CALLBACK_FUNCTION, HMIDIIN, HMIDIOUT, MIDIINCAPSW,
    MIDIOUTCAPSW, MIDIHDR, MIDI_WAVE_OPEN_TYPE, MIXER_OBJECTF_HANDLE, MIXER_OBJECTF_MIDIIN,
    MIXER_OBJECTF_MIDIOUT, midiInClose, midiInGetDevCapsW, midiInGetErrorTextW,
    midiInGetID, midiInGetNumDevs, midiInOpen, midiInReset, midiInStart, midiInStop,
    midiInUnprepareHeader, midiOutCacheDrumPatches, midiOutCachePatches, midiOutClose,
    midiOutGetDevCapsW, midiOutGetErrorTextW, midiOutGetID, midiOutGetNumDevs,
    midiOutGetVolume, midiOutOpen, midiOutReset, midiOutSetVolume, midiOutShortMsg,
    midiOutUnprepareHeader, mixerGetID,
};
use windows_sys::Win32::Media::{MM_MIM_CLOSE, MM_MOM_CLOSE};
use super::super::guest_text::GuestTextCodec;

use super::{
    MidiDevice, MidiDirection, NativeMidiHandle, Win16MidiHost, direction,
    invalid_device, native_handle_matches,
};
use super::callback::{self, CallbackContext};
use super::errors::host_result;

const MIDI_CACHE_QUERY: u16 = 3;
const MIDI_CACHE_ALL: u16 = 1;
const MIDI_CACHE_BESTFIT: u16 = 2;
const MIDI_UNCACHE: u16 = 4;
const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_NOMEM: u32 = 7;
const MIDI_MAPPER_GUEST: u16 = u16::MAX;
const CALLBACK_FLAGS: u32 = 0x0007_0000;

pub(super) fn device_count(direction: Direction) -> Result<ResultValue, RuntimeError> {
    // Win16 and the host expose a WORD/UINT device count respectively; the
    // runtime checks the projection before it writes a guest-visible value.
    let count = unsafe { match direction {
        Direction::Input => midiInGetNumDevs(),
        Direction::Output => midiOutGetNumDevs(),
    }};
    Ok(ResultValue::Scalar(count))
}

pub(super) fn get_caps(
    direction: Direction,
    device_id: u16,
    codec: GuestTextCodec,
) -> Result<ResultValue, RuntimeError> {
    let native_id = native_device_id(device_id);
    match direction {
        Direction::Input => {
            let mut native = MIDIINCAPSW::default();
            let result = unsafe { midiInGetDevCapsW(native_id, &mut native, size_of::<MIDIINCAPSW>() as u32) };
            if result != 0 { return Ok(ResultValue::Caps { result, caps: None }); }
            // MIDIINCAPSW is packed by windows-sys; read fields unaligned.
            let manufacturer = unsafe { ptr::addr_of!(native.wMid).read_unaligned() };
            let product = unsafe { ptr::addr_of!(native.wPid).read_unaligned() };
            let raw_version = unsafe { ptr::addr_of!(native.vDriverVersion).read_unaligned() };
            let name = unsafe { ptr::addr_of!(native.szPname).read_unaligned() };
            let version = u16::try_from(raw_version).map_err(|error| RuntimeError::with_source(
                Kind::CompatibilityGap, "native MIDI input version does not fit Win16 VERSION", error))?;
            Ok(ResultValue::Caps { result, caps: Some(Caps::Input {
                manufacturer,
                product,
                driver_version: version,
                product_name: guest_product_name(codec, name)?,
            }) })
        }
        Direction::Output => {
            let mut native = MIDIOUTCAPSW::default();
            let result = unsafe { midiOutGetDevCapsW(native_id, &mut native, size_of::<MIDIOUTCAPSW>() as u32) };
            if result != 0 { return Ok(ResultValue::Caps { result, caps: None }); }
            // MIDIOUTCAPSW is packed by windows-sys; read fields unaligned.
            let manufacturer = unsafe { ptr::addr_of!(native.wMid).read_unaligned() };
            let product = unsafe { ptr::addr_of!(native.wPid).read_unaligned() };
            let raw_version = unsafe { ptr::addr_of!(native.vDriverVersion).read_unaligned() };
            let name = unsafe { ptr::addr_of!(native.szPname).read_unaligned() };
            let technology = unsafe { ptr::addr_of!(native.wTechnology).read_unaligned() };
            let voices = unsafe { ptr::addr_of!(native.wVoices).read_unaligned() };
            let notes = unsafe { ptr::addr_of!(native.wNotes).read_unaligned() };
            let channel_mask = unsafe { ptr::addr_of!(native.wChannelMask).read_unaligned() };
            let support = unsafe { ptr::addr_of!(native.dwSupport).read_unaligned() };
            let version = u16::try_from(raw_version).map_err(|error| RuntimeError::with_source(
                Kind::CompatibilityGap, "native MIDI output version does not fit Win16 VERSION", error))?;
            Ok(ResultValue::Caps { result, caps: Some(Caps::Output {
                manufacturer,
                product,
                driver_version: version,
                product_name: guest_product_name(codec, name)?,
                technology,
                voices,
                notes,
                channel_mask,
                support,
            }) })
        }
    }
}

fn guest_product_name<const N: usize>(
    codec: GuestTextCodec,
    name: [u16; N],
) -> Result<[u8; N], RuntimeError> {
    let length = name.iter().position(|unit| *unit == 0).unwrap_or(N);
    let encoded = codec.from_wide_bounded(&name[..length], N.saturating_sub(1))?;
    let mut bytes = [0; N];
    bytes[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(bytes)
}

pub(super) fn get_error_text(
    direction: Direction,
    error: u16,
    capacity: u16,
    codec: GuestTextCodec,
) -> Result<ResultValue, RuntimeError> {
    let capacity = usize::from(capacity);
    let mut wide = Vec::new();
    wide.try_reserve_exact(capacity).map_err(|source| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve native MIDI error-text buffer", source,
    ))?;
    wide.resize(capacity, 0);
    let pointer = if wide.is_empty() { std::ptr::null_mut() } else { wide.as_mut_ptr() };
    let result = unsafe { match direction {
        Direction::Input => midiInGetErrorTextW(u32::from(error), pointer, capacity as u32),
        Direction::Output => midiOutGetErrorTextW(u32::from(error), pointer, capacity as u32),
    }};
    if result != 0 { return Ok(ResultValue::ErrorText { result, bytes: Vec::new() }); }
    if capacity == 0 {
        return Ok(ResultValue::ErrorText { result, bytes: Vec::new() });
    }
    let text_length = wide.iter().position(|unit| *unit == 0).unwrap_or(wide.len());
    let encoded = codec.from_wide_bounded(&wide[..text_length], capacity - 1)?;
    let mut bytes = encoded.bytes;
    bytes.try_reserve(1).map_err(|source| RuntimeError::with_source(
        Kind::ResourceExhausted, "terminate guest MIDI error text", source,
    ))?;
    bytes.push(0);
    Ok(ResultValue::ErrorText { result, bytes })
}

impl Win16MidiHost {
    pub(super) fn open(
        &mut self,
        guest_direction: Direction,
        device_id: u16,
        guest_instance: u32,
        flags: u32,
    ) -> Result<ResultValue, RuntimeError> {
        self.devices.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native MIDI device owner", error))?;
        self.unpublished_callbacks.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve native MIDI callback-only owner", error))?;
        let token = self.allocate_pair(|token, generation| DeviceToken { token, generation })?;
        let context_id = usize::try_from(token.token).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "native MIDI callback context exceeds pointer width", error))?;
        let context = Arc::new(CallbackContext::new(
            Arc::clone(&self.event_sequences), self.wake.clone(),
            Arc::clone(&self.queue_wake)));
        callback::register(context_id, Arc::clone(&context))?;

        let native_direction = direction(guest_direction);
        let native_flags = (flags & !CALLBACK_FLAGS) | CALLBACK_FUNCTION;
        let native_flags: MIDI_WAVE_OPEN_TYPE = native_flags;
        let callback = callback::procedure();
        let (result, handle) = match native_direction {
            MidiDirection::Input => {
                let mut output: HMIDIIN = std::ptr::null_mut();
                let result = unsafe { midiInOpen(&mut output, native_device_id_u32(device_id),
                    callback, context_id, native_flags) };
                (result, (!output.is_null()).then_some(NativeMidiHandle::Input(output)))
            }
            MidiDirection::Output => {
                let mut output: HMIDIOUT = std::ptr::null_mut();
                let result = unsafe { midiOutOpen(&mut output, native_device_id_u32(device_id),
                    callback, context_id, native_flags) };
                (result, (!output.is_null()).then_some(NativeMidiHandle::Output(output)))
            }
        };
        let Some(handle) = handle else {
            if result == 0 {
                self.unpublished_callbacks.push(super::UnpublishedCallbackOwner {
                    token,
                    context_id,
                    callback: context,
                    open_failed_without_handle: false,
                });
                return Err(RuntimeError::new(Kind::HostFailure,
                    "WinMM returned success without a native MIDI handle"));
            }
            match callback::unregister_if_idle(context_id, &context) {
                true => {}
                false => self.unpublished_callbacks.push(super::UnpublishedCallbackOwner {
                    token,
                    context_id,
                    callback: context,
                    open_failed_without_handle: true,
                }),
            }
            return Ok(ResultValue::Opened { result, device: None });
        };
        if result != 0 {
            if let Err(cleanup) = close_native(handle) {
                // The native close failed, so keep both handle and callback
                // context owned for task teardown. The guest never received a
                // token for this partial-open handle, so its callbacks are not
                // projected into the guest event stream.
                self.devices.push(MidiDevice {
                    token,
                    direction: native_direction,
                    native: handle,
                    context_id,
                    callback: context,
                    guest_instance,
                    // The attempted close failed. This owner is not yet
                    // quiesced and task cleanup must retry the real close.
                    closing: false,
                    close_reset_result: None,
                    close_reset_failure: None,
                    close_result: None,
                    close_seen: false,
                    projected: None,
                    orphaned: true,
                });
                return Err(host_result("midiOpen", result).with_cleanup(
                    "native MIDI open failed and partial handle cleanup also failed",
                    cleanup,
                ));
            }
            // Even a successful close of a partial Open does not retire the
            // callback context until its exact close event and in-flight
            // trampolines have drained.
            self.devices.push(MidiDevice {
                token,
                direction: native_direction,
                native: handle,
                context_id,
                callback: context,
                guest_instance,
                closing: true,
                close_reset_result: None,
                close_reset_failure: None,
                close_result: Some(MMSYSERR_NOERROR),
                close_seen: false,
                projected: None,
                orphaned: true,
            });
            return Ok(ResultValue::Opened { result, device: None });
        }
        if !native_handle_matches(handle, native_direction) {
            self.devices.push(MidiDevice {
                token,
                direction: native_direction,
                native: handle,
                context_id,
                callback: context,
                guest_instance,
                closing: false,
                close_reset_result: None,
                close_reset_failure: None,
                close_result: None,
                close_seen: false,
                projected: None,
                orphaned: true,
            });
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native MIDI open returned a handle of the wrong device direction"));
        }
        self.devices.push(MidiDevice {
            token,
            direction: native_direction,
            native: handle,
            context_id,
            callback: context,
            guest_instance,
            closing: false,
            close_reset_result: None,
            close_reset_failure: None,
            close_result: None,
            close_seen: false,
            projected: None,
            orphaned: false,
        });
        Ok(ResultValue::Opened { result, device: Some(token) })
    }

    pub(super) fn close(&mut self, token: DeviceToken) -> Result<ResultValue, RuntimeError> {
        let Some(index) = self.device_index(token) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI close lost the exact native device owner"));
        };
        if self.devices[index].closing {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI close was repeated for an owner already marked closing"));
        }
        let native = self.devices[index].native;
        let count = self.validate_prepared_headers(token, native)?;
        let mut retired_headers = Vec::new();
        retired_headers.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native MIDI unprepare receipts", error))?;
        if let Some((header, result)) = self.unprepare_prepared_headers(
            token, native, |state| retired_headers.push(state))
        {
            return Ok(ResultValue::Closed {
                result,
                retired_headers,
                reset_result: None,
                unprepare_header: Some(header),
                unprepare_result: Some(result),
                close_result: None,
            });
        }
        let close_result = close_native_result(native);
        if close_result == 0 {
            self.devices[index].closing = true;
            self.devices[index].close_reset_result = None;
            self.devices[index].close_result = Some(close_result);
            for header in self.headers.iter_mut().filter(|header|
                header.device == token && header.retired)
            {
                header.defer_release = false;
            }
        }
        Ok(ResultValue::Closed {
            result: close_result,
            retired_headers,
            reset_result: None,
            unprepare_header: None,
            unprepare_result: None,
            close_result: Some(close_result),
        })
    }

    fn unprepare_prepared_headers(
        &mut self,
        token: DeviceToken,
        native: NativeMidiHandle,
        mut record_unprepared: impl FnMut(HeaderState),
    ) -> Option<(HeaderToken, u32)> {
        // WinMM requires UnprepareHeader to succeed before its HDR/data storage
        // may be released. A later Close result is not an unprepare receipt.
        for index in 0..self.headers.len() {
            if self.headers[index].device != token || !self.headers[index].prepared {
                continue;
            }
            let header_token = self.headers[index].token;
            let pointer = &mut self.headers[index].storage[0].header as *mut MIDIHDR;
            let result = unsafe { match native {
                NativeMidiHandle::Input(handle) =>
                    midiInUnprepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
                NativeMidiHandle::Output(handle) =>
                    midiOutUnprepareHeader(handle, pointer, size_of::<MIDIHDR>() as u32),
            }};
            if result != 0 { return Some((header_token, result)); }
            let callback_pending = self.header_has_queued_callback(token, header_token);
            let header = &mut self.headers[index];
            header.prepared = false;
            header.retired = true;
            header.defer_release = true;
            let native = &header.storage[0].header;
            record_unprepared(HeaderState {
                header: header_token,
                submission: header.active_submission,
                completed_submission: None,
                capacity: header.capacity,
                bytes_recorded: native.dwBytesRecorded,
                user: header.user,
                flags: native.dwFlags,
                callback_pending,
                input_data: None,
            });
        }
        None
    }

    fn validate_prepared_headers(
        &self,
        token: DeviceToken,
        native: NativeMidiHandle,
    ) -> Result<usize, RuntimeError> {
        let expected_direction = match native {
            NativeMidiHandle::Input(_) => MidiDirection::Input,
            NativeMidiHandle::Output(_) => MidiDirection::Output,
        };
        let mut count = 0usize;
        for header in self.headers.iter().filter(|header|
            header.device == token && header.prepared)
        {
            if header.storage.len() != 1
                || header.direction != expected_direction
                || header.retired
                || header.storage[0].samples.as_ptr()
                    != header.storage[0].header.lpData.cast::<u8>()
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "prepared MIDI header lost its exact direction or stable native storage"));
            }
            count = count.checked_add(1).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted, "MIDI prepared-header receipt count overflowed"))?;
        }
        Ok(count)
    }

    pub(super) fn close_unpublished(
        &mut self,
        token: DeviceToken,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(index) = self.device_index(token) else { return Ok(invalid_device()); };
        // This handle never became a guest alias. Even after native close,
        // keep the callback context until its exact terminal event and all
        // in-flight trampolines have drained.
        self.devices[index].orphaned = true;
        self.close(token)
    }

    pub(super) fn get_id(&self, token: DeviceToken) -> Result<ResultValue, RuntimeError> {
        let Some(device) = self.devices.iter().find(|device| device.token == token && !device.closing)
        else { return Ok(ResultValue::DeviceId { result: 5, device_id: None }); };
        let mut device_id = 0u32;
        let result = unsafe { match device.native {
            NativeMidiHandle::Input(handle) => midiInGetID(handle, &mut device_id),
            NativeMidiHandle::Output(handle) => midiOutGetID(handle, &mut device_id),
        }};
        Ok(ResultValue::DeviceId {
            result,
            device_id: (result == 0).then_some(device_id),
        })
    }

    pub(super) fn get_mixer_id_native(
        &self,
        token: DeviceToken,
        expected: Direction,
    ) -> Win16HostMidiMixerId {
        let Some(device) = self.devices.iter().find(|entry| entry.token == token && !entry.closing)
        else { return Win16HostMidiMixerId { result: 5, mixer_id: None }; };
        if device.direction != direction(expected) {
            return Win16HostMidiMixerId { result: 5, mixer_id: None };
        }
        let (native, object_flag) = match device.native {
            NativeMidiHandle::Input(handle) => (handle.cast(), MIXER_OBJECTF_MIDIIN),
            NativeMidiHandle::Output(handle) => (handle.cast(), MIXER_OBJECTF_MIDIOUT),
        };
        let mut mixer_id = 0u32;
        let flags = (MIXER_OBJECTF_HANDLE | object_flag) as u32;
        let result = unsafe { mixerGetID(native, &mut mixer_id, flags) };
        Win16HostMidiMixerId { result, mixer_id: (result == 0).then_some(mixer_id) }
    }

    pub(super) fn close_all_devices(&mut self) -> Result<Win16HostMidiCloseAll, RuntimeError> {
        let count = self.devices.len();
        let mut plans = Vec::new();
        plans.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve MIDI shutdown owner plans", error))?;
        for device in &self.devices {
            if device.orphaned {
                if self.headers.iter().any(|header| header.device == device.token) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "unpublished MIDI owner unexpectedly owns guest header tokens"));
                }
                plans.push(None);
                continue;
            }
            if device.closing && device.close_result != Some(MMSYSERR_NOERROR) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "closed MIDI owner lost its successful native close receipt"));
            }
            let header_count = self.validate_prepared_headers(device.token, device.native)?;
            if device.closing && header_count != 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "closed MIDI owner still has a prepared native header"));
            }
            let mut unprepared_headers = Vec::new();
            unprepared_headers.try_reserve_exact(header_count).map_err(|error| {
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve MIDI shutdown unprepare receipts", error)
            })?;
            plans.push(Some(Win16HostMidiClosedDevice {
                device: device.token,
                reset_result: device.close_reset_result,
                unprepared_headers,
                close_result: if device.closing { device.close_result } else { None },
            }));
        }
        let mut closed = Vec::new();
        closed.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve MIDI shutdown receipts", error))?;
        let mut failures = Vec::new();
        let failure_capacity = count.checked_mul(2).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "MIDI close failure capacity overflow"))?;
        failures.try_reserve_exact(failure_capacity).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve MIDI shutdown failures", error))?;
        for index in (0..count).rev() {
            if self.devices[index].closing {
                if !self.devices[index].orphaned {
                    if let Some(receipt) = plans[index].take() { closed.push(receipt); }
                }
                continue;
            }
            let device = &self.devices[index];
            let token = device.token;
            let native = device.native;
            let reset = self.reset_for_retirement(index);
            if reset != 0 {
                failures.push(Win16HostMidiCloseFailure {
                    device: token,
                    reset_result: Some(self.devices[index].close_reset_failure.unwrap_or(reset)),
                    unprepared_headers: Vec::new(),
                    unprepare_header: None,
                    unprepare_result: None,
                    close_result: None,
                    unpublished_owner: self.devices[index].orphaned,
                    unpublished_owner_error: None,
                });
                continue;
            }
            if let Some(plan) = plans[index].as_mut() {
                plan.reset_result = Some(reset);
            }

            let unprepare_failure = if let Some(plan) = plans[index].as_mut() {
                self.unprepare_prepared_headers(token, native,
                    |state| plan.unprepared_headers.push(state.header))
            } else {
                None
            };
            if let Some((header, result)) = unprepare_failure {
                let unprepared_headers = plans[index].as_mut()
                    .map(|plan| std::mem::take(&mut plan.unprepared_headers))
                    .unwrap_or_default();
                failures.push(Win16HostMidiCloseFailure {
                    device: token,
                    reset_result: Some(MMSYSERR_NOERROR),
                    unprepared_headers,
                    unprepare_header: Some(header),
                    unprepare_result: Some(result),
                    close_result: None,
                    unpublished_owner: self.devices[index].orphaned,
                    unpublished_owner_error: None,
                });
                continue;
            }

            let close_result = close_native_result(native);
            if close_result == MMSYSERR_NOERROR {
                self.devices[index].closing = true;
                self.devices[index].close_reset_result = Some(reset);
                self.devices[index].close_result = Some(close_result);
                for header in self.headers.iter_mut().filter(|header|
                    header.device == token && header.retired)
                {
                    header.defer_release = false;
                }
                if let Some(plan) = plans[index].as_mut() {
                    plan.close_result = Some(close_result);
                }
                if let Some(receipt) = plans[index].take() { closed.push(receipt); }
            } else {
                let unprepared_headers = plans[index].as_mut()
                    .map(|plan| std::mem::take(&mut plan.unprepared_headers))
                    .unwrap_or_default();
                failures.push(Win16HostMidiCloseFailure {
                    device: token,
                    reset_result: Some(MMSYSERR_NOERROR),
                    unprepared_headers,
                    unprepare_header: None,
                    unprepare_result: None,
                    close_result: Some(close_result),
                    unpublished_owner: self.devices[index].orphaned,
                    unpublished_owner_error: None,
                });
            }
        }
        for index in (0..self.devices.len()).rev() {
            if !self.devices[index].orphaned || !self.devices[index].closing { continue; }
            let token = self.devices[index].token;
            if let Err(error) = self.drain_unpublished_owner(token) {
                failures.push(Win16HostMidiCloseFailure {
                    device: token,
                    reset_result: self.devices[index].close_reset_result,
                    unprepared_headers: Vec::new(),
                    unprepare_header: None,
                    unprepare_result: None,
                    close_result: self.devices[index].close_result,
                    unpublished_owner: true,
                    unpublished_owner_error: Some(error),
                });
            }
        }
        self.drain_unpublished_callbacks(true)?;
        if callback::has_unknown_context_failure() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "MIDI shutdown observed a callback for an unregistered native owner"));
        }
        Ok(Win16HostMidiCloseAll { devices: closed, failures })
    }

    fn drain_unpublished_owner(&mut self, token: DeviceToken) -> Result<(), RuntimeError> {
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            let Some(index) = self.device_index(token) else { return Ok(()); };
            if !self.devices[index].orphaned || !self.devices[index].closing {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "unpublished MIDI cleanup lost its exact closed owner"));
            }
            if let Some(error) = self.devices[index].callback.take_failure() {
                return Err(error);
            }
            if let Some(event) = self.devices[index].callback.peek() {
                if event.native_device != super::device_pointer(self.devices[index].native) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "unpublished MIDI callback changed its native owner identity"));
                }
                let close_event = matches!(event.message, MM_MOM_CLOSE | MM_MIM_CLOSE);
                self.devices[index].callback.acknowledge(
                    event.sequence,
                    Disposition::Cancelled(Win16HostMidiCancellationReason::UnpublishedOwner),
                )?;
                if close_event { self.devices[index].close_seen = true; }
                continue;
            }
            if self.devices[index].close_seen
                && self.devices[index].callback.in_flight() == 0
                && self.retire_closed_device(token)?
            {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "unpublished MIDI owner awaits exact close callback quiescence; host token is retained"));
            }
            self.queue_wake.wait(remaining);
        }
    }

    pub(super) fn output_short(&self, token: DeviceToken, message: u32) -> Result<ResultValue, RuntimeError> {
        let Some(device) = self.devices.iter().find(|entry| entry.token == token && !entry.closing)
        else { return Ok(invalid_device()); };
        let NativeMidiHandle::Output(handle) = device.native else { return Ok(invalid_device()); };
        Ok(ResultValue::Scalar(unsafe { midiOutShortMsg(handle, message) }))
    }

    pub(super) fn output_reset(&self, token: DeviceToken) -> Result<ResultValue, RuntimeError> {
        let Some(device) = self.devices.iter().find(|entry| entry.token == token && !entry.closing)
        else { return Ok(invalid_device()); };
        let NativeMidiHandle::Output(handle) = device.native else { return Ok(invalid_device()); };
        Ok(ResultValue::Scalar(unsafe { midiOutReset(handle) }))
    }

    pub(super) fn input_control(&self, token: DeviceToken, command: InputControl) -> Result<ResultValue, RuntimeError> {
        let Some(device) = self.devices.iter().find(|entry| entry.token == token && !entry.closing)
        else { return Ok(invalid_device()); };
        let NativeMidiHandle::Input(handle) = device.native else { return Ok(invalid_device()); };
        let result = unsafe { match command {
            InputControl::Start => midiInStart(handle),
            InputControl::Stop => midiInStop(handle),
            InputControl::Reset => midiInReset(handle),
        }};
        Ok(ResultValue::Scalar(result))
    }

    pub(super) fn output_get_volume_by_id(
        &self,
        device_id: u16,
    ) -> Result<ResultValue, RuntimeError> {
        // WinMM explicitly accepts a UINT device identifier in this HMIDIOUT
        // parameter. Keep the Win16 WORD identity numeric; do not open a guest
        // handle or reinterpret it as a host pointer. MIDI_MAPPER is widened
        // as UINT32_MAX before the host pointer-width carrier conversion.
        let native_id = native_device_id_u32(device_id) as usize as HMIDIOUT;
        let mut value = 0u32;
        let result = unsafe { midiOutGetVolume(native_id, &mut value) };
        Ok(ResultValue::Volume { result, value: (result == 0).then_some(value) })
    }

    pub(super) fn output_set_volume_by_id(
        &self,
        device_id: u16,
        value: u32,
    ) -> Result<ResultValue, RuntimeError> {
        // See output_get_volume_by_id: this slot carries the documented UINT
        // device ID, including MIDI_MAPPER == UINT32_MAX, not an HMIDIOUT
        // opened for the guest.
        let native_id = native_device_id_u32(device_id) as usize as HMIDIOUT;
        let result = unsafe { midiOutSetVolume(native_id, value) };
        Ok(ResultValue::Scalar(result))
    }

    pub(super) fn output_cache_patches(
        &self,
        token: DeviceToken,
        bank: u16,
        mut values: Vec<u16>,
        flags: u16,
        drums: bool,
    ) -> Result<ResultValue, RuntimeError> {
        let Some(device) = self.devices.iter().find(|entry| entry.token == token && !entry.closing)
        else { return Ok(ResultValue::PatchArray { result: 5, values: Vec::new() }); };
        let NativeMidiHandle::Output(handle) = device.native else {
            return Ok(ResultValue::PatchArray { result: 5, values: Vec::new() });
        };
        if values.len() != 128 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 MIDI cache operation did not carry 128 entries"));
        }
        let result = unsafe { if drums {
            midiOutCacheDrumPatches(handle, u32::from(bank), values.as_mut_ptr(), u32::from(flags))
        } else {
            midiOutCachePatches(handle, u32::from(bank), values.as_mut_ptr(), u32::from(flags))
        }};
        let returned = if patch_array_is_output(flags, result) { values } else { Vec::new() };
        Ok(ResultValue::PatchArray { result, values: returned })
    }
}

fn patch_array_is_output(flags: u16, result: u32) -> bool {
    (flags == MIDI_CACHE_ALL && result == MMSYSERR_NOMEM)
        || (flags == MIDI_CACHE_BESTFIT && result == MMSYSERR_NOMEM)
        || (flags == MIDI_CACHE_QUERY && result == MMSYSERR_NOERROR)
        || (flags == MIDI_UNCACHE && result == MMSYSERR_NOERROR)
}

#[derive(Clone, Copy)]
pub(super) enum InputControl { Start, Stop, Reset }

fn native_device_id(device_id: u16) -> usize { native_device_id_u32(device_id) as usize }

fn native_device_id_u32(device_id: u16) -> u32 {
    // MMSYSTEM.H defines MIDI_MAPPER as UINT(-1); the Win16 WORD spelling is
    // widened to the API's UINT32 value before any host-width conversion.
    if device_id == MIDI_MAPPER_GUEST { u32::MAX } else { u32::from(device_id) }
}

fn close_native(handle: NativeMidiHandle) -> Result<(), RuntimeError> {
    let result = close_native_result(handle);
    if result == 0 { Ok(()) } else { Err(host_result("midiClose partial open", result)) }
}

fn close_native_result(handle: NativeMidiHandle) -> u32 {
    unsafe { match handle {
        NativeMidiHandle::Input(handle) => midiInClose(handle),
        NativeMidiHandle::Output(handle) => midiOutClose(handle),
    }}
}
