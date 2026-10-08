//! Native WAVE owner. Guest tokens map to WinMM handles and stable native
//! headers; neither a guest FAR nor a native pointer crosses RuntimeHost.

#[path = "win16_multimedia_buffers_callback.rs"]
mod callback;
#[path = "win16_multimedia_buffers_cleanup.rs"]
mod cleanup;
#[path = "win16_multimedia_buffers_consumer.rs"]
mod consumer;
#[path = "win16_multimedia_buffers_events.rs"]
mod events;
#[path = "win16_multimedia_buffers_mixer.rs"]
mod mixer;
#[path = "win16_multimedia_buffers_native.rs"]
mod native;
#[path = "win16_multimedia_buffers_open.rs"]
mod open;
#[path = "win16_multimedia_buffers_poll.rs"]
mod poll;
#[path = "win16_multimedia_buffers_retired.rs"]
mod retired;
#[path = "win16_multimedia_buffers_sound.rs"]
mod sound;

use std::collections::VecDeque;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::guest_text::GuestTextCodec;
use super::multimedia_wake::MultimediaWakeSender;
use super::win16_wave_format_storage::WaveFormatStorage;
use callback::{CallbackContext, CallbackSignal, CallbackWake};
pub(super) use events::insert_reserved_pending_wave_event;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWaveBuffer, Win16HostWaveCapabilities,
    Win16HostWaveControl, Win16HostWaveDevice, Win16HostWaveDirection, Win16HostWaveEvent,
    Win16HostWaveEventKind, Win16HostWaveFormat, Win16HostWaveFormatSpec, Win16HostWaveHeaderState,
    Win16HostWaveInitialBuffer, Win16HostWaveMixerId, Win16HostWaveOperation,
    Win16HostWaveParameter, Win16HostWavePosition, Win16HostWaveResult, Win16HostWaveSubmission,
    Win16HostWaveSubmit,
};
use windows_sys::Win32::Media::Audio::{
    CALLBACK_FUNCTION, CALLBACK_NULL, HWAVEIN, HWAVEOUT, WAVE_ALLOWSYNC, WAVE_FORMAT_QUERY,
    WAVE_MAPPER, WAVEHDR, WHDR_BEGINLOOP, WHDR_DONE, WHDR_ENDLOOP, WHDR_INQUEUE, WHDR_PREPARED,
    waveInGetNumDevs, waveOutGetNumDevs,
};

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_INVALPARAM: u32 = 11;
const WAVERR_STILLPLAYING: u32 = 33;
const WAVERR_UNPREPARED: u32 = 34;
const WAVE_FORMAT_DIRECT: u32 = 0x0008;
const CALLBACK_TYPEMASK: u32 = 0x0007_0000;
const CALLBACK_NULL_WIN16: u32 = 0x0000_0000;
const CALLBACK_FUNCTION_WIN16: u32 = 0x0003_0000;

// The host crate cannot call RuntimeError::with_cleanup, so host-side WAVE and
// SOUND aggregates use the same typed-cause priority here.
pub(super) fn cleanup_failure_kind(primary: Kind, cleanup: Kind) -> Kind {
    match (primary, cleanup) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::ExecutionLimit, additional) => additional,
        (first, _) => first,
    }
}

pub(super) fn cleanup_failures_kind(failures: &[RuntimeError]) -> Kind {
    let Some((first, rest)) = failures.split_first() else {
        return Kind::HostFailure;
    };
    rest.iter().fold(first.kind(), |kind, failure| {
        cleanup_failure_kind(kind, failure.kind())
    })
}

pub(super) struct Win16WaveHost {
    identity_source: Arc<AtomicU64>,
    text_codec: GuestTextCodec,
    event_sequences: Arc<AtomicU64>,
    callback_wake: Arc<CallbackWake>,
    wake_start_error: Option<Arc<RuntimeError>>,
    devices: Vec<WaveDevice>,
    sound: sound::SoundState,
    pending_wave_events: VecDeque<Win16HostWaveEvent>,
}

struct WaveDevice {
    token: Win16HostWaveDevice,
    direction: Win16HostWaveDirection,
    native: NativeWaveHandle,
    callback: Option<Box<CallbackContext>>,
    callback_function: bool,
    closing: bool,
    native_closed: bool,
    close_event_delivered: bool,
    close_event_sequence: Option<u64>,
    owner_thread: std::thread::ThreadId,
    retirement_slot_reserved: bool,
    buffers: Vec<WaveBuffer>,
}

enum NativeWaveHandle {
    Input(HWAVEIN),
    Output(HWAVEOUT),
}

struct WaveBuffer {
    token: Win16HostWaveBuffer,
    storage: Box<NativeWaveBuffer>,
    signal: Arc<CallbackSignal>,
    prepared: bool,
    in_flight: bool,
    submission_generation: u64,
    active_submission: Option<Win16HostWaveSubmission>,
}

/// WinMM retains `header` and its sample pointer from PrepareHeader through a
/// successful UnprepareHeader. The Box allocation and Vec allocation are
/// created before native prepare and never moved, resized, or replaced while
/// the native header is prepared. The Win16 WAVEHDR16 is separately marshalled
/// by RuntimeHost and is never overlaid on this native structure.
struct NativeWaveBuffer {
    header: WAVEHDR,
    samples: Option<Vec<u8>>,
    capacity: u32,
    data_present: bool,
}

impl Win16WaveHost {
    pub(super) fn new(
        identity_source: Arc<AtomicU64>,
        multimedia_wake: Result<MultimediaWakeSender, RuntimeError>,
        text_codec: GuestTextCodec,
    ) -> Self {
        let (multimedia_wake, wake_start_error) = match multimedia_wake {
            Ok(sender) => (Some(sender), None),
            Err(error) => (None, Some(Arc::new(error))),
        };
        Self {
            identity_source,
            text_codec,
            event_sequences: Arc::new(AtomicU64::new(1)),
            callback_wake: Arc::new(CallbackWake::new(multimedia_wake)),
            wake_start_error,
            devices: Vec::new(),
            sound: sound::SoundState::default(),
            pending_wave_events: VecDeque::new(),
        }
    }

    pub(super) fn execute(
        &mut self,
        operation: Win16HostWaveOperation,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        match operation {
            Win16HostWaveOperation::DeviceCount { direction } => {
                let count = unsafe {
                    match direction {
                        Win16HostWaveDirection::Input => waveInGetNumDevs(),
                        Win16HostWaveDirection::Output => waveOutGetNumDevs(),
                    }
                };
                Ok(Win16HostWaveResult::DeviceCount(count))
            }
            Win16HostWaveOperation::DeviceCapabilities {
                direction,
                device_id,
            } => {
                let (result, capabilities) =
                    native::device_capabilities(direction, device_id, self.text_codec)?;
                if result == MMSYSERR_NOERROR && capabilities.is_none() {
                    return Err(wave_invariant(
                        "successful WinMM device-capabilities query omitted its output",
                    ));
                }
                if result != MMSYSERR_NOERROR && capabilities.is_some() {
                    return Err(wave_invariant(
                        "failed WinMM device-capabilities query returned output",
                    ));
                }
                Ok(Win16HostWaveResult::DeviceCapabilities {
                    result,
                    capabilities,
                })
            }
            Win16HostWaveOperation::GetDeviceId { device } => Ok(self.get_device_id(device)),
            Win16HostWaveOperation::GetParameter { device, parameter } => {
                Ok(self.get_parameter(device, parameter))
            }
            Win16HostWaveOperation::GetVolumeById { device_id } => {
                let (result, value) = unsafe { native::get_volume_by_id(device_id) };
                if result == MMSYSERR_NOERROR && value.is_none() {
                    return Err(wave_invariant(
                        "successful WinMM device-volume query omitted output",
                    ));
                }
                if result != MMSYSERR_NOERROR && value.is_some() {
                    return Err(wave_invariant(
                        "failed WinMM device-volume query returned output",
                    ));
                }
                Ok(Win16HostWaveResult::Parameter { result, value })
            }
            Win16HostWaveOperation::SetParameter {
                device,
                parameter,
                value,
            } => Ok(self.set_parameter(device, parameter, value)),
            Win16HostWaveOperation::SetVolumeById { device_id, value } => {
                Ok(Win16HostWaveResult::Scalar(unsafe {
                    native::set_volume_by_id(device_id, value)
                }))
            }
            Win16HostWaveOperation::QueryMappable {
                direction,
                device_id,
            } => {
                let result = unsafe { native::query_mappable(direction, device_id) };
                Ok(Win16HostWaveResult::Scalar(result))
            }
            Win16HostWaveOperation::ErrorText {
                direction,
                error,
                capacity,
            } => {
                let (result, bytes) =
                    native::error_text(direction, error, capacity, self.text_codec)?;
                Ok(Win16HostWaveResult::ErrorText { result, bytes })
            }
            Win16HostWaveOperation::Open {
                direction,
                device_id,
                output_handle_present,
                format,
                flags,
            } => self.open(direction, device_id, output_handle_present, format, flags),
            Win16HostWaveOperation::Prepare {
                device,
                initial,
                length,
                loops,
            } => self.prepare(device, initial, length, loops),
            Win16HostWaveOperation::Submit {
                device,
                buffer,
                operation,
            } => self.submit(device, buffer, operation),
            Win16HostWaveOperation::Unprepare { device, buffer } => self.unprepare(device, buffer),
            Win16HostWaveOperation::GetPosition {
                device,
                requested_time,
            } => self.get_position(device, requested_time),
            Win16HostWaveOperation::Control { device, command } => self.control(device, command),
        }
    }

    pub(super) fn poll(&mut self) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
        consumer::poll(self)
    }

    pub(super) fn poll_sound(
        &mut self,
    ) -> Result<Option<runtime::Win16SoundPlaybackEvent>, RuntimeError> {
        sound::poll(self)
    }

    pub(super) fn sound(
        &mut self,
        operation: runtime::Win16SoundHostOperation,
    ) -> Result<runtime::Win16SoundHostResult, RuntimeError> {
        sound::execute(self, operation)
    }

    fn poll_native_event(&mut self) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
        // Reaping may publish one Quiescent event per device before native
        // polling returns another owner event. Keep one further queue slot so
        // a private SOUND retry can reinsert that exact event without loss.
        self.pending_wave_events
            .try_reserve(self.devices.len().saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve WAVE receipts before native event consumption",
                    error,
                )
            })?;
        if let Some(error) = self.callback_wake.take_signal_failure() {
            return Err(error.with_context("signal WAVE callback event to USER worker"));
        }
        poll::reap_closed_devices(self)?;
        poll::reap_retired_buffers(self);
        if self.devices.iter().any(|device| {
            device
                .callback
                .as_ref()
                .is_some_and(|callback| callback.take_failure())
        }) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native WAVE callback could not be correlated with its owned header",
            ));
        }
        if let Some(event) = poll::poll_callback_signal(self)? {
            return Ok(Some(event));
        }
        poll::poll_native_completion(self)
    }

    pub(super) fn poll_wait(
        &mut self,
        max_wait: Duration,
    ) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
        let observed = self.callback_wake.generation();
        if let Some(event) = self.poll()? {
            return Ok(Some(event));
        }
        if max_wait.is_zero() {
            return Ok(None);
        }
        self.callback_wake.wait_for_change(observed, max_wait);
        self.poll()
    }

    fn get_device_id(&self, token: Win16HostWaveDevice) -> Win16HostWaveResult {
        let Some(device) = self.devices.iter().find(|device| device.token == token) else {
            return Win16HostWaveResult::DeviceId {
                result: MMSYSERR_INVALHANDLE,
                device_id: None,
            };
        };
        // SAFETY: the table entry owns this still-live native device handle;
        // WinMM's getter writes only the local numeric device ID.
        let (result, device_id) =
            unsafe { native::get_device_id(device.direction, &device.native) };
        Win16HostWaveResult::DeviceId { result, device_id }
    }

    fn get_parameter(
        &self,
        token: Win16HostWaveDevice,
        parameter: Win16HostWaveParameter,
    ) -> Win16HostWaveResult {
        let Some(device) = self.devices.iter().find(|device| device.token == token) else {
            return Win16HostWaveResult::Parameter {
                result: MMSYSERR_INVALHANDLE,
                value: None,
            };
        };
        // SAFETY: the table entry owns the exact open handle and getter output
        // is written to the local DWORD inside the native helper.
        let (result, value) =
            unsafe { native::get_parameter(device.direction, &device.native, parameter) };
        Win16HostWaveResult::Parameter { result, value }
    }

    fn set_parameter(
        &self,
        token: Win16HostWaveDevice,
        parameter: Win16HostWaveParameter,
        value: u32,
    ) -> Win16HostWaveResult {
        let Some(device) = self.devices.iter().find(|device| device.token == token) else {
            return Win16HostWaveResult::Scalar(MMSYSERR_INVALHANDLE);
        };
        // SAFETY: the table entry owns the exact open handle; setter values
        // are scalars and no guest pointers are forwarded.
        let result =
            unsafe { native::set_parameter(device.direction, &device.native, parameter, value) };
        Win16HostWaveResult::Scalar(result)
    }

    fn prepare(
        &mut self,
        device_token: Win16HostWaveDevice,
        initial: Win16HostWaveInitialBuffer,
        length: u32,
        loops: u32,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let Some(device_index) = self
            .devices
            .iter()
            .position(|device| device.token == device_token)
        else {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        };
        if self.devices[device_index].native_closed {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        }
        self.devices[device_index]
            .buffers
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native WAVE header table",
                    error,
                )
            })?;
        let (samples, data_present) = native::initial_samples(initial, length)?;
        let buffer_token = Win16HostWaveBuffer(self.allocate_identity()?);
        let signal = Arc::new(CallbackSignal::default());
        let mut storage = Box::new(NativeWaveBuffer {
            header: native::zero_header(),
            samples,
            capacity: length,
            data_present,
        });
        native::write_header(
            ptr::addr_of_mut!(storage.header),
            storage.sample_pointer(),
            length,
            0,
            loops,
            0,
        );
        let native_header = ptr::addr_of_mut!(storage.header);
        let native_header_address = native_header as usize;
        if let Some(callback) = self.devices[device_index].callback.as_ref() {
            callback.register_header(native_header_address, Arc::clone(&signal))?;
        }
        let result = unsafe {
            native::prepare_native(
                self.devices[device_index].direction,
                &self.devices[device_index].native,
                native_header,
            )
        };
        let state = Some(unsafe { callback::header_state(native_header) });
        if result != MMSYSERR_NOERROR {
            if let Some(callback) = self.devices[device_index].callback.as_ref() {
                callback.unregister_header(native_header_address);
            }
            return Ok(header_result(result, None, state));
        }
        self.devices[device_index].buffers.push(WaveBuffer {
            token: buffer_token,
            storage,
            signal,
            prepared: true,
            in_flight: false,
            submission_generation: 0,
            active_submission: None,
        });
        Ok(header_result(result, Some(buffer_token), state))
    }

    fn submit(
        &mut self,
        device_token: Win16HostWaveDevice,
        buffer_token: Win16HostWaveBuffer,
        operation: Win16HostWaveSubmit,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let Some(device_index) = self
            .devices
            .iter()
            .position(|device| device.token == device_token)
        else {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        };
        if self.devices[device_index].native_closed {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        }
        let Some(buffer_index) = self.devices[device_index]
            .buffers
            .iter()
            .position(|buffer| buffer.token == buffer_token)
        else {
            return Ok(header_result(WAVERR_UNPREPARED, Some(buffer_token), None));
        };
        let device = &mut self.devices[device_index];
        let direction = device.direction;
        let native_device = &device.native;
        let buffer = &mut device.buffers[buffer_index];
        if !buffer.prepared {
            return Ok(header_result(WAVERR_UNPREPARED, Some(buffer_token), None));
        }
        // WinMM reports only the stable WAVEHDR address in WOM_DONE/WIM_DATA.
        // Do not arm the next generation until this submission's one native
        // completion callback has been consumed by the owner thread.
        if buffer.in_flight || buffer.active_submission.is_some() || buffer.signal.peek().is_some()
        {
            return Ok(header_result(WAVERR_STILLPLAYING, Some(buffer_token), None));
        }
        let (length, loops, flags, playback_bytes) = match operation {
            Win16HostWaveSubmit::Playback {
                bytes,
                length,
                flags,
                loops,
            } => {
                if direction != Win16HostWaveDirection::Output {
                    return Err(wave_invariant(
                        "playback submit reached a wave input device",
                    ));
                }
                if bytes.len() != length as usize {
                    return Err(wave_invariant(
                        "WAVE playback byte count does not match its length",
                    ));
                }
                (length, loops, flags, Some(bytes))
            }
            Win16HostWaveSubmit::Capture { length, flags } => {
                if direction != Win16HostWaveDirection::Input {
                    return Err(wave_invariant(
                        "capture submit reached a wave output device",
                    ));
                }
                (length, 0, flags, None)
            }
        };
        if length > buffer.storage.capacity || (length != 0 && !buffer.storage.data_present) {
            return Ok(header_result(
                MMSYSERR_INVALPARAM,
                Some(buffer_token),
                Some(unsafe { callback::header_state(ptr::addr_of!(buffer.storage.header)) }),
            ));
        }
        if let Some(bytes) = playback_bytes.as_deref().filter(|bytes| !bytes.is_empty()) {
            let Some(samples) = buffer.storage.samples.as_mut() else {
                return Ok(header_result(MMSYSERR_INVALPARAM, Some(buffer_token), None));
            };
            if bytes.len() > samples.len() {
                return Err(wave_invariant(
                    "playback bytes exceed stable prepared storage",
                ));
            }
            samples[..bytes.len()].copy_from_slice(bytes);
        }
        let native_header = ptr::addr_of_mut!(buffer.storage.header);
        let loop_flags = flags & (WHDR_BEGINLOOP | WHDR_ENDLOOP);
        native::write_header(
            native_header,
            buffer.storage.sample_pointer(),
            length,
            0,
            loops,
            WHDR_PREPARED | loop_flags,
        );
        let next_generation = buffer.submission_generation.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 native WAVE submission generation is exhausted",
            )
        })?;
        let submission = Win16HostWaveSubmission(next_generation);
        buffer.submission_generation = next_generation;
        buffer.active_submission = Some(submission);
        buffer.signal.arm_submission(submission);
        buffer.in_flight = true;
        let result = unsafe { native::submit_native(direction, native_device, native_header) };
        let state = unsafe { callback::header_state(native_header) };
        if result != MMSYSERR_NOERROR {
            buffer.in_flight = false;
            buffer.active_submission = None;
            buffer.signal.disarm_submission();
            return Ok(header_result(result, Some(buffer_token), Some(state)));
        }
        buffer.in_flight = state.flags & WHDR_INQUEUE != 0;
        // Keep the submit pending until the configured completion source
        // reports it. CALLBACK_NULL uses the real WHDR_DONE/INQUEUE state;
        // CALLBACK_FUNCTION uses the native WOM_DONE/WIM_DATA signal. This
        // also captures input completed synchronously by the driver.
        Ok(header_submitted_result(
            result,
            buffer_token,
            state,
            submission,
        ))
    }

    fn unprepare(
        &mut self,
        device_token: Win16HostWaveDevice,
        buffer_token: Win16HostWaveBuffer,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let Some(device_index) = self
            .devices
            .iter()
            .position(|device| device.token == device_token)
        else {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        };
        if self.devices[device_index].native_closed {
            return Ok(header_result(MMSYSERR_INVALHANDLE, None, None));
        }
        let Some(buffer_index) = self.devices[device_index]
            .buffers
            .iter()
            .position(|buffer| buffer.token == buffer_token)
        else {
            return Err(wave_invariant(
                "runtime unprepared a header absent from native owner table",
            ));
        };
        let direction = self.devices[device_index].direction;
        let (result, state, submission, completion_pending) = {
            let device = &mut self.devices[device_index];
            let buffer = &mut device.buffers[buffer_index];
            let native_header = ptr::addr_of_mut!(buffer.storage.header);
            let result = if buffer.prepared {
                unsafe { native::unprepare_native(device.direction, &device.native, native_header) }
            } else {
                // A prior native unprepare may have succeeded before a
                // fallible completion copy. Retry from the retained owner
                // state without calling WinMM on an already unprepared header.
                MMSYSERR_NOERROR
            };
            let state = unsafe { callback::header_state(native_header) };
            let submission = buffer.active_submission;
            let had_submission = submission.is_some();
            if result == MMSYSERR_NOERROR && had_submission {
                if state.flags & WHDR_DONE == 0 {
                    return Err(wave_invariant(
                        "native unprepare succeeded before its header was done",
                    ));
                }
            }
            // Unprepare releases WinMM's prepared/queued ownership, but it
            // does not consume the exact-generation completion notification.
            // Retain the stable header until CALLBACK_FUNCTION or real
            // CALLBACK_NULL state publishes that notification.
            let completion_pending = result == MMSYSERR_NOERROR && had_submission;
            if result == MMSYSERR_NOERROR {
                buffer.prepared = false;
                if had_submission {
                    buffer.in_flight = false;
                }
            }
            (result, state, submission, completion_pending)
        };
        let input_bytes = if result == MMSYSERR_NOERROR
            && completion_pending
            && direction == Win16HostWaveDirection::Input
        {
            let device = &self.devices[device_index];
            let buffer = &device.buffers[buffer_index];
            Some(native::completed_input_bytes(direction, buffer, state)?)
        } else {
            None
        };
        if result == MMSYSERR_NOERROR {
            poll::reap_retired_buffers(self);
        }
        Ok(Win16HostWaveResult::Header {
            result,
            buffer: Some(buffer_token),
            submission,
            completion_pending,
            state: Some(state),
            input_bytes,
        })
    }

    fn control(
        &mut self,
        device_token: Win16HostWaveDevice,
        command: Win16HostWaveControl,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let Some(device) = self
            .devices
            .iter_mut()
            .find(|device| device.token == device_token)
        else {
            return Ok(Win16HostWaveResult::Scalar(MMSYSERR_INVALHANDLE));
        };
        if device.native_closed {
            return Ok(Win16HostWaveResult::Scalar(MMSYSERR_INVALHANDLE));
        }
        let result = unsafe { native::control_native(device.direction, &device.native, command) };
        if command == Win16HostWaveControl::Close && result == MMSYSERR_NOERROR {
            device.closing = true;
            device.native_closed = true;
            // Successful waveClose invalidates WinMM's prepared ownership.
            // Keep each stable header and exact submission token until any
            // already queued callback has been consumed, but never unprepare
            // a header through the now-closed native handle.
            for buffer in &mut device.buffers {
                buffer.prepared = false;
            }
        }
        Ok(Win16HostWaveResult::Scalar(result))
    }

    fn get_position(
        &mut self,
        device_token: Win16HostWaveDevice,
        requested_time: u32,
    ) -> Result<Win16HostWaveResult, RuntimeError> {
        let Some(device) = self
            .devices
            .iter()
            .find(|device| device.token == device_token)
        else {
            return Ok(Win16HostWaveResult::Position {
                result: MMSYSERR_INVALHANDLE,
                position: None,
            });
        };
        if device.native_closed {
            return Ok(Win16HostWaveResult::Position {
                result: MMSYSERR_INVALHANDLE,
                position: None,
            });
        }
        // SAFETY: the owner keeps the matching native handle live for this
        // synchronous WinMM call and no native pointer crosses this method.
        let (result, position) =
            unsafe { native::position_native(device.direction, &device.native, requested_time) };
        Ok(Win16HostWaveResult::Position {
            result,
            position: if result == MMSYSERR_NOERROR {
                position
            } else {
                None
            },
        })
    }

    fn allocate_identity(&self) -> Result<u64, RuntimeError> {
        self.identity_source
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |next| {
                (next != 0 && next != u64::MAX).then_some(next + 1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 native WAVE identity space is exhausted",
                )
            })
    }
}

impl super::win16_windows::Win16Windows {
    pub(super) fn new_wave_host(
        &self,
        identity_source: Arc<AtomicU64>,
        text_codec: GuestTextCodec,
    ) -> Win16WaveHost {
        Win16WaveHost::new(identity_source, self.multimedia_wake_sender(), text_codec)
    }
}

fn header_result(
    result: u32,
    buffer: Option<Win16HostWaveBuffer>,
    state: Option<Win16HostWaveHeaderState>,
) -> Win16HostWaveResult {
    Win16HostWaveResult::Header {
        result,
        buffer,
        submission: None,
        completion_pending: false,
        state,
        input_bytes: None,
    }
}

fn header_submitted_result(
    result: u32,
    buffer: Win16HostWaveBuffer,
    state: Win16HostWaveHeaderState,
    submission: Win16HostWaveSubmission,
) -> Win16HostWaveResult {
    Win16HostWaveResult::Header {
        result,
        buffer: Some(buffer),
        submission: Some(submission),
        completion_pending: true,
        state: Some(state),
        input_bytes: None,
    }
}

fn native_handle_is_null(handle: &NativeWaveHandle) -> bool {
    match handle {
        NativeWaveHandle::Input(value) => value.is_null(),
        NativeWaveHandle::Output(value) => value.is_null(),
    }
}

fn wave_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
