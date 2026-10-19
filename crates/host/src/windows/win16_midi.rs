//! Native WinMM MIDI owner. Guest handles/FAR values never reach this module.
//!
//! MIDIHDR16 is separately marshalled by the runtime. Native MIDIHDR and its
//! sample allocation remain at stable host addresses through successful
//! unprepare/close, and CALLBACK_FUNCTION only publishes owned native events.

#[path = "win16_midi_callback.rs"]
mod callback;
#[path = "win16_midi_calls.rs"]
mod calls;
#[path = "win16_midi_errors.rs"]
mod errors;
#[path = "win16_midi_headers.rs"]
mod headers;
#[path = "win16_midi_notifications.rs"]
mod notifications;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::guest_text::GuestTextCodec;
use super::multimedia_wake::MultimediaWakeSender;
use calls::InputControl;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMidiCall as Call,
    Win16HostMidiCancellationReason, Win16HostMidiCloseAll, Win16HostMidiDevice as DeviceToken,
    Win16HostMidiDirection as Direction, Win16HostMidiDirection,
    Win16HostMidiHeader as HeaderToken, Win16HostMidiMixerId, Win16HostMidiNotification,
    Win16HostMidiNotificationDisposition as Disposition,
    Win16HostMidiProducerFailure as ProducerFailure, Win16HostMidiProducerOwner as ProducerOwner,
    Win16HostMidiProducerQuiescence as ProducerQuiescence,
    Win16HostMidiProducerReceipt as ProducerReceipt, Win16HostMidiResult as ResultValue,
};
use windows_sys::Win32::Media::Audio::{HMIDIIN, HMIDIOUT, MIDIHDR, midiInReset, midiOutReset};

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_INVALPARAM: u32 = 11;
const MIDIERR_UNPREPARED: u32 = 64;

/// A host token owns one real WinMM handle. The generation is independent of
/// the guest WORD alias, and the shared allocator prevents identity reuse.
pub(super) struct Win16MidiHost {
    identity_source: Arc<AtomicU64>,
    event_sequences: Arc<AtomicU64>,
    queue_wake: Arc<callback::QueueWake>,
    wake: MultimediaWakeSender,
    devices: Vec<MidiDevice>,
    unpublished_callbacks: Vec<UnpublishedCallbackOwner>,
    headers: Vec<MidiHeader>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MidiDirection {
    Input,
    Output,
}

#[derive(Clone, Copy)]
enum NativeMidiHandle {
    Input(HMIDIIN),
    Output(HMIDIOUT),
}

struct MidiDevice {
    token: DeviceToken,
    direction: MidiDirection,
    native: NativeMidiHandle,
    context_id: usize,
    callback: Arc<callback::CallbackContext>,
    guest_instance: u32,
    closing: bool,
    /// Actual successful staged-close receipts are repeated while callback
    /// quiescence is pending; absent values mean that stage was not attempted.
    close_reset_result: Option<u32>,
    /// Keep the first reset failure for this exact native device generation.
    close_reset_failure: Option<u32>,
    close_result: Option<u32>,
    close_seen: bool,
    projected: Option<Win16HostMidiNotification>,
    orphaned: bool,
}

/// Failed Open calls can publish callbacks before reporting that no usable
/// device handle exists. Keep the exact registered context until its queued
/// records and in-flight native trampolines have retired.
struct UnpublishedCallbackOwner {
    token: DeviceToken,
    context_id: usize,
    callback: Arc<callback::CallbackContext>,
    open_failed_without_handle: bool,
}

struct MidiHeader {
    token: HeaderToken,
    device: DeviceToken,
    direction: MidiDirection,
    storage: Box<[NativeMidiBuffer]>,
    capacity: u32,
    user: u32,
    prepared: bool,
    retired: bool,
    active_submission: Option<runtime::Win16HostMidiSubmission>,
    completed_submissions: Vec<runtime::Win16HostMidiSubmission>,
    submission_generation: u64,
    /// A Close-stage unprepare is retained until runtime source/ACK quiescence
    /// explicitly releases it; ordinary guest Unprepare keeps its old path.
    defer_release: bool,
}

/// Box owns the packed native header while Vec owns its fixed-length data.
/// Neither field moves or resizes while WinMM retains either address.
struct NativeMidiBuffer {
    header: MIDIHDR,
    samples: Vec<u8>,
}

impl NativeMidiBuffer {
    fn header_address(&self) -> usize {
        std::ptr::addr_of!(self.header) as usize
    }
}

impl Win16MidiHost {
    pub(super) fn new(identity_source: Arc<AtomicU64>, wake: MultimediaWakeSender) -> Self {
        Self {
            identity_source,
            event_sequences: Arc::new(AtomicU64::new(1)),
            queue_wake: Arc::new(callback::QueueWake::new()),
            wake,
            devices: Vec::new(),
            unpublished_callbacks: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub(super) fn execute(
        &mut self,
        call: Call,
        codec: GuestTextCodec,
    ) -> Result<ResultValue, RuntimeError> {
        match call {
            Call::DeviceCount { direction } => calls::device_count(direction),
            Call::GetCaps {
                direction,
                device_id,
                size: _,
            } => calls::get_caps(direction, device_id, codec),
            Call::GetErrorText {
                direction,
                error,
                capacity,
            } => calls::get_error_text(direction, error, capacity, codec),
            Call::Open {
                direction,
                device_id,
                instance,
                flags,
            } => self.open(direction, device_id, instance, flags),
            Call::Close { device } => self.close(device),
            Call::CloseUnpublished { device } => self.close_unpublished(device),
            Call::ReleaseRetiredHeader { device, header } => {
                self.release_retired_header(device, header)
            }
            Call::PrepareHeader {
                device,
                capacity,
                user,
                initial_data,
            } => self.prepare_header(device, capacity, user, initial_data),
            Call::UnprepareHeader { device, header } => self.unprepare_header(device, header),
            Call::OutputShort { device, message } => self.output_short(device, message),
            Call::OutputLong {
                device,
                header,
                data,
            } => self.output_long(device, header, data),
            Call::OutputReset { device } => self.output_reset(device),
            Call::OutputGetVolumeById { device_id } => self.output_get_volume_by_id(device_id),
            Call::OutputSetVolumeById { device_id, volume } => {
                self.output_set_volume_by_id(device_id, volume)
            }
            Call::OutputCachePatches {
                device,
                bank,
                patches,
                flags,
            } => self.output_cache_patches(device, bank, patches, flags, false),
            Call::OutputCacheDrumPatches {
                device,
                patch,
                keys,
                flags,
            } => self.output_cache_patches(device, patch, keys, flags, true),
            Call::GetId { device } => self.get_id(device),
            Call::InputAddBuffer { device, header } => self.input_add_buffer(device, header),
            Call::InputStart { device } => self.input_control(device, InputControl::Start),
            Call::InputStop { device } => self.input_control(device, InputControl::Stop),
            Call::InputReset { device } => self.input_control(device, InputControl::Reset),
        }
    }

    pub(super) fn peek_notification(
        &mut self,
    ) -> Result<Option<Win16HostMidiNotification>, RuntimeError> {
        notifications::peek(self)
    }

    pub(super) fn ack_notification(
        &mut self,
        device: DeviceToken,
        sequence: u64,
        disposition: Disposition,
    ) -> Result<(), RuntimeError> {
        notifications::ack(self, device, sequence, disposition)
    }

    pub(super) fn get_mixer_id(
        &self,
        token: DeviceToken,
        expected: Win16HostMidiDirection,
    ) -> Win16HostMidiMixerId {
        self.get_mixer_id_native(token, expected)
    }

    pub(super) fn close_all(&mut self) -> Result<Win16HostMidiCloseAll, RuntimeError> {
        self.close_all_devices()
    }

    pub(super) fn quiesce_all(&mut self) -> Result<ProducerQuiescence, RuntimeError> {
        self.quiesce_all_devices()
    }

    fn reset_for_retirement(&mut self, index: usize) -> u32 {
        if self.devices[index].close_reset_result == Some(MMSYSERR_NOERROR) {
            return MMSYSERR_NOERROR;
        }
        // SAFETY: `Input`, `midiInReset`, `Output` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let result = unsafe {
            match self.devices[index].native {
                NativeMidiHandle::Input(handle) => midiInReset(handle),
                NativeMidiHandle::Output(handle) => midiOutReset(handle),
            }
        };
        if result == MMSYSERR_NOERROR {
            self.devices[index].close_reset_result = Some(MMSYSERR_NOERROR);
        } else {
            self.devices[index].close_reset_result = None;
            let _ = self.devices[index]
                .close_reset_failure
                .get_or_insert(result);
        }
        result
    }

    fn quiesce_all_devices(&mut self) -> Result<ProducerQuiescence, RuntimeError> {
        if callback::has_unknown_context_failure() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "MIDI callback registry has an unowned failure during producer quiescence",
            ));
        }
        self.drain_unpublished_callbacks(true)?;
        self.validate_callback_owners()?;

        let count = self.devices.len();
        let mut devices = Vec::new();
        devices.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MIDI producer receipts",
                error,
            )
        })?;
        let mut failures = Vec::new();
        failures.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MIDI producer failures",
                error,
            )
        })?;

        for index in (0..count).rev() {
            let owner = producer_owner(&self.devices[index]);
            let token = self.devices[index].token;
            if self.devices[index].closing {
                if self.devices[index].close_result != Some(MMSYSERR_NOERROR) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "closed MIDI producer owner lost its exact successful Close result",
                    ));
                }
                devices.push(ProducerReceipt {
                    device: token,
                    owner,
                    reset_result: self.devices[index].close_reset_result,
                    close_result: self.devices[index].close_result,
                });
                continue;
            }

            let reset = self.reset_for_retirement(index);
            if reset == MMSYSERR_NOERROR {
                devices.push(ProducerReceipt {
                    device: token,
                    owner,
                    reset_result: Some(reset),
                    close_result: None,
                });
            } else {
                failures.push(ProducerFailure {
                    device: token,
                    owner,
                    reset_result: self.devices[index].close_reset_failure.unwrap_or(reset),
                });
            }
        }
        if callback::has_unknown_context_failure() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MIDI producer barrier observed an unregistered native callback owner",
            ));
        }

        Ok(ProducerQuiescence {
            observed_owner_count: count,
            devices,
            failures,
        })
    }

    fn validate_callback_owners(&self) -> Result<(), RuntimeError> {
        for index in 0..self.devices.len() {
            let device = &self.devices[index];
            let expected_context_id = usize::try_from(device.token.token).map_err(|error| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    "MIDI callback identity does not fit its native registry key",
                    error,
                )
            })?;
            if device.token.token == 0
                || device.token.generation == 0
                || device.context_id != expected_context_id
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MIDI native owner lost its exact callback registry identity",
                ));
            }
            if self.devices[..index]
                .iter()
                .any(|prior| prior.token == device.token || prior.context_id == device.context_id)
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MIDI native owner registry duplicated a device or callback identity",
                ));
            }
        }
        Ok(())
    }

    fn drain_unpublished_callbacks(&mut self, wait: bool) -> Result<(), RuntimeError> {
        let deadline = wait.then(|| Instant::now() + Duration::from_millis(250));
        let index = 0;
        while index < self.unpublished_callbacks.len() {
            let owner = &self.unpublished_callbacks[index];
            if !owner.open_failed_without_handle {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "MIDI Open reported success without a handle; callback owner has no native close proof",
                ));
            }
            let token = owner.token;
            let context_id = owner.context_id;
            let context = Arc::clone(&owner.callback);
            if let Some(error) = context.take_failure() {
                return Err(error.with_context(format!(
                    "failed MIDI Open callback owner {} generation {} remains registered",
                    token.token, token.generation
                )));
            }
            if context.in_flight() == 0 {
                if let Some(event) = context.peek() {
                    context.acknowledge(
                        event.sequence,
                        Disposition::Cancelled(Win16HostMidiCancellationReason::UnpublishedOwner),
                    )?;
                    continue;
                }
                if callback::unregister_if_idle(context_id, &context) {
                    self.unpublished_callbacks.remove(index);
                    continue;
                }
            }
            let Some(deadline) = deadline else {
                return Ok(());
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    format!(
                        "failed MIDI Open callback owner {} generation {} did not quiesce; registry owner is retained",
                        token.token, token.generation
                    ),
                ));
            }
            self.queue_wake.wait(remaining);
        }
        Ok(())
    }

    pub(super) fn finalize_closed_device(
        &mut self,
        device: DeviceToken,
    ) -> Result<bool, RuntimeError> {
        self.retire_closed_device(device)
    }

    pub(super) fn wait_notification(&self, timeout: std::time::Duration) -> bool {
        if callback::has_unknown_context_failure() {
            return true;
        }
        self.queue_wake.wait(timeout) || callback::has_unknown_context_failure()
    }

    pub(super) fn allocate_identity(&self) -> Result<u64, RuntimeError> {
        self.identity_source
            .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1).filter(|value| *value != 0)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 MIDI identity source exhausted",
                )
            })
    }

    fn device_index(&self, token: DeviceToken) -> Option<usize> {
        self.devices.iter().position(|entry| entry.token == token)
    }

    fn header_index(&self, device: DeviceToken, token: HeaderToken) -> Option<usize> {
        self.headers
            .iter()
            .position(|entry| entry.device == device && entry.token == token)
    }

    fn allocate_pair<T>(&self, make: impl FnOnce(u64, u64) -> T) -> Result<T, RuntimeError> {
        Ok(make(self.allocate_identity()?, self.allocate_identity()?))
    }
}

impl Drop for Win16MidiHost {
    fn drop(&mut self) {
        // WinMM may still retain MIDIHDR and lpData addresses when reset,
        // unprepare, close, callback drain, or engine shutdown failed. A plain
        // Vec/Box drop would free memory still reachable by the driver. Keep
        // the complete owner graph alive unless the explicit close ledger has
        // retired every device and header. This is a last-resort process-lifetime
        // quarantine; normal teardown empties both collections after receipts.
        if !self.devices.is_empty()
            || !self.unpublished_callbacks.is_empty()
            || !self.headers.is_empty()
        {
            std::mem::forget(std::mem::take(&mut self.devices));
            std::mem::forget(std::mem::take(&mut self.unpublished_callbacks));
            std::mem::forget(std::mem::take(&mut self.headers));
        }
    }
}

fn direction(value: Direction) -> MidiDirection {
    match value {
        Direction::Input => MidiDirection::Input,
        Direction::Output => MidiDirection::Output,
    }
}

fn producer_owner(device: &MidiDevice) -> ProducerOwner {
    let direction = match device.direction {
        MidiDirection::Input => Direction::Input,
        MidiDirection::Output => Direction::Output,
    };
    if device.orphaned {
        ProducerOwner::Unpublished {
            direction,
            callback_instance: device.guest_instance,
        }
    } else {
        ProducerOwner::GuestPublished {
            direction,
            callback_instance: device.guest_instance,
        }
    }
}

fn native_handle_matches(handle: NativeMidiHandle, expected: MidiDirection) -> bool {
    matches!(
        (handle, expected),
        (NativeMidiHandle::Input(_), MidiDirection::Input)
            | (NativeMidiHandle::Output(_), MidiDirection::Output)
    )
}

fn device_pointer(handle: NativeMidiHandle) -> usize {
    match handle {
        NativeMidiHandle::Input(native) => native as usize,
        NativeMidiHandle::Output(native) => native as usize,
    }
}

fn invalid_device() -> ResultValue {
    ResultValue::Scalar(MMSYSERR_INVALHANDLE)
}

fn invalid_header() -> ResultValue {
    ResultValue::Header {
        result: MIDIERR_UNPREPARED,
        state: None,
    }
}

fn invalid_parameter_header() -> ResultValue {
    ResultValue::Header {
        result: MMSYSERR_INVALPARAM,
        state: None,
    }
}

fn allocate_samples(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native MIDI sample storage",
            error,
        )
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}
