//! WAVE runtime ownership and guest WAVEHDR16 marshalling; native buffers stay host-owned.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::{
    Win16HostWaveBuffer, Win16HostWaveCapabilities, Win16HostWaveControl, Win16HostWaveDevice,
    Win16HostWaveDirection, Win16HostWaveEvent, Win16HostWaveEventKind, Win16HostWaveHeaderState,
    Win16HostWaveInitialBuffer, Win16HostWaveOperation, Win16HostWaveParameter,
    Win16HostWaveResult, Win16HostWaveSubmission, Win16HostWaveSubmit,
};
use guest_core::memory::Memory;
use win16_abi::{
    MMTIME16_SIZE, WAVEHDR16_BYTES_RECORDED_OFFSET, WAVEHDR16_FLAGS_OFFSET, WAVEHDR16_SIZE,
    WAVEINCAPS16_SIZE, WAVEOUTCAPS16_SIZE, Win16Mmtime16, Win16WaveControl, Win16WaveDirection,
    Win16WaveHeader16, Win16WaveInputCapabilities16, Win16WaveOutputCapabilities16,
    Win16WaveParameter, Win16WaveRequest,
};

#[path = "win16_multimedia_buffers_codec.rs"]
mod codec;
use codec::{WaveFormatRead, read_wave_data, read_wave_format};
#[path = "win16_multimedia_buffers_calls.rs"]
mod calls;
#[path = "win16_multimedia_buffers_close.rs"]
mod close;
#[path = "win16_multimedia_buffers_cleanup.rs"]
mod cleanup;
#[path = "win16_multimedia_buffers_native_shutdown.rs"]
mod native_shutdown;
#[path = "win16_multimedia_buffers_proof.rs"]
mod proof;
#[path = "win16_multimedia_buffers_device_caps.rs"]
mod device_caps;
#[path = "win16_multimedia_buffers_notifications.rs"]
mod notifications;
#[path = "win16_multimedia_buffers_open_call.rs"]
mod open_call;
pub(in crate::win16_runtime) use cleanup::WaveCallbackCancellationReason;
#[path = "win16_multimedia_buffers_volume.rs"]
mod volume;
#[path = "win16_multimedia_buffers_window_wait.rs"]
mod window_wait;
#[path = "win16_multimedia_buffers_user_posts.rs"]
mod user_posts;
#[path = "win16_multimedia_buffers_events.rs"]
mod events;
#[path = "win16_multimedia_buffers_identity.rs"]
mod identity;
use identity::WaveCallbackRoute;
pub(in crate::win16_runtime) use identity::{WaveCallbackReceipt, WaveTaskIdentity};

use super::guest_ranges::{GuestInputRange, GuestOutputRange, commit_guest_writes};
use super::{
    Win16State, far_callback::Win16FarCallbackConvention, far_callback::Win16FarCallbackReturn,
};
use super::window_post::WindowPostAttempt;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16GuestNotificationSource,
};

// Windows 3.1 MMSYSTEM.H / MMSYSTEM.INC values; native WAVEHDR is never overlaid on guest RAM.
const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_NOMEM: u32 = 7;
const MMSYSERR_NOTSUPPORTED: u32 = 8;
const MMSYSERR_INVALFLAG: u32 = 10;
const MMSYSERR_INVALPARAM: u32 = 11;
const WAVERR_STILLPLAYING: u32 = 33;
const WAVERR_UNPREPARED: u32 = 34;
const CALLBACK_TYPEMASK: u32 = 0x0007_0000;
const CALLBACK_NULL: u32 = 0x0000_0000;
const CALLBACK_WINDOW: u32 = 0x0001_0000;
const CALLBACK_TASK: u32 = 0x0002_0000;
const CALLBACK_FUNCTION: u32 = 0x0003_0000;
const CALLBACK_EVENT: u32 = 0x0005_0000;
const WAVE_FORMAT_QUERY: u32 = 0x0001;
const WAVE_ALLOWSYNC: u32 = 0x0002;
const WAVE_FORMAT_DIRECT: u32 = 0x0008;
// MMDDK's DRV_QUERYMAPPABLE, supported by the documented system-intercepted
// wave*Message contract. The host uses its windows-sys constant for the call.
const DRV_QUERYMAPPABLE: u16 = 2053;
const WHDR_DONE: u32 = 0x0001;
const WHDR_INQUEUE: u32 = 0x0010;
const WOM_OPEN: u16 = 0x03bb;
const WOM_CLOSE: u16 = 0x03bc;
const WOM_DONE: u16 = 0x03bd;
const WIM_OPEN: u16 = 0x03be;
const WIM_CLOSE: u16 = 0x03bf;
const WIM_DATA: u16 = 0x03c0;
const MAX_WAVE_EVENTS_PER_POLL: usize = 128;

#[derive(Debug)]
pub(super) struct Win16WaveState {
    next_guest_handle: u16,
    next_notification_id: u64,
    next_device_generation: u64,
    devices: Vec<WaveDeviceRecord>,
    headers: Vec<WaveHeaderRecord>,
    pending_callbacks: VecDeque<PendingWaveCallback>,
    pending_host_events: VecDeque<Win16HostWaveEvent>,
    warned_unsupported: bool,
    /// Keeps the shared host-owner inventory barrier enabled after WAVE or
    /// SOUND operations that can leave a native owner without a guest token.
    owner_barrier_required: bool,
    producers_quiesced: bool,
    cleanup_complete: bool,
}

#[derive(Clone, Copy, Debug)]
struct WaveDeviceRecord {
    guest_handle: u16,
    direction: Win16WaveDirection,
    host: Win16HostWaveDevice,
    generation: u64,
    callback: Option<WaveCallbackRoute>,
    instance: u32,
    closing: bool,
    /// Only a successful native Reset is a receipt. Preserve the first
    /// failure separately while later cleanup retries the real operation.
    reset_result: Option<u32>,
    reset_failure_result: Option<u32>,
    close_result: Option<u32>,
    last_received_sequence: u64,
    close_event_sequence: Option<u64>,
    producer_quiescence_sequence: Option<u64>,
}

#[derive(Clone, Debug)]
struct WaveHeaderRecord {
    guest_handle: u16,
    direction: Win16WaveDirection,
    host_device: Win16HostWaveDevice,
    host_buffer: Win16HostWaveBuffer,
    header_far: u32,
    data_far: u32,
    capacity: u32,
    queued_length: u32,
    submission: Option<Win16HostWaveSubmission>,
    header_range: GuestOutputRange,
    flags_range: GuestOutputRange,
    bytes_recorded_range: GuestOutputRange,
    data_range: Option<GuestOutputRange>,
    data_input_range: Option<GuestInputRange>,
    native_prepared: bool,
    guest_prepared: bool,
    native_queued: bool,
    unprepare_state: Option<Win16HostWaveHeaderState>,
    unprepare_input_bytes: Option<Vec<u8>>,
    completion_projection: WaveCompletionProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaveCompletionProjection {
    Pending,
    Committed(Win16HostWaveHeaderState),
    Suppressed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaveCallbackDispatchState {
    Available,
    Reserved,
    CallbackRunning(super::CallbackFrameId),
    RollbackRetained(super::CallbackFrameId),
    SourceReleasePending(super::CallbackFrameId),
    CallbackUnavailable,
    CallbackRetired(super::CallbackFrameId),
}

#[derive(Clone, Debug)]
struct PendingWaveCallback {
    notification_id: u64,
    source: Win16GuestNotificationSource,
    route: WaveCallbackRoute,
    guest_handle: u16,
    instance: u32,
    message: u16,
    header_far: u32,
    header_selector_generation: Option<u64>,
    closed_device: Option<Win16HostWaveDevice>,
    dispatch: WaveCallbackDispatchState,
    /// The exact host-created USER POST failure remains on this source owner
    /// until terminal ACK and native WAVE source retirement both complete.
    post_failure: Option<Arc<crate::Win16WindowOperationStartedFailure>>,
    /// Normal USER source proof/result/cause stays on this WAVE source row
    /// until its exact proof has been read back and consumed.
    post_attempt: Option<WindowPostAttempt>,
    /// Terminal callback cleanup caches the exact real device-quiescence
    /// receipt here before the central scheduler pops the callback frame.
    terminal_producer_proof: Option<WaveProducerQuiescenceReceipt>,
    terminal_ack: Option<crate::Win16WindowTerminalAck>,
    terminal_acknowledged: bool,
}

/// A device-scoped proof minted only after this runtime consumed the real
/// terminal Close event and verified no host events or header owners remain.
/// The exact callback row and scheduler frame are bound into the proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct WaveProducerQuiescenceReceipt {
    callback: WaveCallbackReceipt,
    callback_id: Option<super::CallbackFrameId>,
    device: Win16HostWaveDevice,
    device_generation: u64,
    close_event_sequence: u64,
    quiescence_event_sequence: u64,
    guest_header_count: usize,
    pending_host_event_count: usize,
    pending_source_count: usize,
    pending_source_max_sequence: u64,
}

impl Default for Win16WaveState {
    fn default() -> Self {
        Self {
            next_guest_handle: 1,
            next_notification_id: 1,
            next_device_generation: 1,
            devices: Vec::new(),
            headers: Vec::new(),
            pending_callbacks: VecDeque::new(),
            pending_host_events: VecDeque::new(),
            warned_unsupported: false,
            owner_barrier_required: false,
            producers_quiesced: false,
            cleanup_complete: false,
        }
    }
}

impl Win16WaveState {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.devices.is_empty()
            || !self.headers.is_empty()
            || !self.pending_callbacks.is_empty()
            || !self.pending_host_events.is_empty()
    }

    pub(super) fn native_sources_quiescent(&self) -> bool {
        self.devices.iter().all(|device| {
            device.closing && device.producer_quiescence_sequence.is_some()
        }) && self.headers.is_empty() && self.pending_callbacks.is_empty()
            && self.pending_host_events.is_empty()
    }

    fn allocate_device_generation(&mut self) -> Result<u64, RuntimeError> {
        let generation = self.next_device_generation;
        self.next_device_generation = generation.checked_add(1).ok_or_else(|| {
            wave_invariant("Win16 WAVE device generations are exhausted")
        })?;
        if generation == 0 {
            return Err(wave_invariant("Win16 WAVE device generation is zero"));
        }
        Ok(generation)
    }
}

impl Win16State {
    /// SOUND's separate request adapter shares the WAVE owner barrier. Keep
    /// this bit in the WAVE state so accepted PlaySound leases and direct
    /// SOUND open/query calls join the same teardown gate as waveOpen.
    pub(in crate::win16_runtime) fn require_wave_owner_barrier(&mut self) {
        self.wave_audio.owner_barrier_required = true;
    }

    pub(super) fn wave_api(
        &mut self,
        request: Win16WaveRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.poll_wave_events(memory, host, true)?;
        let dword_return = matches!(&request, Win16WaveRequest::Message { .. });
        let result = match request {
            Win16WaveRequest::DeviceCount { direction } => {
                let result = host.win16_wave(Win16HostWaveOperation::DeviceCount {
                    direction: host_direction(direction),
                })?;
                match result {
                    Win16HostWaveResult::DeviceCount(count) => u32::from(count as u16),
                    _ => {
                        return Err(wave_invariant(
                            "WAVE device count returned the wrong result",
                        ));
                    }
                }
            }
            Win16WaveRequest::DeviceCapabilities {
                direction,
                device,
                output,
                size,
            } => self.wave_device_capabilities(direction, device, output, size, memory, host)?,
            Win16WaveRequest::ErrorText {
                direction,
                error,
                output,
                size,
            } => self.wave_error_text(direction, error, output, size, memory, host)?,
            Win16WaveRequest::GetParameter {
                direction,
                handle,
                parameter,
                output,
            } => self.wave_get_parameter(direction, handle, parameter, output, memory, host)?,
            Win16WaveRequest::SetParameter {
                direction,
                handle,
                parameter,
                value,
            } => self.wave_set_parameter(direction, handle, parameter, value, host)?,
            Win16WaveRequest::GetDeviceVolume { device_id, output } => {
                self.wave_get_device_volume(device_id, output, memory, host)?
            }
            Win16WaveRequest::SetDeviceVolume { device_id, value } => {
                self.wave_set_device_volume(device_id, value, host)?
            }
            Win16WaveRequest::GetDeviceId {
                direction,
                handle,
                output,
            } => self.wave_get_device_id(direction, handle, output, memory, host)?,
            Win16WaveRequest::Message {
                direction,
                device_or_handle,
                message,
                parameter1,
                parameter2,
            } => self.wave_message(
                direction,
                device_or_handle,
                message,
                parameter1,
                parameter2,
                host,
            )?,
            Win16WaveRequest::Open {
                direction,
                output_handle,
                device,
                format,
                callback,
                instance,
                flags,
            } => self.wave_open(
                direction,
                output_handle,
                device,
                format,
                callback,
                instance,
                flags,
                memory,
                host,
            )?,
            Win16WaveRequest::PrepareHeader {
                direction,
                handle,
                header,
                size,
            } => self.wave_prepare(direction, handle, header, size, memory, host)?,
            Win16WaveRequest::UnprepareHeader {
                direction,
                handle,
                header,
                size,
            } => self.wave_unprepare(direction, handle, header, size, memory, host)?,
            Win16WaveRequest::SubmitBuffer {
                direction,
                handle,
                header,
                size,
            } => self.wave_submit(direction, handle, header, size, memory, host)?,
            Win16WaveRequest::Control {
                direction,
                handle,
                command,
            } => self.wave_control(direction, handle, command, memory, host)?,
            Win16WaveRequest::GetPosition {
                direction,
                handle,
                time,
                size,
            } => self.wave_get_position(direction, handle, time, size, memory, host)?,
        };
        self.poll_wave_events(memory, host, true)?;
        Ok(if dword_return {
            result
        } else {
            result as u16 as u32
        })
    }

    fn capture_wave_header(
        &self,
        memory: &Memory,
        header_far: u32,
    ) -> Result<WaveHeaderCapture, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(header_far)
            .map_err(crate::runtime_error)?;
        let header_range = GuestOutputRange::capture(self, memory, pointer, WAVEHDR16_SIZE)?;
        let bytes = header_range.read(self, memory)?;
        let header = Win16WaveHeader16::decode(&bytes)
            .ok_or_else(|| wave_invariant("captured Win16 WAVEHDR has an invalid fixed size"))?;
        let bytes_pointer = self
            .selectors
            .add_bytes(pointer, WAVEHDR16_BYTES_RECORDED_OFFSET as u32)
            .map_err(crate::runtime_error)?;
        let flags_pointer = self
            .selectors
            .add_bytes(pointer, WAVEHDR16_FLAGS_OFFSET as u32)
            .map_err(crate::runtime_error)?;
        let bytes_recorded_range = GuestOutputRange::capture(self, memory, bytes_pointer, 4)?;
        let flags_range = GuestOutputRange::capture(self, memory, flags_pointer, 4)?;
        Ok(WaveHeaderCapture {
            header,
            header_range,
            flags_range,
            bytes_recorded_range,
        })
    }

    fn capture_wave_output(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> Result<GuestOutputRange, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length)
    }

    fn guest_pointer(&self, far: u32) -> Result<Option<win16_abi::SegmentedPointer>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        self.selectors
            .pointer_from_far(far)
            .map(Some)
            .map_err(crate::runtime_error)
    }

    fn commit_header_state(
        &self,
        memory: &mut Memory,
        buffer: Win16HostWaveBuffer,
        state: Win16HostWaveHeaderState,
        input_bytes: Option<&[u8]>,
    ) -> Result<(), RuntimeError> {
        let Some(record) = self.wave_audio.header_by_host(buffer).cloned() else {
            return Err(wave_invariant(
                "native WAVE event has no guest header mapping",
            ));
        };
        self.commit_header_state_for_record(&record, memory, state, input_bytes)
    }

    fn commit_header_state_for_record(
        &self,
        record: &WaveHeaderRecord,
        memory: &mut Memory,
        state: Win16HostWaveHeaderState,
        input_bytes: Option<&[u8]>,
    ) -> Result<(), RuntimeError> {
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(2 + usize::from(input_bytes.is_some_and(|bytes| !bytes.is_empty())))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve WAVE guest completion writes",
                    error,
                )
            })?;
        writes.push((
            record.flags_range.clone(),
            wave_bytes(state.flags.to_le_bytes())?,
        ));
        if record.direction == Win16WaveDirection::Input {
            writes.push((
                record.bytes_recorded_range.clone(),
                wave_bytes(state.bytes_recorded.to_le_bytes())?,
            ));
        }
        if let Some(bytes) = input_bytes.filter(|bytes| !bytes.is_empty()) {
            let Some(range) = record.data_range.clone() else {
                return Err(RuntimeError::new(
                    Kind::GuestFault,
                    "native WAVE input completed bytes for a null guest buffer",
                ));
            };
            let mut owned = Vec::new();
            owned.try_reserve_exact(bytes.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve WAVE input guest copyback",
                    error,
                )
            })?;
            owned.extend_from_slice(bytes);
            writes.push((range, owned));
        }
        commit_guest_writes(self, memory, writes)
    }

    fn validate_header_record_ranges(
        &self,
        record: &WaveHeaderRecord,
        memory: &Memory,
    ) -> Result<Win16WaveHeader16, RuntimeError> {
        record.header_range.is_live(self, memory)?;
        record.flags_range.is_live(self, memory)?;
        record.bytes_recorded_range.is_live(self, memory)?;
        if let Some(range) = &record.data_range {
            range.is_live(self, memory)?;
        }
        if let Some(range) = &record.data_input_range {
            range.is_live(self, memory)?;
        }
        let bytes = record.header_range.read(self, memory)?;
        let header = Win16WaveHeader16::decode(&bytes)
            .ok_or_else(|| wave_invariant("saved WAVE header range lost its fixed layout"))?;
        if header.data != record.data_far || header.buffer_length > record.capacity {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 WAVE header pointer or capacity changed while prepared",
            ));
        }
        Ok(header)
    }

    fn warn_wave_unsupported(&mut self, host: &mut impl RuntimeHost, message: &str) {
        if self.wave_audio.warned_unsupported {
            return;
        }
        self.wave_audio.warned_unsupported = true;
        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap, message));
    }

}

impl Win16WaveState {
    fn allocate_guest_handle(&mut self) -> Option<u16> {
        for _ in 0..u16::MAX {
            let candidate = self.next_guest_handle.max(1);
            self.next_guest_handle = candidate.wrapping_add(1).max(1);
            if !self
                .devices
                .iter()
                .any(|record| record.guest_handle == candidate)
            {
                return Some(candidate);
            }
        }
        None
    }

    fn device(&self, handle: u16, direction: Win16WaveDirection) -> Option<&WaveDeviceRecord> {
        self.devices.iter().find(|record| {
            record.guest_handle == handle && record.direction == direction && !record.closing
        })
    }

    fn header(&self, handle: u16, far: u32) -> Option<&WaveHeaderRecord> {
        self.headers
            .iter()
            .find(|record| record.guest_handle == handle && record.header_far == far)
    }

    fn header_by_host(&self, buffer: Win16HostWaveBuffer) -> Option<&WaveHeaderRecord> {
        self.headers
            .iter()
            .find(|record| record.host_buffer == buffer)
    }

    fn retire_device(&mut self, device: Win16HostWaveDevice) {
        self.devices.retain(|record| record.host != device);
        self.headers.retain(|record| record.host_device != device);
    }
}

struct WaveHeaderCapture {
    header: Win16WaveHeader16,
    header_range: GuestOutputRange,
    flags_range: GuestOutputRange,
    bytes_recorded_range: GuestOutputRange,
}

const fn host_direction(direction: Win16WaveDirection) -> Win16HostWaveDirection {
    match direction {
        Win16WaveDirection::Input => Win16HostWaveDirection::Input,
        Win16WaveDirection::Output => Win16HostWaveDirection::Output,
    }
}

const fn host_control(command: Win16WaveControl) -> Win16HostWaveControl {
    match command {
        Win16WaveControl::Close => Win16HostWaveControl::Close,
        Win16WaveControl::Start => Win16HostWaveControl::Start,
        Win16WaveControl::Stop => Win16HostWaveControl::Stop,
        Win16WaveControl::Pause => Win16HostWaveControl::Pause,
        Win16WaveControl::Restart => Win16HostWaveControl::Restart,
        Win16WaveControl::Reset => Win16HostWaveControl::Reset,
        Win16WaveControl::BreakLoop => Win16HostWaveControl::BreakLoop,
    }
}

const fn wave_message(direction: Win16WaveDirection, open: bool) -> u16 {
    match (direction, open) {
        (Win16WaveDirection::Output, true) => WOM_OPEN,
        (Win16WaveDirection::Output, false) => WOM_CLOSE,
        (Win16WaveDirection::Input, true) => WIM_OPEN,
        (Win16WaveDirection::Input, false) => WIM_CLOSE,
    }
}

const fn wave_completion_message(direction: Win16WaveDirection) -> u16 {
    match direction {
        Win16WaveDirection::Output => WOM_DONE,
        Win16WaveDirection::Input => WIM_DATA,
    }
}

fn is_guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn wave_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn wave_bytes<const N: usize>(bytes: [u8; N]) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(N).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 WAVE output bytes",
            error,
        )
    })?;
    output.extend_from_slice(&bytes);
    Ok(output)
}
