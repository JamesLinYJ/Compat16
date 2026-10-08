//! Win16 multimedia-family decoding results and checked runtime marshalling.
//!
//! The host-facing operations contain copied bytes and opaque native window
//! identities only. Guest FAR values remain in the decoded call until this
//! module validates and stages their output buffers.

use std::collections::BTreeMap;

#[path = "win16_multimedia_timer.rs"]
mod timer;
#[path = "win16_multimedia_joystick.rs"]
mod joystick;
#[path = "win16_multimedia_cleanup.rs"]
mod cleanup;
#[path = "win16_multimedia_services.rs"]
mod services;

use guest_core::Registers;
use guest_core::memory::Memory;
use compat_services::win16_multimedia::{
    FourCc, Win16MultimediaCallback,
};
use win16_abi::{
    Win16MultimediaArgument, Win16MultimediaCall, Win16ReturnKind,
};

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16GuestCallbackSender,
    Win16GuestCallbackToken, Win16HostWindow,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaVersionApi {
    Mmsystem,
    AudioCompressionManager,
    VideoForWindows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaDeviceApi {
    Joystick,
    MidiInput,
    MidiOutput,
    AuxiliaryOutput,
    WaveInput,
    WaveOutput,
    Mixer,
    VideoCapture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaErrorApi {
    MidiInput,
    MidiOutput,
    WaveInput,
    WaveOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaAudioApi {
    WaveInput,
    WaveOutput,
    MidiInput,
    MidiOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaAudioCommand {
    Close,
    Start,
    Stop,
    Pause,
    Restart,
    Reset,
    BreakLoop,
    GetVolume,
    SetVolume(u32),
    ShortMessage(u32),
    GetDeviceId,
}

/// Normalized result from the native MMTIME service. The host adapter converts
/// its union into this owned value; runtime serializes the explicit Win16
/// MMTIME16 layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMultimediaTimeValue {
    Milliseconds(u32),
    Samples(u32),
    Bytes(u32),
    Smpte([u8; 6]),
    Midi(u32),
    Ticks(u32),
    Unsupported(u32),
}

/// Host work requested after Win16 addresses and callback handles have been
/// separated from native pointers. Every byte buffer is owned by this request.
#[derive(Debug)]
pub enum Win16HostMultimediaOperation {
    Version(Win16MultimediaVersionApi),
    DeviceCount(Win16MultimediaDeviceApi),
    TimePeriod { begin: bool, period: u16 },
    TimeSystemTime,
    TimeDeviceCapabilities,
    TimerSet {
        guest_timer_id: u16,
        delay: u16,
        resolution: u16,
        user_data: u32,
        flags: u16,
        callback: Win16HostGuestCallback,
    },
    TimerKill {
        timer_id: u32,
        callback: Win16HostMultimediaCallbackId,
        force_unregister: bool,
    },
    JoystickThresholdGet { device: u16 },
    JoystickThresholdSet { device: u16, threshold: u16 },
    JoystickPosition { device: u16 },
    JoystickReleaseCapture { device: u16 },
    JoystickSetCapture {
        window: Win16HostWindow,
        device: u16,
        period: u16,
        changed: bool,
    },
    ErrorText {
        api: Win16MultimediaErrorApi,
        error: u16,
        buffer: Vec<u8>,
    },
    MciSendString {
        command: Vec<u8>,
        buffer: Vec<u8>,
        callback: Option<Win16HostWindow>,
    },
    MciGetDeviceId { device_name: Vec<u8> },
    MciGetErrorString { error: u32, buffer: Vec<u8> },
    AviFileLifecycle { initialize: bool },
    MmioOpen { path: Vec<u8>, flags: u32 },
    MmioClose { file: Win16HostMultimediaHandle, flags: u16 },
    MmioRead { file: Win16HostMultimediaHandle, count: u32 },
    MmioWrite { file: Win16HostMultimediaHandle, data: Vec<u8> },
    MmioSeek { file: Win16HostMultimediaHandle, offset: i32, origin: i16 },
    MmioFlush { file: Win16HostMultimediaHandle, flags: u16 },
    MmioRename { old_path: Vec<u8>, new_path: Vec<u8>, flags: u32 },
    AudioOpen {
        api: Win16MultimediaAudioApi,
        device: u16,
        format: Option<Vec<u8>>,
        callback_window: Option<Win16HostWindow>,
        callback: Option<Win16HostGuestCallback>,
        instance: u32,
        flags: u32,
    },
    AudioCall {
        api: Win16MultimediaAudioApi,
        file: Win16HostMultimediaHandle,
        command: Win16MultimediaAudioCommand,
        callback: Option<Win16HostMultimediaCallbackId>,
        force_unregister: bool,
    },
    MciGetDeviceIdFromElement { element_id: u32, device_type: Vec<u8> },
    MciExecute { command: Vec<u8> },
    MciDriverYield { device_id: u16 },
    MciDriverNotify { window: Win16HostWindow, device_id: u16, status: u16 },
    MciGetDriverData { device_id: u16 },
    MciSetDriverData { device_id: u16, value: u32 },
    AuxGetVolume { device: u16 },
    AuxSetVolume { device: u16, value: u32 },
}

#[derive(Debug)]
pub enum Win16HostMultimediaResult {
    Scalar(u32),
    Buffer { result: u32, bytes: Vec<u8> },
    Transfer { result: i32, bytes: Vec<u8> },
    Handle(Option<Win16HostMultimediaHandle>),
    Opened {
        result: u32,
        handle: Option<Win16HostMultimediaHandle>,
        callback: Option<Win16HostMultimediaCallbackId>,
    },
    TimerSet {
        result: u32,
        timer_id: Option<u32>,
        callback: Option<Win16HostMultimediaCallbackId>,
    },
    TimeSystemTime { result: u32, value: Win16HostMultimediaTimeValue },
    TimeCapabilities { result: u32, minimum_period: u32, maximum_period: u32 },
    JoystickPosition { result: u32, x: u32, y: u32, z: u32, buttons: u32 },
    Output { result: u32, value: u32 },
    Unit,
}

/// Opaque native multimedia identity. This integer is created only by the
/// host adapter and is never derived from a Win16 guest handle or address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMultimediaHandle(pub u64);

/// Host-owned registration identity for a native callback context. It is
/// unrelated to the guest FAR procedure and can only be used to retire this
/// runtime-owned context when its audio handle or timer is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMultimediaCallbackId(pub u64);

/// Data required by a native callback producer. The guest procedure stays
/// behind the opaque scheduler token; only owned event values cross threads.
#[derive(Clone, Debug)]
pub struct Win16HostGuestCallback {
    pub callback: Win16GuestCallbackToken,
    pub guest_handle: u16,
    pub user_data: u32,
    pub sender: Win16GuestCallbackSender,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Win16MultimediaHandleKind {
    Mmio,
    WaveInput,
    WaveOutput,
    MidiInput,
    MidiOutput,
    MidiStream,
    Mixer,
    AviFile,
    AviStream,
    AviFrame,
    Video,
    VideoStream,
    DrawDib,
    Codec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MultimediaHandleRecord {
    kind: Win16MultimediaHandleKind,
    host: Option<Win16HostMultimediaHandle>,
    guest_callback: Option<Win16GuestCallbackToken>,
    host_callback: Option<Win16HostMultimediaCallbackId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MultimediaTimerRecord {
    host_timer_id: Option<u32>,
    guest_callback: Win16GuestCallbackToken,
    host_callback: Option<Win16HostMultimediaCallbackId>,
    one_shot: bool,
}

/// Guest-visible multimedia handles are small checked tokens. Native handles
/// stay opaque in this table, and each token is restricted to one API family.
#[derive(Debug, Default)]
pub struct Win16MultimediaState {
    next_guest_handle: u16,
    handles: BTreeMap<u16, MultimediaHandleRecord>,
    next_guest_timer: u16,
    timers: BTreeMap<u16, MultimediaTimerRecord>,
    avi_file_init_count: u32,
}

impl Win16MultimediaState {
    pub fn new() -> Self {
        Self {
            next_guest_handle: 1,
            handles: BTreeMap::new(),
            next_guest_timer: 1,
            timers: BTreeMap::new(),
            avi_file_init_count: 0,
        }
    }

    pub fn add_handle(
        &mut self,
        kind: Win16MultimediaHandleKind,
        host: Win16HostMultimediaHandle,
    ) -> Option<u16> {
        self.add_handle_with_callbacks(kind, host, None, None)
    }

    pub fn add_handle_with_callbacks(
        &mut self,
        kind: Win16MultimediaHandleKind,
        host: Win16HostMultimediaHandle,
        guest_callback: Option<Win16GuestCallbackToken>,
        host_callback: Option<Win16HostMultimediaCallbackId>,
    ) -> Option<u16> {
        let mut candidate = self.next_guest_handle.max(1);
        for _ in 0..u16::MAX {
            if !self.handles.contains_key(&candidate) {
                self.handles.insert(candidate, MultimediaHandleRecord {
                    kind,
                    host: Some(host),
                    guest_callback,
                    host_callback,
                });
                self.next_guest_handle = candidate.wrapping_add(1).max(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }

    /// Reserve an alias before opening a native handle. Audio callback events
    /// can then contain the value the guest will receive, even when Windows
    /// notifies during the open call. The reservation is bound or removed
    /// before the runtime returns to the guest.
    pub fn reserve_handle(
        &mut self,
        kind: Win16MultimediaHandleKind,
        guest_callback: Option<Win16GuestCallbackToken>,
    ) -> Option<u16> {
        let mut candidate = self.next_guest_handle.max(1);
        for _ in 0..u16::MAX {
            if !self.handles.contains_key(&candidate) {
                self.handles.insert(candidate, MultimediaHandleRecord {
                    kind,
                    host: None,
                    guest_callback,
                    host_callback: None,
                });
                self.next_guest_handle = candidate.wrapping_add(1).max(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }

    pub fn bind_handle(
        &mut self,
        guest: u16,
        kind: Win16MultimediaHandleKind,
        host: Win16HostMultimediaHandle,
        host_callback: Option<Win16HostMultimediaCallbackId>,
    ) -> bool {
        let Some(record) = self.handles.get_mut(&guest) else { return false; };
        if record.kind != kind || record.host.is_some() { return false; }
        record.host = Some(host);
        record.host_callback = host_callback;
        true
    }

    pub fn host_handle(
        &self,
        guest: u16,
        kind: Win16MultimediaHandleKind,
    ) -> Option<Win16HostMultimediaHandle> {
        self.handles.get(&guest).filter(|record| record.kind == kind)
            .and_then(|record| record.host)
    }

    pub fn callback_ids(
        &self,
        guest: u16,
        kind: Win16MultimediaHandleKind,
    ) -> (Option<Win16GuestCallbackToken>, Option<Win16HostMultimediaCallbackId>) {
        self.handles.get(&guest).filter(|record| record.kind == kind)
            .map_or((None, None), |record| (record.guest_callback, record.host_callback))
    }

    pub fn remove_handle(
        &mut self,
        guest: u16,
        kind: Win16MultimediaHandleKind,
    ) -> Option<Win16HostMultimediaHandle> {
        self.remove_handle_record(guest, kind).and_then(|(host, _, _)| host)
    }

    pub fn remove_handle_record(
        &mut self,
        guest: u16,
        kind: Win16MultimediaHandleKind,
    ) -> Option<(
        Option<Win16HostMultimediaHandle>,
        Option<Win16GuestCallbackToken>,
        Option<Win16HostMultimediaCallbackId>,
    )> {
        if self.handles.get(&guest).is_some_and(|record| record.kind == kind) {
            self.handles.remove(&guest).map(|record| {
                (record.host, record.guest_callback, record.host_callback)
            })
        } else {
            None
        }
    }

    /// Move all live host identities to task cleanup. The caller closes each
    /// through the API matching its recorded kind before discarding the table.
    pub fn take_all_handles(
        &mut self,
    ) -> impl Iterator<Item = (
        Win16MultimediaHandleKind,
        Option<Win16HostMultimediaHandle>,
        Option<Win16GuestCallbackToken>,
        Option<Win16HostMultimediaCallbackId>,
    )> {
        std::mem::take(&mut self.handles).into_values().map(|record| (
            record.kind, record.host, record.guest_callback, record.host_callback,
        ))
    }

    pub fn reserve_timer(
        &mut self,
        guest_callback: Win16GuestCallbackToken,
        one_shot: bool,
    ) -> Option<u16> {
        let mut candidate = self.next_guest_timer.max(1);
        for _ in 0..u16::MAX {
            if !self.timers.contains_key(&candidate) {
                self.timers.insert(candidate, MultimediaTimerRecord {
                    host_timer_id: None,
                    guest_callback,
                    host_callback: None,
                    one_shot,
                });
                self.next_guest_timer = candidate.wrapping_add(1).max(1);
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }

    pub fn bind_timer(
        &mut self,
        guest: u16,
        host_timer_id: u32,
        host_callback: Win16HostMultimediaCallbackId,
    ) -> bool {
        let Some(record) = self.timers.get_mut(&guest) else { return false; };
        if record.host_timer_id.is_some() { return false; }
        record.host_timer_id = Some(host_timer_id);
        record.host_callback = Some(host_callback);
        true
    }

    pub fn timer(
        &self,
        guest: u16,
    ) -> Option<(u32, Win16GuestCallbackToken, Win16HostMultimediaCallbackId)> {
        self.timers.get(&guest).and_then(|record| Some((
            record.host_timer_id?, record.guest_callback, record.host_callback?,
        )))
    }

    pub fn remove_timer(
        &mut self,
        guest: u16,
    ) -> Option<(
        Option<u32>, Win16GuestCallbackToken, Option<Win16HostMultimediaCallbackId>, bool,
    )> {
        self.timers.remove(&guest).map(|record| (
            record.host_timer_id, record.guest_callback, record.host_callback,
            record.one_shot,
        ))
    }

    /// Retire a one-shot timer after its opaque callback token was resolved
    /// and queued on the guest CPU. The active callback frame has already
    /// captured the procedure, so its scheduler token may then be removed.
    pub fn retire_one_shot_timer(
        &mut self,
        callback: Win16GuestCallbackToken,
    ) -> Option<u16> {
        let guest_id = self.timers.iter().find_map(|(guest_id, record)| {
            (record.guest_callback == callback && record.one_shot).then_some(*guest_id)
        })?;
        self.timers.remove(&guest_id).map(|_| guest_id)
    }

    pub fn take_all_timers(
        &mut self,
    ) -> impl Iterator<Item = (
        Option<u32>, Win16GuestCallbackToken, Option<Win16HostMultimediaCallbackId>, bool,
    )> {
        std::mem::take(&mut self.timers).into_values().map(|record| (
            record.host_timer_id, record.guest_callback, record.host_callback,
            record.one_shot,
        ))
    }
}

impl super::Win16State {
    /// Execute the immediately bridgeable scalar, error-text, MCI-string, and
    /// version queries. Other known signatures remain explicit compatibility
    /// gaps until their structures, resource lifetimes, and callbacks have a
    /// family-specific codec.
    pub(super) fn multimedia_compat_api(
        &mut self,
        call: Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let module = call.module;
        let name = call.name.unwrap_or("");

        if services::is_multimedia_service_export(module, name) {
            return self.multimedia_services_api(
                &call, registers, memory, host, return_to, return_kind,
            );
        }

        if module.eq_ignore_ascii_case("MMSYSTEM") {
            if name.eq_ignore_ascii_case("timeGetTime") {
                let value = host.win16_get_tick_count()?;
                return self.finish_multimedia(registers, return_to, value, return_kind);
            }
            if timer::is_timer_export(name) {
                return self.multimedia_timer_api(
                    &call, registers, memory, host, return_to, return_kind,
                );
            }
            if joystick::is_joystick_export(name) {
                return self.multimedia_joystick_api(
                    &call, registers, memory, host, return_to, return_kind,
                );
            }
            if name.eq_ignore_ascii_case("mmioStringToFOURCC") {
                let text = string(&call, 0)?;
                let flags = word(&call, 1)?;
                let fourcc = FourCc::from_win16_string(text, flags).map_err(|error| {
                    RuntimeError::with_source(Kind::GuestFault,
                        "convert Win16 multimedia string to FOURCC", error)
                })?;
                return self.finish_multimedia(
                    registers, return_to, fourcc.raw(), return_kind,
                );
            }
            if name.eq_ignore_ascii_case("auxGetVolume") {
                let device = word(&call, 0)?;
                let output = self.prepare_multimedia_output(memory, pointer(&call, 1)?, 4)?
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "auxiliary volume output was not prepared"))?;
                let reply = host.win16_multimedia(
                    Win16HostMultimediaOperation::AuxGetVolume { device },
                )?;
                let Win16HostMultimediaResult::Output { result, value } = reply else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "auxGetVolume returned the wrong multimedia result"));
                };
                if result == 0 { output.commit(memory, &value.to_le_bytes())?; }
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            if name.eq_ignore_ascii_case("auxSetVolume") {
                let device = word(&call, 0)?;
                let value = dword(&call, 1)?;
                let result = scalar(host.win16_multimedia(
                    Win16HostMultimediaOperation::AuxSetVolume { device, value },
                )?)?;
                return self.finish_multimedia(registers, return_to, result, return_kind);
            }
            if super::audio::is_audio_export(name) {
                return self.audio_compat_api(
                    &call, registers, memory, host, return_to, return_kind,
                );
            }
            if super::mmio::is_mmio_export(name) {
                return self.mmio_compat_api(
                    &call, registers, memory, host, return_to, return_kind,
                );
            }
            if super::mci::is_mci_export(name) {
                return self.mci_compat_api(
                    &call, registers, memory, host, return_to, return_kind,
                );
            }
        }

        Err(RuntimeError::new(Kind::CompatibilityGap, format!(
            "Win16 multimedia export {} ordinal {} ({name}) has no structure-safe host bridge",
            module, call.ordinal,
        )))
    }

    pub(super) fn prepare_multimedia_output(
        &self,
        memory: &Memory,
        pointer: u32,
        capacity: usize,
    ) -> Result<Option<super::win16_text_memory::PreparedTextWrite>, RuntimeError> {
        if capacity == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(pointer).map_err(crate::runtime_error)?;
        self.prepare_text_write(memory, pointer, capacity).map(Some)
    }

    pub(super) fn finish_multimedia(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
        value: u32,
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(registers, return_to.0, return_to.1,
            return_to.2, value, return_kind)
    }

}

pub(super) fn word(call: &Win16MultimediaCall, index: usize) -> Result<u16, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::Word(value)) => Ok(*value),
        _ => Err(bad_decoded_argument(call, index)),
    }
}

pub(super) fn dword(call: &Win16MultimediaCall, index: usize) -> Result<u32, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::Dword(value)) => Ok(*value),
        _ => Err(bad_decoded_argument(call, index)),
    }
}

pub(super) fn pointer(call: &Win16MultimediaCall, index: usize) -> Result<u32, RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::GuestFarPointer(value)) => Ok(*value),
        _ => Err(bad_decoded_argument(call, index)),
    }
}

pub(super) fn string(call: &Win16MultimediaCall, index: usize) -> Result<&[u8], RuntimeError> {
    match call.arguments.get(index) {
        Some(Win16MultimediaArgument::AnsiString(value)) => Ok(value),
        _ => Err(bad_decoded_argument(call, index)),
    }
}

fn bad_decoded_argument(call: &Win16MultimediaCall, index: usize) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, format!(
        "Win16 multimedia decoder produced the wrong value kind for {} ordinal {} argument {}",
        call.module, call.ordinal, index,
    ))
}

pub(super) fn scalar(reply: Win16HostMultimediaResult) -> Result<u32, RuntimeError> {
    match reply {
        Win16HostMultimediaResult::Scalar(value) => Ok(value),
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia host service returned the wrong result kind")),
    }
}

fn buffer_result(reply: Win16HostMultimediaResult) -> Result<(u32, Vec<u8>), RuntimeError> {
    match reply {
        Win16HostMultimediaResult::Buffer { result, bytes } => Ok((result, bytes)),
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia host service returned the wrong buffer result kind")),
    }
}


fn zeroed_buffer(capacity: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 multimedia output buffer", error,
    ))?;
    buffer.resize(capacity, 0);
    Ok(buffer)
}

fn commit_text_result(
    output: Option<crate::win16_text_memory::PreparedTextWrite>,
    memory: &mut Memory,
    capacity: usize,
    mut bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    if bytes.len() > capacity {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "host Win16 multimedia output exceeded its guest buffer capacity"));
    }
    if let Some(prepared) = output {
        let written = bytes.iter().position(|byte| *byte == 0)
            .map_or(bytes.len(), |index| index + 1);
        bytes.truncate(written);
        prepared.commit(memory, &bytes)?;
    } else if !bytes.is_empty() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "host Win16 multimedia service wrote bytes for a zero-capacity output"));
    }
    Ok(())
}

#[allow(dead_code)]
fn decode_callback(flags: u32, value: u32) -> Win16MultimediaCallback {
    Win16MultimediaCallback::decode(flags, value)
}
