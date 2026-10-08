//! Owned native WAVE requests and results crossing the RuntimeHost boundary.
//!
//! Guest FAR pointers, WAVEHDR16 bytes, and guest handles are deliberately
//! absent. The runtime validates/copies them before creating these values.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWaveDirection {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWaveDevice(pub u64);

/// Native mixer-ID lookup result for a live WAVE token. The native WAVE
/// handle remains owned by the host and is never exposed as a mixer ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWaveMixerId {
    pub result: u32,
    /// Present only when WinMM defines the output for this result, including
    /// MMSYSERR_NODRIVER where the API writes UINT(-1).
    pub mixer_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWaveBuffer(pub u64);

/// One accepted Write/AddBuffer operation. A prepared header can be submitted
/// repeatedly, so completion is correlated with this per-device/header phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostWaveSubmission(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWaveParameter {
    Pitch,
    PlaybackRate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWaveFormat {
    pub channels: u16,
    pub samples_per_second: u32,
    pub average_bytes_per_second: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
}

/// WinMM device capability values copied from native WAVEINCAPS/WAVEOUTCAPS.
/// Driver version stays at its native width here; the guest projection uses
/// the Windows 3.1 SDK's 16-bit VERSION field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWaveCapabilities {
    Input {
        manufacturer_id: u16,
        product_id: u16,
        driver_version: u32,
        product_name: [u8; 32],
        formats: u32,
        channels: u16,
    },
    Output {
        manufacturer_id: u16,
        product_id: u16,
        driver_version: u32,
        product_name: [u8; 32],
        formats: u32,
        channels: u16,
        support: u32,
    },
}

/// Owned guest WAVE format. `PcmWaveFormat` is the 16-byte Windows 3.1
/// PCMWAVEFORMAT; `WaveFormatEx` carries an explicit 18-byte header and its
/// `cb_size` extension. The FAR address remains runtime-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostWaveFormatSpec {
    pub format_tag: u16,
    pub channels: u16,
    pub samples_per_second: u32,
    pub average_bytes_per_second: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    pub extension: Vec<u8>,
    pub shape: Win16HostWaveFormatShape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWaveFormatShape {
    PcmWaveFormat,
    WaveFormatEx { cb_size: u16 },
}

#[derive(Debug)]
pub enum Win16HostWaveInitialBuffer {
    Null,
    Playback { bytes: Vec<u8> },
    Capture { capacity: u32, data_present: bool },
}

#[derive(Debug)]
pub enum Win16HostWaveSubmit {
    Playback {
        bytes: Vec<u8>,
        length: u32,
        flags: u32,
        loops: u32,
    },
    Capture {
        length: u32,
        flags: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostWaveControl {
    Close,
    Start,
    Stop,
    Pause,
    Restart,
    Reset,
    BreakLoop,
}

#[derive(Debug)]
pub enum Win16HostWaveOperation {
    DeviceCount {
        direction: Win16HostWaveDirection,
    },
    DeviceCapabilities {
        direction: Win16HostWaveDirection,
        device_id: u16,
    },
    GetDeviceId {
        device: Win16HostWaveDevice,
    },
    GetParameter {
        device: Win16HostWaveDevice,
        parameter: Win16HostWaveParameter,
    },
    GetVolumeById {
        device_id: u16,
    },
    SetParameter {
        device: Win16HostWaveDevice,
        parameter: Win16HostWaveParameter,
        value: u32,
    },
    SetVolumeById {
        device_id: u16,
        value: u32,
    },
    QueryMappable {
        direction: Win16HostWaveDirection,
        device_id: u16,
    },
    ErrorText {
        direction: Win16HostWaveDirection,
        error: u16,
        capacity: u16,
    },
    Open {
        direction: Win16HostWaveDirection,
        device_id: u16,
        output_handle_present: bool,
        format: Option<Win16HostWaveFormatSpec>,
        flags: u32,
    },
    Prepare {
        device: Win16HostWaveDevice,
        initial: Win16HostWaveInitialBuffer,
        length: u32,
        loops: u32,
    },
    Submit {
        device: Win16HostWaveDevice,
        buffer: Win16HostWaveBuffer,
        operation: Win16HostWaveSubmit,
    },
    Unprepare {
        device: Win16HostWaveDevice,
        buffer: Win16HostWaveBuffer,
    },
    GetPosition {
        device: Win16HostWaveDevice,
        requested_time: u32,
    },
    Control {
        device: Win16HostWaveDevice,
        command: Win16HostWaveControl,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWaveHeaderState {
    pub flags: u32,
    pub bytes_recorded: u32,
}

/// Native MMTIME fields copied from WinMM. The fixed bytes are translated to
/// the eight-byte Win16 MMTIME only after the caller's output range is checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWavePosition {
    pub time_type: u32,
    pub value: [u8; 8],
}

#[derive(Debug)]
pub struct Win16HostWaveCompletion {
    pub buffer: Win16HostWaveBuffer,
    pub submission: Win16HostWaveSubmission,
    pub header: Win16HostWaveHeaderState,
    pub input_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum Win16HostWaveResult {
    DeviceCount(u32),
    DeviceCapabilities {
        result: u32,
        capabilities: Option<Win16HostWaveCapabilities>,
    },
    DeviceId {
        result: u32,
        device_id: Option<u32>,
    },
    Parameter {
        result: u32,
        value: Option<u32>,
    },
    ErrorText {
        result: u32,
        bytes: Option<Vec<u8>>,
    },
    Opened {
        result: u32,
        device: Option<Win16HostWaveDevice>,
    },
    Header {
        result: u32,
        buffer: Option<Win16HostWaveBuffer>,
        submission: Option<Win16HostWaveSubmission>,
        completion_pending: bool,
        state: Option<Win16HostWaveHeaderState>,
        input_bytes: Option<Vec<u8>>,
    },
    Position {
        result: u32,
        position: Option<Win16HostWavePosition>,
    },
    Scalar(u32),
}

#[derive(Debug)]
pub enum Win16HostWaveEventKind {
    Open,
    Close,
    Quiescent { close_sequence: u64 },
    Completed(Win16HostWaveCompletion),
}

#[derive(Debug)]
pub struct Win16HostWaveEvent {
    pub device: Win16HostWaveDevice,
    pub sequence: u64,
    pub kind: Win16HostWaveEventKind,
}
