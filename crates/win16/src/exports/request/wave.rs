//! Typed Win16 WAVE requests. FAR fields stay guest address values here.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WaveDirection {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WaveControl {
    Close,
    Start,
    Stop,
    Pause,
    Restart,
    Reset,
    BreakLoop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WaveParameter {
    Pitch,
    Volume,
    PlaybackRate,
}

/// Fixed Windows 3.1 guest WAVEHDR. Pointer-shaped fields remain 16:16
/// integers; native WAVEHDR has pointer-sized members and a different layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16WaveHeader16 {
    pub data: u32,
    pub buffer_length: u32,
    pub bytes_recorded: u32,
    pub user: u32,
    pub flags: u32,
    pub loops: u32,
    pub next: u32,
    pub reserved: u32,
}

pub const WAVEHDR16_SIZE: usize = 32;
pub const WAVEHDR16_BYTES_RECORDED_OFFSET: usize = 8;
pub const WAVEHDR16_FLAGS_OFFSET: usize = 16;
pub const WAVEOUTCAPS16_SIZE: usize = 48;
pub const WAVEINCAPS16_SIZE: usize = 44;

// The target Win16 header is eight little-endian DWORDs. `zerocopy`'s
// alignment-one wrappers express that packed guest wire without overlaying
// native pointers or depending on host alignment.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct WaveHeader16Wire {
    data: U32,
    buffer_length: U32,
    bytes_recorded: U32,
    user: U32,
    flags: U32,
    loops: U32,
    next: U32,
    reserved: U32,
}

const _: () = {
    assert!(core::mem::size_of::<WaveHeader16Wire>() == WAVEHDR16_SIZE);
    assert!(core::mem::align_of::<WaveHeader16Wire>() == 1);
    assert!(core::mem::offset_of!(WaveHeader16Wire, data) == 0);
    assert!(core::mem::offset_of!(WaveHeader16Wire, buffer_length) == 4);
    assert!(
        core::mem::offset_of!(WaveHeader16Wire, bytes_recorded) == WAVEHDR16_BYTES_RECORDED_OFFSET
    );
    assert!(core::mem::offset_of!(WaveHeader16Wire, user) == 12);
    assert!(core::mem::offset_of!(WaveHeader16Wire, flags) == WAVEHDR16_FLAGS_OFFSET);
    assert!(core::mem::offset_of!(WaveHeader16Wire, loops) == 20);
    assert!(core::mem::offset_of!(WaveHeader16Wire, next) == 24);
    assert!(core::mem::offset_of!(WaveHeader16Wire, reserved) == 28);
};

impl Win16WaveHeader16 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < WAVEHDR16_SIZE {
            return None;
        }
        let wire = WaveHeader16Wire::read_from_bytes(&bytes[..WAVEHDR16_SIZE]).ok()?;
        Some(Self {
            data: wire.data.get(),
            buffer_length: wire.buffer_length.get(),
            bytes_recorded: wire.bytes_recorded.get(),
            user: wire.user.get(),
            flags: wire.flags.get(),
            loops: wire.loops.get(),
            next: wire.next.get(),
            reserved: wire.reserved.get(),
        })
    }
}

/// Target Windows 3.1 WAVEOUTCAPS fields. The version is the SDK's 16-bit
/// `VERSION`; the native WinMM structure is projected field by field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16WaveOutputCapabilities16 {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub formats: u32,
    pub channels: u16,
    pub support: u32,
}

/// Target Windows 3.1 WAVEINCAPS fields. It has no output support field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16WaveInputCapabilities16 {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub formats: u32,
    pub channels: u16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct WaveOutputCapabilities16Wire {
    manufacturer_id: U16,
    product_id: U16,
    driver_version: U16,
    product_name: [u8; 32],
    formats: U32,
    channels: U16,
    support: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct WaveInputCapabilities16Wire {
    manufacturer_id: U16,
    product_id: U16,
    driver_version: U16,
    product_name: [u8; 32],
    formats: U32,
    channels: U16,
}

const _: () = {
    assert!(core::mem::size_of::<WaveOutputCapabilities16Wire>() == WAVEOUTCAPS16_SIZE);
    assert!(core::mem::align_of::<WaveOutputCapabilities16Wire>() == 1);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, manufacturer_id) == 0);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, product_id) == 2);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, driver_version) == 4);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, product_name) == 6);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, formats) == 38);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, channels) == 42);
    assert!(core::mem::offset_of!(WaveOutputCapabilities16Wire, support) == 44);
    assert!(core::mem::size_of::<WaveInputCapabilities16Wire>() == WAVEINCAPS16_SIZE);
    assert!(core::mem::align_of::<WaveInputCapabilities16Wire>() == 1);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, manufacturer_id) == 0);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, product_id) == 2);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, driver_version) == 4);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, product_name) == 6);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, formats) == 38);
    assert!(core::mem::offset_of!(WaveInputCapabilities16Wire, channels) == 42);
};

impl Win16WaveOutputCapabilities16 {
    pub fn encode(self) -> [u8; WAVEOUTCAPS16_SIZE] {
        let wire = WaveOutputCapabilities16Wire {
            manufacturer_id: U16::new(self.manufacturer_id),
            product_id: U16::new(self.product_id),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
            formats: U32::new(self.formats),
            channels: U16::new(self.channels),
            support: U32::new(self.support),
        };
        let mut bytes = [0; WAVEOUTCAPS16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }
}

impl Win16WaveInputCapabilities16 {
    pub fn encode(self) -> [u8; WAVEINCAPS16_SIZE] {
        let wire = WaveInputCapabilities16Wire {
            manufacturer_id: U16::new(self.manufacturer_id),
            product_id: U16::new(self.product_id),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
            formats: U32::new(self.formats),
            channels: U16::new(self.channels),
        };
        let mut bytes = [0; WAVEINCAPS16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WaveRequest {
    DeviceCount {
        direction: Win16WaveDirection,
    },
    DeviceCapabilities {
        direction: Win16WaveDirection,
        device: u16,
        output: u32,
        size: u16,
    },
    ErrorText {
        direction: Win16WaveDirection,
        error: u16,
        output: u32,
        size: u16,
    },
    GetParameter {
        direction: Win16WaveDirection,
        handle: u16,
        parameter: Win16WaveParameter,
        output: u32,
    },
    SetParameter {
        direction: Win16WaveDirection,
        handle: u16,
        parameter: Win16WaveParameter,
        value: u32,
    },
    /// Windows 3.1 MMSYSTEM.H declares both volume exports with a `UINT`
    /// device ID; they do not consume the opaque handle used by pitch/rate.
    GetDeviceVolume {
        device_id: u16,
        output: u32,
    },
    SetDeviceVolume {
        device_id: u16,
        value: u32,
    },
    GetDeviceId {
        direction: Win16WaveDirection,
        handle: u16,
        output: u32,
    },
    Message {
        direction: Win16WaveDirection,
        device_or_handle: u16,
        message: u16,
        parameter1: u32,
        parameter2: u32,
    },
    Open {
        direction: Win16WaveDirection,
        output_handle: u32,
        device: u16,
        format: u32,
        callback: u32,
        instance: u32,
        flags: u32,
    },
    PrepareHeader {
        direction: Win16WaveDirection,
        handle: u16,
        header: u32,
        size: u16,
    },
    UnprepareHeader {
        direction: Win16WaveDirection,
        handle: u16,
        header: u32,
        size: u16,
    },
    SubmitBuffer {
        direction: Win16WaveDirection,
        handle: u16,
        header: u32,
        size: u16,
    },
    GetPosition {
        direction: Win16WaveDirection,
        handle: u16,
        time: u32,
        size: u16,
    },
    Control {
        direction: Win16WaveDirection,
        handle: u16,
        command: Win16WaveControl,
    },
}
