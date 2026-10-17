//! Win16 mixer records. `MMVERSION` is a 16-bit `UINT`, the same width as
//! `WAVEOUTCAPS16`. The Windows 3.1 SDK header does not publish these records.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MIXER_SHORT_NAME_CHARS: usize = 16;
pub const MIXER_LONG_NAME_CHARS: usize = 64;
pub const MAXPNAMELEN: usize = 32;

pub const MIXERCAPS16_SIZE: usize = 46;
pub const MIXERLINE16_SIZE: usize = 166;
pub const MIXERCONTROL16_SIZE: usize = 148;
pub const MIXERLINECONTROLS16_SIZE: usize = 24;
pub const MIXERCONTROLDETAILS16_SIZE: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MixerCaps16 {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; MAXPNAMELEN],
    pub support: u32,
    pub destinations: u32,
}

impl Win16MixerCaps16 {
    pub fn encode(self) -> [u8; MIXERCAPS16_SIZE] {
        let wire = MixerCaps16Wire {
            manufacturer_id: U16::new(self.manufacturer_id),
            product_id: U16::new(self.product_id),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
            support: U32::new(self.support),
            destinations: U32::new(self.destinations),
        };
        let mut bytes = [0; MIXERCAPS16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MixerLine16 {
    pub destination: u32,
    pub source: u32,
    pub line_id: u32,
    pub flags: u32,
    pub user: u32,
    pub component_type: u32,
    pub channels: u32,
    pub connections: u32,
    pub controls: u32,
    pub short_name: [u8; MIXER_SHORT_NAME_CHARS],
    pub name: [u8; MIXER_LONG_NAME_CHARS],
    pub target_type: u32,
    pub target_device: u32,
    pub target_manufacturer: u16,
    pub target_product: u16,
    pub target_version: u16,
    pub target_name: [u8; MAXPNAMELEN],
}

impl Win16MixerLine16 {
    pub fn decode(bytes: &[u8; MIXERLINE16_SIZE]) -> Self {
        let wire = MixerLine16Wire::read_from_bytes(bytes).expect("MIXERLINE16 size matches");
        Self {
            destination: wire.destination.get(),
            source: wire.source.get(),
            line_id: wire.line_id.get(),
            flags: wire.flags.get(),
            user: wire.user.get(),
            component_type: wire.component_type.get(),
            channels: wire.channels.get(),
            connections: wire.connections.get(),
            controls: wire.controls.get(),
            short_name: wire.short_name,
            name: wire.name,
            target_type: wire.target_type.get(),
            target_device: wire.target_device.get(),
            target_manufacturer: wire.target_manufacturer.get(),
            target_product: wire.target_product.get(),
            target_version: wire.target_version.get(),
            target_name: wire.target_name,
        }
    }

    pub fn encode(self) -> [u8; MIXERLINE16_SIZE] {
        let wire = MixerLine16Wire {
            cb_struct: U32::new(MIXERLINE16_SIZE as u32),
            destination: U32::new(self.destination),
            source: U32::new(self.source),
            line_id: U32::new(self.line_id),
            flags: U32::new(self.flags),
            user: U32::new(self.user),
            component_type: U32::new(self.component_type),
            channels: U32::new(self.channels),
            connections: U32::new(self.connections),
            controls: U32::new(self.controls),
            short_name: self.short_name,
            name: self.name,
            target_type: U32::new(self.target_type),
            target_device: U32::new(self.target_device),
            target_manufacturer: U16::new(self.target_manufacturer),
            target_product: U16::new(self.target_product),
            target_version: U16::new(self.target_version),
            target_name: self.target_name,
        };
        let mut bytes = [0; MIXERLINE16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }

    pub fn struct_size(bytes: &[u8; MIXERLINE16_SIZE]) -> u32 {
        MixerLine16Wire::read_from_bytes(bytes).expect("MIXERLINE16 size matches").cb_struct.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MixerControl16 {
    pub control_id: u32,
    pub control_type: u32,
    pub flags: u32,
    pub multiple_items: u32,
    pub short_name: [u8; MIXER_SHORT_NAME_CHARS],
    pub name: [u8; MIXER_LONG_NAME_CHARS],
    pub minimum: u32,
    pub maximum: u32,
    pub steps: u32,
}

impl Win16MixerControl16 {
    pub fn encode(self) -> [u8; MIXERCONTROL16_SIZE] {
        let wire = MixerControl16Wire {
            cb_struct: U32::new(MIXERCONTROL16_SIZE as u32),
            control_id: U32::new(self.control_id),
            control_type: U32::new(self.control_type),
            flags: U32::new(self.flags),
            multiple_items: U32::new(self.multiple_items),
            short_name: self.short_name,
            name: self.name,
            minimum: U32::new(self.minimum),
            maximum: U32::new(self.maximum),
            bounds_reserved: [0; 16],
            steps: U32::new(self.steps),
            metrics_reserved: [0; 20],
        };
        let mut bytes = [0; MIXERCONTROL16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MixerLineControls16 {
    pub struct_size: u32,
    pub line_id: u32,
    pub control: u32,
    pub count: u32,
    pub control_size: u32,
    pub controls: u32,
}

impl Win16MixerLineControls16 {
    pub fn decode(bytes: &[u8; MIXERLINECONTROLS16_SIZE]) -> Self {
        let wire = MixerLineControls16Wire::read_from_bytes(bytes)
            .expect("MIXERLINECONTROLS16 size matches");
        Self {
            struct_size: wire.cb_struct.get(),
            line_id: wire.line_id.get(),
            control: wire.control.get(),
            count: wire.count.get(),
            control_size: wire.control_size.get(),
            controls: wire.controls.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MixerControlDetails16 {
    pub struct_size: u32,
    pub control_id: u32,
    pub channels: u32,
    pub multiple_items: u32,
    pub detail_size: u32,
    pub details: u32,
}

impl Win16MixerControlDetails16 {
    pub fn decode(bytes: &[u8; MIXERCONTROLDETAILS16_SIZE]) -> Self {
        let wire = MixerControlDetails16Wire::read_from_bytes(bytes)
            .expect("MIXERCONTROLDETAILS16 size matches");
        Self {
            struct_size: wire.cb_struct.get(),
            control_id: wire.control_id.get(),
            channels: wire.channels.get(),
            multiple_items: wire.multiple_items.get(),
            detail_size: wire.detail_size.get(),
            details: wire.details.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MixerRequest {
    GetNumDevs,
    GetDevCaps { device: u16, capabilities: u32, size: u16 },
    Open { handle_out: u32, device: u16, callback: u32, instance: u32, flags: u32 },
    Close { handle: u16 },
    Message { handle: u16, message: u16, param1: u32, param2: u32 },
    GetLineInfo { object: u16, line: u32, flags: u32 },
    GetId { object: u16, device_id: u32, flags: u32 },
    GetLineControls { object: u16, controls: u32, flags: u32 },
    GetControlDetails { object: u16, details: u32, flags: u32 },
    SetControlDetails { object: u16, details: u32, flags: u32 },
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MixerCaps16Wire {
    manufacturer_id: U16,
    product_id: U16,
    driver_version: U16,
    product_name: [u8; MAXPNAMELEN],
    support: U32,
    destinations: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MixerLine16Wire {
    cb_struct: U32,
    destination: U32,
    source: U32,
    line_id: U32,
    flags: U32,
    user: U32,
    component_type: U32,
    channels: U32,
    connections: U32,
    controls: U32,
    short_name: [u8; MIXER_SHORT_NAME_CHARS],
    name: [u8; MIXER_LONG_NAME_CHARS],
    target_type: U32,
    target_device: U32,
    target_manufacturer: U16,
    target_product: U16,
    target_version: U16,
    target_name: [u8; MAXPNAMELEN],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MixerControl16Wire {
    cb_struct: U32,
    control_id: U32,
    control_type: U32,
    flags: U32,
    multiple_items: U32,
    short_name: [u8; MIXER_SHORT_NAME_CHARS],
    name: [u8; MIXER_LONG_NAME_CHARS],
    minimum: U32,
    maximum: U32,
    bounds_reserved: [u8; 16],
    steps: U32,
    metrics_reserved: [u8; 20],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MixerLineControls16Wire {
    cb_struct: U32,
    line_id: U32,
    control: U32,
    count: U32,
    control_size: U32,
    controls: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MixerControlDetails16Wire {
    cb_struct: U32,
    control_id: U32,
    channels: U32,
    multiple_items: U32,
    detail_size: U32,
    details: U32,
}

const _: () = {
    assert!(core::mem::size_of::<MixerCaps16Wire>() == MIXERCAPS16_SIZE);
    assert!(core::mem::align_of::<MixerCaps16Wire>() == 1);
    assert!(core::mem::offset_of!(MixerCaps16Wire, product_name) == 6);
    assert!(core::mem::offset_of!(MixerCaps16Wire, support) == 38);
    assert!(core::mem::offset_of!(MixerCaps16Wire, destinations) == 42);
    assert!(core::mem::size_of::<MixerLine16Wire>() == MIXERLINE16_SIZE);
    assert!(core::mem::align_of::<MixerLine16Wire>() == 1);
    assert!(core::mem::offset_of!(MixerLine16Wire, short_name) == 40);
    assert!(core::mem::offset_of!(MixerLine16Wire, name) == 56);
    assert!(core::mem::offset_of!(MixerLine16Wire, target_type) == 120);
    assert!(core::mem::offset_of!(MixerLine16Wire, target_version) == 132);
    assert!(core::mem::offset_of!(MixerLine16Wire, target_name) == 134);
    assert!(core::mem::size_of::<MixerControl16Wire>() == MIXERCONTROL16_SIZE);
    assert!(core::mem::align_of::<MixerControl16Wire>() == 1);
    assert!(core::mem::offset_of!(MixerControl16Wire, minimum) == 100);
    assert!(core::mem::offset_of!(MixerControl16Wire, steps) == 124);
    assert!(core::mem::size_of::<MixerLineControls16Wire>() == MIXERLINECONTROLS16_SIZE);
    assert!(core::mem::align_of::<MixerLineControls16Wire>() == 1);
    assert!(core::mem::size_of::<MixerControlDetails16Wire>() == MIXERCONTROLDETAILS16_SIZE);
    assert!(core::mem::align_of::<MixerControlDetails16Wire>() == 1);
};
