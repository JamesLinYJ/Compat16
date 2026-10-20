//! Fixed Win16 MIDIHDR wire codec from the Windows 3.1 MMSYSTEM contract.
//!
//! Native MIDIHDR uses pointer-sized fields and is never overlaid on this
//! packed guest prefix. zerocopy supplies the fixed little-endian layout;
//! runtime still performs selector, permission, and range checks.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MIDIHDR16_SIZE: usize = 28;
/// Packed Windows 3.1 `MIDIINCAPS`. `VERSION` is a word and `szPname` is 32
/// bytes. The later Win32 `dwSupport` dword is not part of this record.
pub const MIDIINCAPS16_SIZE: usize = 38;
pub const MIDIOUTCAPS16_SIZE: usize = 50;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MidiHeader16Wire {
    data: U32,
    buffer_length: U32,
    bytes_recorded: U32,
    user: U32,
    flags: U32,
    next: U32,
    reserved: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MidiInCaps16Wire {
    manufacturer: U16,
    product: U16,
    driver_version: U16,
    product_name: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct MidiOutCaps16Wire {
    manufacturer: U16,
    product: U16,
    driver_version: U16,
    product_name: [u8; 32],
    technology: U16,
    voices: U16,
    notes: U16,
    channel_mask: U16,
    support: U32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MidiInCaps16 {
    pub manufacturer: u16,
    pub product: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MidiOutCaps16 {
    pub manufacturer: u16,
    pub product: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub technology: u16,
    pub voices: u16,
    pub notes: u16,
    pub channel_mask: u16,
    pub support: u32,
}

impl Win16MidiInCaps16 {
    pub fn encode(self) -> [u8; MIDIINCAPS16_SIZE] {
        MidiInCaps16Wire {
            manufacturer: U16::new(self.manufacturer),
            product: U16::new(self.product),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
        }
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!("MIDIINCAPS16 size is asserted"))
    }
}

impl Win16MidiOutCaps16 {
    pub fn encode(self) -> [u8; MIDIOUTCAPS16_SIZE] {
        MidiOutCaps16Wire {
            manufacturer: U16::new(self.manufacturer),
            product: U16::new(self.product),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
            technology: U16::new(self.technology),
            voices: U16::new(self.voices),
            notes: U16::new(self.notes),
            channel_mask: U16::new(self.channel_mask),
            support: U32::new(self.support),
        }
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!("MIDIOUTCAPS16 size is asserted"))
    }
}

/// Logical MIDIHDR16 values. Pointer fields remain guest FAR integers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16MidiHeader16 {
    pub data: u32,
    pub buffer_length: u32,
    pub bytes_recorded: u32,
    pub user: u32,
    pub flags: u32,
    pub next: u32,
    pub reserved: u32,
}

impl Win16MidiHeader16 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let wire = MidiHeader16Wire::read_from_bytes(bytes).ok()?;
        Some(Self {
            data: wire.data.get(),
            buffer_length: wire.buffer_length.get(),
            bytes_recorded: wire.bytes_recorded.get(),
            user: wire.user.get(),
            flags: wire.flags.get(),
            next: wire.next.get(),
            reserved: wire.reserved.get(),
        })
    }

    pub fn encode(self) -> [u8; MIDIHDR16_SIZE] {
        let wire = MidiHeader16Wire {
            data: U32::new(self.data),
            buffer_length: U32::new(self.buffer_length),
            bytes_recorded: U32::new(self.bytes_recorded),
            user: U32::new(self.user),
            flags: U32::new(self.flags),
            next: U32::new(self.next),
            reserved: U32::new(self.reserved),
        };
        wire.as_bytes()
            .try_into()
            .unwrap_or_else(|_| unreachable!("MIDIHDR16 size is compile-time asserted"))
    }
}

const _: () = {
    assert!(core::mem::size_of::<MidiHeader16Wire>() == MIDIHDR16_SIZE);
    assert!(core::mem::align_of::<MidiHeader16Wire>() == 1);
    assert!(core::mem::offset_of!(MidiHeader16Wire, data) == 0);
    assert!(core::mem::offset_of!(MidiHeader16Wire, buffer_length) == 4);
    assert!(core::mem::offset_of!(MidiHeader16Wire, bytes_recorded) == 8);
    assert!(core::mem::offset_of!(MidiHeader16Wire, user) == 12);
    assert!(core::mem::offset_of!(MidiHeader16Wire, flags) == 16);
    assert!(core::mem::offset_of!(MidiHeader16Wire, next) == 20);
    assert!(core::mem::offset_of!(MidiHeader16Wire, reserved) == 24);
    assert!(core::mem::size_of::<MidiInCaps16Wire>() == MIDIINCAPS16_SIZE);
    assert!(core::mem::align_of::<MidiInCaps16Wire>() == 1);
    assert!(core::mem::offset_of!(MidiInCaps16Wire, manufacturer) == 0);
    assert!(core::mem::offset_of!(MidiInCaps16Wire, product) == 2);
    assert!(core::mem::offset_of!(MidiInCaps16Wire, driver_version) == 4);
    assert!(core::mem::offset_of!(MidiInCaps16Wire, product_name) == 6);
    assert!(core::mem::size_of::<MidiOutCaps16Wire>() == MIDIOUTCAPS16_SIZE);
    assert!(core::mem::align_of::<MidiOutCaps16Wire>() == 1);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, manufacturer) == 0);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, product) == 2);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, driver_version) == 4);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, product_name) == 6);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, technology) == 38);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, voices) == 40);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, notes) == 42);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, channel_mask) == 44);
    assert!(core::mem::offset_of!(MidiOutCaps16Wire, support) == 46);
};
