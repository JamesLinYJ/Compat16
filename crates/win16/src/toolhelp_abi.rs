//! Fixed-width Win16 ToolHelp logical structures and constants.
//!
//! Their private byte-aligned wire records use explicit little-endian fields,
//! independent of host C layout.

mod enumeration;
mod notify;
mod wire;
pub use enumeration::*;
pub use notify::*;

use wire::{GlobalEntry16Wire, GlobalInfo16Wire, encode_wire, read_wire};
use zerocopy::byteorder::little_endian::{U16, U32};

/// Byte offsets in the packed Win16 `GLOBALENTRY` ABI representation.
pub mod globalentry16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const ADDRESS: usize = 4;
    pub const BLOCK_SIZE: usize = 8;
    pub const BLOCK_HANDLE: usize = 12;
    pub const LOCK_COUNT: usize = 14;
    pub const PAGE_LOCK_COUNT: usize = 16;
    pub const FLAGS: usize = 18;
    pub const HEAP_PRESENT: usize = 20;
    pub const OWNER: usize = 22;
    pub const BLOCK_TYPE: usize = 24;
    pub const DATA: usize = 26;
    pub const NEXT: usize = 28;
    pub const NEXT_ALT: usize = 32;
    pub const SIZE: usize = 36;
}

/// Byte offsets in the packed Win16 `GLOBALINFO` ABI representation.
pub mod globalinfo16_offsets {
    pub const DW_SIZE: usize = 0;
    pub const ITEMS: usize = 4;
    pub const FREE_ITEMS: usize = 6;
    pub const LRU_ITEMS: usize = 8;
    pub const SIZE: usize = 10;
}

pub const GLOBALENTRY16_SIZE: usize = globalentry16_offsets::SIZE;
pub const GLOBALINFO16_SIZE: usize = globalinfo16_offsets::SIZE;

/// Flags accepted by `GlobalFirst` and `GlobalNext`.
pub const GLOBAL_ALL: u16 = 0;
pub const GLOBAL_LRU: u16 = 1;
pub const GLOBAL_FREE: u16 = 2;

/// `GLOBALENTRY.wType` values.
pub const GT_UNKNOWN: u16 = 0;
pub const GT_DGROUP: u16 = 1;
pub const GT_DATA: u16 = 2;
pub const GT_CODE: u16 = 3;
pub const GT_TASK: u16 = 4;
pub const GT_RESOURCE: u16 = 5;
pub const GT_MODULE: u16 = 6;
pub const GT_FREE: u16 = 7;
pub const GT_INTERNAL: u16 = 8;
pub const GT_SENTINEL: u16 = 9;
pub const GT_BURGERMASTER: u16 = 10;

/// `GLOBALENTRY.wData` resource-kind values.
pub const GD_USERDEFINED: u16 = 0;
pub const GD_CURSORCOMPONENT: u16 = 1;
pub const GD_BITMAP: u16 = 2;
pub const GD_ICONCOMPONENT: u16 = 3;
pub const GD_MENU: u16 = 4;
pub const GD_DIALOG: u16 = 5;
pub const GD_STRING: u16 = 6;
pub const GD_FONTDIR: u16 = 7;
pub const GD_FONT: u16 = 8;
pub const GD_ACCELERATORS: u16 = 9;
pub const GD_RCDATA: u16 = 10;
pub const GD_ERRTABLE: u16 = 11;
pub const GD_CURSOR: u16 = 12;
pub const GD_ICON: u16 = 14;
pub const GD_NAMETABLE: u16 = 15;
pub const GD_MAX_RESOURCE: u16 = 15;

/// `GLOBALENTRY.wFlags` bits.
pub const GF_PDB_OWNER: u16 = 0x0100;

/// Logical fields of the packed, 36-byte Win16 `GLOBALENTRY` structure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct GlobalEntry16 {
    pub address: u32,
    pub block_size: u32,
    pub block_handle: u16,
    pub lock_count: u16,
    pub page_lock_count: u16,
    pub flags: u16,
    pub heap_present: bool,
    pub owner: u16,
    pub block_type: u16,
    pub data: u16,
    pub next: u32,
    pub next_alt: u32,
}

impl GlobalEntry16 {
    pub const SIZE: usize = GLOBALENTRY16_SIZE;

    /// Decodes the fields of one packed Win16 `GLOBALENTRY` byte sequence.
    /// The structure-size DWORD is accepted as input but not retained by this
    /// value type; use `encode_with_size` when a caller's declared size must
    /// be preserved.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire = read_wire::<GlobalEntry16Wire>(bytes);

        Self {
            address: wire.address.get(),
            block_size: wire.block_size.get(),
            block_handle: wire.block_handle.get(),
            lock_count: wire.lock_count.get(),
            page_lock_count: wire.page_lock_count.get(),
            flags: wire.flags.get(),
            heap_present: wire.heap_present.get() != 0,
            owner: wire.owner.get(),
            block_type: wire.block_type.get(),
            data: wire.data.get(),
            next: wire.next.get(),
            next_alt: wire.next_alt.get(),
        }
    }

    /// Encodes this value as exactly 36 guest-format bytes with `dwSize=36`.
    pub fn encode(self) -> [u8; Self::SIZE] {
        self.encode_with_size(Self::SIZE as u32)
    }

    /// Encodes the known fields while preserving the caller's `dwSize` value.
    /// The returned slice remains the known 36-byte prefix; callers leave any
    /// declared extension tail untouched in guest memory.
    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(GlobalEntry16Wire {
            dw_size: U32::new(dw_size),
            address: U32::new(self.address),
            block_size: U32::new(self.block_size),
            block_handle: U16::new(self.block_handle),
            lock_count: U16::new(self.lock_count),
            page_lock_count: U16::new(self.page_lock_count),
            flags: U16::new(self.flags),
            heap_present: U16::new(u16::from(self.heap_present)),
            owner: U16::new(self.owner),
            block_type: U16::new(self.block_type),
            data: U16::new(self.data),
            next: U32::new(self.next),
            next_alt: U32::new(self.next_alt),
        })
    }
}

/// Logical fields of the packed, 10-byte Win16 `GLOBALINFO` structure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct GlobalInfo16 {
    pub items: u16,
    pub free_items: u16,
    pub lru_items: u16,
}

impl GlobalInfo16 {
    pub const SIZE: usize = GLOBALINFO16_SIZE;

    /// Decodes the three count fields of one packed Win16 `GLOBALINFO`.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire = read_wire::<GlobalInfo16Wire>(bytes);

        Self {
            items: wire.items.get(),
            free_items: wire.free_items.get(),
            lru_items: wire.lru_items.get(),
        }
    }

    /// Encodes this value as exactly 10 guest-format bytes with `dwSize=10`.
    pub fn encode(self) -> [u8; Self::SIZE] {
        self.encode_with_size(Self::SIZE as u32)
    }

    /// Encodes the known fields while preserving the caller's `dwSize` value.
    /// The returned slice remains the known 10-byte prefix; callers leave any
    /// declared extension tail untouched in guest memory.
    pub fn encode_with_size(self, dw_size: u32) -> [u8; Self::SIZE] {
        encode_wire(GlobalInfo16Wire {
            dw_size: U32::new(dw_size),
            items: U16::new(self.items),
            free_items: U16::new(self.free_items),
            lru_items: U16::new(self.lru_items),
        })
    }
}
