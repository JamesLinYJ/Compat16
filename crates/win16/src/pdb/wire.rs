//! Private alignment-one byte layout for the fixed protected PDB prefix.

use super::{
    PDB_ENVIRONMENT_SELECTOR_OFFSET, PDB_FILE_HANDLE_COUNT_OFFSET,
    PDB_FILE_HANDLES_POINTER_OFFSET, PDB_PREFIX_LEN,
};
use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct PdbPrefixWire {
    pub(super) int20: U16,
    pub(super) next_paragraph: U16,
    pub(super) reserved_04: u8,
    pub(super) dispatcher: [u8; 5],
    pub(super) saved_int22: U32,
    pub(super) saved_int23: U32,
    pub(super) saved_int24: U32,
    pub(super) parent_pdb: U16,
    pub(super) jft_slots: [u8; 20],
    pub(super) environment_selector: U16,
    pub(super) saved_stack: U32,
    pub(super) file_handle_count: U16,
    pub(super) file_handles_pointer: U32,
    pub(super) file_handles_handle: U16,
    pub(super) reserved_3a_4f: [u8; 0x16],
    pub(super) dos_call_stub: [u8; 4],
    pub(super) reserved_54_5b: [u8; 8],
    pub(super) fcb1: [u8; 16],
    pub(super) fcb2: [u8; 20],
    pub(super) command_tail: [u8; 128],
}

const _: () = {
    assert!(core::mem::size_of::<PdbPrefixWire>() == PDB_PREFIX_LEN);
    assert!(core::mem::align_of::<PdbPrefixWire>() == 1);
    assert!(core::mem::offset_of!(PdbPrefixWire, int20) == 0x00);
    assert!(core::mem::offset_of!(PdbPrefixWire, next_paragraph) == 0x02);
    assert!(core::mem::offset_of!(PdbPrefixWire, reserved_04) == 0x04);
    assert!(core::mem::offset_of!(PdbPrefixWire, dispatcher) == 0x05);
    assert!(core::mem::offset_of!(PdbPrefixWire, saved_int22) == 0x0a);
    assert!(core::mem::offset_of!(PdbPrefixWire, saved_int23) == 0x0e);
    assert!(core::mem::offset_of!(PdbPrefixWire, saved_int24) == 0x12);
    assert!(core::mem::offset_of!(PdbPrefixWire, parent_pdb) == 0x16);
    assert!(core::mem::offset_of!(PdbPrefixWire, jft_slots) == 0x18);
    assert!(core::mem::offset_of!(PdbPrefixWire, environment_selector)
        == PDB_ENVIRONMENT_SELECTOR_OFFSET as usize);
    assert!(core::mem::offset_of!(PdbPrefixWire, saved_stack) == 0x2e);
    assert!(core::mem::offset_of!(PdbPrefixWire, file_handle_count)
        == PDB_FILE_HANDLE_COUNT_OFFSET as usize);
    assert!(core::mem::offset_of!(PdbPrefixWire, file_handles_pointer)
        == PDB_FILE_HANDLES_POINTER_OFFSET as usize);
    assert!(core::mem::offset_of!(PdbPrefixWire, file_handles_handle) == 0x38);
    assert!(core::mem::offset_of!(PdbPrefixWire, reserved_3a_4f) == 0x3a);
    assert!(core::mem::offset_of!(PdbPrefixWire, dos_call_stub) == 0x50);
    assert!(core::mem::offset_of!(PdbPrefixWire, reserved_54_5b) == 0x54);
    assert!(core::mem::offset_of!(PdbPrefixWire, fcb1) == 0x5c);
    assert!(core::mem::offset_of!(PdbPrefixWire, fcb2) == 0x6c);
    assert!(core::mem::offset_of!(PdbPrefixWire, command_tail) == 0x80);
};
