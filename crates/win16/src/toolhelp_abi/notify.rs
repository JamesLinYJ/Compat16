//! Fixed Win16 payload records passed through TOOLHELP notification `dwData`.
//!
//! These are guest-owned packed records from Microsoft's Windows 3.1 SDK
//! `TOOLHELP.H`. Their FAR fields remain 32-bit guest values; no host pointer
//! or host C layout crosses the callback boundary.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const NF_NORMAL: u16 = 0;
pub const NF_TASKSWITCH: u16 = 1;
pub const NF_RIP: u16 = 2;

pub const NFY_UNKNOWN: u16 = 0;
pub const NFY_LOADSEG: u16 = 1;
pub const NFY_FREESEG: u16 = 2;
pub const NFY_STARTDLL: u16 = 3;
pub const NFY_STARTTASK: u16 = 4;
pub const NFY_EXITTASK: u16 = 5;
pub const NFY_DELMODULE: u16 = 6;
pub const NFY_RIP: u16 = 7;
pub const NFY_TASKIN: u16 = 8;
pub const NFY_TASKOUT: u16 = 9;
pub const NFY_INCHAR: u16 = 10;
pub const NFY_OUTSTR: u16 = 11;
pub const NFY_LOGERROR: u16 = 12;
pub const NFY_LOGPARAMERROR: u16 = 13;

pub const NFYLOADSEG16_SIZE: usize = 16;
pub const NFYSTARTDLL16_SIZE: usize = 10;
pub const NFYRIP16_SIZE: usize = 14;

/// Packed Windows 3.1 `NFYLOADSEG`. `module_name` is a guest FAR pointer to
/// a separately owned NUL-terminated ANSI string.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct NfyLoadSeg16Wire {
    pub dw_size: U32,
    pub selector: U16,
    pub segment_number: U16,
    pub segment_type: U16,
    pub instance_count: U16,
    pub module_name: U32,
}

/// Packed Windows 3.1 `NFYSTARTDLL` structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct NfyStartDll16Wire {
    pub dw_size: U32,
    pub module: U16,
    pub code_segment: U16,
    pub instruction_pointer: U16,
}

/// Packed Windows 3.1 `NFYRIP` structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct NfyRip16Wire {
    pub dw_size: U32,
    pub instruction_pointer: U16,
    pub code_segment: U16,
    pub stack_segment: U16,
    pub base_pointer: U16,
    pub exit_code: U16,
}

const _: () = {
    assert!(core::mem::size_of::<NfyLoadSeg16Wire>() == NFYLOADSEG16_SIZE);
    assert!(core::mem::offset_of!(NfyLoadSeg16Wire, module_name) == 12);
    assert!(core::mem::size_of::<NfyStartDll16Wire>() == NFYSTARTDLL16_SIZE);
    assert!(core::mem::offset_of!(NfyStartDll16Wire, instruction_pointer) == 8);
    assert!(core::mem::size_of::<NfyRip16Wire>() == NFYRIP16_SIZE);
    assert!(core::mem::offset_of!(NfyRip16Wire, exit_code) == 12);
};
