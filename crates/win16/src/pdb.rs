//! Fixed 256-byte protected Win16 PDB prefix.
//!
//! The Windows 3.1 Programmer's Reference, volume 2, pp. 346–347, documents a
//! selector returned by `GetCurrentPDB` and shows a 256-byte PSP-shaped sample;
//! that sample labels offset 0x2C as a DOS environment segment. The protected
//! CALC trace and a private implementation layout instead consume a selector
//! there.
//! This codec models that observed protected view while keeping DOS paragraph
//! values and Win16 selectors distinct. See `work/win16-pdb-contract.md` for
//! the evidence boundary and unresolved fields.

use crate::SegmentedPointer;
use guest_core::Selector;
use zerocopy::byteorder::little_endian::{U16, U32};

#[path = "pdb/wire.rs"]
mod wire;

/// Number of bytes in the supported Windows 3.1 PDB prefix.
pub const PDB_PREFIX_LEN: usize = 256;

/// Protected PDB offset containing the environment selector.
pub const PDB_ENVIRONMENT_SELECTOR_OFFSET: u16 = 0x2c;

/// Protected PDB offset containing the inline JFT entry count.
pub const PDB_FILE_HANDLE_COUNT_OFFSET: u16 = 0x32;

/// Protected PDB offset containing the selector:offset JFT pointer.
pub const PDB_FILE_HANDLES_POINTER_OFFSET: u16 = 0x34;

/// A DOS paragraph address stored as a scalar in the protected PDB.
///
/// This is not a selector and must never be resolved through `SelectorTable`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct RealModeParagraph(pub u16);

/// The exact supported PDB prefix, encoded in Win16 little-endian form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdbPrefix {
    bytes: [u8; PDB_PREFIX_LEN],
}

impl PdbPrefix {
    /// Creates the bootstrap view without copying DOS-only pointers or call
    /// bytes. Unimplemented dispatcher, callback, parent, and DOS stub fields
    /// stay zero until their protected contracts are implemented.
    pub fn bootstrap(
        next_paragraph: RealModeParagraph,
        command_tail: &[u8; 128],
        jft_slots: &[u8; 20],
        environment: Selector,
        file_handles: SegmentedPointer,
    ) -> Self {
        let wire = wire::PdbPrefixWire {
            int20: U16::new(0x20cd),
            next_paragraph: U16::new(next_paragraph.0),
            reserved_04: 0,
            dispatcher: [0; 5],
            saved_int22: U32::new(0),
            saved_int23: U32::new(0),
            saved_int24: U32::new(0),
            parent_pdb: U16::new(0),
            jft_slots: *jft_slots,
            environment_selector: U16::new(environment.0),
            saved_stack: U32::new(0),
            file_handle_count: U16::new(20),
            file_handles_pointer: U32::new(file_handles.far_value()),
            file_handles_handle: U16::new(0),
            reserved_3a_4f: [0; 0x16],
            dos_call_stub: [0; 4],
            reserved_54_5b: [0; 8],
            fcb1: [0; 16],
            fcb2: [0; 20],
            command_tail: *command_tail,
        };

        Self {
            bytes: zerocopy::transmute!(wire),
        }
    }

    /// Returns the complete fixed-size guest byte prefix.
    pub const fn as_bytes(&self) -> &[u8; PDB_PREFIX_LEN] {
        &self.bytes
    }

    /// Reads the raw selector value stored at PDB:0x2C.
    ///
    /// The result is only a guest selector word. Resolving it still requires
    /// the owning task's selector table and generation checks.
    pub fn environment_selector(&self) -> Selector {
        Selector(self.wire().environment_selector.get())
    }

    /// Reads the raw protected JFT slot count.
    pub fn file_handle_count(&self) -> u16 {
        self.wire().file_handle_count.get()
    }

    /// Reads the raw 32-bit selector:offset value stored at PDB:0x34.
    ///
    /// This does not recreate a `SegmentedPointer` or prove selector validity.
    pub fn file_handles_pointer(&self) -> u32 {
        self.wire().file_handles_pointer.get()
    }

    fn wire(&self) -> wire::PdbPrefixWire {
        zerocopy::transmute!(self.bytes)
    }
}
