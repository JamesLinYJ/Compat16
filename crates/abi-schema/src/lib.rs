//! Shared schema for attributes recorded on guest export declarations.
//!
//! Architecture constraints remain separate metadata and are not encoded in
//! this bit field.

#![forbid(unsafe_code)]

use bitflags::bitflags;

bitflags! {
    /// Named export attributes with stable numeric values used by generated
    /// declaration tables.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct ExportAttributes: u16 {
        const NO_RELAY = 1;
        const NONAME = 2;
        const RET16 = 4;
        const RET64 = 8;
        const REGISTER = 16;
        const PRIVATE = 32;
        const ORDINAL = 64;
        const STACK_PROLOG = 128;
        const LEGACY_I386 = 256;
        const FORWARDED = 512;
        /// The function has no return value; guest AX/DX remain unspecified.
        const RETVOID = 1024;
    }
}
