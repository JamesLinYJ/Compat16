//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LibraryStringsRequest {
    /// Compare checked strings with the selected Win16 collation semantics.
    StringCompare {
        left: Vec<u8>,
        right: Vec<u8>,
        comparison: Win16StringComparison,
    },

    /// Convert bytes copied from a NUL-terminated guest OEM string to ANSI.
    /// `source` excludes the terminator; the destination is retained as a raw
    /// guest FAR pointer so the runtime can size and validate output including
    /// its terminator before writing it.
    OemToAnsi { source: Vec<u8>, destination: u32 },
}
