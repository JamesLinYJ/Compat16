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
    /// `source` excludes the terminator and may cross a 64K selector inside
    /// its owned allocation. The destination stays a guest address so the
    /// runtime can validate the translated bytes, including the terminator,
    /// before writing them.
    OemToAnsi { source: Vec<u8>, destination: u32 },

    /// Convert bytes copied from a NUL-terminated guest ANSI string to OEM.
    /// `source` excludes the terminator and may cross a 64K selector inside
    /// its owned allocation. The destination stays a guest address so the
    /// runtime can validate the translated bytes, including the terminator,
    /// before writing them.
    AnsiToOem { source: Vec<u8>, destination: u32 },
}
