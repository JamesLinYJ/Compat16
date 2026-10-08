//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserAnsiRequest {
    /// Lowercase a Win16 ANSI string in place or convert the encoded
    /// single-character form. The string form retains its guest FAR pointer
    /// for the API result and owns checked bytes copied from guest memory.
    AnsiLower { target: Win16AnsiCaseTarget },

    /// Uppercase a string in place or convert the encoded single-character form.
    AnsiUpper { target: Win16AnsiCaseTarget },

    /// Transform a fixed guest buffer through host locale handling. `length ==
    /// 0` means 65536 bytes to the API, while the API returns the original WORD.
    /// Pointer validation and transactional writeback belong to the runtime.
    AnsiCaseBuffer {
        pointer: u32,
        length: u16,
        upper: bool,
    },

    /// Advance a raw guest FAR pointer by one locale-aware ANSI character.
    AnsiNext { pointer: u32 },

    /// Find the previous ANSI character boundary from raw guest FAR pointers.
    AnsiPrev { start: u32, current: u32 },
}
