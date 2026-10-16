//! Typed WINNLS IME profile calls.

use crate::SegmentedPointer;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WinnlsRequest {
    EnableIme {
        hwnd: u16,
        enable: bool,
    },
    GetEnableStatus {
        hwnd: u16,
    },
    QueryIme {
        /// Only the name is input; the remaining profile fields are output.
        /// `None` denotes an invalid input pointer, not an empty query name.
        name: Option<[u8; 80]>,
        output: Option<SegmentedPointer>,
    },
    GetIme {
        hwnd: u16,
        output: Option<SegmentedPointer>,
    },
    SetIme {
        hwnd: u16,
        name: Option<[u8; 80]>,
    },
    /// The legacy WINNLS entrypoints return zero in the target WOW path and do
    /// not inspect their structure or string pointers.
    UnsupportedProfileMutation,
}
