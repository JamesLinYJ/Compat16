//! Owned USER worker values for cursor, accelerator, and WinHelp operations.

use crate::{Win16HostCursor, Win16HostQueuedMessage, Win16HostWindow};

/// Opaque host USER accelerator-table identity. The native HACCEL remains in
/// the USER worker's private table and never becomes a guest handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostAccelerator(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostAccelEntry {
    pub flags: u8,
    pub key: u16,
    pub command: u16,
}

/// Native WinHelp data after the command-specific Win16 fields have been
/// widened and copied. These values contain no guest FAR addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostHelpData {
    Ignored,
    Scalar(u32),
    String(Option<Vec<u8>>),
    MultiKey {
        key_list: u8,
        key_phrase: Vec<u8>,
    },
    WindowPosition {
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        max_state: i16,
        member: Vec<u8>,
    },
    NullPointer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostUserCursorAcceleratorOperation {
    GetCursor,
    SetCursor {
        cursor: Option<Win16HostCursor>,
    },
    ShowCursor {
        show: bool,
    },
    WinHelp {
        window: Option<Win16HostWindow>,
        help_file: Option<Vec<u8>>,
        command: u16,
        data: Win16HostHelpData,
    },
    LoadAccelerators {
        entries: Vec<Win16HostAccelEntry>,
    },
    TranslateAccelerator {
        window: Option<Win16HostWindow>,
        table: Win16HostAccelerator,
        message: Win16HostQueuedMessage,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostUserCursorAcceleratorResult {
    GetCursor(Option<Win16HostCursor>),
    SetCursor(Option<Win16HostCursor>),
    /// Retain native USER's complete `int` result until the runtime applies
    /// the Win16 16-bit return slot, preserving its low-word bit pattern.
    ShowCursor(i32),
    WinHelp(bool),
    LoadAccelerators(Option<Win16HostAccelerator>),
    TranslateAccelerator(i32),
}
