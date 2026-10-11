//! Owned Win16 USER cursor, accelerator, and WinHelp call values.

use crate::{Msg16, Win16ResourceName};
use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

const ACCELERATOR_ENTRY_BYTES: usize = 5;
const MAX_ACCELERATOR_RESOURCE_BYTES: usize = 1024 * 1024;
const ACCELERATOR_END: u8 = 0x80;
pub(crate) const HELP_WINDOW_INFO16_HEADER_BYTES: usize = 12;
pub(crate) const HELP_WINDOW_INFO16_MIN_BYTES: usize = 14;

/// One decoded entry from an SDK 3.1 RT_ACCELERATOR wire resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16AcceleratorEntry {
    /// Win16 FVIRTKEY/FNOINVERT/FSHIFT/FCONTROL/FALT bits. The resource-only
    /// FEND bit is removed after delimiting the last record.
    pub flags: u8,
    pub key: u16,
    pub command: u16,
}

/// Five-byte, byte-aligned Win16 accelerator resource record. The SDK 3.1
/// Resources reference defines BYTE fFlags followed by WORD wEvent and WORD
/// wId; zerocopy keeps those packed fields independent of host alignment.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
struct AcceleratorEntry16Wire {
    flags: u8,
    event: U16,
    command: U16,
}

const _: () = {
    assert!(core::mem::size_of::<AcceleratorEntry16Wire>() == ACCELERATOR_ENTRY_BYTES);
    assert!(core::mem::align_of::<AcceleratorEntry16Wire>() == 1);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16AcceleratorResourceError {
    Empty,
    TooLarge,
    TruncatedRecord,
    MissingLastMarker,
    AllocationFailed,
}

impl Win16AcceleratorResourceError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "RT_ACCELERATOR contains no entries",
            Self::TooLarge => "RT_ACCELERATOR exceeds the bounded parser size",
            Self::TruncatedRecord => "RT_ACCELERATOR ends in a partial record",
            Self::MissingLastMarker => "RT_ACCELERATOR has no final FEND record",
            Self::AllocationFailed => "could not allocate the decoded RT_ACCELERATOR entries",
        }
    }
}

/// Decode packed five-byte accelerator entries. NE resource extents may include
/// alignment padding after the first complete record carrying FEND.
pub fn decode_accelerator_resource(
    bytes: &[u8],
) -> Result<Vec<Win16AcceleratorEntry>, Win16AcceleratorResourceError> {
    if bytes.is_empty() {
        return Err(Win16AcceleratorResourceError::Empty);
    }
    if bytes.len() > MAX_ACCELERATOR_RESOURCE_BYTES {
        return Err(Win16AcceleratorResourceError::TooLarge);
    }
    let count = bytes.len() / ACCELERATOR_ENTRY_BYTES;
    if count == 0 {
        return Err(Win16AcceleratorResourceError::TruncatedRecord);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| Win16AcceleratorResourceError::AllocationFailed)?;
    let mut records = bytes.chunks_exact(ACCELERATOR_ENTRY_BYTES);
    for record in records.by_ref() {
        let wire = AcceleratorEntry16Wire::read_from_bytes(record)
            .map_err(|_| Win16AcceleratorResourceError::TruncatedRecord)?;
        let last = wire.flags & ACCELERATOR_END != 0;
        entries.push(Win16AcceleratorEntry {
            flags: wire.flags & !ACCELERATOR_END,
            key: wire.event.get(),
            command: wire.command.get(),
        });
        if last {
            return Ok(entries);
        }
    }
    if !records.remainder().is_empty() {
        return Err(Win16AcceleratorResourceError::TruncatedRecord);
    }
    Err(Win16AcceleratorResourceError::MissingLastMarker)
}

/// The guest MULTIKEYHELP fixed header is byte-packed and followed by a
/// variable-length phrase; the Win16 WORD is decoded by zerocopy.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub(crate) struct MultiKeyHelp16HeaderWire {
    pub(crate) size: U16,
    pub(crate) key_list: u8,
}

/// The guest HELPWININFO fixed prefix is six signed 16-bit fields (12 bytes);
/// `rgchMember` begins there and continues through the declared structure size.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub(crate) struct HelpWindowInfo16HeaderWire {
    pub(crate) size: zerocopy::byteorder::little_endian::I16,
    pub(crate) x: zerocopy::byteorder::little_endian::I16,
    pub(crate) y: zerocopy::byteorder::little_endian::I16,
    pub(crate) width: zerocopy::byteorder::little_endian::I16,
    pub(crate) height: zerocopy::byteorder::little_endian::I16,
    pub(crate) max_state: zerocopy::byteorder::little_endian::I16,
}

const _: () = {
    assert!(core::mem::size_of::<MultiKeyHelp16HeaderWire>() == 3);
    assert!(core::mem::align_of::<MultiKeyHelp16HeaderWire>() == 1);
    assert!(core::mem::size_of::<HelpWindowInfo16HeaderWire>() == HELP_WINDOW_INFO16_HEADER_BYTES);
    assert!(core::mem::align_of::<HelpWindowInfo16HeaderWire>() == 1);
};

/// WinHelp's `dwData` after a command-specific Win16 decode. FAR values are
/// copied into owned data; guest pointers never reach the native USER call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HelpData {
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
    /// Unknown commands retain raw bits for diagnostics but are not passed to
    /// WinHelp because their `dwData` pointer/scalar meaning is unspecified.
    Unsupported {
        raw_data: u32,
    },
}

/// One decoded Win16 USER.69/71/171/177/178/247 call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserCursorAcceleratorRequest {
    GetCursor,
    SetCursor {
        cursor: u16,
    },
    ShowCursor {
        show: bool,
    },
    WinHelp {
        window: u16,
        help_file: Option<Vec<u8>>,
        command: u16,
        data: Win16HelpData,
    },
    LoadAccelerators {
        instance: u16,
        name: Win16ResourceName,
    },
    TranslateAccelerator {
        window: u16,
        accelerator: u16,
        message: Msg16,
    },
}
