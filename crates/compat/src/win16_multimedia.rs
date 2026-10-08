//! Small, platform-neutral Win16 multimedia ABI helpers.
//!
//! Guest FAR values remain integer tokens here. These helpers do not turn a
//! guest address into a host pointer; runtime code must validate and copy
//! pointed-to data before issuing a host request.

use std::fmt;

/// `mmioStringToFOURCC` flag: uppercase ASCII letters before packing.
pub const MMIO_TOUPPER: u16 = 0x0010;

/// WinMM callback-kind mask and documented callback modes.
pub const CALLBACK_TYPEMASK: u32 = 0x0007_0000;
pub const CALLBACK_NULL: u32 = 0x0000_0000;
pub const CALLBACK_WINDOW: u32 = 0x0001_0000;
pub const CALLBACK_THREAD: u32 = 0x0002_0000;
pub const CALLBACK_FUNCTION: u32 = 0x0003_0000;
pub const CALLBACK_EVENT: u32 = 0x0005_0000;

/// WinMM multimedia timer flags and errors retained by the Win16 ABI.
pub const TIME_PERIODIC: u16 = 0x0001;
pub const TIMERR_NOCANDO: u16 = 97;
pub const TIMERR_STRUCT: u16 = 129;

/// Win16 `MMTIME16.wType` values.
pub const TIME_MS: u16 = 0x0001;
pub const TIME_SAMPLES: u16 = 0x0002;
pub const TIME_BYTES: u16 = 0x0004;
pub const TIME_SMPTE: u16 = 0x0008;
pub const TIME_MIDI: u16 = 0x0010;
pub const TIME_TICKS: u16 = 0x0020;

/// Packed Win16 structure sizes and field offsets used by timer marshalling.
pub const MMTIME16_TYPE_OFFSET: usize = 0;
pub const MMTIME16_UNION_OFFSET: usize = 2;
pub const MMTIME16_UNION_SIZE: usize = 6;
pub const MMTIME16_SIZE: usize = MMTIME16_UNION_OFFSET + MMTIME16_UNION_SIZE;
pub const TIMECAPS16_MIN_PERIOD_OFFSET: usize = 0;
pub const TIMECAPS16_MAX_PERIOD_OFFSET: usize = 2;
pub const TIMECAPS16_SIZE: usize = 4;
pub const JOYINFO16_X_OFFSET: usize = 0;
pub const JOYINFO16_Y_OFFSET: usize = 2;
pub const JOYINFO16_Z_OFFSET: usize = 4;
pub const JOYINFO16_BUTTONS_OFFSET: usize = 6;
pub const JOYINFO16_SIZE: usize = 8;

/// Win16 waveform format constants used by the legacy `waveIn/OutOpen` ABI.
pub const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
pub const WAVE_FORMAT_QUERY: u32 = 0x0001;
pub const WAVEFORMAT16_TAG_OFFSET: usize = 0;
pub const WAVEFORMAT16_CHANNELS_OFFSET: usize = 2;
pub const WAVEFORMAT16_SAMPLES_PER_SEC_OFFSET: usize = 4;
pub const WAVEFORMAT16_AVG_BYTES_PER_SEC_OFFSET: usize = 8;
pub const WAVEFORMAT16_BLOCK_ALIGN_OFFSET: usize = 12;
pub const WAVEFORMAT16_SIZE: usize = 14;
pub const PCMWAVEFORMAT16_BITS_PER_SAMPLE_OFFSET: usize = WAVEFORMAT16_SIZE;
pub const PCMWAVEFORMAT16_SIZE: usize = 16;

/// The Win16 callback discriminator is separate from its payload. A function
/// value is preserved as a guest FARPROC; window, task, and event values stay
/// guest identities until runtime translates or rejects them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MultimediaCallback {
    None,
    Function { far_proc: u32 },
    Window { guest_window: u16 },
    Task { guest_task: u32 },
    Event { guest_event: u32 },
    Unknown { kind: u32, value: u32 },
}

impl Win16MultimediaCallback {
    pub const fn decode(flags: u32, value: u32) -> Self {
        match flags & CALLBACK_TYPEMASK {
            CALLBACK_NULL => Self::None,
            CALLBACK_FUNCTION => Self::Function { far_proc: value },
            CALLBACK_WINDOW => Self::Window { guest_window: value as u16 },
            CALLBACK_THREAD => Self::Task { guest_task: value },
            CALLBACK_EVENT => Self::Event { guest_event: value },
            kind => Self::Unknown { kind, value },
        }
    }

    /// Only function callbacks contain a guest code address. Other modes are
    /// guest object identities or task identifiers and must not be validated
    /// as executable memory.
    pub const fn guest_far_proc(self) -> Option<u32> {
        match self {
            Self::Function { far_proc } => Some(far_proc),
            _ => None,
        }
    }
}

/// A FOURCC packed in the Windows multimedia little-endian byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FourCc(u32);

impl FourCc {
    /// Convert a checked, NUL-free Win16 string into a FOURCC. Microsoft
    /// specifies one-to-four ASCII characters, padded on the right with
    /// spaces; longer strings are truncated after four characters.
    pub fn from_win16_string(text: &[u8], flags: u16) -> Result<Self, FourCcError> {
        if text.contains(&0) {
            return Err(FourCcError::EmbeddedNul);
        }

        let mut bytes = [b' '; 4];
        for (destination, source) in bytes.iter_mut().zip(text.iter().copied().take(4)) {
            if source > 0x7f {
                return Err(FourCcError::NonAscii(source));
            }
            *destination = if flags & MMIO_TOUPPER != 0 {
                source.to_ascii_uppercase()
            } else {
                source
            };
        }
        Ok(Self(u32::from_le_bytes(bytes)))
    }

    pub const fn from_raw(value: u32) -> Self { Self(value) }
    pub const fn raw(self) -> u32 { self.0 }
    pub const fn bytes(self) -> [u8; 4] { self.0.to_le_bytes() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourCcError {
    EmbeddedNul,
    NonAscii(u8),
}

impl fmt::Display for FourCcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmbeddedNul => f.write_str("FOURCC input contains an embedded NUL byte"),
            Self::NonAscii(byte) => write!(f, "FOURCC input contains non-ASCII byte 0x{byte:02X}"),
        }
    }
}

impl std::error::Error for FourCcError {}

/// Convert a Win16 multimedia error code to the 16-bit result returned by
/// WinMM APIs without interpreting ordinary error values as host failures.
pub const fn error_word(code: u32) -> u16 { code as u16 }
