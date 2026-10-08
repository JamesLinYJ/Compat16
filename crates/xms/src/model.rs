use std::fmt;

use guest_core::{MemoryError, OwnerId, PhysAddr};

pub(super) const HANDLE_COUNT: usize = 255;
pub(super) const KIB: u32 = 1024;
pub(super) const FIRST_XMS_ADDRESS: u32 = 0x0011_0000;
pub(super) const DEFAULT_ARENA_END: u32 = 0x0110_0000;
pub(super) const HMA_END_EXCLUSIVE: u32 = 0x0010_fff0;
pub(super) const BIOS_ROM_START: u32 = 0x000f_0000;

/// Physical range used for XMS allocations. The end address is exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmsConfig {
    pub arena_start: PhysAddr,
    pub arena_end: PhysAddr,
}

impl Default for XmsConfig {
    fn default() -> Self {
        Self {
            arena_start: PhysAddr(FIRST_XMS_ADDRESS),
            arena_end: PhysAddr(DEFAULT_ARENA_END),
        }
    }
}

/// XMS version metadata and this service's highest implemented function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmsVersion {
    pub major: u8,
    pub minor: u8,
    pub driver_revision: u16,
    pub highest_function: u8,
}

/// Features that are actually implemented by this service instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmsCapabilities {
    pub extended_memory: bool,
    pub moves: bool,
    pub locking: bool,
    pub a20_control: bool,
    pub hma: bool,
    pub umb: bool,
}

/// A real-mode guest far pointer. This carries guest register values only;
/// it is never converted to a host pointer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestFarPointer {
    pub segment: u16,
    pub offset: u16,
}

/// Service-level version metadata. `highest_function` is local capability
/// metadata; INT 2Fh function 00h returns `DX` as the HMA-existence flag.
pub const XMS_VERSION: XmsVersion = XmsVersion {
    major: 2,
    minor: 0,
    driver_revision: 1,
    highest_function: 0x0f,
};

pub const XMS_CAPABILITIES: XmsCapabilities = XmsCapabilities {
    extended_memory: true,
    moves: true,
    locking: true,
    a20_control: true,
    hma: true,
    umb: false,
};

/// Errors returned by XMS service operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XmsError {
    InvalidConfiguration,
    InvalidHandle,
    OutOfMemory,
    HandleTableFull,
    BlockLocked,
    LockCountOverflow,
    BlockNotLocked,
    InvalidSourceHandle,
    InvalidSourceOffset,
    InvalidDestinationHandle,
    InvalidDestinationOffset,
    InvalidLength,
    InvalidMoveOverlap,
    HmaDoesNotExist,
    HmaAlreadyAllocated,
    HmaMinimumNotMet,
    HmaNotAllocated,
    A20CounterOverflow,
    A20CounterUnderflow,
    A20StillEnabled,
    UnsupportedFunction(u8),
    /// Configured XMS physical storage could not be read or written.
    ArenaMemory(MemoryError),
    /// A move descriptor or move buffer could not be accessed.
    Memory(MemoryError),
}

impl XmsError {
    /// XMS error byte corresponding to this failure.
    pub fn error_code(&self) -> u8 {
        match self {
            Self::InvalidConfiguration => 0x8e,
            Self::InvalidHandle => 0xa2,
            Self::OutOfMemory => 0xa0,
            Self::HandleTableFull => 0xa1,
            Self::BlockLocked => 0xab,
            Self::LockCountOverflow => 0xac,
            Self::BlockNotLocked => 0xaa,
            Self::InvalidSourceHandle => 0xa3,
            Self::InvalidSourceOffset => 0xa4,
            Self::InvalidDestinationHandle => 0xa5,
            Self::InvalidDestinationOffset => 0xa6,
            Self::InvalidLength => 0xa7,
            Self::InvalidMoveOverlap => 0xa8,
            Self::HmaDoesNotExist => 0x90,
            Self::HmaAlreadyAllocated => 0x91,
            Self::HmaMinimumNotMet => 0x92,
            Self::HmaNotAllocated => 0x93,
            Self::A20CounterOverflow | Self::A20CounterUnderflow => 0x82,
            Self::A20StillEnabled => 0x94,
            Self::UnsupportedFunction(_) => 0x80,
            Self::ArenaMemory(_) => 0xa0,
            Self::Memory(MemoryError::AllocationFailed) => 0x8e,
            Self::Memory(_) => 0xa7,
        }
    }
}

impl fmt::Display for XmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XMS error {:02X}h: ", self.error_code())?;
        match self {
            Self::InvalidConfiguration => f.write_str("the XMS memory configuration is invalid"),
            Self::InvalidHandle => f.write_str("the XMS handle is invalid"),
            Self::OutOfMemory => f.write_str("there is not enough extended memory"),
            Self::HandleTableFull => f.write_str("the XMS handle table is full"),
            Self::BlockLocked => f.write_str("the XMS block is locked"),
            Self::LockCountOverflow => f.write_str("the XMS block lock count cannot be increased"),
            Self::BlockNotLocked => f.write_str("the XMS block is not locked"),
            Self::InvalidSourceHandle => f.write_str("the XMS move source handle is invalid"),
            Self::InvalidSourceOffset => f.write_str("the XMS move source offset is outside its block"),
            Self::InvalidDestinationHandle => f.write_str("the XMS move destination handle is invalid"),
            Self::InvalidDestinationOffset => {
                f.write_str("the XMS move destination offset is outside its block")
            }
            Self::InvalidLength => f.write_str("the XMS move length or descriptor is invalid"),
            Self::InvalidMoveOverlap => f.write_str("the XMS move ranges overlap"),
            Self::HmaDoesNotExist => f.write_str("the high memory area is not available"),
            Self::HmaAlreadyAllocated => f.write_str("the high memory area is already allocated"),
            Self::HmaMinimumNotMet => f.write_str("the requested high memory area size is too small"),
            Self::HmaNotAllocated => f.write_str("the high memory area has not been allocated"),
            Self::A20CounterOverflow => f.write_str("the XMS A20 enable count overflowed"),
            Self::A20CounterUnderflow => f.write_str("the XMS A20 enable count is already zero"),
            Self::A20StillEnabled => f.write_str("the A20 line cannot be disabled while another owner holds it"),
            Self::UnsupportedFunction(function) => {
                write!(f, "XMS function AH={function:02X}h is not supported")
            }
            Self::ArenaMemory(error) => write!(f, "XMS arena storage access failed: {error}"),
            Self::Memory(error) => write!(f, "guest memory access failed: {error}"),
        }
    }
}

impl std::error::Error for XmsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Memory(error) | Self::ArenaMemory(error) => Some(error), _ => None }
    }
}

impl From<MemoryError> for XmsError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Block {
    pub(super) base: PhysAddr,
    pub(super) size_kb: u16,
    pub(super) locks: u8,
    pub(super) owner: OwnerId,
}

/// Per-handle information returned by the XMS 0Eh query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleInfo {
    pub size_kb: u16,
    pub lock_count: u8,
    pub owner: OwnerId,
    pub free_handles: u16,
}

/// Largest contiguous and total unallocated XMS memory, in KiB.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FreeSpace {
    pub largest_kb: u16,
    pub total_kb: u16,
}

/// XMS move descriptor, with the exact 16-byte XMS wire layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoveRequest {
    pub length: u32,
    pub source_handle: u16,
    pub source_offset: u32,
    pub destination_handle: u16,
    pub destination_offset: u32,
}

impl MoveRequest {
    pub const BYTE_LEN: usize = 16;

    /// Decode the packed, little-endian descriptor from guest bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, XmsError> {
        let bytes: &[u8; Self::BYTE_LEN] = bytes.try_into().map_err(|_| XmsError::InvalidLength)?;
        Ok(Self {
            length: u32::from_le_bytes(bytes[0..4].try_into().expect("fixed slice")),
            source_handle: u16::from_le_bytes(bytes[4..6].try_into().expect("fixed slice")),
            source_offset: u32::from_le_bytes(bytes[6..10].try_into().expect("fixed slice")),
            destination_handle: u16::from_le_bytes(bytes[10..12].try_into().expect("fixed slice")),
            destination_offset: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice")),
        })
    }

    /// Encode this request using the packed, little-endian XMS layout.
    pub fn encode(self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0; Self::BYTE_LEN];
        bytes[0..4].copy_from_slice(&self.length.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.source_handle.to_le_bytes());
        bytes[6..10].copy_from_slice(&self.source_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.destination_handle.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.destination_offset.to_le_bytes());
        bytes
    }
}

/// Runtime-prepared XMS entrypoint call. A move descriptor must be fetched
/// through the runtime's A20-aware bus before constructing `Move`; all other
/// functions carry only their register-selected function number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedXmsCall {
    OtherFunction(u8),
    Move(Result<MoveRequest, XmsError>),
}

/// The runtime prepared a call variant that does not match AH or omitted the
/// required pre-read move descriptor. This is an adapter invariant error, not
/// a guest XMS error, and leaves guest registers untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedCallMismatch {
    FunctionNumber {
        register_function: u8,
        prepared_function: u8,
    },
    MoveDescriptorRequired,
    UnexpectedMoveDescriptor {
        register_function: u8,
    },
}

impl fmt::Display for PreparedCallMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionNumber { register_function, prepared_function } => write!(
                f,
                "XMS call preparation mismatch: register AH={register_function:02X}h does not match prepared AH={prepared_function:02X}h"
            ),
            Self::MoveDescriptorRequired => {
                f.write_str("XMS call preparation mismatch: the move function requires a pre-read move descriptor")
            }
            Self::UnexpectedMoveDescriptor { register_function } => write!(
                f,
                "XMS call preparation mismatch: a move descriptor was prepared for AH={register_function:02X}h"
            ),
        }
    }
}
impl std::error::Error for PreparedCallMismatch {}

#[cfg(test)]
mod display_tests {
    use super::{PreparedCallMismatch, XmsError};
    use guest_core::MemoryError;
    use std::error::Error;

    #[test]
    fn xms_display_keeps_protocol_code_and_function_number() {
        let error = XmsError::UnsupportedFunction(0x10);
        assert_eq!(error.error_code(), 0x80);
        let display = error.to_string();
        assert!(display.contains("80h"));
        assert!(display.contains("AH=10h"));
        assert!(!display.contains("UnsupportedFunction"));
    }

    #[test]
    fn xms_display_and_source_keep_nested_memory_cause() {
        let error = XmsError::Memory(MemoryError::OutOfBounds { address: 0x1234, length: 4 });
        let display = error.to_string();
        assert!(display.contains("A7h"));
        assert!(display.contains("0x00001234"));
        assert!(error.source().is_some());
    }

    #[test]
    fn prepared_call_mismatch_names_both_function_numbers() {
        let mismatch = PreparedCallMismatch::FunctionNumber {
            register_function: 0x0b,
            prepared_function: 0x09,
        };
        let display = mismatch.to_string();
        assert!(display.contains("AH=0Bh"));
        assert!(display.contains("AH=09h"));
        assert!(!display.contains("FunctionNumber"));
    }
}

/// Current desired A20 state. The runtime applies `enabled` to the shared
/// memory's A20-gated bus view; XMS byte transfers themselves use raw memory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct A20State {
    pub global_enabled: bool,
    pub local_enable_count: u32,
    pub enabled: bool,
}
