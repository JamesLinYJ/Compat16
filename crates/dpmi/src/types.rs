use guest_core::{LinearAddr, MemoryError, PhysAddr};

/// DPMI's 4 KiB page size.
pub const DPMI_PAGE_SIZE: u32 = 4096;

/// Opaque 32-bit DPMI memory handle. It is not a guest or host address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DpmiHandle(pub u32);

/// The linear address and requested extent returned by a successful service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    pub handle: DpmiHandle,
    pub linear: LinearAddr,
    pub size: u32,
}

/// A live linear-to-physical mapping for one allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinearMapping {
    pub linear: LinearAddr,
    pub physical: PhysAddr,
    pub size: u32,
}

/// The explicit, page-aligned arena assigned to this DPMI memory manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaBounds {
    pub physical_start: PhysAddr,
    pub linear_start: LinearAddr,
    /// Arena end addresses are exclusive and therefore represented as u64;
    /// a valid 32-bit arena may end at 0x1_0000_0000.
    pub physical_end: u64,
    pub linear_end: u64,
    pub size: u32,
}

/// Snapshot of allocator capacity and current use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DpmiMemoryStats {
    pub page_size: u32,
    pub total_pages: u32,
    pub free_pages: u32,
    pub allocated_pages: u32,
    pub largest_free_block: u64,
    pub free_bytes: u64,
    pub allocated_bytes: u64,
    pub requested_bytes: u64,
    pub allocation_count: usize,
}

/// Errors from arena configuration, allocation, access, or INT 31h dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DpmiError {
    InvalidArenaConfiguration,
    InvalidSize,
    InvalidHandle,
    InvalidLinearAddress,
    LinearMemoryUnavailable,
    HandleSpaceExhausted,
    GuestMemory(MemoryError),
    UnsupportedFunction(u16),
}

impl DpmiError {
    /// DPMI 0.9 error word used by the implemented INT 31h functions.
    pub fn dpmi_code(&self) -> u16 {
        match self {
            Self::InvalidArenaConfiguration | Self::LinearMemoryUnavailable => 0x8012,
            Self::InvalidSize => 0x8021,
            Self::InvalidHandle => 0x8023,
            Self::InvalidLinearAddress => 0x8021,
            Self::HandleSpaceExhausted => 0x8016,
            Self::GuestMemory(_) => 0x8012,
            Self::UnsupportedFunction(_) => 0x8001,
        }
    }
}

impl std::fmt::Display for DpmiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DPMI error {:04X}h: ", self.dpmi_code())?;
        match self {
            Self::InvalidArenaConfiguration => f.write_str("the DPMI memory arena configuration is invalid"),
            Self::InvalidSize => f.write_str("the requested DPMI memory size is invalid"),
            Self::InvalidHandle => f.write_str("the DPMI memory handle is invalid"),
            Self::InvalidLinearAddress => f.write_str("the DPMI linear address is invalid"),
            Self::LinearMemoryUnavailable => f.write_str("DPMI linear memory is unavailable"),
            Self::HandleSpaceExhausted => f.write_str("no DPMI memory handles are available"),
            Self::GuestMemory(error) => write!(f, "guest memory access failed: {error}"),
            Self::UnsupportedFunction(function) => {
                write!(f, "DPMI function AX={function:04X}h is not supported")
            }
        }
    }
}

impl std::error::Error for DpmiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GuestMemory(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod display_tests {
    use super::DpmiError;
    use guest_core::MemoryError;
    use std::error::Error;

    #[test]
    fn dpmi_display_keeps_protocol_code_and_function_number() {
        let error = DpmiError::UnsupportedFunction(0x0501);
        assert_eq!(error.dpmi_code(), 0x8001);
        let display = error.to_string();
        assert!(display.contains("8001h"));
        assert!(display.contains("AX=0501h"));
        assert!(!display.contains("UnsupportedFunction"));
    }

    #[test]
    fn dpmi_display_and_source_keep_guest_memory_cause() {
        let error = DpmiError::GuestMemory(MemoryError::ReadOnly { address: 0x1234, length: 8 });
        let display = error.to_string();
        assert!(display.contains("8012h"));
        assert!(display.contains("0x00001234"));
        assert!(error.source().is_some());
    }
}

/// Result of routing an INT 31h function through the implemented memory subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceDisposition {
    Handled,
}
