use guest_core::{MemoryError, PhysAddr};

use crate::CpuError;

/// Architectural mode reported by the machine-owned segment state.
///
/// A selector-based resolver is not enough to infer protected mode or CPL:
/// those require the CPU's hidden segment and privilege state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuExecutionMode {
    RealAddress,
    Protected,
    Virtual8086,
}

/// Translates a guest segment and offset to an address on the emulated bus.
/// This points only into `GuestMemory`'s process-owned guest buffer; it never
/// represents host physical RAM or a device mapping.
pub trait SegmentResolver {
    fn resolve(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError>;
    fn code_bits(&self) -> u32 { 16 }
    fn stack32(&self) -> bool { false }
    fn protected_mode(&self) -> bool { false }
    /// Return architectural execution mode only when the machine owns that
    /// state. The legacy `protected_mode` hint is not sufficient evidence.
    fn execution_mode(&self) -> Option<CpuExecutionMode> { None }
    /// Return the architectural current privilege level, when known.
    /// Real-address mode has CPL 0; protected and VM86 resolvers must provide
    /// the value from guest CPU state rather than selector RPL bits.
    fn current_privilege_level(&self) -> Option<u8> {
        (self.execution_mode() == Some(CpuExecutionMode::RealAddress)).then_some(0)
    }
    fn resolve_read(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        self.resolve(segment, offset, address32)
    }
    fn resolve_write(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        self.resolve(segment, offset, address32)
    }
    fn resolve_execute(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        self.resolve(segment, offset, address32)
    }
}

pub struct RealModeSegments;

impl SegmentResolver for RealModeSegments {
    fn resolve(&self, segment: u16, offset: u32, address32: bool) -> Result<PhysAddr, CpuError> {
        let effective_offset = if address32 { offset } else { u32::from(offset as u16) };
        let base = u32::from(segment) * 16;
        let address = base
            .checked_add(effective_offset)
            .ok_or(MemoryError::AddressOverflow)?;
        Ok(PhysAddr(address))
    }

    fn execution_mode(&self) -> Option<CpuExecutionMode> {
        Some(CpuExecutionMode::RealAddress)
    }

    fn current_privilege_level(&self) -> Option<u8> {
        Some(0)
    }
}
