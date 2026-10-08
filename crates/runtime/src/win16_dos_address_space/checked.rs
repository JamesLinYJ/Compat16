//! Checked address mapping and typed errors for the DOS caller adapter.

use std::error::Error;
use std::fmt::{Display, Formatter};

use dos_kernel::{DosCallerAddressSpaceFailureKind as FailureKind, DosError, DosPointerAccess};
use guest_core::{MemoryError, PhysAddr};
use win16_abi::{Access, AccessRights, Win16Error};

use super::SELECTOR_BYTES;

const A20_BOUNDARY: u32 = 0x10_0000;

pub(super) fn alias_layout(
    segment: u16,
    offset: u16,
    length: usize,
    access: DosPointerAccess,
) -> Result<(PhysAddr, u32, u16, usize, AccessRights), DosError> {
    let (start, allocation_length, key_offset, key_length, rights) = match access {
        DosPointerAccess::Execute => {
            let end = usize::from(offset).checked_add(length).ok_or_else(|| {
                address_failure(
                    FailureKind::InvalidPointer,
                    "layout DOS executable alias",
                    "DOS code view offset arithmetic overflowed",
                )
            })?;
            if end > SELECTOR_BYTES {
                return Err(address_failure(
                    FailureKind::InvalidPointer,
                    "layout DOS executable alias",
                    "DOS executable span crosses its real-mode segment",
                ));
            }
            (
                guest_core::real_address(segment, 0),
                SELECTOR_BYTES as u32,
                0,
                SELECTOR_BYTES,
                AccessRights::code(),
            )
        }
        DosPointerAccess::Read => (
            guest_core::real_address(segment, offset),
            length as u32,
            offset,
            length,
            AccessRights::read_only(),
        ),
        DosPointerAccess::Write => (
            guest_core::real_address(segment, offset),
            length as u32,
            offset,
            length,
            AccessRights::read_write(),
        ),
    };
    let end = start.0.checked_add(allocation_length).ok_or_else(|| {
        address_failure(
            FailureKind::InvalidPointer,
            "layout DOS-owned selector alias",
            "DOS-owned alias address range overflowed",
        )
    })?;
    // A DOS pointer exposed to protected code must keep a stable flat backing
    // if the guest toggles A20 later. Current DOS NLS and conventional DTA
    // objects fit below 1 MiB; HMA/cross-A20 aliases need a multi-region selector
    // model and are reported as unsupported instead of silently mis-mapped.
    if end > A20_BOUNDARY {
        return Err(address_failure(
            FailureKind::Unsupported,
            "layout DOS-owned selector alias",
            "DOS alias leaves the A20-invariant first MiB",
        ));
    }
    Ok((start, allocation_length, key_offset, key_length, rights))
}

pub(super) fn selector_access(access: DosPointerAccess) -> Access {
    match access {
        DosPointerAccess::Read => Access::Read,
        DosPointerAccess::Write => Access::Write,
        DosPointerAccess::Execute => Access::Execute,
    }
}

pub(super) fn selector_failure(operation: &'static str, error: Win16Error) -> DosError {
    let kind = match &error {
        Win16Error::SelectorTableFull
        | Win16Error::OutOfMemory
        | Win16Error::GenerationExhausted
        | Win16Error::IdentityExhausted => FailureKind::ResourceExhausted,
        Win16Error::Memory(MemoryError::StorageAccess { .. }) => FailureKind::HostFailure,
        Win16Error::Memory(MemoryError::AllocationFailed) => FailureKind::ResourceExhausted,
        Win16Error::ReallocRollbackFailed { .. } => FailureKind::InternalInvariant,
        Win16Error::InvalidSelector
        | Win16Error::StaleSelector
        | Win16Error::ForeignSelector
        | Win16Error::InvalidRange
        | Win16Error::LimitViolation { .. }
        | Win16Error::StackOffsetWrap { .. }
        | Win16Error::AccessDenied { .. }
        | Win16Error::Memory(_) => FailureKind::InvalidPointer,
        _ => FailureKind::InternalInvariant,
    };
    DosError::caller_address_space(kind, operation, error)
}

pub(super) fn memory_failure(operation: &'static str, error: MemoryError) -> DosError {
    let kind = match &error {
        MemoryError::StorageAccess { .. } => FailureKind::HostFailure,
        MemoryError::AllocationFailed => FailureKind::ResourceExhausted,
        _ => FailureKind::InvalidPointer,
    };
    DosError::caller_address_space(kind, operation, error)
}

pub(super) fn address_failure(
    kind: FailureKind,
    operation: &'static str,
    detail: &'static str,
) -> DosError {
    DosError::caller_address_space(kind, operation, AddressFailure(detail))
}

#[derive(Debug)]
struct AddressFailure(&'static str);

impl Display for AddressFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AddressFailure {}
