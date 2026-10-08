//! Guest return translation for KERNEL selector helper failures.

use guest_core::MemoryError;
use win16_abi::Win16Error;

use crate::RuntimeError;

pub(super) fn canonical_selector(selector: u16) -> u16 { selector & !0x0007 }

pub(super) fn selector_allocation_failure(error: Win16Error) -> Result<u16, RuntimeError> {
    match error {
        error @ Win16Error::Memory(MemoryError::StorageAccess { .. }) => {
            // StorageAccess is sticky: the caller must stop guest execution.
            Err(crate::runtime_error(error))
        }
        Win16Error::SelectorTableFull
        | Win16Error::OutOfMemory
        | Win16Error::InvalidRange
        | Win16Error::InvalidSelector
        | Win16Error::StaleSelector
        | Win16Error::ForeignSelector
        | Win16Error::SelectorBlockInterior
        | Win16Error::LimitViolation { .. }
        | Win16Error::AccessDenied { .. }
        | Win16Error::InvalidSize
        | Win16Error::GenerationExhausted
        | Win16Error::IdentityExhausted
        | Win16Error::Memory(
            MemoryError::AllocationFailed
            | MemoryError::AddressOverflow
            | MemoryError::OutOfBounds { .. }
            | MemoryError::ReadOnly { .. },
        ) => Ok(0),
        error => Err(crate::runtime_error(error)),
    }
}

pub(super) fn selector_change_failure(error: Win16Error) -> Result<u16, RuntimeError> {
    match error {
        error @ Win16Error::Memory(MemoryError::StorageAccess { .. }) => {
            // Preserve the original sticky host-storage failure and its cause.
            Err(crate::runtime_error(error))
        }
        Win16Error::InvalidRange
        | Win16Error::InvalidSelector
        | Win16Error::StaleSelector
        | Win16Error::ForeignSelector
        | Win16Error::SelectorBlockInterior
        | Win16Error::LimitViolation { .. }
        | Win16Error::AccessDenied { .. }
        | Win16Error::InvalidSize
        | Win16Error::Memory(
            MemoryError::AddressOverflow
            | MemoryError::OutOfBounds { .. }
            | MemoryError::ReadOnly { .. },
        ) => Ok(0),
        error => Err(crate::runtime_error(error)),
    }
}
