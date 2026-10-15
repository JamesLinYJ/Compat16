//! Safe byte-storage boundary for simulated guest physical memory.

use std::ops::Range;

use crate::{AtomicMemoryRange, MemoryError};

/// Fixed-size, host-owned bytes used as guest physical memory backing.
///
/// The length is sampled once when constructing [`super::Memory`] and remains
/// fixed for that memory's lifetime. Implementations must keep every byte in
/// that range available. Reads and writes receive checked guest-relative
/// offsets, never host pointers. [`super::Memory`] validates the complete guest
/// range before access. Backends must report native access failures with the
/// transferred-byte count; a partial transfer is an error and is not rolled
/// back by copying a snapshot over the storage. Callers must stop execution
/// after such an error.
pub trait MemoryStorage {
    /// Return the storage length in bytes.
    fn len(&self) -> u32;

    /// Optional stable RAM snapshot for a bounded, callback-free CPU quantum.
    /// See GuestMemory::read_plain_code. Shared or observable backends retain
    /// the default; false must have no externally observable read effects.
    fn read_plain_code(&self, _offset: u32, _output: &mut [u8]) -> Result<bool, MemoryError> {
        Ok(false)
    }

    /// Read a checked range beginning at `offset` into `output`.
    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError>;

    /// Write a checked range beginning at `offset` from `input`.
    fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError>;

    /// Perform one linearizable read-transform-write over ordered ranges.
    /// Implementations must serialize this with their `read` and `write`
    /// methods, including accesses made by other host actors. Validate all
    /// ranges before invoking `update`; if an error occurs after that callback,
    /// report the actual committed byte count as `StorageAccess`.
    fn atomic_update(
        &mut self,
        _ranges: &[AtomicMemoryRange],
        _value: &mut [u8],
        _update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        Err(MemoryError::AtomicityUnavailable)
    }
}

pub(super) enum MemoryBacking {
    Owned(Vec<u8>),
    External {
        storage: Box<dyn MemoryStorage>,
        fixed_length: u32,
    },
}

impl MemoryBacking {
    pub(super) fn read_plain_code(&self, offset: u32, output: &mut [u8]) -> Result<bool, MemoryError> {
        match self {
            Self::Owned(bytes) => {
                let range = checked_storage_range(offset, output.len(), bytes.len())?;
                output.copy_from_slice(&bytes[range]);
                Ok(true)
            }
            Self::External { storage, fixed_length } => {
                checked_storage_range(offset, output.len(), *fixed_length as usize)?;
                storage.read_plain_code(offset, output)
            }
        }
    }
    pub(super) fn external(storage: Box<dyn MemoryStorage>, fixed_length: u32) -> Self {
        Self::External {
            storage,
            fixed_length,
        }
    }

    pub(super) fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), MemoryError> {
        match self {
            Self::Owned(bytes) => {
                let range = checked_storage_range(offset, output.len(), bytes.len())?;
                output.copy_from_slice(&bytes[range]);
                Ok(())
            }
            Self::External {
                storage,
                fixed_length,
            } => {
                let fixed_length = usize::try_from(*fixed_length)
                    .map_err(|_| MemoryError::AddressOverflow)?;
                checked_storage_range(offset, output.len(), fixed_length)?;
                storage.read(offset, output)
            }
        }
    }

    pub(super) fn write(&mut self, offset: u32, input: &[u8]) -> Result<(), MemoryError> {
        match self {
            Self::Owned(bytes) => {
                let range = checked_storage_range(offset, input.len(), bytes.len())?;
                bytes[range].copy_from_slice(input);
                Ok(())
            }
            Self::External {
                storage,
                fixed_length,
            } => {
                let fixed_length = usize::try_from(*fixed_length)
                    .map_err(|_| MemoryError::AddressOverflow)?;
                checked_storage_range(offset, input.len(), fixed_length)?;
                storage.write(offset, input)
            }
        }
    }

    pub(super) fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        let total = validate_atomic_ranges(ranges, value.len())?;
        if total != value.len() {
            return Err(MemoryError::InvalidMapping);
        }
        match self {
            Self::Owned(bytes) => {
                let mut checked = Vec::new();
                checked
                    .try_reserve_exact(ranges.len())
                    .map_err(|_| MemoryError::AllocationFailed)?;
                for range in ranges {
                    checked.push(checked_storage_range(
                        range.offset,
                        range.length,
                        bytes.len(),
                    )?);
                }

                let mut cursor = 0;
                for range in &checked {
                    let next = cursor + range.len();
                    value[cursor..next].copy_from_slice(&bytes[range.clone()]);
                    cursor = next;
                }
                // Owned RAM has no shared alias: `Memory` holds an exclusive
                // borrow while this callback and its writes run.
                update(value);
                cursor = 0;
                for range in checked {
                    let next = cursor + range.len();
                    bytes[range].copy_from_slice(&value[cursor..next]);
                    cursor = next;
                }
                Ok(())
            }
            Self::External {
                storage,
                fixed_length,
            } => {
                let fixed_length = usize::try_from(*fixed_length)
                    .map_err(|_| MemoryError::AddressOverflow)?;
                for range in ranges {
                    checked_storage_range(range.offset, range.length, fixed_length)?;
                }
                storage.atomic_update(ranges, value, update)
            }
        }
    }

    pub(super) fn owned_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Owned(bytes) => Some(bytes),
            Self::External { .. } => None,
        }
    }

    pub(super) fn owned_bytes_mut(&mut self) -> Option<&mut [u8]> {
        match self {
            Self::Owned(bytes) => Some(bytes),
            Self::External { .. } => None,
        }
    }
}

fn validate_atomic_ranges(
    ranges: &[AtomicMemoryRange],
    value_length: usize,
) -> Result<usize, MemoryError> {
    if ranges.is_empty() {
        return Err(MemoryError::InvalidMapping);
    }
    let mut total = 0usize;
    for range in ranges {
        if range.length == 0 {
            return Err(MemoryError::InvalidMapping);
        }
        total = total
            .checked_add(range.length)
            .ok_or(MemoryError::AddressOverflow)?;
        if total > value_length {
            return Err(MemoryError::InvalidMapping);
        }
    }
    if total != value_length {
        return Err(MemoryError::InvalidMapping);
    }
    Ok(total)
}

fn checked_storage_range(
    offset: u32,
    length: usize,
    storage_length: usize,
) -> Result<Range<usize>, MemoryError> {
    let start = u64::from(offset);
    let length_u64 = u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?;
    let end = start.checked_add(length_u64).ok_or(MemoryError::AddressOverflow)?;
    if end > u64::from(u32::MAX) + 1 {
        return Err(MemoryError::AddressOverflow);
    }
    let storage_length = u64::try_from(storage_length).map_err(|_| MemoryError::AddressOverflow)?;
    if end > storage_length {
        return Err(MemoryError::OutOfBounds { address: offset, length });
    }
    let start = usize::try_from(start).map_err(|_| MemoryError::AddressOverflow)?;
    let end = usize::try_from(end).map_err(|_| MemoryError::AddressOverflow)?;
    Ok(start..end)
}
