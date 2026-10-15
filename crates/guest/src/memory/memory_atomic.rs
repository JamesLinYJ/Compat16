//! Atomic guest-memory provider routing.
//!
//! This child module keeps provider dispatch out of `memory.rs`; it can access
//! the memory owner's private mapping table without widening that API.

use crate::{AtomicMemoryRange, GuestMemory, MemoryError, PhysAddr};

use super::{BusMemory, Memory};

impl GuestMemory for Memory {
    fn read_plain_code(&self, address: PhysAddr, output: &mut [u8]) -> Result<bool, MemoryError> {
        self.check_storage_failure()?;
        if self.validate_ram_range(address, output.len(), false).is_err() { return Ok(false); }
        self.record_storage_result(self.backing.read_plain_code(address.0, output))
    }
    fn len(&self) -> u32 {
        self.size_bytes()
    }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_physical_access(address, length, false)
            .map(|_| ())
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_physical_access(address, length, true)
            .map(|_| ())
    }

    /// Raw physical read. Use `Memory::bus` for A20-aware CPU/DOS access.
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.read_physical(address, bytes)
    }

    /// Raw physical write. Use `Memory::bus` for A20-aware CPU/DOS access.
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.write_physical(address, bytes)
    }

    fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        validate_atomic_range_set(ranges, value.len())?;

        // Complete guest-range, ROM, device-read, and device-write validation
        // before routing the operation to its provider.
        for range in ranges {
            self.validate_physical_access(PhysAddr(range.offset), range.length, false)?;
            self.validate_physical_access(PhysAddr(range.offset), range.length, true)?;
        }

        let mut provider: Option<Option<usize>> = None;
        let mut device_ranges = Vec::new();
        for range in ranges {
            let chunks = self.physical_chunks(range.offset, range.length);
            for chunk in chunks {
                match provider {
                    Some(provider_index) if provider_index != chunk.device_index => {
                        return Err(MemoryError::AtomicityUnavailable);
                    }
                    None => provider = Some(chunk.device_index),
                    _ => {}
                }
                if let Some(index) = chunk.device_index {
                    let mapping = &self.devices[index];
                    device_ranges
                        .try_reserve(1)
                        .map_err(|_| MemoryError::AllocationFailed)?;
                    device_ranges.push(AtomicMemoryRange {
                        offset: chunk.address - mapping.start,
                        length: chunk.length,
                    });
                }
            }
        }

        match provider {
            Some(None) => {
                let result = self.backing.atomic_update(ranges, value, update);
                self.record_storage_result(result)
            }
            Some(Some(index)) => {
                let mapping = &self.devices[index];
                self.record_storage_result(
                    mapping
                        .device
                        .atomic_update(&device_ranges, value, update),
                )
            }
            None => Err(MemoryError::InvalidMapping),
        }
    }
}

impl GuestMemory for BusMemory<'_> {
    fn read_plain_code(&self, address: PhysAddr, output: &mut [u8]) -> Result<bool, MemoryError> {
        // A20 wrap must not join discontiguous banks into a code span.
        let Ok(delta) = u32::try_from(output.len().saturating_sub(1)) else { return Ok(false); };
        let Some(last) = address.0.checked_add(delta) else { return Ok(false); };
        if !self.memory.a20_enabled() && address.0 >> 20 != last >> 20 { return Ok(false); }
        let first = self.memory.decode_a20(address.0);
        if first.checked_add(delta) != Some(self.memory.decode_a20(last)) { return Ok(false); }
        self.memory.read_plain_code(PhysAddr(first), output)
    }
    fn len(&self) -> u32 {
        self.memory.len()
    }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory
            .validate_bus_range(address, length, false)
            .map(|_| ())
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory
            .validate_bus_range(address, length, true)
            .map(|_| ())
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read_bus(address, bytes)
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bus(address, bytes)
    }

    fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        validate_atomic_range_set(ranges, value.len())?;
        let mut decoded = Vec::new();
        for range in ranges {
            let end = Memory::checked_bus_logical_end(PhysAddr(range.offset), range.length)?;
            let mut cursor = u64::from(range.offset);
            while cursor < end {
                let chunk_len = self.memory.bus_chunk_length(cursor, end);
                decoded
                    .try_reserve(1)
                    .map_err(|_| MemoryError::AllocationFailed)?;
                decoded.push(AtomicMemoryRange {
                    offset: self.memory.decode_a20(cursor as u32),
                    length: chunk_len,
                });
                cursor += u64::try_from(chunk_len).map_err(|_| MemoryError::AddressOverflow)?;
            }
        }
        self.memory.atomic_update(&decoded, value, update)
    }
}

fn validate_atomic_range_set(
    ranges: &[AtomicMemoryRange],
    value_length: usize,
) -> Result<(), MemoryError> {
    if ranges.is_empty() || value_length == 0 {
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
    Ok(())
}
