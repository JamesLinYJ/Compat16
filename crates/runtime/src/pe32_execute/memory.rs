use std::cell::Cell;

use guest_core::{
    AtomicMemoryRange, GuestMemory, MemoryError, PhysAddr, memory::Memory,
};

use crate::{DiagnosticKind as Kind, RuntimeError};

/// CPU memory view for PE32 execution. It checks each individual access against
/// ordinary RAM before forwarding to Memory's raw physical backing, so mapped
/// device callbacks never run from this execution domain.
pub(super) struct Pe32RamMemory<'a> {
    memory: &'a mut Memory,
    device_rejection: Cell<Option<MemoryError>>,
}

impl<'a> Pe32RamMemory<'a> {
    pub(super) fn new(memory: &'a mut Memory) -> Self {
        Self {
            memory,
            device_rejection: Cell::new(None),
        }
    }

    pub(super) fn take_device_rejection(&self) -> Option<MemoryError> {
        self.device_rejection.take()
    }

    fn validate(
        &self,
        address: PhysAddr,
        length: usize,
        writable: bool,
    ) -> Result<(), MemoryError> {
        match self.memory.validate_ram_range(address, length, writable) {
            Err(error) => {
                // validate_ram_range reports mapped-device overlap as
                // InvalidMapping. Preserve that cause for a typed PE32 gap.
                if matches!(&error, MemoryError::InvalidMapping) {
                    self.device_rejection.set(Some(error.clone()));
                }
                Err(error)
            }
            Ok(()) => Ok(()),
        }
    }
}

impl GuestMemory for Pe32RamMemory<'_> {
    fn len(&self) -> u32 {
        self.memory.size_bytes()
    }

    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate(address, length, false)
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate(address, length, true)
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate(address, bytes.len(), false)?;
        self.memory.read_physical(address, bytes)
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate(address, bytes.len(), true)?;
        self.memory.write_physical(address, bytes)
    }

    fn atomic_update(
        &mut self,
        ranges: &[AtomicMemoryRange],
        value: &mut [u8],
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), MemoryError> {
        for range in ranges {
            let address = PhysAddr(range.offset);
            self.validate(address, range.length, false)?;
            self.validate(address, range.length, true)?;
        }
        self.memory.atomic_update(ranges, value, update)
    }
}

pub(super) fn disallowed_device_access(error: MemoryError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::CompatibilityGap,
        "PE32 guest memory access overlaps a mapped device outside the RAM-only view",
        error,
    )
}
