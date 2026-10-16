//! One atomic publication of stack bytes, instance headers and the task TDB.

use crate::{DiagnosticKind as Kind, RuntimeError};
use guest_core::{AtomicMemoryRange, GuestMemory, memory::Memory};
use win16_abi::{Access, SegmentedPointer, SelectorTable};

pub(super) struct StackWrites {
    ranges: Vec<AtomicMemoryRange>,
    replacement: Vec<u8>,
}

impl StackWrites {
    pub(super) fn new() -> Result<Self, RuntimeError> {
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(5).map_err(allocation)?;
        Ok(Self {
            ranges,
            replacement: Vec::new(),
        })
    }

    pub(super) fn add(
        &mut self,
        selectors: &SelectorTable,
        memory: &Memory,
        pointer: SegmentedPointer,
        value: &[u8],
    ) -> Result<(), RuntimeError> {
        let address = selectors
            .translate(pointer, Access::Write, value.len(), memory)
            .map_err(crate::runtime_error)?;
        self.ranges.try_reserve(1).map_err(allocation)?;
        self.replacement
            .try_reserve(value.len())
            .map_err(allocation)?;
        self.ranges.push(AtomicMemoryRange {
            offset: address.0,
            length: value.len(),
        });
        self.replacement.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn publish(self, memory: &mut Memory) -> Result<(), RuntimeError> {
        let mut value = Vec::new();
        value
            .try_reserve_exact(self.replacement.len())
            .map_err(allocation)?;
        value.resize(self.replacement.len(), 0);
        // Ranges concatenate in operation order, including any guest aliases.
        // Unsupported providers reject before mutation. A partial storage
        // failure propagates without a CPU transfer or stale-snapshot rollback.
        memory
            .atomic_update(&self.ranges, &mut value, &mut |value| {
                value.copy_from_slice(&self.replacement)
            })
            .map_err(crate::runtime_error)
    }
}

fn allocation(error: std::collections::TryReserveError) -> RuntimeError {
    RuntimeError::with_source(Kind::ResourceExhausted, "prepare Win16 stack writes", error)
}
