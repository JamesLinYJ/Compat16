//! Operations on the prepared CPU bus that need provider-specific closure.

use guest_core::{AtomicMemoryRange, GuestMemory, MemoryError};

use crate::{CpuCompatibilityGap, CpuError, SegmentResolver};

use super::{AccessKind, AccessRequest, CpuMemoryAccess};

pub(super) fn atomic_update<M: GuestMemory, S: SegmentResolver>(
    bus: &mut CpuMemoryAccess<'_, M, S>,
    request: AccessRequest,
    update: &mut dyn FnMut(&mut [u8]),
) -> Result<(), CpuError> {
    let AccessRequest::Logical {
        span,
        kind: AccessKind::DataReadWrite,
        ..
    } = request
    else {
        return Err(bus.error_site());
    };
    if !matches!(span.len, 1 | 2 | 4 | 8) {
        return Err(bus.error_site());
    }
    let mut value = Vec::new();
    value
        .try_reserve_exact(span.len)
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    value.resize(span.len, 0);
    let access = bus.prepare_request(request)?;
    bus.validate_plan(&access, value.len(), false)?;
    bus.validate_plan(&access, value.len(), true)?;

    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(access.write_chunks.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    for chunk in &access.write_chunks {
        ranges.push(AtomicMemoryRange {
            offset: chunk.address.0,
            length: chunk.len,
        });
    }
    // GuestMemory success means one atomic read-transform-write; the executing
    // caller also rejects a success that produced no transform outcome.
    match bus.memory.atomic_update(&ranges, &mut value, update) {
        Ok(()) => {
            bus.record_data_breakpoints(&access, false);
            bus.record_data_breakpoints(&access, true);
            Ok(())
        }
        Err(MemoryError::AtomicityUnavailable) => Err(bus
            .compatibility_gap(CpuCompatibilityGap::AtomicBusTransaction)),
        Err(error) => Err(CpuError::Memory(error)),
    }
}
