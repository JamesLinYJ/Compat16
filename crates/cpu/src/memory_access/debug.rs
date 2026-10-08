//! i486 alignment faults and debug-register memory matches.

use guest_core::LinearAddr;

use crate::{
    CpuError, CpuExecutionMode, SegmentResolver, system::CR0_AM,
};

use super::{
    AccessKind, AccessOrigin, CpuMemoryAccess, DataAlignment, PreparedAccess,
};

impl<M: guest_core::GuestMemory, S: SegmentResolver> CpuMemoryAccess<'_, M, S> {
    pub(super) fn check_prepared_alignment(
        &self,
        access: &PreparedAccess,
    ) -> Result<(), CpuError> {
        let Some(origin) = access.origin else {
            return Ok(());
        };
        self.check_alignment(
            access.kind,
            access.alignment,
            origin,
            access.alignment_cpl,
            access.linear_start,
        )
    }

    pub(super) fn check_alignment(
        &self,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        target_cpl: Option<u8>,
        linear_start: Option<LinearAddr>,
    ) -> Result<(), CpuError> {
        if !matches!(
            kind,
            AccessKind::DataRead
                | AccessKind::DataWrite
                | AccessKind::DataReadWrite
                | AccessKind::StackRead
                | AccessKind::StackWrite
        )
        {
            return Ok(());
        }
        let Some(linear) = linear_start else {
            return Ok(());
        };
        // ProcessorEvent changes only the possible EXT error bit below. The
        // gate uses the target CPL for stack switches, so a same-CPL ring-3
        // event frame can still raise #AC.
        let gate_enabled = alignment_check_gate_enabled(self, target_cpl)?;
        let bytes = match alignment {
            DataAlignment::Natural(bytes) if bytes > 1 => bytes,
            DataAlignment::Natural(bytes) => bytes,
            DataAlignment::Unaligned => return Ok(()),
            DataAlignment::Unspecified if gate_enabled => {
                // The Intel486 manuals list the BCD memory form but do not
                // define its alignment modulus; do not invent an 8-byte rule.
                return Err(self.compatibility_gap(crate::CpuCompatibilityGap::AlignmentCheck));
            }
            DataAlignment::Unspecified => return Ok(()),
        };
        if bytes == 0 || !matches!(bytes, 1 | 2 | 4 | 8) {
            return Err(self.error_site());
        }
        if !gate_enabled {
            return Ok(());
        }
        if linear.0 % u32::from(bytes) != 0 {
            return Err(CpuError::AlignmentCheckFault {
                // During delivery of an event other than a software interrupt,
                // Intel permits the #AC stack-frame error EXT bit to be set.
                error_code: u32::from(
                    origin == AccessOrigin::ProcessorEvent
                        && self.processor_event_error_ext,
                ),
                ip: self.site.ip,
            });
        }
        Ok(())
    }

    pub(super) fn record_data_breakpoints(&mut self, access: &PreparedAccess, write: bool) {
        if access.origin != Some(AccessOrigin::GuestInstruction)
            || !matches!(
                access.kind,
                AccessKind::DataRead
                    | AccessKind::DataWrite
                    | AccessKind::DataReadWrite
                    | AccessKind::StackRead
                    | AccessKind::StackWrite
            )
        {
            return;
        }
        let Some(linear_start) = access.linear_start else {
            return;
        };
        let control = self.system.debug.control;
        for index in 0..4_u32 {
            let enabled = (control >> (index * 2)) & 0b11 != 0;
            let rw = (control >> (16 + index * 4)) & 0b11;
            if !matches!(rw, 0b01 | 0b11) || (rw == 0b01 && !write) {
                continue;
            }
            let length_code = (control >> (18 + index * 4)) & 0b11;
            let length = match length_code {
                0b00 => 1_usize,
                0b01 => 2,
                // Intel486 reserves LEN=10; do not assign a later width.
                0b11 => 4,
                _ => continue,
            };
            let address = self.system.debug.addresses[index as usize];
            let aligned_address = match length_code {
                0b01 => address & !1,
                0b11 => address & !3,
                _ => address,
            };
            if linear_range_overlaps(
                linear_start.0,
                access.len,
                aligned_address,
                length,
            ) {
                let mask = 1_u8 << index;
                self.data_breakpoint_hits.matching |= mask;
                if enabled {
                    self.data_breakpoint_hits.enabled |= mask;
                }
            }
        }
    }
}

fn linear_range_overlaps(
    access_start: u32,
    access_length: usize,
    watch_start: u32,
    watch_length: usize,
) -> bool {
    const LINEAR_SPACE_SIZE: u64 = 0x1_0000_0000;

    let Ok(access_length) = u64::try_from(access_length) else {
        return true;
    };
    if access_length == 0 || watch_length == 0 {
        return false;
    }
    if access_length >= LINEAR_SPACE_SIZE {
        return true;
    }

    let access_start = u64::from(access_start);
    let watch_start = u64::from(watch_start);
    // DR7 length alignment keeps the watch range within the 32-bit space;
    // only the operand range may split at FFFFFFFFh.
    let watch_end = watch_start + watch_length as u64;
    let first_length = access_length.min(LINEAR_SPACE_SIZE - access_start);
    let first_end = access_start + first_length;
    let first_overlap = access_start < watch_end && watch_start < first_end;
    let wrapped_length = access_length - first_length;
    first_overlap || (wrapped_length != 0 && watch_start < wrapped_length)
}

fn alignment_check_gate_enabled<M: guest_core::GuestMemory, S: SegmentResolver>(
    bus: &CpuMemoryAccess<'_, M, S>,
    target_cpl: Option<u8>,
) -> Result<bool, CpuError> {
    if bus.system.cr0 & CR0_AM == 0 || bus.access_context_eflags() & (1 << 18) == 0 {
        return Ok(false);
    }
    let Some(mode) = bus.checked_execution_mode()? else {
        return Err(bus.unsupported_mode());
    };
    let cpl = target_cpl.or_else(|| bus.checked_cpl());
    Ok(cpl == Some(3)
        && matches!(
            mode,
            CpuExecutionMode::Protected | CpuExecutionMode::Virtual8086
        ))
}
