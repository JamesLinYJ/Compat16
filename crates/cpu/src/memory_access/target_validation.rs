//! Segment-only target validation for near branches and returns.

use guest_core::GuestMemory;

use crate::{
    CpuError, CpuExecutionMode, SegmentResolver,
    registers::SegmentRegister,
    system::{SegmentAccess, map_fault},
};

use super::CpuMemoryAccess;

pub(super) fn validate_near_code_target<M: GuestMemory, S: SegmentResolver>(
    bus: &mut CpuMemoryAccess<'_, M, S>,
    selector: u16,
    target: u32,
) -> Result<(), CpuError> {
    if bus.uses_legacy_projection() {
        if bus.checked_execution_mode()? == Some(CpuExecutionMode::RealAddress)
            && target > u32::from(u16::MAX)
        {
            return Err(general_protection(bus.site.ip));
        }
        // `target` is already truncated by the branch operand size. Resolve
        // it as a canonical offset so a 32-bit near target in a 16-bit code
        // profile is not silently wrapped before the segment-limit check.
        bus.resolver.validate_near_code_target(selector, target)?;
        return Ok(());
    }

    let mode = bus
        .checked_execution_mode()?
        .ok_or_else(|| bus.unsupported_mode())?;
    let cache = *bus.system.segment_cache(SegmentRegister::Cs);
    if cache.selector != selector {
        return Err(bus.unsupported_mode());
    }
    if cache.unusable {
        return Err(CpuError::GeneralProtectionFault {
            error_code: 0,
            ip: bus.site.ip,
        });
    }

    match mode {
        CpuExecutionMode::RealAddress => {
            if target > cache.descriptor.limit {
                return Err(general_protection(bus.site.ip));
            }
        }
        CpuExecutionMode::Virtual8086 => {
            if cache.descriptor.base != u32::from(selector) << 4
                || cache.descriptor.limit != u32::from(u16::MAX)
                || cache.descriptor.default_big
                || !cache.descriptor.present
            {
                return Err(bus.compatibility_gap(crate::CpuCompatibilityGap::Virtual8086Mode));
            }
            if target > cache.descriptor.limit {
                return Err(general_protection(bus.site.ip));
            }
        }
        CpuExecutionMode::Protected => {
            let cpl = bus
                .checked_cpl()
                .ok_or_else(|| bus.unsupported_mode())?;
            cache
                .descriptor
                .check_access(
                    selector,
                    SegmentAccess::InstructionFetch,
                    cpl,
                    (selector & 3) as u8,
                    target,
                    1,
                )
                .map_err(|fault| map_fault(fault, bus))?;
        }
    }
    Ok(())
}

fn general_protection(ip: u32) -> CpuError {
    CpuError::GeneralProtectionFault { error_code: 0, ip }
}
