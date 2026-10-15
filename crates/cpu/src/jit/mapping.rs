//! Side-effect-free segment certification. Paging keeps the checked walker.
use crate::{
    Cpu, CpuExecutionMode, SegmentAccess, SegmentResolver,
    registers::{SegmentRegister, read_segment},
    system,
};
use guest_core::PhysAddr;
pub(super) fn range(
    cpu: &Cpu,
    resolver: &impl SegmentResolver,
    segment: SegmentRegister,
    offset: u32,
    length: usize,
    access: SegmentAccess,
) -> Option<PhysAddr> {
    if cpu.system.cr0 & system::CR0_PG != 0 || length == 0 {
        return None;
    }
    let selector = read_segment(&cpu.regs, segment);
    if !cpu.system.architectural_context_initialized {
        if cpu.system.cr0 & system::CR0_PE != 0 {
            return None;
        }
        return resolver.jit_range(selector, offset, length, access);
    }
    let cache = cpu.system.segment_cache(segment);
    if cache.selector != selector || cache.unusable {
        return None;
    }
    match cpu.architectural_execution_mode()? {
        CpuExecutionMode::Protected => {
            let access = match access {
                SegmentAccess::Execute => system::SegmentAccess::InstructionFetch,
                SegmentAccess::Read if segment == SegmentRegister::Ss => {
                    system::SegmentAccess::StackRead
                }
                SegmentAccess::Write if segment == SegmentRegister::Ss => {
                    system::SegmentAccess::StackWrite
                }
                SegmentAccess::Read => system::SegmentAccess::Read,
                SegmentAccess::Write => system::SegmentAccess::Write,
            };
            cache
                .descriptor
                .check_access(
                    selector,
                    access,
                    cpu.system.cpl,
                    (selector & 3) as u8,
                    offset,
                    length,
                )
                .ok()?;
        }
        CpuExecutionMode::RealAddress => {
            if u64::from(offset) + length as u64 > u64::from(cache.descriptor.limit) + 1 {
                return None;
            }
        }
        CpuExecutionMode::Virtual8086 => return None,
    }
    let start = cache.descriptor.base.checked_add(offset)?;
    start.checked_add(u32::try_from(length - 1).ok()?)?;
    Some(PhysAddr(start))
}
pub(super) fn code(
    cpu: &Cpu,
    resolver: &impl SegmentResolver,
    ip: u32,
    requested: usize,
) -> Option<(PhysAddr, usize)> {
    // Shrinking is metadata-only. An unavailable future byte never becomes
    // an early architectural fault or an extra provider read.
    let mut length = requested;
    while length > 0 {
        if let Some(address) = range(
            cpu,
            resolver,
            SegmentRegister::Cs,
            ip,
            length,
            SegmentAccess::Execute,
        ) {
            return Some((address, length));
        }
        length /= 2;
    }
    None
}
