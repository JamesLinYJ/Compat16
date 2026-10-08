//! Checked 16-bit callback entry and IRET-image application for machine-owned
//! observers. This module has no knowledge of any guest callback family.

use guest_core::GuestMemory;

use crate::{
    Cpu, CpuError, CpuExecutionMode, SegmentResolver,
    memory_access::{
        AccessKind, AccessOrigin, AccessRequest, AccessSite, CpuBus, CpuMemoryAccess,
        DataAlignment, LogicalSpan,
    },
    registers::SegmentRegister,
    system::{CpuSystem, SegmentCache},
};

use super::{
    flags_transfer::FlagContext,
    protected_iret::merge_protected_iret_flags,
    segment_load::{commit_code_transfer, load_data_register, validate_runtime_code_transfer},
};

const EFLAGS_NT: u32 = 1 << 14;
const EFLAGS_RF: u32 = 1 << 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Guest16BitReturnImage {
    pub(crate) code_segment: u16,
    pub(crate) instruction_pointer: u16,
    pub(crate) flags: u16,
}

/// Enter a 16-bit guest callback using a checked return frame already prepared
/// by the machine owner. The CPU validates selectors, the stack image, and
/// target code without knowing which guest subsystem requested the callback.
pub(crate) fn enter_checked_16bit_callback<M: GuestMemory, S: SegmentResolver>(
    cpu: &mut Cpu,
    target_cs: u16,
    target_ip: u16,
    callback_ss: u16,
    callback_sp: u16,
    return_cs: u16,
    return_ip: u16,
    memory: &mut M,
    segments: &S,
) -> Result<(), CpuError> {
    let ip = cpu.regs.eip;
    let site = AccessSite {
        opcode: 0,
        ip,
        eflags: cpu.regs.eflags,
    };
    if !cpu.system.architectural_context_initialized {
        return Err(CpuError::UnsupportedSystemMode { opcode: 0, ip });
    }
    let mode = cpu
        .system
        .execution_mode(cpu.regs.eflags)
        .ok_or(CpuError::UnsupportedSystemMode { opcode: 0, ip })?;
    if !matches!(mode, CpuExecutionMode::RealAddress | CpuExecutionMode::Protected) {
        return Err(CpuError::CompatibilityGap {
            opcode: 0,
            ip,
            feature: crate::CpuCompatibilityGap::Virtual8086Mode,
        });
    }

    let mut candidate_system: CpuSystem = cpu.system.clone();
    let mut bus = CpuMemoryAccess::new(memory, segments, &mut candidate_system, site);
    if bus.stack32() {
        return Err(CpuError::CompatibilityGap {
            opcode: 0,
            ip,
            feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
        });
    }
    if mode == CpuExecutionMode::Protected {
        let origin_cache = *bus.system().segment_cache(SegmentRegister::Cs);
        if origin_cache.descriptor.default_big {
            return Err(CpuError::CompatibilityGap {
                opcode: 0,
                ip,
                feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
            });
        }
    }
    let (target_cache, target_cpl) =
        validate_runtime_code_transfer(&mut bus, target_cs, target_ip, false)?;
    if target_cache.descriptor.default_big {
        return Err(CpuError::CompatibilityGap {
            opcode: 0,
            ip,
            feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
        });
    }
    let mut registers = cpu.regs.clone();
    load_data_register(
        &mut registers,
        &mut bus,
        SegmentRegister::Ss,
        callback_ss,
    )?;
    let return_span = LogicalSpan {
        register: SegmentRegister::Ss,
        selector: callback_ss,
        offset: u32::from(callback_sp),
        len: 4,
        address32: false,
    };
    let return_access = bus.prepare(AccessRequest::instruction(
        return_span,
        AccessKind::StackRead,
        DataAlignment::Natural(2),
    ))?;
    let mut return_bytes = [0_u8; 4];
    bus.read_prepared(&return_access, &mut return_bytes)?;
    let frame_ip = u16::from_le_bytes([return_bytes[0], return_bytes[1]]);
    let frame_cs = u16::from_le_bytes([return_bytes[2], return_bytes[3]]);
    if frame_ip != return_ip || frame_cs != return_cs {
        return Err(CpuError::InvalidMemoryAccessPlan { ip });
    }
    let _target_fetch = bus.prepare_logical_with_cache(
        LogicalSpan {
            register: SegmentRegister::Cs,
            selector: target_cs,
            offset: u32::from(target_ip),
            len: 1,
            address32: false,
        },
        AccessKind::Fetch,
        DataAlignment::Natural(1),
        AccessOrigin::GuestInstruction,
        target_cache,
    )?;
    registers.ss = callback_ss;
    registers.set_sp(callback_sp);
    registers.eip = u32::from(target_ip);
    // The observer callback is not part of the trapped instruction stream.
    // Preserve TF in the machine-owned return image while preventing a nested
    // single-step event from reentering this same observer.
    registers.eflags &= !crate::TF;
    // This entry is an event observer, not part of the trapped instruction.
    // Normal event entry clears RF so its first instruction is checked; the
    // captured event token keeps the original RF provenance for restart.
    registers.eflags &= !EFLAGS_RF;
    // Protected IRET checks live NT before reading its stack image. Match
    // normal protected event entry; the callback return frame still carries
    // the guest's original NT bit for an edited same-level IRET.
    if mode == CpuExecutionMode::Protected {
        registers.eflags &= !EFLAGS_NT;
    }
    commit_code_transfer(&mut registers, &mut bus, target_cs, target_cache, target_cpl);
    drop(bus);
    cpu.regs = registers;
    cpu.system = candidate_system;
    // The deferred token retains the original REP provenance for chained
    // event FLAGS, while callback execution starts at a fresh instruction
    // boundary and must not inherit the interrupted REP marker.
    cpu.intermediate_rep_boundary = false;
    cpu.control_transfer = None;
    cpu.invalidate_control_transfer_provenance();
    Ok(())
}

/// Resolve a guest-selected 16-bit stack descriptor before an observer commits
/// an edited SS:SP image. The caller applies the returned cache only after its
/// other return-frame checks succeed.
pub(crate) fn prepare_guest_16bit_stack_cache<M: GuestMemory, S: SegmentResolver>(
    cpu: &Cpu,
    selector: u16,
    stack_pointer: u16,
    memory: &mut M,
    segments: &S,
) -> Result<SegmentCache, CpuError> {
    let ip = cpu.regs.eip;
    let site = AccessSite {
        opcode: 0,
        ip,
        eflags: cpu.regs.eflags,
    };
    let mode = cpu
        .system
        .execution_mode(cpu.regs.eflags)
        .ok_or(CpuError::UnsupportedSystemMode { opcode: 0, ip })?;
    match mode {
        CpuExecutionMode::RealAddress => {
            if !cpu.system.architectural_context_initialized {
                return Err(CpuError::UnsupportedSystemMode { opcode: 0, ip });
            }
            let probe = stack_pointer.wrapping_sub(1);
            if !cpu.guest_stack_range_is_identity_mapped(
                selector,
                probe,
                1,
                true,
                memory,
                segments,
            )? {
                return Err(CpuError::InvalidMemoryAccessPlan { ip });
            }
            Ok(SegmentCache::real_mode(selector, false))
        }
        CpuExecutionMode::Protected => {
            if !cpu.system.architectural_context_initialized {
                return Err(CpuError::UnsupportedSystemMode { opcode: 0, ip });
            }
            let mut system = cpu.system.clone();
            let mut registers = cpu.regs.clone();
            let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
            load_data_register(&mut registers, &mut bus, SegmentRegister::Ss, selector)?;
            let cache = *bus.system().segment_cache(SegmentRegister::Ss);
            if cache.descriptor.default_big {
                return Err(CpuError::CompatibilityGap {
                    opcode: 0,
                    ip,
                    feature: crate::CpuCompatibilityGap::ProtectedExceptionDelivery,
                });
            }
            drop(bus);
            let probe = stack_pointer.wrapping_sub(1);
            if !cpu.guest_stack_range_is_identity_mapped(
                selector,
                probe,
                1,
                true,
                memory,
                segments,
            )? {
                return Err(CpuError::InvalidMemoryAccessPlan { ip });
            }
            Ok(cache)
        }
        CpuExecutionMode::Virtual8086 => Err(CpuError::CompatibilityGap {
            opcode: 0,
            ip,
            feature: crate::CpuCompatibilityGap::Virtual8086Mode,
        }),
    }
}

/// Apply the same-level 16-bit return image carried by an observer frame.
/// Protected returns use the CPU's descriptor and IRET flag rules; a frame
/// without the extra SS:SP words cannot request an outer-privilege return.
pub(crate) fn apply_16bit_return_image<M: GuestMemory, S: SegmentResolver>(
    cpu: &mut Cpu,
    image: Guest16BitReturnImage,
    memory: &mut M,
    segments: &S,
) -> Result<(), CpuError> {
    let ip = cpu.regs.eip;
    let site = AccessSite {
        opcode: 0,
        ip,
        eflags: cpu.regs.eflags,
    };
    let mode = cpu
        .system
        .execution_mode(cpu.regs.eflags)
        .ok_or(CpuError::UnsupportedSystemMode { opcode: 0, ip })?;
    match mode {
        CpuExecutionMode::RealAddress => {
            if !cpu.system.architectural_context_initialized {
                return Err(CpuError::UnsupportedSystemMode { opcode: 0, ip });
            }
            let cache = SegmentCache::real_mode(image.code_segment, true);
            if u32::from(image.instruction_pointer) > cache.descriptor.limit {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip,
                });
            }
            cpu.regs.cs = image.code_segment;
            cpu.regs.eip = u32::from(image.instruction_pointer);
            cpu.regs.eflags = super::merge_real_mode_iret16_flags(
                cpu.regs.eflags,
                image.flags,
                cpu.model(),
            );
            cpu.system.segments[0] = cache;
            Ok(())
        }
        CpuExecutionMode::Protected => {
            if !cpu.system.architectural_context_initialized {
                return Err(CpuError::UnsupportedSystemMode { opcode: 0, ip });
            }
            let cpl = cpu.system.cpl;
            let model = cpu.model();
            let mut bus = CpuMemoryAccess::new(memory, segments, &mut cpu.system, site);
            let (cache, return_cpl) =
                validate_runtime_code_transfer(&mut bus, image.code_segment, image.instruction_pointer, true)?;
            if return_cpl != cpl {
                // This observer frame carries no outer SS:SP pair, so it cannot
                // request a privilege-return frame.
                return Err(CpuError::GeneralProtectionFault {
                    error_code: u32::from(image.code_segment & 0xfffc),
                    ip,
                });
            }
            let flags = merge_protected_iret_flags(
                cpu.regs.eflags,
                u32::from(image.flags),
                2,
                FlagContext::Architectural { mode, cpl },
                model,
            );
            let mut registers = cpu.regs.clone();
            registers.cs = cache.selector;
            registers.eip = u32::from(image.instruction_pointer);
            registers.eflags = flags;
            commit_code_transfer(&mut registers, &mut bus, image.code_segment, cache, return_cpl);
            cpu.regs = registers;
            Ok(())
        }
        CpuExecutionMode::Virtual8086 => Err(CpuError::CompatibilityGap {
            opcode: 0,
            ip,
            feature: crate::CpuCompatibilityGap::Virtual8086Mode,
        }),
    }
}

/// Merge a 16-bit return image for selector-projected legacy mode without
/// assigning a synthetic CPL or replacing the high EFLAGS word.
pub(crate) fn apply_legacy_16bit_return_image(
    cpu: &mut Cpu,
    image: Guest16BitReturnImage,
) -> Result<(), CpuError> {
    if cpu.architectural_execution_mode().is_some() {
        return Err(CpuError::InvalidMemoryAccessPlan { ip: cpu.regs.eip });
    }
    cpu.regs.cs = image.code_segment;
    cpu.regs.eip = u32::from(image.instruction_pointer);
    cpu.regs.eflags = super::merge_legacy_iret16_flags(
        cpu.regs.eflags,
        image.flags,
        cpu.model(),
    );
    Ok(())
}
