//! Architectural segment-register loads shared by MOV, POP, and far loads.

use guest_core::Registers;

use crate::{
    CpuError, CpuExecutionMode,
    memory_access::CpuBus,
    registers::{SegmentRegister, set_segment},
    system::{SegmentCache, map_fault, mark_segment_accessed, read_descriptor},
    x86_decode::NormalizedInstruction,
};

pub(super) fn load_data_register(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    segment: SegmentRegister,
    selector: u16,
) -> Result<(), CpuError> {
    if segment == SegmentRegister::Cs {
        return Err(invalid_opcode_at_bus(bus));
    }
    if !bus.architectural_mode_active() {
        set_segment(registers, segment, selector);
        return Ok(());
    }
    let mode = bus
        .execution_mode()
        .ok_or_else(|| unsupported_mode_at_bus(bus))?;
    match mode {
        CpuExecutionMode::RealAddress => {
            if segment == SegmentRegister::Cs {
                return Err(invalid_opcode_at_bus(bus));
            }
            bus.system_mut().load_real_segment(segment, selector);
        }
        CpuExecutionMode::Virtual8086 => {
            let system = bus.system_mut();
            system.segments[segment_index(segment)] =
                SegmentCache::real_mode(selector, segment == SegmentRegister::Cs);
        }
        CpuExecutionMode::Protected => {
            let cache = if selector & 0xfffc == 0 {
                if segment == SegmentRegister::Ss {
                    return Err(CpuError::GeneralProtectionFault {
                        error_code: 0,
                        ip: bus.instruction_site().ip,
                    });
                }
                SegmentCache::unusable(selector)
            } else {
                let record = read_descriptor(bus, selector)?;
                let cpl = bus
                    .current_privilege_level()
                    .ok_or_else(|| unsupported_mode_at_bus(bus))?;
                if segment == SegmentRegister::Ss {
                    record
                        .descriptor
                        .validate_stack_load(selector, cpl)
                        .map_err(|fault| map_fault(fault, bus))?;
                } else {
                    record
                        .descriptor
                        .validate_data_load(selector, cpl)
                        .map_err(|fault| map_fault(fault, bus))?;
                }
                let descriptor = mark_segment_accessed(bus, record)?;
                SegmentCache::from_descriptor(selector, descriptor)
            };
            let system = bus.system_mut();
            system.segments[segment_index(segment)] = cache;
        }
    }
    set_segment(registers, segment, selector);
    Ok(())
}

pub(super) fn validate_code_transfer(
    bus: &mut impl CpuBus,
    selector: u16,
    target: u32,
    instruction: &NormalizedInstruction,
    is_return: bool,
) -> Result<(SegmentCache, u8), CpuError> {
    let mode = mode(bus, instruction)?;
    if !bus.architectural_mode_active() {
        return Err(unsupported_mode(instruction));
    }
    if mode == CpuExecutionMode::RealAddress {
        let cache = SegmentCache::real_mode(selector, true);
        if target > cache.descriptor.limit {
            return Err(general_protection(0, instruction));
        }
        return Ok((cache, 0));
    }
    if mode == CpuExecutionMode::Virtual8086 {
        let cache = SegmentCache::real_mode(selector, true);
        if target > cache.descriptor.limit {
            return Err(general_protection(0, instruction));
        }
        return Ok((cache, 3));
    }
    let cpl = bus
        .current_privilege_level()
        .ok_or_else(|| unsupported_mode(instruction))?;
    if selector & 0xfffc == 0 {
        return Err(general_protection(0, instruction));
    }
    let record = read_descriptor(bus, selector)?;
    let resulting_cpl = if is_return {
        record
            .descriptor
            .validate_code_return(selector, cpl)
            .map_err(|fault| map_fault(fault, bus))?
    } else {
        record
            .descriptor
            .validate_direct_code_transfer(selector, cpl)
            .map_err(|fault| map_fault(fault, bus))?
    };
    if target > record.descriptor.limit {
        return Err(general_protection(0, instruction));
    }
    let descriptor = mark_segment_accessed(bus, record)?;
    let cached_selector = (selector & !3) | u16::from(resulting_cpl);
    Ok((
        SegmentCache::from_descriptor(cached_selector, descriptor),
        resulting_cpl,
    ))
}

/// Validate a machine-owned 16-bit far transfer or return without inventing a
/// decoded guest instruction. Runtime callback entry and deferred 16-bit
/// return-frame application still use the same architectural descriptors and
/// accessed-bit updates as ordinary CALL/IRET instructions.
pub(crate) fn validate_runtime_code_transfer(
    bus: &mut impl CpuBus,
    selector: u16,
    target: u16,
    is_return: bool,
) -> Result<(SegmentCache, u8), CpuError> {
    let site = bus.instruction_site();
    let unsupported = || CpuError::UnsupportedSystemMode {
        opcode: site.opcode,
        ip: site.ip,
    };
    if !bus.architectural_mode_active() {
        return Err(unsupported());
    }
    match bus.execution_mode().ok_or_else(unsupported)? {
        CpuExecutionMode::RealAddress => {
            let cache = SegmentCache::real_mode(selector, true);
            if u32::from(target) > cache.descriptor.limit {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: site.ip,
                });
            }
            Ok((cache, 0))
        }
        CpuExecutionMode::Virtual8086 => Err(CpuError::CompatibilityGap {
            opcode: site.opcode,
            ip: site.ip,
            feature: crate::CpuCompatibilityGap::Virtual8086Mode,
        }),
        CpuExecutionMode::Protected => {
            let cpl = bus.current_privilege_level().ok_or_else(unsupported)?;
            if selector & 0xfffc == 0 {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: site.ip,
                });
            }
            let record = read_descriptor(bus, selector)?;
            let resulting_cpl = if is_return {
                record.descriptor.validate_code_return(selector, cpl)
            } else {
                record.descriptor.validate_direct_code_transfer(selector, cpl)
            }
            .map_err(|fault| map_fault(fault, bus))?;
            if u32::from(target) > record.descriptor.limit {
                return Err(CpuError::GeneralProtectionFault {
                    error_code: 0,
                    ip: site.ip,
                });
            }
            let descriptor = mark_segment_accessed(bus, record)?;
            let cache_selector = (selector & !3) | u16::from(resulting_cpl);
            Ok((
                SegmentCache::from_descriptor(cache_selector, descriptor),
                resulting_cpl,
            ))
        }
    }
}

pub(super) fn commit_code_transfer(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    _selector: u16,
    cache: SegmentCache,
    cpl: u8,
) {
    registers.cs = cache.selector;
    let system = bus.system_mut();
    system.segments[0] = cache;
    system.cpl = cpl;
}

fn mode(
    bus: &impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<CpuExecutionMode, CpuError> {
    bus.execution_mode()
        .ok_or_else(|| unsupported_mode(instruction))
}

fn segment_index(segment: SegmentRegister) -> usize {
    match segment {
        SegmentRegister::Cs => 0,
        SegmentRegister::Ss => 1,
        SegmentRegister::Ds => 2,
        SegmentRegister::Es => 3,
        SegmentRegister::Fs => 4,
        SegmentRegister::Gs => 5,
    }
}

fn unsupported_mode(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedSystemMode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}

fn invalid_opcode_at_bus(bus: &impl CpuBus) -> CpuError {
    let site = bus.instruction_site();
    CpuError::InvalidOpcode {
        opcode: site.opcode,
        ip: site.ip,
    }
}

fn unsupported_mode_at_bus(bus: &impl CpuBus) -> CpuError {
    let site = bus.instruction_site();
    CpuError::UnsupportedSystemMode {
        opcode: site.opcode,
        ip: site.ip,
    }
}

fn general_protection(error_code: u32, instruction: &NormalizedInstruction) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code,
        ip: instruction.decoded.start_ip,
    }
}
