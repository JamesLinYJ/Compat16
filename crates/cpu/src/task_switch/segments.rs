//! Incoming task selector checks after the architectural switch point.

use guest_core::Registers;

use crate::{
    CpuError, CpuExecutionMode,
    memory_access::{CpuBus, PagingAddressSpace},
    system::{
        DescriptorRecord, DescriptorType, SegmentCache, SegmentDescriptor, SystemSegmentCache,
    },
};

use super::memory::{
    read_descriptor, read_gdt_descriptor, selector_error_code, write_selector_access_byte,
};

pub(super) fn load_ldt(
    bus: &mut impl CpuBus,
    incoming_ldt_selector: u16,
    space: PagingAddressSpace,
    ip: u32,
    external: bool,
) -> Result<SystemSegmentCache, CpuError> {
    if incoming_ldt_selector & 0xfffc != 0 {
        if incoming_ldt_selector & 4 != 0 {
            return Err(invalid_tss(incoming_ldt_selector, ip, external));
        }
        let record = read_gdt_descriptor(bus, incoming_ldt_selector, space)
            .map_err(|error| remap_descriptor_fault(error, incoming_ldt_selector, ip, external))?;
        if !matches!(
            record.descriptor.descriptor_type,
            DescriptorType::System { system_type: 2 }
        ) {
            return Err(invalid_tss(incoming_ldt_selector, ip, external));
        }
        if !record.descriptor.present {
            // Task-switch LDTR loading has a distinct #TS rule; ordinary
            // LLDT still reports #NP for this same non-present descriptor.
            return Err(invalid_tss(incoming_ldt_selector, ip, external));
        }
        let ldt = SystemSegmentCache {
            selector: incoming_ldt_selector,
            base: record.descriptor.base,
            limit: record.descriptor.limit,
            system_type: 2,
            present: true,
            valid: true,
        };
        return Ok(ldt);
    }
    Ok(SystemSegmentCache {
        // A null LDTR selector may carry nonzero RPL bits; SLDT returns the
        // loaded selector value even though the hidden LDT cache is invalid.
        selector: incoming_ldt_selector,
        ..SystemSegmentCache::default()
    })
}

pub(super) fn load_incoming_segments(
    bus: &mut impl CpuBus,
    registers: &Registers,
    ldt: SystemSegmentCache,
    task_width_32: bool,
    mode: CpuExecutionMode,
    space: PagingAddressSpace,
    ip: u32,
    external: bool,
) -> Result<(), CpuError> {
    let selectors = [
        registers.cs,
        registers.ss,
        registers.ds,
        registers.es,
        registers.fs,
        registers.gs,
    ];
    let is_v86 = mode == CpuExecutionMode::Virtual8086;
    let cpl = if is_v86 { 3 } else { (registers.cs & 3) as u8 };
    let mut caches = bus.system().segments;
    let segment_count = if task_width_32 { 6 } else { 4 };
    for (index, selector) in selectors.into_iter().take(segment_count).enumerate() {
        caches[index] = SegmentCache::unusable(selector);
    }

    if is_v86 {
        if !task_width_32 {
            return Err(general_protection(0, ip, external));
        }
        // A 32-bit TSS can supply a VM86 EIP beyond the real-style CS limit.
        // Finish loading the committed task's segment state; its first fetch
        // then raises #GP(0) in the new task context.
        for (index, selector) in selectors.into_iter().enumerate() {
            caches[index] = SegmentCache::real_mode(selector, index == 0);
        }
        bus.system_mut().segments = caches;
        bus.system_mut().cpl = cpl;
        return Ok(());
    }

    let cs_record = read_descriptor(bus, selectors[0], ldt, space)
        .map_err(|error| remap_descriptor_fault(error, selectors[0], ip, external))?;
    let cs_descriptor = cs_record.descriptor;
    let code_privilege_ok = match cs_descriptor.descriptor_type {
        DescriptorType::Code {
            conforming: true, ..
        } => cs_descriptor.dpl <= cpl,
        DescriptorType::Code {
            conforming: false, ..
        } => cs_descriptor.dpl == cpl && selectors[0] & 3 == u16::from(cpl),
        _ => false,
    };
    if !code_privilege_ok || cs_descriptor.long_mode {
        return Err(invalid_tss(selectors[0], ip, external));
    }
    if !cs_descriptor.present {
        return Err(CpuError::SegmentNotPresentFault {
            error_code: external_error_code(selectors[0], external),
            ip,
        });
    }
    // The task switch is already committed. A target EIP outside the new CS
    // limit faults as #GP(0) on the first instruction fetch in the new task.
    let cs_descriptor = mark_accessed(bus, cs_record, space)?;
    caches[0] = SegmentCache::from_descriptor(selectors[0], cs_descriptor);
    bus.system_mut().segments[0] = caches[0];

    let ss_record = read_descriptor(bus, selectors[1], ldt, space)
        .map_err(|error| remap_descriptor_fault(error, selectors[1], ip, external))?;
    let ss_descriptor = ss_record.descriptor;
    let stack_privilege_ok = selectors[1] & 3 == u16::from(cpl)
        && ss_descriptor.dpl == cpl
        && matches!(
            ss_descriptor.descriptor_type,
            DescriptorType::Data { writable: true, .. }
        );
    if !stack_privilege_ok || ss_descriptor.long_mode {
        return Err(invalid_tss(selectors[1], ip, external));
    }
    if !ss_descriptor.present {
        return Err(CpuError::StackSegmentFault {
            error_code: external_error_code(selectors[1], external),
            ip,
        });
    }
    let ss_descriptor = mark_accessed(bus, ss_record, space)?;
    caches[1] = SegmentCache::from_descriptor(selectors[1], ss_descriptor);
    bus.system_mut().segments[1] = caches[1];

    let data_count = if task_width_32 { 6 } else { 4 };
    for index in 2..data_count {
        let selector = selectors[index];
        if selector & 0xfffc == 0 {
            caches[index] = SegmentCache::unusable(selector);
            bus.system_mut().segments[index] = caches[index];
            continue;
        }
        let record = read_descriptor(bus, selector, ldt, space)
            .map_err(|error| remap_descriptor_fault(error, selector, ip, external))?;
        let descriptor = record.descriptor;
        let privilege_ok = match descriptor.descriptor_type {
            DescriptorType::Data { .. } => cpl.max((selector & 3) as u8) <= descriptor.dpl,
            DescriptorType::Code {
                readable: true,
                conforming: false,
                ..
            } => cpl.max((selector & 3) as u8) <= descriptor.dpl,
            DescriptorType::Code {
                readable: true,
                conforming: true,
                ..
            } => true,
            _ => false,
        };
        if !privilege_ok || descriptor.long_mode {
            return Err(invalid_tss(selector, ip, external));
        }
        if !descriptor.present {
            return Err(CpuError::SegmentNotPresentFault {
                error_code: external_error_code(selector, external),
                ip,
            });
        }
        let descriptor = mark_accessed(bus, record, space)?;
        caches[index] = SegmentCache::from_descriptor(selector, descriptor);
        bus.system_mut().segments[index] = caches[index];
    }

    Ok(())
}

fn mark_accessed(
    bus: &mut impl CpuBus,
    record: DescriptorRecord,
    space: PagingAddressSpace,
) -> Result<SegmentDescriptor, CpuError> {
    let already_accessed = matches!(
        record.descriptor.descriptor_type,
        DescriptorType::Code { accessed: true, .. } | DescriptorType::Data { accessed: true, .. }
    );
    if already_accessed {
        return Ok(record.descriptor);
    }
    let access_byte = (record.raw >> 40) as u8;
    write_selector_access_byte(bus, record, access_byte | 1, space)?;
    Ok(SegmentDescriptor::parse(record.raw | (1_u64 << 40)))
}

fn remap_descriptor_fault(error: CpuError, selector: u16, ip: u32, external: bool) -> CpuError {
    match error {
        CpuError::GeneralProtectionFault { .. } | CpuError::InvalidTssFault { .. } => {
            invalid_tss(selector, ip, external)
        }
        CpuError::SegmentNotPresentFault { .. } => CpuError::SegmentNotPresentFault {
            error_code: external_error_code(selector, external),
            ip,
        },
        other => other,
    }
}

fn general_protection(selector: u16, ip: u32, external: bool) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: external_error_code(selector, external),
        ip,
    }
}

fn invalid_tss(selector: u16, ip: u32, external: bool) -> CpuError {
    CpuError::InvalidTssFault {
        error_code: external_error_code(selector, external),
        ip,
    }
}

fn external_error_code(selector: u16, external: bool) -> u32 {
    selector_error_code(selector) | u32::from(external)
}
