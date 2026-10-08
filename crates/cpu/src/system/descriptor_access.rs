use guest_core::LinearAddr;

use crate::{
    CpuError,
    memory_access::{AccessKind, AccessRequest, CpuBus},
    system::{CpuFault, DescriptorType, ExceptionVector, SegmentDescriptor, SegmentTableRegister},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DescriptorRecord {
    pub(crate) selector: u16,
    pub(crate) address: LinearAddr,
    pub(crate) raw: u64,
    pub(crate) descriptor: SegmentDescriptor,
}

pub(crate) fn read_descriptor(
    bus: &mut impl CpuBus,
    selector: u16,
) -> Result<DescriptorRecord, CpuError> {
    if selector & 0xfffc == 0 {
        return Err(general_protection(selector, bus));
    }
    let table = if selector & 0x04 == 0 {
        bus.system().gdtr
    } else {
        let ldt = bus.system().ldtr;
        if !ldt.valid || !ldt.present {
            return Err(general_protection(selector, bus));
        }
        SegmentTableRegister {
            base: LinearAddr(ldt.base),
            limit: ldt.limit,
        }
    };
    read_from_table(bus, table, selector)
}

pub(crate) fn read_gdt_descriptor(
    bus: &mut impl CpuBus,
    selector: u16,
) -> Result<DescriptorRecord, CpuError> {
    if selector & 0x04 != 0 || selector & 0xfffc == 0 {
        return Err(general_protection(selector, bus));
    }
    read_from_table(bus, bus.system().gdtr, selector)
}

fn read_from_table(
    bus: &mut impl CpuBus,
    table: SegmentTableRegister,
    selector: u16,
) -> Result<DescriptorRecord, CpuError> {
    let address = table
        .descriptor_address(selector)
        .map_err(|fault| map_fault(fault, bus))?;
    let access = bus.prepare(AccessRequest::SystemLinear {
        address,
        len: 8,
        kind: AccessKind::SystemTableRead,
    })?;
    let mut bytes = [0_u8; 8];
    bus.read_prepared(&access, &mut bytes)?;
    // This fixed i486 descriptor is read only after the CPU bus has checked
    // the table range and guest address. Keep its raw scalar alongside the
    // decoded fields because LAR and accessed/busy-bit writes use exact bits;
    // a generic wire codec cannot replace those architectural checks.
    let raw = u64::from_le_bytes(bytes);
    Ok(DescriptorRecord {
        selector,
        address,
        raw,
        descriptor: SegmentDescriptor::parse(raw),
    })
}

pub(crate) fn write_access_byte(
    bus: &mut impl CpuBus,
    address: LinearAddr,
    access_byte: u8,
) -> Result<(), CpuError> {
    // Descriptor readers validate the full eight-byte range before returning
    // a record; still keep this derived linear address checked at the write
    // boundary so a future caller cannot wrap a guest address.
    let access_address = address
        .0
        .checked_add(5)
        .map(LinearAddr)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    let plan = bus.prepare(AccessRequest::SystemLinear {
        address: access_address,
        len: 1,
        kind: AccessKind::SystemTableWrite,
    })?;
    bus.write_prepared(plan, &[access_byte])
}

pub(crate) fn mark_segment_accessed(
    bus: &mut impl CpuBus,
    record: DescriptorRecord,
) -> Result<SegmentDescriptor, CpuError> {
    let (access, _) = record.descriptor.cache_fields();
    let already_accessed = matches!(
        record.descriptor.descriptor_type,
        DescriptorType::Code { accessed: true, .. } | DescriptorType::Data { accessed: true, .. }
    );
    if already_accessed {
        return Ok(record.descriptor);
    }
    write_access_byte(bus, record.address, access | 1)?;
    Ok(SegmentDescriptor::parse(record.raw | (1_u64 << 40)))
}

pub(crate) fn set_system_descriptor_type(
    bus: &mut impl CpuBus,
    record: DescriptorRecord,
    system_type: u8,
) -> Result<(), CpuError> {
    let access_byte = (record.raw >> 40) as u8;
    write_access_byte(
        bus,
        record.address,
        (access_byte & 0xf0) | (system_type & 0x0f),
    )
}

fn general_protection(selector: u16, bus: &impl CpuBus) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: if selector & 0xfffc == 0 {
            0
        } else {
            u32::from(selector & 0xfffc)
        },
        ip: bus.instruction_site().ip,
    }
}

pub(crate) fn map_fault(fault: CpuFault, bus: &impl CpuBus) -> CpuError {
    let ip = bus.instruction_site().ip;
    match fault.vector {
        ExceptionVector::GeneralProtection => CpuError::GeneralProtectionFault {
            error_code: fault.error_code.unwrap_or(0),
            ip,
        },
        ExceptionVector::SegmentNotPresent => CpuError::SegmentNotPresentFault {
            error_code: fault.error_code.unwrap_or(0),
            ip,
        },
        ExceptionVector::StackSegment => CpuError::StackSegmentFault {
            error_code: fault.error_code.unwrap_or(0),
            ip,
        },
        ExceptionVector::PageFault => match fault.linear_address {
            Some(address) => CpuError::PageFault {
                error_code: fault.error_code.unwrap_or(0),
                linear_address: address.0,
                ip,
            },
            None => CpuError::InvalidMemoryAccessPlan { ip },
        },
    }
}
