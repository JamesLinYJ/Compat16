//! Descriptor and TSS accesses in an explicit CPU address space.

use guest_core::LinearAddr;

use crate::{
    CpuError,
    memory_access::{AccessKind, CpuBus, PagingAddressSpace},
    system::{DescriptorRecord, SegmentTableRegister, SystemSegmentCache, map_fault},
};

pub(super) fn read_descriptor(
    bus: &mut impl CpuBus,
    selector: u16,
    ldt: SystemSegmentCache,
    space: PagingAddressSpace,
) -> Result<DescriptorRecord, CpuError> {
    if selector & 0xfffc == 0 {
        return Err(general_protection(selector, bus.instruction_site().ip));
    }
    let table = if selector & 4 == 0 {
        bus.system().gdtr
    } else {
        if !ldt.valid || !ldt.present {
            return Err(general_protection(selector, bus.instruction_site().ip));
        }
        SegmentTableRegister {
            base: LinearAddr(ldt.base),
            limit: ldt.limit,
        }
    };
    let address = table
        .descriptor_address(selector)
        .map_err(|fault| map_fault(fault, bus))?;
    let access =
        bus.prepare_system_linear_in_address_space(address, 8, AccessKind::SystemTableRead, space)?;
    let mut bytes = [0_u8; 8];
    bus.read_prepared(&access, &mut bytes)?;
    let raw = u64::from_le_bytes(bytes);
    Ok(DescriptorRecord {
        selector,
        address,
        raw,
        descriptor: crate::system::SegmentDescriptor::parse(raw),
    })
}

pub(super) fn read_gdt_descriptor(
    bus: &mut impl CpuBus,
    selector: u16,
    space: PagingAddressSpace,
) -> Result<DescriptorRecord, CpuError> {
    if selector & 4 != 0 || selector & 0xfffc == 0 {
        return Err(general_protection(selector, bus.instruction_site().ip));
    }
    read_descriptor(bus, selector, SystemSegmentCache::default(), space)
}

pub(super) fn read_system_bytes<const N: usize>(
    bus: &mut impl CpuBus,
    base: u32,
    offset: u32,
    space: PagingAddressSpace,
) -> Result<[u8; N], CpuError> {
    let address = base
        .checked_add(offset)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    let access = bus.prepare_system_linear_in_address_space(
        LinearAddr(address),
        N,
        AccessKind::SystemTableRead,
        space,
    )?;
    let mut bytes = [0_u8; N];
    bus.read_prepared(&access, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn read_system_bytes_into(
    bus: &mut impl CpuBus,
    base: u32,
    offset: u32,
    bytes: &mut [u8],
    space: PagingAddressSpace,
) -> Result<(), CpuError> {
    let address = base
        .checked_add(offset)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    let access = bus.prepare_system_linear_in_address_space(
        LinearAddr(address),
        bytes.len(),
        AccessKind::SystemTableRead,
        space,
    )?;
    bus.read_prepared(&access, bytes)
}

pub(super) fn prepare_system_write(
    bus: &mut impl CpuBus,
    address: LinearAddr,
    len: usize,
    space: PagingAddressSpace,
) -> Result<crate::memory_access::PreparedAccess, CpuError> {
    bus.prepare_system_linear_in_address_space(address, len, AccessKind::SystemTableWrite, space)
}

pub(super) fn prepare_tss_write(
    bus: &mut impl CpuBus,
    base: u32,
    offset: u32,
    len: usize,
    space: PagingAddressSpace,
) -> Result<crate::memory_access::PreparedAccess, CpuError> {
    let address = base
        .checked_add(offset)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    prepare_system_write(bus, LinearAddr(address), len, space)
}

pub(super) fn write_selector_access_byte(
    bus: &mut impl CpuBus,
    record: DescriptorRecord,
    access_byte: u8,
    space: PagingAddressSpace,
) -> Result<(), CpuError> {
    let address = record
        .address
        .0
        .checked_add(5)
        .map(LinearAddr)
        .ok_or(CpuError::Memory(guest_core::MemoryError::AddressOverflow))?;
    let plan = prepare_system_write(bus, address, 1, space)?;
    bus.write_prepared(plan, &[access_byte])
}

pub(super) fn general_protection(selector: u16, ip: u32) -> CpuError {
    CpuError::GeneralProtectionFault {
        error_code: selector_error_code(selector),
        ip,
    }
}

pub(super) fn selector_error_code(selector: u16) -> u32 {
    if selector & 0xfffc == 0 {
        0
    } else {
        u32::from(selector & 0xfffc)
    }
}
