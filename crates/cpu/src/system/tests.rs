use guest_core::memory::Memory;
use guest_core::{GuestMemory, LinearAddr, PhysAddr};

use super::{
    CR0_CD, CR0_NE, CR0_NW, CR0_PE, CR0_PG, CR0_WP, CR4_PSE, CpuFault, CpuSystem, DescriptorType,
    ExceptionVector, PageAccess, SegmentAccess, SegmentDescriptor, SegmentTableRegister,
    TranslationError,
};

const PRESENT: u32 = 1;
const WRITABLE: u32 = 1 << 1;
const USER: u32 = 1 << 2;
const ACCESSED: u32 = 1 << 5;
const DIRTY: u32 = 1 << 6;
const PAGE_SIZE: u32 = 1 << 7;

fn guest_memory() -> Memory {
    Memory::with_size(4 * 1024 * 1024).expect("test guest RAM")
}

fn put_u32(memory: &mut Memory, address: u32, value: u32) {
    memory
        .write_physical(PhysAddr(address), &value.to_le_bytes())
        .expect("write guest physical dword");
}

fn paging_enabled(writable_protect: bool) -> CpuSystem {
    let mut system = CpuSystem::reset();
    system.write_cr3(0x1000).expect("aligned page directory");
    let cr0 = CR0_PE | CR0_PG | if writable_protect { CR0_WP } else { 0 };
    system.write_cr0(cr0).expect("enable protected paging");
    system
}

fn install_4k_page(
    memory: &mut Memory,
    linear: u32,
    page_frame: u32,
    directory_flags: u32,
    table_flags: u32,
) {
    let directory_index = (linear >> 22) & 0x3ff;
    let table_index = (linear >> 12) & 0x3ff;
    let pde_address = 0x1000 + directory_index * 4;
    let page_table = 0x2000;
    put_u32(memory, pde_address, page_table | PRESENT | directory_flags);
    put_u32(
        memory,
        page_table + table_index * 4,
        page_frame | PRESENT | table_flags,
    );
}

#[test]
fn paging_disabled_is_identity_and_does_not_touch_memory() {
    let mut memory = guest_memory();
    let mut system = CpuSystem::reset();
    let translated = system
        .translate_linear(LinearAddr(0xdead_beef), PageAccess::Read, 0, &mut memory)
        .expect("identity map");
    assert_eq!(translated, PhysAddr(0xdead_beef));
    assert_eq!(system.cr2, 0);
}

#[test]
fn four_kib_walk_combines_permissions_and_sets_accessed_dirty_bits() {
    let mut memory = guest_memory();
    let linear = 0x0040_1234;
    install_4k_page(
        &mut memory,
        linear,
        0x7000,
        WRITABLE | USER,
        WRITABLE | USER,
    );
    let mut system = paging_enabled(false);

    let translated = system
        .translate_linear(LinearAddr(linear), PageAccess::Write, 3, &mut memory)
        .expect("user write to writable page");

    assert_eq!(translated, PhysAddr(0x7234));
    assert_eq!(
        memory.read_u32(PhysAddr(0x1004)).unwrap() & ACCESSED,
        ACCESSED
    );
    assert_eq!(
        memory.read_u32(PhysAddr(0x2004)).unwrap() & (ACCESSED | DIRTY),
        ACCESSED | DIRTY
    );
}

#[test]
fn read_only_page_obeys_cr0_wp_for_supervisor_writes() {
    let mut memory = guest_memory();
    let linear = 0x1000;
    install_4k_page(&mut memory, linear, 0x7000, USER, USER);
    let mut system = paging_enabled(false);

    assert_eq!(
        system
            .translate_linear(LinearAddr(linear), PageAccess::Write, 0, &mut memory)
            .expect("supervisor writes through RO when WP is clear"),
        PhysAddr(0x7000)
    );

    let mut protected_system = paging_enabled(true);
    let fault = protected_system
        .translate_linear(LinearAddr(linear), PageAccess::Write, 0, &mut memory)
        .expect_err("WP protects a supervisor write");
    assert_page_fault(fault, linear, 0b0011);
}

#[test]
fn not_present_pte_fault_sets_cr2_and_only_directory_accessed_bit() {
    let mut memory = guest_memory();
    let linear = 0x0040_1000;
    let directory_index = linear >> 22;
    let pde_address = 0x1000 + directory_index * 4;
    put_u32(&mut memory, pde_address, 0x2000 | PRESENT | WRITABLE | USER);
    let mut system = paging_enabled(false);

    let fault = system
        .translate_linear(LinearAddr(linear), PageAccess::Read, 3, &mut memory)
        .expect_err("missing PTE must fault");

    assert_page_fault(fault, linear, 0b0100);
    assert_eq!(system.cr2, linear);
    assert_eq!(
        memory.read_u32(PhysAddr(pde_address)).unwrap() & ACCESSED,
        ACCESSED
    );
    assert_eq!(memory.read_u32(PhysAddr(0x2004)).unwrap(), 0);
}

#[test]
fn user_write_protection_fault_has_architectural_error_bits() {
    let mut memory = guest_memory();
    let linear = 0x2000;
    install_4k_page(&mut memory, linear, 0x8000, WRITABLE | USER, USER);
    let mut system = paging_enabled(false);

    let fault = system
        .translate_linear(LinearAddr(linear), PageAccess::Write, 3, &mut memory)
        .expect_err("user cannot write read-only PTE");
    assert_page_fault(fault, linear, 0b0111);
    assert_eq!(memory.read_u32(PhysAddr(0x1000)).unwrap() & ACCESSED, 0);
    assert_eq!(memory.read_u32(PhysAddr(0x2008)).unwrap() & ACCESSED, 0);
}

#[test]
fn reserved_large_page_bits_raise_present_reserved_page_fault() {
    let mut memory = guest_memory();
    let linear = 0x0123_4567;
    let directory_index = linear >> 22;
    put_u32(
        &mut memory,
        0x1000 + directory_index * 4,
        0x0080_0000 | PRESENT | PAGE_SIZE | WRITABLE | USER | (1 << 12),
    );
    let mut system = paging_enabled(false);
    system.write_cr4(CR4_PSE).expect("enable 4-MiB pages");

    let fault = system
        .translate_linear(LinearAddr(linear), PageAccess::Read, 3, &mut memory)
        .expect_err("reserved PDE bit must fault");
    assert_page_fault(fault, linear, 0b1101);
}

#[test]
fn pse_reserved_bits_in_4k_entries_raise_present_reserved_page_faults() {
    let mut memory = guest_memory();
    let linear = 0x0020_1000;
    let directory_index = linear >> 22;
    let table_index = (linear >> 12) & 0x3ff;
    put_u32(
        &mut memory,
        0x1000 + directory_index * 4,
        0x2000 | PRESENT | WRITABLE | USER | DIRTY,
    );
    put_u32(
        &mut memory,
        0x2000 + table_index * 4,
        0x8000 | PRESENT | WRITABLE | USER | PAGE_SIZE,
    );
    let mut system = paging_enabled(false);
    system
        .write_cr4(CR4_PSE)
        .expect("enable PSE reserved-bit checks");

    let pde_fault = system
        .translate_linear(LinearAddr(linear), PageAccess::Read, 3, &mut memory)
        .expect_err("reserved PDE bits must fault");

    assert_page_fault(pde_fault, linear, 0b1101);
    put_u32(
        &mut memory,
        0x1000 + directory_index * 4,
        0x2000 | PRESENT | WRITABLE | USER,
    );
    let pte_fault = system
        .translate_linear(LinearAddr(linear), PageAccess::Read, 3, &mut memory)
        .expect_err("reserved PTE bits must fault");
    assert_page_fault(pte_fault, linear, 0b1101);
    assert_eq!(memory.read_u32(PhysAddr(0x1004)).unwrap() & ACCESSED, 0);
    assert_eq!(memory.read_u32(PhysAddr(0x2004)).unwrap() & ACCESSED, 0);
}

#[test]
fn four_mebibyte_page_translation_sets_leaf_accessed_and_dirty() {
    let mut memory = guest_memory();
    let linear = 0x0123_4567;
    let pde_address = 0x1000 + (linear >> 22) * 4;
    put_u32(
        &mut memory,
        pde_address,
        0x0080_0000 | PRESENT | PAGE_SIZE | WRITABLE | USER,
    );
    let mut system = paging_enabled(false);
    system.write_cr4(CR4_PSE).expect("enable 4-MiB pages");

    let physical = system
        .translate_linear(LinearAddr(linear), PageAccess::Write, 3, &mut memory)
        .expect("valid 4-MiB mapping");

    assert_eq!(physical, PhysAddr(0x00a3_4567));
    assert_eq!(
        memory.read_u32(PhysAddr(pde_address)).unwrap() & (ACCESSED | DIRTY),
        ACCESSED | DIRTY
    );
}

#[test]
fn each_linear_page_is_translated_independently_for_cross_page_operands() {
    let mut memory = guest_memory();
    install_4k_page(&mut memory, 0x4fff, 0x7000, WRITABLE, WRITABLE);
    install_4k_page(&mut memory, 0x5000, 0x9000, WRITABLE, WRITABLE);
    let mut system = paging_enabled(false);

    let first = system
        .translate_linear(LinearAddr(0x4fff), PageAccess::Read, 0, &mut memory)
        .unwrap();
    let second = system
        .translate_linear(LinearAddr(0x5000), PageAccess::Read, 0, &mut memory)
        .unwrap();

    assert_eq!(first, PhysAddr(0x7fff));
    assert_eq!(second, PhysAddr(0x9000));
}

#[test]
fn invalid_control_register_writes_fault_without_changing_registers() {
    let mut system = CpuSystem::reset();
    let old_cr0 = system.cr0;
    assert_eq!(
        system.write_cr0(CR0_PG),
        Err(CpuFault::general_protection(0))
    );
    assert_eq!(system.cr0, old_cr0);
    assert_eq!(old_cr0, CR0_CD | super::CR0_ET);

    assert_eq!(
        system.write_cr0(CR0_NE | CR0_NW),
        Err(CpuFault::general_protection(0))
    );
    assert_eq!(system.cr0, old_cr0);
    assert!(system.write_cr0(1 << 6).is_err());
    assert_eq!(system.cr0, old_cr0);

    system
        .write_cr3(0x1001)
        .expect("reserved low bit is ignored");
    assert_eq!(system.cr3, 0x1000);
    system
        .write_cr3(0x2018)
        .expect("486 CR3 cache controls are supported");
    assert_eq!(system.cr3, 0x2018);
    assert!(system.write_cr4(1 << 5).is_err());
    assert_eq!(system.cr4, 0);
}

#[test]
fn cr2_is_software_writable_and_execute_has_read_permissions() {
    let mut memory = guest_memory();
    let linear = 0x3000;
    install_4k_page(&mut memory, linear, 0x8000, USER, USER);
    let mut system = paging_enabled(false);

    system.write_cr2(0x1234_5678);
    assert_eq!(system.cr2, 0x1234_5678);
    assert_eq!(
        system
            .translate_linear(LinearAddr(linear), PageAccess::Execute, 3, &mut memory)
            .unwrap(),
        PhysAddr(0x8000)
    );
}

#[test]
fn inaccessible_page_table_update_does_not_partially_set_leaf_accessed_bits() {
    let mut memory = guest_memory();
    let linear = 0x1000;
    let pde = 0x2000 | PRESENT | WRITABLE;
    memory
        .initialize_rom(PhysAddr(0x000f_0000), &pde.to_le_bytes())
        .expect("place test directory entry in ROM");
    put_u32(&mut memory, 0x2004, 0x7000 | PRESENT | WRITABLE);

    let mut system = CpuSystem::reset();
    system.write_cr3(0x000f_0000).expect("ROM-aligned CR3");
    system
        .write_cr0(CR0_PE | CR0_PG)
        .expect("enable protected paging");
    let error = system
        .translate_linear(LinearAddr(linear), PageAccess::Read, 0, &mut memory)
        .expect_err("hardware A bit cannot be written to ROM");

    assert!(matches!(error, TranslationError::Memory(_)));
    assert_eq!(memory.read_u32(PhysAddr(0x2004)).unwrap() & ACCESSED, 0);
}

fn assert_page_fault(error: TranslationError, linear: u32, code: u32) {
    assert_eq!(
        error,
        TranslationError::Fault(CpuFault {
            vector: ExceptionVector::PageFault,
            error_code: Some(code),
            linear_address: Some(LinearAddr(linear)),
        })
    );
}

fn raw_descriptor(
    base: u32,
    limit: u32,
    type_bits: u8,
    dpl: u8,
    present: bool,
    default_big: bool,
    granularity: bool,
) -> u64 {
    let mut raw = u64::from(limit & 0xffff)
        | (u64::from(base & 0xffff) << 16)
        | (u64::from((base >> 16) & 0xff) << 32)
        | (u64::from(type_bits | 0x10 | ((dpl & 3) << 5) | if present { 0x80 } else { 0 }) << 40)
        | (u64::from((limit >> 16) & 0x0f) << 48)
        | (u64::from((base >> 24) & 0xff) << 56);
    if default_big {
        raw |= 1 << 54;
    }
    if granularity {
        raw |= 1 << 55;
    }
    raw
}

#[test]
fn descriptor_parser_decodes_base_scaled_limit_access_and_size_flags() {
    let descriptor = SegmentDescriptor::parse(raw_descriptor(
        0x1234_5678,
        0x000a_bcde,
        0b0110,
        3,
        true,
        true,
        true,
    ));

    assert_eq!(descriptor.base, 0x1234_5678);
    assert_eq!(descriptor.limit, 0xabc_defff);
    assert_eq!(descriptor.dpl, 3);
    assert!(descriptor.present);
    assert!(descriptor.default_big);
    assert!(descriptor.granularity);
    assert_eq!(
        descriptor.descriptor_type,
        DescriptorType::Data {
            writable: true,
            expand_down: true,
            accessed: false,
        }
    );
}

#[test]
fn descriptor_access_checks_entire_range_and_cpl_rpl_dpl() {
    let data = SegmentDescriptor::parse(raw_descriptor(0, 0xffff, 0b0010, 3, true, false, false));
    assert!(
        data.check_access(0x1b, SegmentAccess::Write, 3, 3, 0xfffe, 2)
            .is_ok()
    );
    assert!(
        data.check_access(0x1b, SegmentAccess::StackRead, 3, 3, 0, 1)
            .is_ok()
    );
    assert_eq!(
        data.check_access(0x1b, SegmentAccess::Write, 3, 3, 0xffff, 2),
        Err(CpuFault::general_protection(0x18))
    );
    assert!(
        data.check_access(0x1b, SegmentAccess::Read, 0, 3, 0, 1)
            .is_ok()
    );
    let supervisor_data =
        SegmentDescriptor::parse(raw_descriptor(0, 0xffff, 0b0010, 0, true, false, false));
    assert_eq!(
        supervisor_data.check_access(0x08, SegmentAccess::Read, 3, 0, 0, 1),
        Err(CpuFault::general_protection(0x08))
    );
}

#[test]
fn read_only_data_and_conforming_code_use_distinct_access_rules() {
    let read_only_data =
        SegmentDescriptor::parse(raw_descriptor(0, 0xffff, 0b0000, 3, true, false, false));
    assert!(
        read_only_data
            .check_access(0x23, SegmentAccess::Read, 3, 0, 0, 1)
            .is_ok()
    );
    assert!(
        read_only_data
            .check_access(0x23, SegmentAccess::Write, 3, 0, 0, 1)
            .is_err()
    );

    let conforming_code =
        SegmentDescriptor::parse(raw_descriptor(0, 0xffff, 0b1110, 0, true, false, false));
    assert!(
        conforming_code
            .check_access(0x08, SegmentAccess::Read, 3, 3, 0, 1)
            .is_ok()
    );
    assert!(
        conforming_code
            .check_access(0x08, SegmentAccess::InstructionFetch, 3, 3, 0, 1)
            .is_ok()
    );
}

#[test]
fn expand_down_limit_uses_db_selected_upper_bound() {
    let expand_down_16 =
        SegmentDescriptor::parse(raw_descriptor(0, 0x1000, 0b0110, 0, true, false, false));
    assert!(
        expand_down_16
            .check_access(0x08, SegmentAccess::Write, 0, 0, 0x1001, 1)
            .is_ok()
    );
    assert!(
        expand_down_16
            .check_access(0x08, SegmentAccess::Write, 0, 0, 0xffff, 1)
            .is_ok()
    );
    assert!(
        expand_down_16
            .check_access(0x08, SegmentAccess::Write, 0, 0, 0x1000, 1)
            .is_err()
    );
    assert!(
        expand_down_16
            .check_access(0x08, SegmentAccess::Write, 0, 0, 0x1_0000, 1)
            .is_err()
    );

    let expand_down_32 =
        SegmentDescriptor::parse(raw_descriptor(0, 0x1000, 0b0110, 0, true, true, false));
    assert!(
        expand_down_32
            .check_access(0x08, SegmentAccess::Write, 0, 0, 0x1_0000, 1)
            .is_ok()
    );
}

#[test]
fn not_present_segments_report_np_or_ss_and_selector_error_code() {
    let not_present =
        SegmentDescriptor::parse(raw_descriptor(0, 0xffff, 0b0010, 0, false, false, false));
    assert_eq!(
        not_present.check_access(0x08, SegmentAccess::Read, 0, 0, 0, 1),
        Err(CpuFault::segment_not_present(0x08))
    );
    assert_eq!(
        not_present.check_access(0x08, SegmentAccess::StackWrite, 0, 0, 0, 1),
        Err(CpuFault::stack_segment(0x08))
    );
}

#[test]
fn descriptor_table_register_checks_inclusive_limit_and_address_overflow() {
    let table = SegmentTableRegister {
        base: LinearAddr(0x1000),
        limit: 0x17,
    };
    assert_eq!(table.descriptor_address(0x10), Ok(LinearAddr(0x1010)));
    assert_eq!(
        table.descriptor_address(0x18),
        Err(CpuFault::general_protection(0x18))
    );
    let overflowing = SegmentTableRegister {
        base: LinearAddr(u32::MAX - 3),
        limit: u16::MAX,
    };
    assert!(overflowing.descriptor_address(0x08).is_err());
}
