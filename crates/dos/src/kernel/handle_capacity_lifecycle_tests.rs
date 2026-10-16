//! Expanded DOS JFT allocation, shared SFT ownership, and process cleanup.

use super::*;
use guest_core::real_address;
use super::super::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};

const PSP: u16 = 0x1000;
const PATH_OFFSET: u16 = 0x0200;

fn install_jft(memory: &mut TestMemory, psp: u16) {
    let mut header = [0; 6];
    header[..2].copy_from_slice(&20u16.to_le_bytes());
    header[2..4].copy_from_slice(&0x18u16.to_le_bytes());
    header[4..].copy_from_slice(&psp.to_le_bytes());
    memory.put(real_address(psp, 0x32).0, &header);
    let mut entries = [0xff; 20];
    entries[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(real_address(psp, 0x18).0, &entries);
}

fn fixture() -> (DosKernel, TestHost, TestMemory) {
    let mut dos = DosKernel::new(PSP);
    // Enough conventional memory for a maximum-sized 64 KiB JFT as well as
    // parent/child blocks and a replacement JFT during transactional growth.
    let mut memory = TestMemory(vec![0; 0x40000]);
    install_jft(&mut memory, PSP);
    let mut host = TestHost {
        local_time: Some(crate::DosLocalDateTime {
            year: 1991, month: 6, day: 3, weekday: 1,
            hour: 12, minute: 34, second: 56, hundredth: 78,
        }),
        ..Default::default()
    };
    let mut resize = Registers { es: PSP, ..Default::default() };
    resize.set_ax(0x4a00);
    resize.set_bx(0x100);
    interrupt(&mut dos, &mut host, &mut memory, &mut resize);
    assert!(!resize.carry());
    (dos, host, memory)
}

fn interrupt(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut impl GuestMemory,
    regs: &mut Registers,
) {
    assert_eq!(dos.interrupt(0x21, regs, memory, host).unwrap(), DosAction::Continue);
}

fn grow(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, count: u16) {
    let mut regs = Registers::default();
    regs.set_ax(0x6700);
    regs.set_bx(count);
    interrupt(dos, host, memory, &mut regs);
    assert!(!regs.carry(), "AH=67h failed for {count} handles: AX={:04x}", regs.ax());
    assert_eq!(dos.jft_capacity, count);
}

fn close(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, handle: u16) {
    let mut regs = Registers::default();
    regs.set_ax(0x3e00);
    regs.set_bx(handle);
    interrupt(dos, host, memory, &mut regs);
    assert!(!regs.carry(), "close failed for handle {handle}");
}

fn duplicate(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, source: u16,
) -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(source);
    interrupt(dos, host, memory, &mut regs);
    regs
}

fn forcedup(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    source: u16, target: u16,
) -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(0x4600);
    regs.set_bx(source);
    regs.set_cx(target);
    interrupt(dos, host, memory, &mut regs);
    regs
}

#[derive(Clone, Copy, Debug)]
enum Allocator { Create, CreateNew, Open, ExtendedOpen, Temporary, Duplicate }

const ALLOCATORS: [Allocator; 6] = [
    Allocator::Create, Allocator::CreateNew, Allocator::Open,
    Allocator::ExtendedOpen, Allocator::Temporary, Allocator::Duplicate,
];

fn allocate(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    allocator: Allocator, serial: u16,
) -> Registers {
    let path = match allocator {
        Allocator::Open => b"SOURCE.DAT".to_vec(),
        Allocator::Temporary => b".\\".to_vec(),
        _ => format!("F{serial:04}.DAT").into_bytes(),
    };
    let psp = dos.psp_segment();
    let address = real_address(psp, PATH_OFFSET).0;
    memory.put(address, &path);
    memory.put(address + path.len() as u32, &[0; 14]);
    let mut regs = Registers { ds: psp, ..Default::default() };
    regs.set_dx(PATH_OFFSET);
    match allocator {
        Allocator::Create => regs.set_ax(0x3c00),
        Allocator::CreateNew => regs.set_ax(0x5b00),
        Allocator::Open => regs.set_ax(0x3d02),
        Allocator::ExtendedOpen => {
            regs.set_ax(0x6c00);
            regs.set_bx(2);
            regs.set_dx(0x11);
            regs.set_si(PATH_OFFSET);
        }
        Allocator::Temporary => regs.set_ax(0x5a00),
        Allocator::Duplicate => {
            regs.set_ax(0x4500);
            regs.set_bx(3);
        }
    }
    interrupt(dos, host, memory, &mut regs);
    regs
}

fn create_source(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory) -> u16 {
    let file = host.file_create(b"SOURCE.DAT", 0).unwrap();
    host.file_close(file).unwrap();
    let opened = allocate(dos, host, memory, Allocator::Open, 0);
    assert!(!opened.carry());
    assert_eq!(opened.ax(), 3);
    opened.ax()
}

fn publish(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory) {
    for state in host.files.values_mut() {
        state.status = Some(DosFileStatus {
            short_name: *b"TEST    DAT", size: 0, position: 0,
            attributes: 0, write_time: 0, write_date: 0,
        });
    }
    dos.initialize_system_tables(memory).unwrap();
    dos.refresh_system_tables(memory, host).unwrap();
}

fn jft_entry(memory: &impl GuestMemory, psp: u16, handle: u16) -> u8 {
    let count = memory.read_u16(real_address(psp, 0x32)).unwrap();
    assert!(handle < count);
    let offset = memory.read_u16(real_address(psp, 0x34)).unwrap();
    let segment = memory.read_u16(real_address(psp, 0x36)).unwrap();
    memory.read_u8(PhysAddr(real_address(segment, offset).0 + u32::from(handle))).unwrap()
}

fn sft_references(memory: &impl GuestMemory, index: u8) -> u16 {
    assert_ne!(index, 0xff);
    let offset = usize::from(SFT_OFFSET) + SFT_HEADER_BYTES + usize::from(index) * SFT_ENTRY_BYTES;
    memory.read_u16(real_address(SYSTEM_SEGMENT, offset as u16)).unwrap()
}

#[test]
fn every_allocator_uses_grown_capacity_above_255_and_reuses_lowest_holes() {
    for allocator in ALLOCATORS {
        let (mut dos, mut host, mut memory) = fixture();
        grow(&mut dos, &mut host, &mut memory, 258);
        create_source(&mut dos, &mut host, &mut memory);
        // These are aliases, so reaching guest handle 255 does not exhaust
        // the independent pool of 255 SFT records.
        for expected in 4..255 {
            let regs = duplicate(&mut dos, &mut host, &mut memory, 0);
            assert!(!regs.carry());
            assert_eq!(regs.ax(), expected);
        }
        for expected in 255..258 {
            let regs = allocate(&mut dos, &mut host, &mut memory, allocator, expected);
            assert!(!regs.carry(), "{allocator:?} rejected handle {expected}");
            assert_eq!(regs.ax(), expected, "{allocator:?}");
        }
        let tokens = host.handles.clone();
        let next_id = host.next_id;
        let duplicates = host.duplicate_calls;
        let creates = host.create_new_calls;
        let extended = host.extended_open_calls.len();
        let temporary_sequence = dos.next_temporary_name;
        let full = allocate(&mut dos, &mut host, &mut memory, allocator, 500);
        assert!(full.carry(), "{allocator:?} exceeded its owned JFT capacity");
        assert_eq!(full.ax(), DosErrorCode::TooManyOpenFiles as u16);
        assert_eq!(host.handles, tokens);
        assert_eq!(host.next_id, next_id);
        assert_eq!(host.duplicate_calls, duplicates);
        assert_eq!(host.create_new_calls, creates);
        assert_eq!(host.extended_open_calls.len(), extended);
        assert_eq!(dos.next_temporary_name, temporary_sequence);

        close(&mut dos, &mut host, &mut memory, 256);
        close(&mut dos, &mut host, &mut memory, 9);
        for (serial, expected) in [(501, 9), (502, 256)] {
            let regs = allocate(&mut dos, &mut host, &mut memory, allocator, serial);
            assert!(!regs.carry());
            assert_eq!(regs.ax(), expected, "{allocator:?} must use the lowest free JFT slot");
        }
        publish(&mut dos, &mut host, &mut memory);
        for handle in [9, 254, 255, 256, 257] {
            assert_ne!(jft_entry(&memory, PSP, handle), 0xff, "{allocator:?}, handle {handle}");
        }
        dos.close_all_handles_checked(&mut host).unwrap();
        assert!(host.handles.is_empty());
    }
}

#[test]
fn forcedup_accepts_full_u16_handle_range_without_confusing_ff_with_closed_sft() {
    let (mut dos, mut host, mut memory) = fixture();
    grow(&mut dos, &mut host, &mut memory, 0xfffe);
    let source = create_source(&mut dos, &mut host, &mut memory);
    for target in [254, 255, 256, 0xfffd] {
        let regs = forcedup(&mut dos, &mut host, &mut memory, source, target);
        assert!(!regs.carry(), "forcedup rejected guest handle {target}");
        assert_eq!(regs.ax(), target);
    }
    let duplicates = host.duplicate_calls;
    let tokens = host.handles.clone();
    for target in [0xfffe, 0xffff] {
        let regs = forcedup(&mut dos, &mut host, &mut memory, source, target);
        assert!(regs.carry());
        assert_eq!(regs.ax(), DosErrorCode::InvalidHandle as u16);
    }
    assert_eq!(host.duplicate_calls, duplicates);
    assert_eq!(host.handles, tokens);
    publish(&mut dos, &mut host, &mut memory);
    let index = jft_entry(&memory, PSP, source);
    for target in [254, 255, 256, 0xfffd] {
        assert_eq!(jft_entry(&memory, PSP, target), index);
    }
    assert_eq!(sft_references(&memory, index), 5);
    close(&mut dos, &mut host, &mut memory, 255);
    assert_eq!(jft_entry(&memory, PSP, 255), 0xff);
    assert_eq!(sft_references(&memory, index), 4);
}

#[test]
fn forcedup_replaces_a_high_target_and_releases_only_its_old_reference() {
    let (mut dos, mut host, mut memory) = fixture();
    grow(&mut dos, &mut host, &mut memory, 300);
    let source = create_source(&mut dos, &mut host, &mut memory);
    let other = allocate(&mut dos, &mut host, &mut memory, Allocator::CreateNew, 1).ax();
    assert!(!forcedup(&mut dos, &mut host, &mut memory, other, 299).carry());
    let Handle::File(old) = dos.handles[&299] else { panic!("expected a file"); };
    publish(&mut dos, &mut host, &mut memory);
    let source_index = jft_entry(&memory, PSP, source);
    let other_index = jft_entry(&memory, PSP, other);
    assert_eq!(sft_references(&memory, other_index), 2);
    assert!(!forcedup(&mut dos, &mut host, &mut memory, source, 299).carry());
    assert!(!host.handles.contains_key(&old));
    assert_eq!(jft_entry(&memory, PSP, 299), source_index);
    assert_eq!(sft_references(&memory, source_index), 2);
    assert_eq!(sft_references(&memory, other_index), 1);
    let duplicates = host.duplicate_calls;
    let tokens = host.handles.clone();
    assert!(!forcedup(&mut dos, &mut host, &mut memory, 299, 299).carry());
    assert_eq!(host.duplicate_calls, duplicates);
    assert_eq!(host.handles, tokens);
}

#[test]
fn sft_exhaustion_is_independent_of_grown_jft_space_and_aliases_still_work() {
    let (mut dos, mut host, mut memory) = fixture();
    grow(&mut dos, &mut host, &mut memory, 512);
    create_source(&mut dos, &mut host, &mut memory);
    for expected in 4..255 {
        let regs = allocate(&mut dos, &mut host, &mut memory, Allocator::CreateNew, expected);
        assert!(!regs.carry());
        assert_eq!(regs.ax(), expected);
    }
    assert!(!dos.file_table.has_free_slot());
    let tokens = host.handles.clone();
    let next_id = host.next_id;
    let creates = host.create_new_calls;
    let extended = host.extended_open_calls.len();
    for allocator in ALLOCATORS.into_iter().filter(|kind| !matches!(kind, Allocator::Duplicate)) {
        let regs = allocate(&mut dos, &mut host, &mut memory, allocator, 600);
        assert!(regs.carry(), "{allocator:?} ignored exhausted SFT");
        assert_eq!(regs.ax(), DosErrorCode::TooManyOpenFiles as u16);
    }
    assert_eq!(host.handles, tokens);
    assert_eq!(host.next_id, next_id);
    assert_eq!(host.create_new_calls, creates);
    assert_eq!(host.extended_open_calls.len(), extended);

    let alias = duplicate(&mut dos, &mut host, &mut memory, 3);
    assert!(!alias.carry());
    assert_eq!(alias.ax(), 255);
    assert!(!forcedup(&mut dos, &mut host, &mut memory, 3, 511).carry());
    close(&mut dos, &mut host, &mut memory, 255);
    assert!(!dos.file_table.has_free_slot(), "closing an alias must retain its shared SFT");
    close(&mut dos, &mut host, &mut memory, 250);
    assert!(dos.file_table.has_free_slot());
    let created = allocate(&mut dos, &mut host, &mut memory, Allocator::CreateNew, 601);
    assert!(!created.carry());
    assert_eq!(created.ax(), 250);
    assert!(!dos.file_table.has_free_slot());
}

fn child_fixture() -> (DosKernel, DosKernel, TestHost, TestMemory, u16) {
    let (mut parent, mut host, mut memory) = fixture();
    grow(&mut parent, &mut host, &mut memory, 64);
    let child_psp = parent.allocate_child_process_block(&mut memory, 0x100).unwrap();
    install_jft(&mut memory, child_psp);
    let child = DosKernel::child_process(&mut parent, child_psp, &mut host).unwrap();
    (parent, child, host, memory, child_psp)
}

#[test]
fn exec_inherits_only_first_twenty_eligible_handles_without_host_or_sft_leaks() {
    let (mut parent, mut host, mut memory) = fixture();
    grow(&mut parent, &mut host, &mut memory, 300);
    create_source(&mut parent, &mut host, &mut memory);
    let mut no_inherit = Registers { ds: PSP, ..Default::default() };
    memory.put(real_address(PSP, PATH_OFFSET).0, b"SOURCE.DAT\0");
    no_inherit.set_ax(0x3d82);
    no_inherit.set_dx(PATH_OFFSET);
    interrupt(&mut parent, &mut host, &mut memory, &mut no_inherit);
    assert!(!no_inherit.carry());
    assert_eq!(no_inherit.ax(), 4);
    let high_only = allocate(&mut parent, &mut host, &mut memory, Allocator::CreateNew, 1);
    assert!(!high_only.carry());
    assert_eq!(high_only.ax(), 5);
    for (source, target) in [(3, 19), (3, 255), (5, 20)] {
        assert!(!forcedup(&mut parent, &mut host, &mut memory, source, target).carry());
    }
    close(&mut parent, &mut host, &mut memory, 5);
    publish(&mut parent, &mut host, &mut memory);
    let low_index = jft_entry(&memory, PSP, 3);
    let excluded_index = jft_entry(&memory, PSP, 4);
    let high_index = jft_entry(&memory, PSP, 20);
    assert_eq!(sft_references(&memory, low_index), 3);
    let parent_tokens = host.handles.clone();
    let duplicate_calls = host.duplicate_calls;
    let child_psp = parent.allocate_child_process_block(&mut memory, 0x100).unwrap();
    install_jft(&mut memory, child_psp);
    let mut child = DosKernel::child_process(&mut parent, child_psp, &mut host).unwrap();
    assert_eq!(child.jft_capacity, 20);
    assert_eq!(child.jft_owner_psp, child_psp);
    assert!(child.jft_storage.is_none());
    assert!(child.retired_jft_storage.is_empty());
    assert_eq!(child.handles.keys().copied().collect::<Vec<_>>(), [0, 1, 2, 3, 19]);
    assert_eq!(host.duplicate_calls - duplicate_calls, 2);
    assert_eq!(host.handles.len(), parent_tokens.len() + 2);
    child.refresh_system_tables(&mut memory, &mut host).unwrap();
    assert_eq!(jft_entry(&memory, child_psp, 4), 0xff);
    assert_eq!(jft_entry(&memory, child_psp, 19), low_index);
    assert_eq!(sft_references(&memory, low_index), 5);
    assert_eq!(sft_references(&memory, excluded_index), 1);
    assert_eq!(sft_references(&memory, high_index), 1);
    let calls = host.duplicate_calls;
    let outside = forcedup(&mut child, &mut host, &mut memory, 3, 20);
    assert!(outside.carry());
    assert_eq!(outside.ax(), DosErrorCode::InvalidHandle as u16);
    assert_eq!(host.duplicate_calls, calls);
    let alias = duplicate(&mut child, &mut host, &mut memory, 3);
    assert!(!alias.carry());
    assert_eq!(alias.ax(), 4, "the omitted no-inherit slot is immediately reusable");

    child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
    assert_eq!(host.handles, parent_tokens);
    parent.refresh_system_tables(&mut memory, &mut host).unwrap();
    assert_eq!(sft_references(&memory, low_index), 3);
    assert_eq!(sft_references(&memory, excluded_index), 1);
    assert_eq!(sft_references(&memory, high_index), 1);
    assert_eq!(parent.jft_capacity, 300);
}

#[test]
fn failed_exec_inheritance_rolls_back_only_eligible_duplicates_and_references() {
    let (mut parent, mut host, mut memory) = fixture();
    grow(&mut parent, &mut host, &mut memory, 300);
    create_source(&mut parent, &mut host, &mut memory);
    for target in [19, 20, 255] {
        assert!(!forcedup(&mut parent, &mut host, &mut memory, 3, target).carry());
    }
    publish(&mut parent, &mut host, &mut memory);
    let index = jft_entry(&memory, PSP, 3);
    let parent_tokens = host.handles.clone();
    let before = host.duplicate_calls;
    host.fail_duplicate_at = Some(before + 2);
    let child_psp = parent.allocate_child_process_block(&mut memory, 0x100).unwrap();
    install_jft(&mut memory, child_psp);
    let failure = DosKernel::child_process(&mut parent, child_psp, &mut host).unwrap_err();
    let (mut child, error) = failure.into_parts();
    assert!(matches!(error, DosError::HostOperation(error) if error.code == DosErrorCode::AccessDenied));
    assert_eq!(host.duplicate_calls - before, 2);
    assert_eq!(host.handles, parent_tokens);
    assert!(child.orphan_file_handles.is_empty());
    child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
    parent.refresh_system_tables(&mut memory, &mut host).unwrap();
    assert_eq!(sft_references(&memory, index), 4);
    assert_eq!(host.handles, parent_tokens);
}

#[test]
fn child_finish_and_abort_release_grown_jft_before_owned_process_blocks() {
    for finish in [false, true] {
        let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
        let parent_storage = parent.jft_storage.as_ref().unwrap().extent();
        parent.last_exit_code = 0x33;
        grow(&mut child, &mut host, &mut memory, 300);
        let old_storage = child.jft_storage.as_ref().unwrap().extent();
        grow(&mut child, &mut host, &mut memory, 512);
        assert!(child.owned_block_extent(&mut memory, old_storage.data_segment(), child_psp).unwrap().is_none());
        let child_storage = child.jft_storage.as_ref().unwrap().extent();
        assert_eq!(child_storage.owner_psp_segment(), child_psp);
        child.allocate_owned_block(&mut memory, child_psp, 0x20).unwrap();
        child.pending_input = Some(b'Q');
        // Current PSP can change independently of the process allocation
        // owner. Cleanup must still release this child's JFT and blocks.
        child.psp_segment = PSP;
        if finish {
            child.finish_child_process(&mut parent, &mut memory, &mut host, 7, child_psp).unwrap();
        } else {
            child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
        }
        assert!(child.jft_storage.is_none());
        assert!(child.retired_jft_storage.is_empty());
        assert!(child.mcb_chain(&mut memory).unwrap().iter().all(|mcb| mcb.owner() != child_psp));
        assert!(parent.owned_block_extent(&mut memory, parent_storage.data_segment(), PSP).unwrap().is_some());
        assert_eq!(parent.jft_capacity, 64);
        assert_eq!(parent.pending_input, Some(b'Q'));
        assert_eq!(parent.last_exit_code, if finish { 7 } else { 0x33 });
    }
}

#[test]
fn child_failed_host_close_keeps_jft_and_process_allocations_until_retry() {
    let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
    grow(&mut child, &mut host, &mut memory, 300);
    let file = allocate(&mut child, &mut host, &mut memory, Allocator::CreateNew, 1);
    assert!(!file.carry());
    let storage = child.jft_storage.as_ref().unwrap().extent();
    let tokens = host.handles.clone();
    parent.last_exit_code = 0x33;
    child.pending_input = Some(b'R');
    host.file_close_error = Some(DosErrorCode::AccessDenied);
    assert!(matches!(
        child.finish_child_process(&mut parent, &mut memory, &mut host, 7, child_psp),
        Err(DosError::HostOperation(error)) if error.code == DosErrorCode::AccessDenied
    ));
    assert_eq!(host.handles, tokens);
    assert!(child.handles.contains_key(&file.ax()));
    assert!(child.jft_storage.is_some());
    assert!(child.owned_block_extent(&mut memory, storage.data_segment(), child_psp).unwrap().is_some());
    assert!(child.owned_block_extent(&mut memory, child_psp, child_psp).unwrap().is_some());
    assert_eq!(parent.last_exit_code, 0x33);
    assert_eq!(parent.pending_input, None);
    assert_eq!(child.pending_input, Some(b'R'));
    host.file_close_error = None;
    child.finish_child_process(&mut parent, &mut memory, &mut host, 7, child_psp).unwrap();
    assert!(host.handles.is_empty());
    assert!(child.jft_storage.is_none());
    assert!(child.mcb_chain(&mut memory).unwrap().iter().all(|mcb| mcb.owner() != child_psp));
    assert_eq!(parent.last_exit_code, 7);
    assert_eq!(parent.pending_input, Some(b'R'));
}

#[test]
fn child_failed_jft_release_retains_lease_and_process_blocks_until_retry() {
    let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
    grow(&mut child, &mut host, &mut memory, 300);
    let storage = child.jft_storage.take().unwrap();
    let extent = storage.extent();
    let extra_pin = child.retain_block_lease(&mut memory, &storage).unwrap();
    child.jft_storage = Some(storage);
    parent.last_exit_code = 0x33;
    child.pending_input = Some(b'S');
    assert!(child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).is_err());
    assert!(child.handles.is_empty());
    assert!(child.jft_storage.is_some());
    assert!(child.owned_block_extent(&mut memory, extent.data_segment(), child_psp).unwrap().is_some());
    assert!(child.owned_block_extent(&mut memory, child_psp, child_psp).unwrap().is_some());
    assert_eq!(parent.pending_input, None);
    assert_eq!(child.pending_input, Some(b'S'));
    child.release_block_lease(&mut memory, &extra_pin, false).unwrap();
    child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
    assert!(child.jft_storage.is_none());
    assert!(child.mcb_chain(&mut memory).unwrap().iter().all(|mcb| mcb.owner() != child_psp));
    assert_eq!(parent.last_exit_code, 0x33);
    assert_eq!(parent.pending_input, Some(b'S'));
}

#[test]
fn replaced_jft_release_failure_retains_both_allocations_for_checked_teardown() {
    let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
    grow(&mut child, &mut host, &mut memory, 300);
    let old = child.jft_storage.take().unwrap();
    let old_extent = old.extent();
    let extra_pin = child.retain_block_lease(&mut memory, &old).unwrap();
    child.jft_storage = Some(old);
    let mut regs = Registers::default();
    regs.set_ax(0x6700);
    regs.set_bx(512);
    assert!(matches!(
        child.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    // Publication succeeded before retirement encountered the independent
    // pin. The new table stays current; the old allocation stays tracked.
    assert_eq!(child.jft_capacity, 512);
    let current = child.jft_storage.as_ref().unwrap().extent();
    assert_ne!(current.data_segment(), old_extent.data_segment());
    assert_eq!(memory.read_u16(real_address(child_psp, 0x32)).unwrap(), 512);
    assert_eq!(memory.read_u16(real_address(child_psp, 0x36)).unwrap(), current.data_segment());
    assert_eq!(child.retired_jft_storage.len(), 1);
    assert_eq!(child.retired_jft_storage[0].extent(), old_extent);
    assert!(child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).is_err());
    assert!(child.jft_storage.is_some());
    assert_eq!(child.retired_jft_storage.len(), 1);
    for segment in [child_psp, old_extent.data_segment(), current.data_segment()] {
        assert!(child.owned_block_extent(&mut memory, segment, child_psp).unwrap().is_some());
    }
    child.release_block_lease(&mut memory, &extra_pin, false).unwrap();
    child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
    assert!(child.jft_storage.is_none());
    assert!(child.retired_jft_storage.is_empty());
    assert!(child.mcb_chain(&mut memory).unwrap().iter().all(|mcb| mcb.owner() != child_psp));
    assert!(parent.jft_storage.is_some());
}

#[test]
fn each_dos_exit_releases_grown_jft_before_runtime_frees_process_blocks() {
    for (number, function, code) in [(0x20, 0, 0), (0x21, 0, 0), (0x21, 0x4c09, 9)] {
        let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
        grow(&mut child, &mut host, &mut memory, 300);
        let opened = allocate(&mut child, &mut host, &mut memory, Allocator::CreateNew, 1);
        assert!(!opened.carry());
        let storage = child.jft_storage.as_ref().unwrap().extent();
        let mut regs = Registers::default();
        regs.set_ax(function);
        assert_eq!(
            child.interrupt(number, &mut regs, &mut memory, &mut host).unwrap(),
            DosAction::Exit(code)
        );
        assert!(child.handles.is_empty());
        assert!(host.handles.is_empty());
        assert!(child.jft_storage.is_none());
        assert!(child.owned_block_extent(&mut memory, storage.data_segment(), child_psp).unwrap().is_none());
        assert!(child.owned_block_extent(&mut memory, child_psp, child_psp).unwrap().is_some());
        child.finish_child_process(&mut parent, &mut memory, &mut host, code, child_psp).unwrap();
        assert!(child.mcb_chain(&mut memory).unwrap().iter().all(|mcb| mcb.owner() != child_psp));
        assert_eq!(parent.last_exit_code, code);
    }
}

#[test]
fn same_capacity_retry_finishes_retirement_without_replacing_published_jft() {
    let (mut parent, mut child, mut host, mut memory, child_psp) = child_fixture();
    grow(&mut child, &mut host, &mut memory, 300);
    let old = child.jft_storage.take().unwrap();
    let old_extent = old.extent();
    let extra_pin = child.retain_block_lease(&mut memory, &old).unwrap();
    child.jft_storage = Some(old);
    let mut regs = Registers::default();
    regs.set_ax(0x6700);
    regs.set_bx(512);
    assert!(matches!(
        child.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(child.jft_capacity, 512);
    assert_eq!(child.retired_jft_storage.len(), 1);
    assert_eq!(child.retired_jft_storage[0].extent(), old_extent);
    let current = child.jft_storage.as_ref().unwrap().extent();
    let mut header = [0; 6];
    memory.read(real_address(child_psp, 0x32), &mut header).unwrap();
    assert_eq!(u16::from_le_bytes([header[0], header[1]]), 512);
    assert_eq!(u16::from_le_bytes([header[4], header[5]]), current.data_segment());
    // Hold another pin on the published table. A correct same-count retry
    // never replaces or retires this allocation, even while draining the old one.
    let published = child.jft_storage.take().unwrap();
    let current_pin = child.retain_block_lease(&mut memory, &published).unwrap();
    child.jft_storage = Some(published);
    child.release_block_lease(&mut memory, &extra_pin, false).unwrap();

    grow(&mut child, &mut host, &mut memory, 512);

    assert!(child.retired_jft_storage.is_empty());
    assert_eq!(child.jft_storage.as_ref().unwrap().extent(), current);
    let mut after = [0; 6];
    memory.read(real_address(child_psp, 0x32), &mut after).unwrap();
    assert_eq!(after, header);
    assert!(child.owned_block_extent(&mut memory, old_extent.data_segment(), child_psp).unwrap().is_none());
    assert_eq!(child.owned_block_extent(&mut memory, current.data_segment(), child_psp).unwrap(), Some(current));
    child.release_block_lease(&mut memory, &current_pin, false).unwrap();
    child.abort_child_process(&mut parent, &mut memory, &mut host, child_psp).unwrap();
}
