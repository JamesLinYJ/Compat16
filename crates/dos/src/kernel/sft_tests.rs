use super::super::state::DosKernel;
use super::super::system::{CON_HEADER_OFFSET, SFT_OFFSET, SYSTEM_SEGMENT};
use super::super::tests::{TestHost, TestMemory};
use super::{FileTable, SftEntry};
use guest_core::{GuestMemory, real_address};

// DOS 4 SF.INC: a six-byte list header followed by 59-byte SFT records.
const DOS4_SFT_HEADER_BYTES: usize = 6;
const DOS4_SFT_ENTRY_BYTES: usize = 59;
const PSP_JFT_INLINE_OFFSET: u16 = 0x18;
const PSP_JFT_COUNT_OFFSET: u16 = 0x32;
const DEFAULT_JFT_ENTRIES: usize = 20;

fn install_default_jft(memory: &mut TestMemory, psp: u16) {
    let mut header = [0; 6];
    header[..2].copy_from_slice(&(DEFAULT_JFT_ENTRIES as u16).to_le_bytes());
    header[2..4].copy_from_slice(&PSP_JFT_INLINE_OFFSET.to_le_bytes());
    header[4..6].copy_from_slice(&psp.to_le_bytes());
    memory.put(real_address(psp, PSP_JFT_COUNT_OFFSET).0, &header);

    let mut entries = [0xff; DEFAULT_JFT_ENTRIES];
    entries[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(real_address(psp, PSP_JFT_INLINE_OFFSET).0, &entries);
}

fn sft_entry(memory: &impl GuestMemory, index: usize) -> [u8; DOS4_SFT_ENTRY_BYTES] {
    let offset = usize::from(SFT_OFFSET) + DOS4_SFT_HEADER_BYTES + index * DOS4_SFT_ENTRY_BYTES;
    let mut bytes = [0; DOS4_SFT_ENTRY_BYTES];
    memory
        .read(real_address(SYSTEM_SEGMENT, offset as u16), &mut bytes)
        .expect("SFT entry is inside the installed guest system block");
    bytes
}

#[test]
fn refresh_publishes_sft_header_standard_devices_and_psp_jft() {
    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_default_jft(&mut memory, psp);
    dos.initialize_system_tables(&mut memory).unwrap();

    dos.refresh_system_tables(&mut memory, &mut host).unwrap();

    let header = real_address(SYSTEM_SEGMENT, SFT_OFFSET);
    let mut list_header = [0; DOS4_SFT_HEADER_BYTES];
    memory.read(header, &mut list_header).unwrap();
    assert_eq!(&list_header[..4], &[0xff; 4]);
    assert_eq!(u16::from_le_bytes([list_header[4], list_header[5]]), 255);

    let mut jft = [0; DEFAULT_JFT_ENTRIES];
    memory
        .read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft)
        .unwrap();
    assert_eq!(&jft[..3], &[0, 1, 2]);
    assert!(jft[3..].iter().all(|entry| *entry == 0xff));

    let input = sft_entry(&memory, 0);
    assert_eq!(u16::from_le_bytes([input[0], input[1]]), 1);
    assert_eq!(u16::from_le_bytes([input[2], input[3]]), 0);
    // Device, no EOF, raw mode, and standard-input capability.
    assert_eq!(u16::from_le_bytes([input[5], input[6]]), 0x00e1);
    assert_eq!(&input[7..11], &[CON_HEADER_OFFSET as u8, 0, 0, 0x08]);
    assert_eq!(&input[32..43], b"CON        ");

    for index in [1, 2] {
        let output = sft_entry(&memory, index);
        assert_eq!(u16::from_le_bytes([output[0], output[1]]), 1);
        assert_eq!(u16::from_le_bytes([output[2], output[3]]), 1);
        // Device, no EOF, raw mode, and standard-output capability.
        assert_eq!(u16::from_le_bytes([output[5], output[6]]), 0x00e2);
        assert_eq!(&output[7..11], &[CON_HEADER_OFFSET as u8, 0, 0, 0x08]);
        assert_eq!(&output[32..43], b"CON        ");
    }
}

#[test]
fn duplicate_and_forceduplicate_share_sft_and_replace_old_target_reference() {
    let mut table = FileTable::new();
    assert!(table.duplicate_handle(0, 5));
    assert!(table.duplicate_handle(5, 1));

    assert_eq!(table.index_for_handle(0), Some(0));
    assert_eq!(table.index_for_handle(1), Some(0));
    assert_eq!(table.index_for_handle(5), Some(0));
    let entries = table.entries_snapshot();
    assert_eq!(entries.len(), 2); // input's SFT and the still-open error SFT
    assert_eq!(entries[0].0, 0);
    assert_eq!(entries[0].1.references, 3);
    assert_eq!(entries[1].0, 2);
    assert_eq!(entries[1].1.references, 1);
    assert!(table.can_duplicate_handle(0, 5)); // same SFT alias is already installed
    assert!(table.can_duplicate_handle(0, 255)); // WORD handle, independent of its byte SFT index
    assert!(!table.can_duplicate_handle(0, 0xfffe)); // largest count has slots 0..FFFEh

    let input = match entries[0].1 {
        SftEntry { kind: super::SftKind::Standard(kind), .. } => kind,
        _ => panic!("standard input remains a standard SFT object"),
    };
    assert_eq!(input, super::super::state::StandardHandle::Input);
}

#[test]
fn inherited_jft_adds_shared_sft_references_and_close_releases_them() {
    let parent = DosKernel::new(0x1000);
    let mut child = DosKernel::new(0x1100);
    let mut host = TestHost::default();

    child.inherit_handles_from(&parent, &mut host).unwrap();
    let inherited = parent.file_table.entries_snapshot();
    assert_eq!(inherited.len(), 3);
    assert!(inherited.iter().all(|(_, entry)| entry.references == 2));

    child.close_all_handles(&mut host);
    let remaining = parent.file_table.entries_snapshot();
    assert_eq!(remaining.len(), 3);
    assert!(remaining.iter().all(|(_, entry)| entry.references == 1));
}

#[test]
fn invalid_psp_jft_is_rejected_before_sft_or_jft_mutation() {
    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut memory = TestMemory::new();
    install_default_jft(&mut memory, psp);
    dos.initialize_system_tables(&mut memory).unwrap();
    dos.refresh_system_tables(&mut memory, &mut TestHost::default()).unwrap();

    let invalid_count = (DEFAULT_JFT_ENTRIES as u16 - 1).to_le_bytes();
    memory.put(real_address(psp, PSP_JFT_COUNT_OFFSET).0, &invalid_count);
    let mut sft_before = vec![0; DOS4_SFT_HEADER_BYTES + 255 * DOS4_SFT_ENTRY_BYTES];
    memory
        .read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut sft_before)
        .unwrap();
    let mut jft_before = [0; DEFAULT_JFT_ENTRIES];
    memory
        .read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_before)
        .unwrap();

    assert!(dos.validate_system_tables(&memory).is_err());

    let mut sft_after = vec![0; sft_before.len()];
    memory
        .read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut sft_after)
        .unwrap();
    let mut jft_after = [0; DEFAULT_JFT_ENTRIES];
    memory
        .read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_after)
        .unwrap();
    assert_eq!(sft_after, sft_before);
    assert_eq!(jft_after, jft_before);
}

fn old_representatives(
    table: &FileTable,
    handles: &std::collections::BTreeMap<u16, super::Handle>,
) -> [Option<super::Handle>; super::SFT_ENTRY_COUNT] {
    let mut representatives = [None; super::SFT_ENTRY_COUNT];
    for (index, _) in table.entries_snapshot() {
        representatives[usize::from(index)] = handles.iter().find_map(|(&guest, &handle)| {
            (table.index_for_handle(guest) == Some(index)).then_some(handle)
        });
    }
    representatives
}

#[test]
fn representatives_match_old_selection_for_sparse_aliases_and_missing_records() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    // Deliberately include a mapped index without a pool record, an unmapped
    // DOS handle, and a mapping without a DOS handle. Selection does not repair
    // or diagnose any of these; refresh retains its existing checks.
    table.handles = BTreeMap::from([(4, 2), (20, 2), (1000, 254), (0xfffd, 2), (10, 10), (11, 11)]);
    table.pool().entries[254] = Some(SftEntry::file(2));
    let handles = BTreeMap::from([
        (0xfffd, Handle::File(DosHostFile(1))),
        (1000, Handle::File(DosHostFile(2))),
        (20, Handle::File(DosHostFile(3))),
        (4, Handle::File(DosHostFile(4))),
        (3, Handle::File(DosHostFile(5))),
        (10, Handle::File(DosHostFile(6))),
    ]);
    let actual = table.representatives(&table.entries_snapshot(), handles.iter().map(|(&guest, &handle)| (guest, handle)));
    assert_eq!(actual, old_representatives(&table, &handles));
    assert_eq!(actual[2], Some(Handle::File(DosHostFile(4))));
    assert_eq!(actual[254], Some(Handle::File(DosHostFile(2))));
    assert_eq!(actual[10], None);
}

#[test]
fn representatives_stop_before_trailing_aliases_once_live_slots_are_found() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    let handles: BTreeMap<_, _> = (0..1024u16)
        .map(|guest| (guest, Handle::File(DosHostFile(u64::from(guest)))))
        .collect();
    table.handles.extend((3..1024u16).map(|guest| (guest, 0)));
    let mut visits = 0;
    let actual = table.representatives(&table.entries_snapshot(), handles.iter().map(|(&guest, &handle)| {
        visits += 1;
        (guest, handle)
    }));
    assert_eq!(actual, old_representatives(&table, &handles));
    assert_eq!(visits, 3);
}

#[test]
fn representatives_ignore_stale_slots_when_counting_live_targets() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    table.clear();
    assert_eq!(table.register_open(9, 2), Some(0));
    table.handles.insert(3, 10); // Earlier mapping to an absent pool record.
    let handles = BTreeMap::from([
        (3, Handle::File(DosHostFile(3))),
        (9, Handle::File(DosHostFile(9))),
    ]);
    let mut visits = 0;
    let actual = table.representatives(&table.entries_snapshot(), handles.iter().map(|(&guest, &handle)| {
        visits += 1;
        (guest, handle)
    }));
    assert_eq!(actual, old_representatives(&table, &handles));
    assert_eq!(actual[0], Some(Handle::File(DosHostFile(9))));
    assert_eq!(actual[10], None);
    assert_eq!(visits, 2);
}

#[test]
fn representatives_skip_handles_when_no_live_records_exist() {
    let mut table = FileTable::new();
    table.clear();
    let handles = std::iter::from_fn(|| -> Option<(u16, super::Handle)> {
        panic!("empty SFT must not inspect DOS handles");
    });
    assert_eq!(table.representatives(&table.entries_snapshot(), handles),
        [None; super::SFT_ENTRY_COUNT]);
}

#[test]
fn representatives_ignore_out_of_range_sft_index() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    table.handles.insert(7, 0xff);
    let handles = BTreeMap::from([(7, Handle::File(DosHostFile(7)))]);
    let actual = table.representatives(&table.entries_snapshot(), handles.iter().map(|(&guest, &handle)| (guest, handle)));
    // Remove the intentionally corrupt test mapping before normal drop cleanup.
    table.handles.remove(&7);
    assert_eq!(actual, [None; super::SFT_ENTRY_COUNT]);
}

#[test]
fn representatives_visit_each_handle_once_instead_of_once_per_sft_search() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    let handles: BTreeMap<_, _> = (0..1024u16)
        .map(|guest| (guest, Handle::File(DosHostFile(u64::from(guest)))))
        .collect();
    table.handles = handles.keys().map(|&guest| (guest, 0)).collect();
    table.handles.insert(1023, 254);
    // Shared SFT records can remain live without a handle in this process.
    table.pool().entries.fill(Some(SftEntry::file(2)));
    assert_eq!(table.entries_snapshot().len(), super::SFT_ENTRY_COUNT);
    let mut new_visits = 0usize;
    let actual = table.representatives(&table.entries_snapshot(), handles.iter().map(|(&guest, &handle)| {
        new_visits += 1;
        (guest, handle)
    }));
    let mut old_visits = 0usize;
    let expected: [Option<Handle>; super::SFT_ENTRY_COUNT] = std::array::from_fn(|index| {
        handles.iter().find_map(|(&guest, &handle)| {
            old_visits += 1;
            (table.index_for_handle(guest) == Some(index as u8)).then_some(handle)
        })
    });
    assert_eq!(actual, expected);
    assert_eq!(new_visits, handles.len());
    assert_eq!(old_visits, 1 + 254 * handles.len());
}

fn install_file_status(host: &mut TestHost, file: crate::DosHostFile) {
    host.set_file_status(file, crate::DosFileStatus {
        short_name: *b"FILE       ",
        size: 0,
        position: 0,
        attributes: 0,
        write_time: 0,
        write_date: 0,
    });
}

#[test]
fn refresh_uses_lowest_alias_and_queries_in_sft_order() {
    use super::Handle;
    use crate::DosHost;

    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_default_jft(&mut memory, psp);
    dos.initialize_system_tables(&mut memory).unwrap();
    let first = host.file_create(b"FIRST", 0).unwrap();
    let alias = host.file_duplicate(first).unwrap();
    let second = host.file_create(b"SECOND", 0).unwrap();
    install_file_status(&mut host, first);
    install_file_status(&mut host, second);
    assert_eq!(dos.file_table.register_open(18, 2), Some(3));
    assert!(dos.file_table.duplicate_handle(18, 7));
    assert_eq!(dos.file_table.register_open(4, 2), Some(4));
    dos.handles.insert(18, Handle::File(first));
    dos.handles.insert(7, Handle::File(alias));
    dos.handles.insert(4, Handle::File(second));

    // Guest-writable projections must never influence representative selection.
    memory.put(real_address(psp, PSP_JFT_INLINE_OFFSET).0, &[0xfe; DEFAULT_JFT_ENTRIES]);
    memory.put(real_address(SYSTEM_SEGMENT, SFT_OFFSET).0,
        &vec![0xa5; DOS4_SFT_HEADER_BYTES + super::SFT_ENTRY_COUNT * DOS4_SFT_ENTRY_BYTES]);
    dos.refresh_sft(&mut memory, &mut host).unwrap();

    use super::super::tests::SftQuery::{FileInfo, FileStatus, StandardInfo};
    use crate::DosIoctlStream::{Input, Output, Error};
    assert_eq!(host.sft_queries(), vec![
        StandardInfo(Input), StandardInfo(Output), StandardInfo(Error),
        FileInfo(alias), FileStatus(alias), FileInfo(second), FileStatus(second),
    ]);
    assert_eq!(host.sft_status_calls(), &[alias, second]);
    assert_eq!(u16::from_le_bytes(sft_entry(&memory, 3)[..2].try_into().unwrap()), 2);
    let mut jft = [0; DEFAULT_JFT_ENTRIES];
    memory.read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft).unwrap();
    assert_eq!((jft[7], jft[18], jft[4]), (3, 3, 4));
    assert_eq!(&jft[..3], &[0, 1, 2]);
    assert_eq!(jft[3], 0xff);
    assert_eq!(sft_entry(&memory, 5), [0; DOS4_SFT_ENTRY_BYTES]);
    let mut header = [0; DOS4_SFT_HEADER_BYTES];
    memory.read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut header).unwrap();
    assert_eq!(header, [0xff, 0xff, 0xff, 0xff, 0xff, 0]);
}

#[test]
fn refresh_preserves_missing_mapping_error_order_and_guest_bytes() {
    use super::Handle;
    use crate::{DosError, DosHost, DosHostFile};

    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    install_default_jft(&mut memory, psp);
    dos.initialize_system_tables(&mut memory).unwrap();
    dos.refresh_sft(&mut memory, &mut host).unwrap();
    let mut before = vec![0; DOS4_SFT_HEADER_BYTES + super::SFT_ENTRY_COUNT * DOS4_SFT_ENTRY_BYTES];
    memory.read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut before).unwrap();
    let mut jft_before = [0; DEFAULT_JFT_ENTRIES];
    memory.read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_before).unwrap();

    // A low unmapped DOS handle must not hide an earlier SFT kind error.
    dos.handles.insert(3, Handle::File(DosHostFile(999)));
    assert_eq!(dos.file_table.register_open(4, 2), Some(3));
    dos.handles.insert(4, Handle::Standard(super::StandardHandle::Input));
    assert!(matches!(dos.refresh_sft(&mut memory, &mut host),
        Err(DosError::HostContractViolation("JFT handle kind disagrees with its SFT entry"))));

    let file = host.file_create(b"VALID", 0).unwrap();
    install_file_status(&mut host, file);
    dos.handles.insert(4, Handle::File(file));
    assert!(dos.file_table.duplicate_handle(4, 5));
    // The dangling JFT mapping is checked before the unmapped DOS handle,
    // after querying valid records, exactly as in the original refresh.
    assert!(matches!(dos.refresh_sft(&mut memory, &mut host),
        Err(DosError::HostContractViolation("JFT mapping has no live DOS handle"))));
    assert_eq!(host.sft_status_calls(), &[file]);
    dos.file_table.remove_handle(5);
    assert!(matches!(dos.refresh_sft(&mut memory, &mut host),
        Err(DosError::HostContractViolation("DOS handle has no SFT mapping"))));
    assert_eq!(host.sft_status_calls(), &[file, file]);

    let mut after = vec![0; before.len()];
    memory.read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut after).unwrap();
    let mut jft_after = [0; DEFAULT_JFT_ENTRIES];
    memory.read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_after).unwrap();
    assert_eq!(after, before);
    assert_eq!(jft_after, jft_before);
}

#[test]
fn refresh_small_and_indexed_boundaries_preserve_query_order() {
    use super::Handle;
    use super::super::tests::SftQuery::{FileInfo, FileStatus};
    use crate::DosHost;

    for record_count in [0u16, 1, 3, 4] {
        let psp = 0x1000;
        let mut dos = DosKernel::new(psp);
        let mut memory = TestMemory::new();
        let mut host = TestHost::default();
        install_default_jft(&mut memory, psp);
        dos.initialize_system_tables(&mut memory).unwrap();
        dos.file_table.clear();
        dos.handles.clear();
        let mut expected = Vec::new();
        for index in 0..record_count {
            let file = host.file_create(&[b'A' + index as u8], 0).unwrap();
            install_file_status(&mut host, file);
            let guest = 9 - index; // Guest order is opposite to SFT order.
            assert_eq!(dos.file_table.register_open(guest, 2), Some(index as u8));
            dos.handles.insert(guest, Handle::File(file));
            expected.extend([FileInfo(file), FileStatus(file)]);
        }
        assert_eq!(dos.file_table.entries_snapshot().len(), usize::from(record_count));
        dos.refresh_sft(&mut memory, &mut host).unwrap();
        assert_eq!(host.sft_queries(), expected, "record count {record_count}");
    }
}

#[test]
fn refresh_both_selection_paths_stop_on_first_host_error() {
    use super::Handle;
    use super::super::tests::SftQuery::FileInfo;
    use crate::{DosError, DosErrorCode, DosHostFile};

    for record_count in [3u16, 4] {
        let psp = 0x1000;
        let mut dos = DosKernel::new(psp);
        let mut memory = TestMemory::new();
        let mut host = TestHost::default();
        install_default_jft(&mut memory, psp);
        dos.initialize_system_tables(&mut memory).unwrap();
        dos.file_table.clear();
        dos.handles.clear();
        // A lower unmapped handle cannot preempt the first host-query error.
        dos.handles.insert(0, Handle::File(DosHostFile(99)));
        for index in 0..record_count {
            let guest = 9 - index;
            assert_eq!(dos.file_table.register_open(guest, 2), Some(index as u8));
            dos.handles.insert(guest, Handle::File(DosHostFile(100 + u64::from(index))));
        }
        let mut before = vec![0; DOS4_SFT_HEADER_BYTES + super::SFT_ENTRY_COUNT * DOS4_SFT_ENTRY_BYTES];
        memory.read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut before).unwrap();
        let mut jft_before = [0; DEFAULT_JFT_ENTRIES];
        memory.read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_before).unwrap();

        assert!(matches!(dos.refresh_sft(&mut memory, &mut host),
            Err(DosError::HostOperation(error)) if error.code == DosErrorCode::InvalidHandle));
        assert_eq!(host.sft_queries(), vec![FileInfo(DosHostFile(100))]);
        let mut after = vec![0; before.len()];
        memory.read(real_address(SYSTEM_SEGMENT, SFT_OFFSET), &mut after).unwrap();
        let mut jft_after = [0; DEFAULT_JFT_ENTRIES];
        memory.read(real_address(psp, PSP_JFT_INLINE_OFFSET), &mut jft_after).unwrap();
        assert_eq!(after, before);
        assert_eq!(jft_after, jft_before);
    }
}

#[test]
fn direct_representatives_preserve_original_small_case_work() {
    use super::Handle;
    use crate::DosHostFile;
    use std::collections::BTreeMap;

    let mut table = FileTable::new();
    table.handles.extend((3..1024u16).map(|guest| (guest, 0)));
    let handles: BTreeMap<_, _> = (0..1024u16)
        .map(|guest| (guest, Handle::File(DosHostFile(u64::from(guest)))))
        .collect();
    let records = table.entries_snapshot();
    assert!(records.len() <= super::DIRECT_SFT_RECORD_LIMIT);
    let mut visits = 0;
    for (index, _) in records {
        let actual = table.representative(index, handles.iter().map(|(&guest, &handle)| {
            visits += 1;
            (guest, handle)
        }));
        assert_eq!(actual, Some(Handle::File(DosHostFile(u64::from(index)))));
    }
    assert_eq!(visits, 1 + 2 + 3);
}

#[path = "sft_bench_tests.rs"]
mod bench;
