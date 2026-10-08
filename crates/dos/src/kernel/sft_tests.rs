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
    assert!(!table.can_duplicate_handle(0, 255)); // FF is the closed JFT marker

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
