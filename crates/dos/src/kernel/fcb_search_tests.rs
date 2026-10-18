//! Guest-visible FCB continuation and packed directory records.
use super::*;

const FCB: u16 = 0x100;
const DTA: u16 = 0x400;

fn fcb(pattern: &[u8; 11], attributes: Option<u8>) -> Vec<u8> {
    let skip = usize::from(attributes.is_some()) * 7;
    let mut bytes = vec![0xcc; skip + 37];
    if let Some(attributes) = attributes {
        bytes[..7].fill(0x99);
        bytes[0] = 0xff;
        bytes[6] = attributes;
    }
    bytes[skip] = 0;
    bytes[skip + 1..skip + 12].copy_from_slice(pattern);
    bytes
}

fn registers(ah: u8) -> Registers {
    Registers {
        eax: 0xaabb_0007 | (u32::from(ah) << 8),
        ebx: 0xbbcc_1234,
        ecx: 0xccdd_2345,
        edx: 0xddee_0100,
        esi: 0xeeff_3456,
        edi: 0xffaa_4567,
        ds: 0x1000,
        es: 0x1234,
        eflags: 0xad57,
        ..Default::default()
    }
}

fn fixture(pattern: &[u8; 11], attributes: Option<u8>) -> (DosKernel, TestHost, TestMemory) {
    let mut host = TestHost::default();
    host.drive = 2;
    for (name, contents, attributes) in [
        (b"A.TXT".as_slice(), b"aa".as_slice(), 0x20),
        (b"B.TXT", b"bbbbb", 0),
        (b"H.TXT", b"hide", 2),
        (b"S.TXT", b"sys", 4),
    ] {
        let file = host.file_create(name, attributes).unwrap();
        host.file_write(file, contents).unwrap();
        host.file_close(file).unwrap();
    }
    host.directories.insert(b"SUB".to_vec(), ());
    let mut memory = TestMemory::new();
    memory.put(0x10100, &fcb(pattern, attributes));
    memory.put(0x103ff, &[0xa5; 49]);
    let mut dos = DosKernel::new(0x1000);
    let mut regs = registers(0x1a);
    regs.set_dx(DTA);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    (dos, host, memory)
}

fn call(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, ah: u8, status: u8) {
    let mut regs = registers(ah);
    let mut expected = regs.clone();
    expected.set_al(status);
    assert_eq!(
        dos.interrupt(0x21, &mut regs, memory, host).unwrap(),
        DosAction::Continue
    );
    assert_eq!(regs, expected); // Only AL is the FCB result, including on EOF.
}

fn output(memory: &TestMemory, skip: usize, name: &[u8; 11], size: u32, attributes: u8) {
    let mut bytes = [0; 49];
    memory
        .read(guest_core::real_address(0x1000, DTA - 1), &mut bytes)
        .unwrap();
    assert_eq!(bytes[0], 0xa5);
    let result = &bytes[1..1 + skip + 33];
    if skip != 0 {
        assert_eq!(&result[..6], &[0xff, 0, 0, 0, 0, 0]);
    }
    assert_eq!(result[skip], 3);
    assert_eq!(&result[skip + 1..skip + 12], name);
    assert_eq!(result[skip + 12], attributes);
    assert_eq!(&result[skip + 29..skip + 33], &size.to_le_bytes());
    assert_eq!(&bytes[1 + skip + 33..], &vec![0xa5; 48 - skip - 33]);
}

#[test]
fn fcb_search_normal_first_next_eof_preserve_registers_and_exact_output() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", None);
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    output(&memory, 0, b"A       TXT", 2, 0x20);
    let mut pattern = [0; 12];
    memory
        .read(guest_core::real_address(0x1000, FCB), &mut pattern)
        .unwrap();
    assert_eq!(&pattern, b"\0?       TXT");
    let mut tail = [0; 15];
    memory
        .read(guest_core::real_address(0x1000, FCB + 22), &mut tail)
        .unwrap();
    assert_eq!(tail, [0xcc; 15]);
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    output(&memory, 0, b"B       TXT", 5, 0);
    call(&mut dos, &mut host, &mut memory, 0x12, 0xff);
    output(&memory, 0, b"B       TXT", 5, 0);
    assert_eq!(
        (host.search_open_calls.len(), host.search_close_calls.len()),
        (1, 1)
    );
    assert!(host.searches.is_empty());
    let mut regs = registers(0x59);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(regs.ax(), 18);
}

#[test]
fn fcb_search_copied_positions_survive_exhaustion_restart_and_directory_change() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", None);
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    let mut saved = [0; 22];
    memory
        .read(guest_core::real_address(0x1000, FCB), &mut saved)
        .unwrap();
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    call(&mut dos, &mut host, &mut memory, 0x12, 0xff);
    memory.put(0x10100, &fcb(b"H       TXT", Some(2)));
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    host.current_directories.insert(2, b"OTHER".to_vec());
    host.paths.clear();
    memory.put(0x10100, &saved);
    memory.put(0x103ff, &[0xa5; 49]);
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    // The original immutable directory enumeration is still the source.
    output(&memory, 0, b"B       TXT", 5, 0);
}

#[test]
fn fcb_search_extended_attributes_and_changing_masks_use_the_current_header() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", Some(2));
    for (ah, name, size, attributes) in [
        (0x11, b"A       TXT", 2, 0x20),
        (0x12, b"B       TXT", 5, 0),
        (0x12, b"H       TXT", 4, 2),
    ] {
        call(&mut dos, &mut host, &mut memory, ah, 0);
        output(&memory, 7, name, size, attributes);
    }
    memory.put(0x10106, &[6]);
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    output(&memory, 7, b"S       TXT", 3, 4);
    let mut header = [0; 7];
    memory
        .read(guest_core::real_address(0x1000, DTA), &mut header)
        .unwrap();
    assert_eq!(header, [0xff, 0, 0, 0, 0, 0, 6]);
}

#[test]
fn fcb_search_missing_and_volume_only_do_not_publish_an_input_cookie() {
    for (pattern, attributes) in [(b"MISSING TXT", None), (b"???????????", Some(8))] {
        let (mut dos, mut host, mut memory) = fixture(pattern, attributes);
        let expected = fcb(pattern, attributes);
        call(&mut dos, &mut host, &mut memory, 0x11, 0xff);
        let mut bytes = vec![0; expected.len()];
        memory
            .read(guest_core::real_address(0x1000, FCB), &mut bytes)
            .unwrap();
        assert_eq!(bytes, expected);
        let mut bytes = [0; 48];
        memory
            .read(guest_core::real_address(0x1000, DTA), &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0xa5; 48]);
        assert!(host.searches.is_empty());
    }
}

#[test]
fn fcb_search_bad_destination_does_not_consume_the_copied_continuation() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", None);
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    dos.dta_segment = 0x1fff;
    dos.dta_offset = 15;
    let mut regs = registers(0x12);
    let before = regs.clone();
    assert!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .is_err()
    );
    assert_eq!(regs, before);
    dos.dta_segment = 0x1000;
    dos.dta_offset = DTA;
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    output(&memory, 0, b"B       TXT", 5, 0);
}

#[test]
fn fcb_search_snapshots_are_psp_owned_and_teardown_invalidates_cookies() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", None);
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    dos.psp_segment = 0x1100;
    call(&mut dos, &mut host, &mut memory, 0x12, 0xff);
    dos.psp_segment = 0x1000;
    call(&mut dos, &mut host, &mut memory, 0x12, 0);
    dos.close_searches_for_psp_checked(0x1000, &mut host)
        .unwrap();
    call(&mut dos, &mut host, &mut memory, 0x12, 0xff);
}

#[test]
fn fcb_search_close_failure_retains_native_identity_until_checked_cleanup() {
    let (mut dos, mut host, mut memory) = fixture(b"?       TXT", None);
    host.search_close_error = Some(DosErrorCode::AccessDenied);
    call(&mut dos, &mut host, &mut memory, 0x11, 0xff);
    assert_eq!(host.searches.len(), 1);
    assert!(dos.close_all_searches_checked(&mut host).is_err());
    assert_eq!(host.searches.len(), 1);
    host.search_close_error = None;
    dos.close_all_searches_checked(&mut host).unwrap();
    assert!(host.searches.is_empty());
}

#[test]
fn fcb_search_oem_names_preserve_dbcs_trail_syntax() {
    for (page, raw, field) in [
        (
            text_codec::CodePage::Cp437,
            b"\x81a.txt".as_slice(),
            b"\x81A      TXT".as_slice(),
        ),
        (
            text_codec::CodePage::Cp936,
            b"\x81\\a.txt",
            b"\x81\\A     TXT",
        ),
    ] {
        let (mut dos, mut host, mut memory) = fixture(field.try_into().unwrap(), None);
        host.code_page = Some(page);
        host.search_entries_override = Some(vec![DosDirectoryEntry {
            short_name: raw.to_vec(),
            attributes: 0,
            write_time: 0,
            write_date: 0,
            size: 0,
        }]);
        call(&mut dos, &mut host, &mut memory, 0x11, 0);
        let expected: &[u8; 11] = if page == text_codec::CodePage::Cp437 {
            b"\x9aA      TXT"
        } else {
            b"\x81\\A     TXT"
        };
        output(&memory, 0, expected, 0, 0);
    }
}

#[test]
fn fcb_search_packed_directory_metadata_has_native_field_offsets() {
    let (mut dos, mut host, mut memory) = fixture(b"A       TXT", None);
    memory.put(0x10100, &[3]);
    host.search_entries_override = Some(vec![DosDirectoryEntry {
        short_name: b"A.TXT".to_vec(),
        attributes: 0x21,
        write_time: 0x7bcd,
        write_date: 0x56a7,
        size: 0x1234_5678,
    }]);
    call(&mut dos, &mut host, &mut memory, 0x11, 0);
    let mut record = [0; 33];
    memory
        .read(guest_core::real_address(0x1000, DTA), &mut record)
        .unwrap();
    assert_eq!(&record[..13], b"\x03A       TXT\x21");
    assert_eq!(&record[13..23], &[0; 10]);
    assert_eq!(&record[23..27], &[0xcd, 0x7b, 0xa7, 0x56]);
    assert_eq!(&record[27..29], &[0, 0]);
    assert_eq!(&record[29..], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn fcb_search_real_mode_fcb_and_dta_wrap_within_their_segments() {
    let (mut dos, mut host, mut memory) = fixture(b"A       TXT", None);
    let input = fcb(b"A       TXT", None);
    memory.put(0x1fff8, &input[..8]);
    memory.put(0x10000, &input[8..22]);
    memory.put(0x17ff0, &[0xa5; 16]);
    memory.put(0x8000, &[0xa5; 24]);
    dos.dta_segment = 0x0800;
    dos.dta_offset = 0xfff0;
    let mut regs = registers(0x11);
    regs.set_dx(0xfff8);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(regs.al(), 0);
    let mut record = [0; 33];
    memory.read(PhysAddr(0x17ff0), &mut record[..16]).unwrap();
    memory.read(PhysAddr(0x8000), &mut record[16..]).unwrap();
    assert_eq!(&record[..12], b"\x03A       TXT");
    assert_eq!(&record[29..], &[2, 0, 0, 0]);
    let mut guard = [0; 7];
    memory.read(PhysAddr(0x8011), &mut guard).unwrap();
    assert_eq!(guard, [0xa5; 7]);
}

#[test]
fn fcb_search_bad_first_ranges_precede_native_enumeration() {
    for bad_input in [false, true] {
        let (mut dos, mut host, mut memory) = fixture(b"A       TXT", None);
        let mut regs = registers(0x11);
        if bad_input {
            regs.ds = 0x1fff;
            regs.set_dx(15);
        } else {
            dos.dta_segment = 0x1fff;
            dos.dta_offset = 15;
        }
        let before = regs.clone();
        assert!(
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
                .is_err()
        );
        assert_eq!(regs, before);
        assert!(host.search_open_calls.is_empty());
    }
}

#[test]
fn fcb_search_read_errors_and_invalid_host_entries_keep_ownership() {
    for invalid_entry in [false, true] {
        let (mut dos, mut host, mut memory) = fixture(b"???????????", None);
        if invalid_entry {
            host.search_entries_override = Some(vec![DosDirectoryEntry {
                short_name: b"TOO-LONG-NAME.TXT".to_vec(),
                attributes: 0,
                write_time: 0,
                write_date: 0,
                size: 0,
            }]);
            let mut regs = registers(0x11);
            let before = regs.clone();
            assert!(matches!(
                dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
                Err(DosError::HostContractViolation(_))
            ));
            assert_eq!(regs, before);
        } else {
            host.search_next_error = Some(DosErrorCode::SharingViolation);
            call(&mut dos, &mut host, &mut memory, 0x11, 0xff);
        }
        assert!(host.searches.is_empty());
        assert!(dos.searches.is_empty());
    }
}
