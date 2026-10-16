//! AH=40h uses trusted open access before touching the buffer or file.

use super::*;
use super::super::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};

fn open_file(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, mode: u8,
) -> (u16, DosHostFile) {
    add_test_file(host, b"WRITE.DAT", 0, b"abc");
    memory.put(0x10100, b"WRITE.DAT\0");
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3d00 | u16::from(mode));
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(!regs.carry());
    let handle = regs.ax();
    let Handle::File(file) = dos.handles[&handle] else { panic!("expected file"); };
    assert_eq!(dos.file_table.file_open_mode(handle), Some(u16::from(mode)));
    (handle, file)
}

fn clear_io(host: &mut TestHost) {
    host.file_write_calls.clear();
    host.file_seek_calls.clear();
    host.file_set_len_calls.clear();
}

fn assert_no_io(host: &TestHost) {
    assert!(host.file_write_calls.is_empty());
    assert!(host.file_seek_calls.is_empty());
    assert!(host.file_set_len_calls.is_empty());
    assert!(host.stdout.is_empty());
    assert!(host.stderr.is_empty());
}

fn write(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    handle: u16, count: u16, invalid_buffer: bool, result: Result<u16, DosErrorCode>,
) {
    let mut regs = Registers {
        eax: 0xaaaa_4000, ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_0000 | u32::from(count),
        edx: 0xdddd_0000 | if invalid_buffer { 0xffff } else { 0x300 },
        esi: 0xeeee_1234, edi: 0xffff_5678, eflags: 0xad7,
        ds: if invalid_buffer { 0xffff } else { 0x1000 },
        es: 0x4321, ..Default::default()
    };
    let mut expected = regs.clone();
    expected.set_ax(match result { Ok(count) => count, Err(error) => error as u16 });
    expected.set_carry(result.is_err());
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
}

#[test]
fn readonly_write_denies_before_buffer_access_or_host_io() {
    for mode in [0, 0x40, 0xc0] {
        for count in [0, 1] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let (handle, file) = open_file(&mut dos, &mut host, &mut memory, mode);
            assert_eq!(host.last_open_access, Some(DosFileAccess::ReadOnly));
            host.file_for(file).unwrap().cursor = 1;
            clear_io(&mut host);
            let before = memory.0.clone();
            write(&mut dos, &mut host, &mut memory, handle, count, true, Err(DosErrorCode::AccessDenied));
            assert_no_io(&host);
            assert_eq!(memory.0, before);
            assert_eq!(host.file_for(file).unwrap().cursor, 1);
            assert_eq!(host.file_for(file).unwrap().bytes, b"abc");
            assert!(!host.file_for(file).unwrap().written);
        }
    }
}

#[test]
fn write_aliases_retain_access_after_original_closes_including_stdout() {
    for mode in [0, 1, 2, 0xc0, 0xc1, 0xc2] {
        for forced in [false, true] {
            for count in [0, 1] {
                let mut dos = DosKernel::new(0x1000);
                let mut host = TestHost::default();
                let mut memory = TestMemory::new();
                let (handle, _) = open_file(&mut dos, &mut host, &mut memory, mode);
                let mut regs = Registers::default();
                regs.set_ax(if forced { 0x4600 } else { 0x4500 });
                regs.set_bx(handle);
                regs.set_cx(1);
                dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
                assert!(!regs.carry());
                let alias = if forced { 1 } else { regs.ax() };
                regs.set_ax(0x3e00);
                regs.set_bx(handle);
                dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
                assert!(!regs.carry());
                assert_eq!(dos.file_table.file_open_mode(alias), Some(u16::from(mode)));
                let Handle::File(file) = dos.handles[&alias] else { panic!("expected alias"); };
                host.file_for(file).unwrap().cursor = 1;
                memory.put(0x10300, b"Z");
                clear_io(&mut host);
                let readonly = mode & 7 == 0;
                write(&mut dos, &mut host, &mut memory, alias, count, readonly,
                    if readonly { Err(DosErrorCode::AccessDenied) } else { Ok(count) });
                if readonly {
                    assert_no_io(&host);
                    assert_eq!(host.file_for(file).unwrap().bytes, b"abc");
                    assert_eq!(host.file_for(file).unwrap().cursor, 1);
                } else if count == 0 {
                    assert_eq!(host.file_seek_calls, vec![(file, 0, DosSeekOrigin::Current)]);
                    assert_eq!(host.file_set_len_calls, vec![(file, 1)]);
                    assert!(host.file_write_calls.is_empty());
                    assert_eq!(host.file_for(file).unwrap().bytes, b"a");
                    assert_eq!(host.file_for(file).unwrap().cursor, 1);
                } else {
                    assert_eq!(host.file_write_calls, vec![(file, b"Z".to_vec())]);
                    assert!(host.file_seek_calls.is_empty());
                    assert!(host.file_set_len_calls.is_empty());
                    assert_eq!(host.file_for(file).unwrap().bytes, b"aZc");
                    assert_eq!(host.file_for(file).unwrap().cursor, 2);
                }
                assert!(host.stdout.is_empty());
            }
        }
    }
}

#[test]
fn write_ignores_guest_sft_access_mode_tampering() {
    for (mode, forged_mode) in [(0, 1_u16), (0, 2), (1, 0), (2, 0)] {
        for count in [0, 1] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let (handle, file) = open_file(&mut dos, &mut host, &mut memory, mode);
            host.file_for(file).unwrap().status = Some(DosFileStatus {
                short_name: *b"WRITE   DAT", size: 3, position: 0, attributes: 0,
                write_time: 0, write_date: ((2026 - 1980) << 9) | (10 << 5) | 11,
            });
            memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
            dos.initialize_system_tables(&mut memory).unwrap();
            dos.refresh_system_tables(&mut memory, &mut host).unwrap();
            let (_, index) = dos.file_table.live_handles().find(|(guest, _)| *guest == handle).unwrap();
            let offset = usize::from(SFT_OFFSET) + SFT_HEADER_BYTES
                + usize::from(index) * SFT_ENTRY_BYTES + 2;
            let address = guest_core::real_address(SYSTEM_SEGMENT, offset as u16).0;
            memory.put(address, &forged_mode.to_le_bytes());
            memory.put(0x10300, b"Z");
            clear_io(&mut host);
            write(&mut dos, &mut host, &mut memory, handle, count, mode == 0,
                if mode == 0 { Err(DosErrorCode::AccessDenied) } else { Ok(count) });
            assert_eq!(dos.file_table.file_open_mode(handle), Some(u16::from(mode)));
            let mut published = [0; 2];
            memory.read(PhysAddr(address), &mut published).unwrap();
            assert_eq!(u16::from_le_bytes(published), u16::from(mode));
            if mode == 0 {
                assert_no_io(&host);
                assert_eq!(host.file_for(file).unwrap().bytes, b"abc");
                assert_eq!(host.file_for(file).unwrap().cursor, 0);
            } else {
                assert_eq!(host.file_for(file).unwrap().bytes.as_slice(),
                    if count == 0 { b"".as_slice() } else { b"Zbc".as_slice() });
            }
        }
    }
}

#[test]
fn writable_empty_write_truncates_or_extends_without_reading_buffer() {
    for mode in [1, 2, 0x41, 0xc2] {
        for position in [1, 5] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let (handle, file) = open_file(&mut dos, &mut host, &mut memory, mode);
            host.file_for(file).unwrap().cursor = position;
            clear_io(&mut host);
            write(&mut dos, &mut host, &mut memory, handle, 0, true, Ok(0));
            assert_eq!(host.file_seek_calls, vec![(file, 0, DosSeekOrigin::Current)]);
            assert_eq!(host.file_set_len_calls, vec![(file, position)]);
            assert!(host.file_write_calls.is_empty());
            assert_eq!(host.file_for(file).unwrap().cursor, position);
            assert_eq!(host.file_for(file).unwrap().bytes.as_slice(),
                if position == 1 { b"a".as_slice() } else { b"abc\0\0".as_slice() });
        }
    }
}

#[test]
fn readonly_creation_attribute_does_not_remove_open_write_access() {
    for service in [0x3c00, 0x5b00] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        memory.put(0x10100, b"NEW.DAT\0");
        memory.put(0x10300, b"Z");
        let mut regs = Registers { ds: 0x1000, ..Default::default() };
        regs.set_ax(service);
        regs.set_cx(1);
        regs.set_dx(0x100);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        let handle = regs.ax();
        assert_eq!(dos.file_table.file_open_mode(handle), Some(2));
        assert_eq!(host.attributes[b"NEW.DAT".as_slice()], 1);
        write(&mut dos, &mut host, &mut memory, handle, 1, false, Ok(1));
        let Handle::File(file) = dos.handles[&handle] else { panic!("expected file"); };
        assert_eq!(host.file_for(file).unwrap().bytes, b"Z");
    }
}

#[test]
fn write_invalid_handle_and_defensive_metadata_errors_preserve_frame() {
    for mode in [None, Some(3), Some(7)] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let file = host.file_create(b"WRITE.DAT", 0).unwrap();
        dos.handles.insert(5, Handle::File(file));
        if let Some(mode) = mode { assert!(dos.file_table.register_open(5, mode).is_some()); }
        for count in [0, 1] {
            clear_io(&mut host);
            write(&mut dos, &mut host, &mut memory, 99, count, true, Err(DosErrorCode::InvalidHandle));
            write(&mut dos, &mut host, &mut memory, 5, count, true,
                Err(if mode.is_none() { DosErrorCode::InvalidHandle } else { DosErrorCode::InvalidAccess }));
            assert_no_io(&host);
        }
    }
}

#[test]
fn standard_stream_writes_keep_existing_direction_and_empty_buffer_rules() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10300, b"Z");
    for handle in [0, 1, 2] {
        for count in [0, 1] {
            write(&mut dos, &mut host, &mut memory, handle, count, count == 0,
                if handle == 0 { Err(DosErrorCode::InvalidHandle) } else { Ok(count) });
        }
    }
    assert_eq!(host.stdout, b"Z");
    assert_eq!(host.stderr, b"Z");
    assert!(host.file_write_calls.is_empty());
    assert!(host.file_seek_calls.is_empty());
    assert!(host.file_set_len_calls.is_empty());
}

#[test]
fn writable_short_writes_keep_reported_count_and_cursor() {
    for limit in [0, 1, 3] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost { max_file_write: Some(limit), ..Default::default() };
        let mut memory = TestMemory::new();
        let (handle, file) = open_file(&mut dos, &mut host, &mut memory, 2);
        memory.put(0x10300, b"XYZ");
        clear_io(&mut host);
        write(&mut dos, &mut host, &mut memory, handle, 3, false, Ok(limit as u16));
        assert_eq!(host.file_write_calls, vec![(file, b"XYZ".to_vec())]);
        assert!(host.file_seek_calls.is_empty());
        assert!(host.file_set_len_calls.is_empty());
        assert_eq!(host.file_for(file).unwrap().cursor, limit as u32);
        assert_eq!(host.file_for(file).unwrap().bytes.as_slice(),
            match limit { 0 => b"abc", 1 => b"Xbc", _ => b"XYZ" });
    }
}
