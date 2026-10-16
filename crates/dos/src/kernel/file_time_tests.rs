//! INT 21h/AH=57h queries retain handle identity and leave file state untouched.

use super::*;

const WRITE_TIME: u16 = (21 << 11) | (34 << 5) | 28;
const WRITE_DATE: u16 = ((2026 - 1980) << 9) | (10 << 5) | 9;

fn open_timestamp_file(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    path: &[u8],
    mode: u8,
) -> (u16, DosHostFile) {
    let seed = host.file_create(path, 0x21).unwrap();
    let state = host.file_for(seed).unwrap();
    state.bytes = b"unchanged".to_vec();
    state.status = Some(DosFileStatus {
        short_name: *b"STAMP   DAT",
        size: 9,
        position: 0,
        attributes: 0x21,
        write_time: WRITE_TIME,
        write_date: WRITE_DATE,
    });
    host.file_close(seed).unwrap();
    memory.put(0x10100, path);
    memory.put(0x10100 + path.len() as u32, &[0]);
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3d00 | u16::from(mode));
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(!regs.carry());
    let handle = regs.ax();
    let Handle::File(file) = dos.handles[&handle] else { panic!("expected file"); };
    (handle, file)
}

fn assert_query(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    handle: u16,
    subfunction: u8,
    result: Result<(u16, u16), DosErrorCode>,
    queried_file: Option<DosHostFile>,
) {
    let mut regs = Registers {
        eax: 0xaaaa_5700 | u32::from(subfunction),
        ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_1234, edx: 0xdddd_5678,
        esp: 0x1111_2222, ebp: 0x3333_4444,
        esi: 0xeeee_9abc, edi: 0xffff_def0,
        eip: 0x5555_6666, eflags: if result.is_ok() { 0xad7 } else { 0xad6 },
        cs: 0x7777, ds: 0xffff, es: 0xfffe, ss: 0x8888,
        fs: 0x9999, gs: 0xabcd,
    };
    let mut expected = regs.clone();
    match result {
        Ok((time, date)) => {
            expected.set_cx(time);
            expected.set_dx(date);
            expected.set_carry(false);
        }
        Err(code) => {
            expected.set_ax(code as u16);
            expected.set_carry(true);
        }
    }
    let calls = host.file_status_calls.len();
    let bytes_before = memory.0.clone();
    // This fixture has no installed SFT, so the call log measures only the
    // service itself, independently of the normal system-table refresh.
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    assert_eq!(memory.0, bytes_before);
    assert_eq!(&host.file_status_calls[calls..], queried_file.as_slice());
}

#[test]
fn get_file_time_returns_exact_packed_fields_and_preserves_other_registers() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    assert_eq!(host.last_open_access, Some(DosFileAccess::ReadOnly));
    for (time, date) in [(WRITE_TIME, WRITE_DATE), (0, 0x21), (0xbf7d, 0xff9f)] {
        let status = host.file_for(file).unwrap().status.as_mut().unwrap();
        status.write_time = time;
        status.write_date = date;
        assert_query(&mut dos, &mut host, &mut memory, handle, 0, Ok((time, date)), Some(file));
    }
}

#[test]
fn get_file_time_leaves_read_only_file_cursor_bytes_attributes_and_written_state_unchanged() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
    let status_before = host.file_for(file).unwrap().status;
    let attributes_before = host.attributes.clone();
    let paths_before = host.paths.clone();
    let handles_before = host.handles.clone();
    assert_query(&mut dos, &mut host, &mut memory, handle, 0, Ok((WRITE_TIME, WRITE_DATE)), Some(file));
    let state = host.file_for(file).unwrap();
    assert_eq!(state.bytes, b"unchanged");
    assert_eq!(state.cursor, 3);
    assert!(!state.written);
    assert_eq!(state.status, status_before);
    assert_eq!(host.attributes, attributes_before);
    assert_eq!(host.paths, paths_before);
    assert_eq!(host.handles, handles_before);

    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3f00);
    regs.set_bx(handle);
    regs.set_cx(2);
    regs.set_dx(0x180);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_eq!(regs.ax(), 2);
    assert_eq!(&memory.0[0x10180..0x10182], b"ha");
    assert_eq!(host.file_for(file).unwrap().cursor, 5);
}

#[test]
fn get_file_time_uses_duplicate_identity_even_in_standard_slot_and_after_original_close() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let duplicate = regs.ax();
    regs.set_ax(0x4600);
    regs.set_bx(handle);
    regs.set_cx(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    host.file_seek(original, 4, DosSeekOrigin::Start).unwrap();
    for alias in [handle, duplicate, 0] {
        let Handle::File(file) = dos.handles[&alias] else { panic!("expected file alias"); };
        assert_query(&mut dos, &mut host, &mut memory, alias, 0, Ok((WRITE_TIME, WRITE_DATE)), Some(file));
        assert_eq!(host.file_for(file).unwrap().cursor, 4);
    }
    regs.set_ax(0x3e00);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_query(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidHandle), None);
    for alias in [duplicate, 0] {
        let Handle::File(file) = dos.handles[&alias] else { panic!("expected surviving alias"); };
        assert_ne!(file, original);
        assert_query(&mut dos, &mut host, &mut memory, alias, 0, Ok((WRITE_TIME, WRITE_DATE)), Some(file));
        assert_eq!(host.file_for(file).unwrap().cursor, 4);
    }
}

#[test]
fn get_file_time_resolves_each_owned_file_instead_of_last_opened_file() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (first, first_file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"FIRST.DAT", 0);
    let (second, second_file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"SECOND.DAT", 0);
    host.file_for(second_file).unwrap().status.as_mut().unwrap().write_time = 0;
    assert_query(&mut dos, &mut host, &mut memory, second, 0, Ok((0, WRITE_DATE)), Some(second_file));
    assert_query(&mut dos, &mut host, &mut memory, first, 0, Ok((WRITE_TIME, WRITE_DATE)), Some(first_file));
}

#[test]
fn get_file_time_propagates_host_errors_without_clobbering_time_or_date() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    for code in [DosErrorCode::InvalidFunction, DosErrorCode::AccessDenied, DosErrorCode::InvalidHandle] {
        host.file_status_error = Some(code);
        assert_query(&mut dos, &mut host, &mut memory, handle, 0, Err(code), Some(file));
    }
    host.file_status_error = None;
    host.file_for(file).unwrap().status = None;
    assert_query(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidFunction), Some(file));
}

#[test]
fn get_file_time_rejects_unsupported_subfunctions_before_handle_or_host_access() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    for subfunction in [2, 0xff] {
        for target in [handle, 0, 0xffff] {
            assert_query(&mut dos, &mut host, &mut memory, target, subfunction, Err(DosErrorCode::InvalidFunction), None);
        }
    }
}

#[test]
fn get_file_time_distinguishes_missing_handles_from_standard_object_aliases() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(1);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let alias = regs.ax();
    assert!(alias >= 3);
    for handle in [0, 1, 2, alias] {
        assert_query(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidFunction), None);
    }
    for handle in [alias + 1, 0xffff] {
        assert_query(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidHandle), None);
    }
    regs.set_ax(0x3e00);
    regs.set_bx(1);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_query(&mut dos, &mut host, &mut memory, 1, 0, Err(DosErrorCode::InvalidHandle), None);
    assert_query(&mut dos, &mut host, &mut memory, alias, 0, Err(DosErrorCode::InvalidFunction), None);
}

#[test]
fn get_file_time_stays_on_caller_aware_handle_route() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    let mut regs = Registers { ds: 0xffff, es: 0xfffe, ..Default::default() };
    regs.set_ax(0x5700);
    regs.set_bx(handle);
    let before = regs.clone();
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(regs, before);
    assert!(host.file_status_calls.is_empty());
}

#[path = "file_time_set_tests.rs"]
mod setters;
