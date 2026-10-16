//! AH=06h input and AH=0Bh status follow the owned standard-input object.

use super::*;

fn open_input(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    path: &[u8],
    bytes: &[u8],
    mode: u8,
) -> (u16, DosHostFile) {
    let seed = host.file_create(path, 0).unwrap();
    host.file_for(seed).unwrap().bytes = bytes.to_vec();
    host.file_close(seed).unwrap();
    memory.put(0x10100, path);
    memory.put(0x10100 + path.len() as u32, &[0]);
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3d00 | u16::from(mode));
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(!regs.carry());
    let guest = regs.ax();
    let Handle::File(file) = dos.handles[&guest] else { panic!("expected file"); };
    (guest, file)
}

fn force_input(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    source: u16,
) {
    let mut regs = Registers::default();
    regs.set_ax(0x4600);
    regs.set_bx(source);
    regs.set_cx(0);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(!regs.carry());
}

fn assert_poll(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    protected: bool,
    service: u8,
    result: Result<Option<u8>, DosErrorCode>,
) {
    let mut regs = Registers {
        eax: 0xaaaa_00cc | (u32::from(service) << 8),
        ebx: 0xbbbb_1234, ecx: 0xcccc_5678, edx: 0xdddd_12ff,
        esp: 0x1111_2222, ebp: 0x3333_4444,
        esi: 0xeeee_9abc, edi: 0xffff_def0,
        eip: 0x5555_6666, eflags: if protected { 0xad7 } else { 0xa96 },
        cs: 0x7777, ds: 0xffff, es: 0xfffe, ss: 0x8888,
        fs: 0x9999, gs: 0xabcd,
    };
    let mut expected = regs.clone();
    match result {
        Ok(byte) => {
            expected.set_al(byte.unwrap_or(0));
            if service == 0x06 {
                if byte.is_some() {
                    expected.eflags &= !(1 << 6);
                } else {
                    expected.eflags |= 1 << 6;
                }
            }
        }
        Err(code) => {
            expected.set_ax(code as u16);
            expected.set_carry(true);
        }
    }
    let before = memory.0.clone();
    if protected {
        assert_eq!(dos.interrupt_scalar(0x21, &mut regs, memory, host).unwrap(),
            Some(DosAction::Continue));
    } else {
        assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    }
    assert_eq!(regs, expected);
    assert_eq!(memory.0, before);
}

#[test]
fn direct_input_reads_one_file_byte_per_call_including_control_bytes_and_eof() {
    for protected in [false, true] {
        for mode in [0, 2] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let bytes = [0, 3, 0x1a, 0xff, b'Z'];
            let (guest, source) = open_input(&mut dos, &mut host, &mut memory, b"INPUT.DAT", &bytes, mode);
            force_input(&mut dos, &mut host, &mut memory, guest);
            let Handle::File(alias) = dos.handles[&0] else { panic!("expected alias"); };
            assert_ne!(alias, source);
            dos.pending_input = Some(b'p');
            host.input.push_back(b'q');
            // AH=06h must not depend on a readiness precheck or DOS SFT facts.
            host.file_input_status_error = Some(DosErrorCode::InvalidFunction);
            host.file_status_error = Some(DosErrorCode::InvalidFunction);
            for (index, byte) in bytes.into_iter().enumerate() {
                assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(byte)));
                assert_eq!(host.file_for(source).unwrap().cursor, index as u32 + 1);
                assert_eq!(host.file_read_calls.len(), index + 1);
            }
            for _ in 0..2 {
                assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(None));
            }
            assert_eq!(host.file_read_calls, vec![(alias, 1); bytes.len() + 2]);
            assert!(host.file_input_status_calls.is_empty());
            assert!(host.file_status_calls.is_empty());
            assert_eq!(host.stdin_poll_calls, 0);
            assert_eq!(dos.pending_input, Some(b'p'));
            assert_eq!(host.input, VecDeque::from([b'q']));
            assert!(host.stdout.is_empty());
        }
    }
}

#[test]
fn file_status_is_non_consuming_and_tracks_alias_reads_seeks_and_current_size() {
    for protected in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (guest, source) = open_input(&mut dos, &mut host, &mut memory, b"INPUT.DAT", b"\0B", 0);
        force_input(&mut dos, &mut host, &mut memory, guest);
        let Handle::File(alias) = dos.handles[&0] else { panic!("expected alias"); };
        dos.pending_input = Some(b'p');
        host.file_status_error = Some(DosErrorCode::InvalidFunction);
        for _ in 0..2 {
            assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
        }
        assert_eq!(host.file_input_status_calls, [alias, alias]);
        assert!(host.file_read_calls.is_empty());
        assert_eq!(host.file_for(source).unwrap().cursor, 0);
        let mut byte = [0xcc];
        assert_eq!(host.file_read(source, &mut byte).unwrap(), 1);
        assert_eq!(byte, [0]);
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(b'B')));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0)));
        host.file_seek(source, 9, DosSeekOrigin::Start).unwrap();
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0)));
        assert_eq!(host.file_for(source).unwrap().cursor, 9);
        host.file_seek(source, 0, DosSeekOrigin::Start).unwrap();
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
        // A preceding ready result does not reserve or cache file data.
        host.file_for(source).unwrap().bytes.clear();
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(None));
        host.file_for(source).unwrap().bytes.push(b'N');
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(b'N')));
        assert!(host.file_input_status_calls.iter().all(|file| *file == alias));
        assert!(host.file_status_calls.is_empty());
        assert_eq!(host.stdin_poll_calls, 0);
        assert_eq!(dos.pending_input, Some(b'p'));
    }
}

#[test]
fn switching_input_files_and_restoring_console_preserves_each_stream() {
    for protected in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let mut regs = Registers::default();
        regs.set_ax(0x4500);
        regs.set_bx(0);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        let saved_input = regs.ax();
        let (first, first_file) = open_input(&mut dos, &mut host, &mut memory, b"FIRST.DAT", b"A", 0);
        let (second, second_file) = open_input(&mut dos, &mut host, &mut memory, b"SECOND.DAT", b"B", 0);
        host.input.extend([b'p', b'q']);
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
        force_input(&mut dos, &mut host, &mut memory, first);
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
        force_input(&mut dos, &mut host, &mut memory, second);
        // Closing the original keeps the redirected duplicate alive.
        regs.set_ax(0x3e00);
        regs.set_bx(second);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
        assert!(!host.handles.contains_key(&second_file));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(b'B')));
        assert_eq!(host.file_for(first_file).unwrap().cursor, 0);
        assert_eq!(dos.pending_input, Some(b'p'));
        force_input(&mut dos, &mut host, &mut memory, saved_input);
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(b'p')));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(b'q')));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(None));
    }
}

#[test]
fn input_polling_rejects_write_only_missing_and_wrong_direction_handles_before_host_io() {
    for protected in [false, true] {
        for service in [0x06, 0x0b] {
            for kind in 0..5 {
                let mut dos = DosKernel::new(0x1000);
                let mut host = TestHost::default();
                let mut memory = TestMemory::new();
                let (guest, _) = open_input(&mut dos, &mut host, &mut memory, b"INPUT.DAT", b"X", 1);
                force_input(&mut dos, &mut host, &mut memory, guest);
                match kind {
                    0 => {}
                    1 => {
                        let mut regs = Registers::default();
                        regs.set_ax(0x3e00);
                        regs.set_bx(0);
                        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
                        assert!(!regs.carry());
                    }
                    2 => force_input(&mut dos, &mut host, &mut memory, 1),
                    3 => force_input(&mut dos, &mut host, &mut memory, 2),
                    _ => dos.file_table.remove_handle(0),
                }
                dos.pending_input = Some(b'p');
                let code = if kind == 0 { DosErrorCode::AccessDenied } else { DosErrorCode::InvalidHandle };
                assert_poll(&mut dos, &mut host, &mut memory, protected, service, Err(code));
                assert!(host.file_read_calls.is_empty());
                assert!(host.file_input_status_calls.is_empty());
                assert_eq!(host.stdin_poll_calls, 0);
                assert_eq!(dos.pending_input, Some(b'p'));
            }
        }
    }
}

#[test]
fn input_polling_preserves_host_errors_and_rejects_an_oversized_read_count() {
    for protected in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (guest, _) = open_input(&mut dos, &mut host, &mut memory, b"INPUT.DAT", b"X", 0);
        force_input(&mut dos, &mut host, &mut memory, guest);
        dos.pending_input = Some(b'p');
        for code in [DosErrorCode::AccessDenied, DosErrorCode::InvalidHandle,
            DosErrorCode::InvalidFunction, DosErrorCode::GeneralFailure] {
            host.file_read_error = Some(code);
            assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Err(code));
            host.file_input_status_error = Some(code);
            assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Err(code));
        }
        host.file_read_error = None;
        host.file_read_count_override = Some(2);
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Err(DosErrorCode::GeneralFailure));
        host.file_read_count_override = None;
        host.file_input_status_error = None;
        let Handle::File(alias) = dos.handles[&0] else { panic!("expected alias"); };
        host.file_close(alias).unwrap();
        for service in [0x06, 0x0b] {
            assert_poll(&mut dos, &mut host, &mut memory, protected, service, Err(DosErrorCode::InvalidHandle));
        }
        assert_eq!(dos.pending_input, Some(b'p'));
        assert_eq!(host.stdin_poll_calls, 0);
    }
}

#[test]
fn console_polling_keeps_status_non_consuming_and_changes_only_documented_result_bits() {
    for protected in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        host.input.extend([0, 0xff, b'Z']);
        for byte in [0, 0xff, b'Z'] {
            let polls = host.stdin_poll_calls;
            for _ in 0..2 {
                assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0xff)));
            }
            assert_eq!(host.stdin_poll_calls, polls + 1);
            assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(Some(byte)));
            assert_eq!(host.stdin_poll_calls, polls + 1);
        }
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x0b, Ok(Some(0)));
        assert_poll(&mut dos, &mut host, &mut memory, protected, 0x06, Ok(None));
        assert!(host.file_read_calls.is_empty());
        assert!(host.file_input_status_calls.is_empty());
        assert!(host.stdout.is_empty());
    }
}
