//! AH=68h uses exact owned identities and preserves state on failure/retry.

use super::*;
use guest_core::real_address;

fn open_file(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    path: &[u8],
    mode: u8,
) -> (u16, DosHostFile) {
    let seed = host.file_create(path, 0x20).unwrap();
    let state = host.file_for(seed).unwrap();
    state.bytes = b"unchanged".to_vec();
    state.status = Some(DosFileStatus {
        short_name: *b"COMMIT  DAT", size: 9, position: 0,
        attributes: 0x20, write_time: 0, write_date: 0x21,
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
    (handle, file_token(dos, handle))
}

fn file_token(dos: &DosKernel, handle: u16) -> DosHostFile {
    let Handle::File(file) = dos.handles[&handle] else { panic!("expected file"); };
    file
}

fn commit_registers(handle: u16, al: u8) -> Registers {
    Registers {
        eax: 0xaaaa_6800 | u32::from(al), ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_1234, edx: 0xdddd_5678, esp: 0x1111_2222, ebp: 0x3333_4444,
        esi: 0xeeee_9abc, edi: 0xffff_def0, eip: 0x5555_6666, eflags: 0xad7,
        cs: 0x7777, ds: 0xffff, es: 0xfffe, ss: 0x8888, fs: 0x9999, gs: 0xabcd,
    }
}

fn assert_commit(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    handle: u16,
    al: u8,
    result: Result<(), DosErrorCode>,
    committed: Option<DosHostFile>,
) {
    let mut regs = commit_registers(handle, al);
    regs.set_carry(result.is_ok());
    let mut expected = regs.clone();
    match result {
        Ok(()) => expected.set_carry(false),
        Err(code) => { expected.set_ax(code as u16); expected.set_carry(true); }
    }
    let calls = host.file_commit_calls.len();
    let bytes = memory.0.clone();
    let handles = dos.handles.clone();
    let tokens = host.handles.clone();
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    assert_eq!(&host.file_commit_calls[calls..], committed.as_slice());
    assert_eq!(memory.0, bytes);
    assert_eq!(dos.handles, handles);
    assert_eq!(host.handles, tokens);
}

#[test]
fn file_commit_selects_exact_owned_token_and_preserves_all_other_registers() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (first, first_file) = open_file(&mut dos, &mut host, &mut memory, b"FIRST.DAT", 2);
    let (second, second_file) = open_file(&mut dos, &mut host, &mut memory, b"SECOND.DAT", 2);
    assert_ne!(first_file, second_file);
    for al in [0, 1, 0xff] {
        for (handle, file) in [(second, second_file), (first, first_file)] {
            assert_commit(&mut dos, &mut host, &mut memory, handle, al, Ok(()), Some(file));
        }
    }
}

#[test]
fn file_commit_keeps_cursor_bytes_attributes_and_ever_written_fact() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    host.file_write(file, b"abc").unwrap();
    let bytes = host.file_for(file).unwrap().bytes.clone();
    let status = host.file_for(file).unwrap().status;
    let paths = host.paths.clone();
    let attributes = host.attributes.clone();
    assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(file));
    let state = host.file_for(file).unwrap();
    assert_eq!(state.cursor, 3);
    assert_eq!(state.bytes, bytes);
    assert_eq!(state.status, status);
    assert!(state.written);
    assert_eq!(host.paths, paths);
    assert_eq!(host.attributes, attributes);
}

#[test]
fn file_commit_uses_duplicates_in_standard_slots_and_after_original_close() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let alias = regs.ax();
    for slot in 0..=2 {
        regs.set_ax(0x4600);
        regs.set_bx(handle);
        regs.set_cx(slot);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
    }
    host.file_seek(original, 4, DosSeekOrigin::Start).unwrap();
    regs.set_ax(0x3e00);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidHandle), None);
    for handle in [alias, 0, 1, 2] {
        let token = file_token(&dos, handle);
        assert_ne!(token, original);
        assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(token));
        assert_eq!(host.file_for(token).unwrap().cursor, 4);
    }
}

#[test]
fn file_commit_inherited_handle_uses_child_token_and_survives_parent_close() {
    let mut parent = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_file(&mut parent, &mut host, &mut memory, b"COMMIT.DAT", 2);
    let (private, _) = open_file(&mut parent, &mut host, &mut memory, b"PRIVATE.DAT", 0x82);
    let mut child = DosKernel::new(0x1800);
    child.inherit_handles_from(&parent, &mut host).unwrap();
    let inherited = file_token(&child, handle);
    assert_ne!(original, inherited);
    host.file_seek(original, 5, DosSeekOrigin::Start).unwrap();
    parent.close_all_handles_checked(&mut host).unwrap();
    assert_commit(&mut child, &mut host, &mut memory, handle, 0, Ok(()), Some(inherited));
    assert_eq!(host.file_for(inherited).unwrap().cursor, 5);
    assert_commit(&mut child, &mut host, &mut memory, private, 0, Err(DosErrorCode::InvalidHandle), None);
}

#[test]
fn file_commit_failure_preserves_aliases_cursor_and_retry_with_direct_dos_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
    for code in [DosErrorCode::InvalidFunction, DosErrorCode::AccessDenied,
        DosErrorCode::WriteProtected, DosErrorCode::DriveNotReady, DosErrorCode::DiskFull,
        DosErrorCode::SharingViolation, DosErrorCode::GeneralFailure, DosErrorCode::InvalidHandle] {
        host.file_commit_error = Some(code);
        assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Err(code), Some(file));
        assert_eq!(host.file_for(file).unwrap().cursor, 3);
        host.file_commit_error = None;
        assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(file));
    }
}

#[test]
fn file_commit_invalid_and_closed_handles_never_reach_host() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    for missing in [handle + 1, 0xffff] {
        assert_commit(&mut dos, &mut host, &mut memory, missing, 0, Err(DosErrorCode::InvalidHandle), None);
    }
    dos.close_all_handles_checked(&mut host).unwrap();
    for closed in [0, 1, 2, handle] {
        assert_commit(&mut dos, &mut host, &mut memory, closed, 0, Err(DosErrorCode::InvalidHandle), None);
    }
}

#[test]
fn file_commit_proven_character_device_aliases_are_clean_noops() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    host.input.extend(b"pending");
    dos.pending_input = Some(b'p');
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(1);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    for handle in [0, 1, 2, regs.ax()] {
        assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), None);
    }
    assert_eq!(host.input, VecDeque::from(b"pending".to_vec()));
    assert_eq!(dos.pending_input, Some(b'p'));
    assert!(host.stdout.is_empty());
    assert!(host.stderr.is_empty());
}

#[test]
fn file_commit_redirected_or_unknown_standard_streams_remain_unsupported() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    host.redirect_standard_streams();
    for info in [None, Some(DosIoctlObjectInfo::File { drive: 2, written: false }),
        Some(DosIoctlObjectInfo::File { drive: 2, written: true })] {
        host.standard_info_override = info;
        for handle in [0, 1, 2] {
            assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Err(DosErrorCode::InvalidFunction), None);
        }
    }
}

#[test]
fn file_commit_read_only_handle_still_uses_trusted_host_contract() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 0);
    assert_eq!(host.last_open_access, Some(DosFileAccess::ReadOnly));
    assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(file));
    assert!(!host.file_for(file).unwrap().written);
    assert_eq!(host.file_for(file).unwrap().bytes, b"unchanged");
}

#[test]
fn file_commit_new_empty_and_zero_length_truncated_files_reach_host() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"NEW.DAT\0");
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3c00);
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let handle = regs.ax();
    let file = file_token(&dos, handle);
    assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(file));
    host.file_write(file, b"old data").unwrap();
    host.file_seek(file, 0, DosSeekOrigin::Start).unwrap();
    regs.set_ax(0x4000);
    regs.set_bx(handle);
    regs.set_cx(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(host.file_for(file).unwrap().bytes.is_empty());
    assert_commit(&mut dos, &mut host, &mut memory, handle, 0, Ok(()), Some(file));
}

#[test]
fn file_commit_is_not_accepted_by_unowned_scalar_route() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    let mut regs = commit_registers(handle, 0);
    let before = regs.clone();
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(regs, before);
    assert!(host.file_commit_calls.is_empty());
}

#[test]
fn file_commit_corrupt_mcb_or_jft_fails_preflight_before_host_side_effect() {
    for corrupt_mcb in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (handle, _) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
        memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
        dos.initialize_system_tables(&mut memory).unwrap();
        dos.finish_external_int21(&mut memory, &mut host).unwrap();
        if corrupt_mcb {
            memory.put(real_address(0x0fff, 0).0, b"X");
        } else {
            memory.put(0x10034, &[0xff, 0xff, 0xff, 0xff]);
        }
        let mut regs = commit_registers(handle, 0);
        let before = regs.clone();
        let bytes = memory.0.clone();
        assert!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host).is_err());
        assert!(host.file_commit_calls.is_empty());
        assert_eq!(regs, before);
        assert_eq!(memory.0, bytes);
    }
}

#[test]
fn file_commit_preserves_published_jft_sft_on_success_failure_and_retry() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_file(&mut dos, &mut host, &mut memory, b"COMMIT.DAT", 2);
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    dos.initialize_system_tables(&mut memory).unwrap();
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let duplicate_handle = regs.ax();
    let duplicate = file_token(&dos, duplicate_handle);
    host.file_seek(original, 4, DosSeekOrigin::Start).unwrap();
    dos.finish_external_int21(&mut memory, &mut host).unwrap();
    for (target, file) in [(handle, original), (duplicate_handle, duplicate)] {
        assert_commit(&mut dos, &mut host, &mut memory, target, 0, Ok(()), Some(file));
        host.file_commit_error = Some(DosErrorCode::DiskFull);
        assert_commit(&mut dos, &mut host, &mut memory, target, 0, Err(DosErrorCode::DiskFull), Some(file));
        host.file_commit_error = None;
        assert_commit(&mut dos, &mut host, &mut memory, target, 0, Ok(()), Some(file));
        assert_eq!(host.file_for(file).unwrap().cursor, 4);
    }
}
