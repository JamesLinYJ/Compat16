//! AH=5701 updates the owned object while preserving its open-description state.

use super::*;
use guest_core::real_address;

fn setter_registers(handle: u16, time: u16, date: u16) -> Registers {
    Registers {
        eax: 0xaaaa_5701, ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_0000 | u32::from(time), edx: 0xdddd_0000 | u32::from(date),
        esp: 0x1111_2222, ebp: 0x3333_4444, esi: 0xeeee_9abc, edi: 0xffff_def0,
        eip: 0x5555_6666, eflags: 0xad7,
        cs: 0x7777, ds: 0xffff, es: 0xfffe, ss: 0x8888, fs: 0x9999, gs: 0xabcd,
    }
}

fn assert_set(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    handle: u16,
    pair: (u16, u16),
    result: Result<(), DosErrorCode>,
    called: Option<DosHostFile>,
) {
    let mut regs = setter_registers(handle, pair.0, pair.1);
    regs.set_carry(result.is_ok());
    let mut expected = regs.clone();
    match result {
        Ok(()) => expected.set_carry(false),
        Err(code) => { expected.set_ax(code as u16); expected.set_carry(true); }
    }
    let calls = host.file_set_write_time_calls.len();
    let status_calls = host.file_status_calls.len();
    let bytes = memory.0.clone();
    let handles = dos.handles.clone();
    let tokens = host.handles.clone();
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    let call = called.map(|file| (file, pair.0, pair.1));
    assert_eq!(&host.file_set_write_time_calls[calls..], call.as_slice());
    assert_eq!(host.file_status_calls.len(), status_calls);
    assert_eq!(memory.0, bytes); // These fixtures do not install the SFT mirror.
    assert_eq!(dos.handles, handles);
    assert_eq!(host.handles, tokens);
}

#[test]
fn set_file_time_selects_exact_tokens_and_changes_only_carry_on_success() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (first, first_file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"FIRST.DAT", 2);
    let (second, second_file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"SECOND.DAT", 1);
    for pair in [(0, 0x21), (0xbf7d, 0xff9f), (WRITE_TIME, WRITE_DATE)] {
        for (handle, file) in [(second, second_file), (first, first_file)] {
            assert_set(&mut dos, &mut host, &mut memory, handle, pair, Ok(()), Some(file));
            let status = host.file_for(file).unwrap().status.unwrap();
            assert_eq!((status.write_time, status.write_date), pair);
        }
    }
}

#[test]
fn set_file_time_allows_read_only_dos_modes_and_preserves_cursor_data_and_attributes() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    host.file_seek(file, 4, DosSeekOrigin::Start).unwrap();
    let paths = host.paths.clone();
    let attributes = host.attributes.clone();
    // DOS allows read-only opens; the host decides whether its existing native
    // handle actually holds metadata rights. This mock supplies those rights.
    assert_set(&mut dos, &mut host, &mut memory, handle, (0, 0x21), Ok(()), Some(file));
    assert_eq!(host.last_open_access, Some(DosFileAccess::ReadOnly));
    let state = host.file_for(file).unwrap();
    assert!(state.written);
    assert_eq!(state.cursor, 4);
    assert_eq!(state.bytes, b"unchanged");
    assert_eq!(state.status.unwrap().attributes, 0x21);
    assert_eq!(host.paths, paths);
    assert_eq!(host.attributes, attributes);
}

#[test]
fn set_file_time_preserves_ever_written_flag_and_identity_on_host_failure_then_retry() {
    for written in [false, true] {
        for code in [DosErrorCode::InvalidData, DosErrorCode::InvalidFunction,
            DosErrorCode::AccessDenied, DosErrorCode::WriteProtected,
            DosErrorCode::SharingViolation, DosErrorCode::GeneralFailure] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
            host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
            host.file_for(file).unwrap().written = written;
            let before = host.file_for(file).unwrap().status;
            host.file_set_write_time_error = Some(code);
            assert_set(&mut dos, &mut host, &mut memory, handle, (0, 0x21), Err(code), Some(file));
            let state = host.file_for(file).unwrap();
            assert_eq!(state.written, written);
            assert_eq!(state.status, before);
            assert_eq!(state.cursor, 3);
            assert_eq!(state.bytes, b"unchanged");
            host.file_set_write_time_error = None;
            assert_set(&mut dos, &mut host, &mut memory, handle, (0, 0x21), Ok(()), Some(file));
        }
    }
}

#[test]
fn set_file_time_uses_duplicate_in_standard_slot_after_original_close() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let duplicate = regs.ax();
    for slot in 0..=2 {
        regs.set_ax(0x4600);
        regs.set_bx(handle);
        regs.set_cx(slot);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(!regs.carry());
    }
    regs.set_ax(0x3e00);
    regs.set_bx(handle);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    for alias in [duplicate, 0, 1, 2] {
        let Handle::File(file) = dos.handles[&alias] else { panic!("expected alias"); };
        assert_ne!(file, original);
        assert_set(&mut dos, &mut host, &mut memory, alias, (0, 0x21), Ok(()), Some(file));
        let queried = match dos.handles[&duplicate] { Handle::File(file) => Some(file), _ => None };
        assert_query(&mut dos, &mut host, &mut memory, duplicate, 0, Ok((0, 0x21)), queried);
    }
}

#[test]
fn set_file_time_inherited_token_survives_parent_close() {
    let mut parent = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, original) = open_timestamp_file(&mut parent, &mut host, &mut memory, b"STAMP.DAT", 2);
    let (private, _) = open_timestamp_file(&mut parent, &mut host, &mut memory, b"PRIVATE.DAT", 0x82);
    let mut child = DosKernel::new(0x1800);
    child.inherit_handles_from(&parent, &mut host).unwrap();
    let Handle::File(inherited) = child.handles[&handle] else { panic!("expected inherited file"); };
    assert_ne!(original, inherited);
    parent.close_all_handles_checked(&mut host).unwrap();
    assert_set(&mut child, &mut host, &mut memory, handle, (0, 0x21), Ok(()), Some(inherited));
    assert_set(&mut child, &mut host, &mut memory, private, (0, 0x21), Err(DosErrorCode::InvalidHandle), None);
}

#[test]
fn set_file_time_rejects_missing_closed_and_standard_objects_without_mutation() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(1);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let standard_alias = regs.ax();
    for redirected in [false, true] {
        host.redirected_standard_streams = redirected;
        for standard in [0, 1, 2, standard_alias] {
            assert_set(&mut dos, &mut host, &mut memory, standard, (0, 0x21), Err(DosErrorCode::InvalidFunction), None);
        }
    }
    assert_set(&mut dos, &mut host, &mut memory, 0xffff, (0, 0x21), Err(DosErrorCode::InvalidHandle), None);
    dos.close_all_handles_checked(&mut host).unwrap();
    for closed in [0, 1, 2, handle, standard_alias] {
        assert_set(&mut dos, &mut host, &mut memory, closed, (0, 0x21), Err(DosErrorCode::InvalidHandle), None);
    }
}

#[test]
fn set_file_time_stays_out_of_unowned_scalar_dispatch() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
    let mut regs = setter_registers(handle, 0, 0x21);
    let before = regs.clone();
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(regs, before);
    assert!(host.file_set_write_time_calls.is_empty());
}

fn install_tables(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory) {
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    dos.initialize_system_tables(memory).unwrap();
    dos.finish_external_int21(memory, host).unwrap();
}

#[test]
fn set_file_time_preflights_corrupt_mcb_and_jft_before_host_mutation() {
    for corrupt_mcb in [false, true] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
        install_tables(&mut dos, &mut host, &mut memory);
        if corrupt_mcb {
            memory.put(real_address(0x0fff, 0).0, b"X");
        } else {
            memory.put(0x10034, &[0xff; 4]);
        }
        let mut regs = setter_registers(handle, 0, 0x21);
        let before = regs.clone();
        let bytes = memory.0.clone();
        assert!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host).is_err());
        assert_eq!(regs, before);
        assert_eq!(memory.0, bytes);
        assert!(host.file_set_write_time_calls.is_empty());
        assert!(!host.file_for(file).unwrap().written);
    }
}

#[test]
fn set_file_time_publishes_timestamp_and_metadata_written_bit_in_sft() {
    use crate::kernel::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, _) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 0);
    install_tables(&mut dos, &mut host, &mut memory);
    let index = usize::from(memory.0[0x10018 + usize::from(handle)]);
    let address = real_address(SYSTEM_SEGMENT, SFT_OFFSET).0 as usize
        + SFT_HEADER_BYTES + index * SFT_ENTRY_BYTES;
    let before = memory.0[address..address + SFT_ENTRY_BYTES].to_vec();
    let mut regs = setter_registers(handle, 0, 0x21);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    let mut expected = before;
    expected[5] &= !0x40;
    expected[13..15].copy_from_slice(&0u16.to_le_bytes());
    expected[15..17].copy_from_slice(&0x21u16.to_le_bytes());
    assert_eq!(&memory.0[address..address + SFT_ENTRY_BYTES], expected);
}

#[test]
fn set_file_time_retains_native_mutation_when_later_sft_refresh_returns_typed_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_timestamp_file(&mut dos, &mut host, &mut memory, b"STAMP.DAT", 2);
    install_tables(&mut dos, &mut host, &mut memory);
    host.file_status_error = Some(DosErrorCode::DriveNotReady);
    let handles = dos.handles.clone();
    let tokens = host.handles.clone();
    let mut regs = setter_registers(handle, 0, 0x21);
    let mut expected = regs.clone();
    expected.set_carry(false);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostOperation(error)) if error.code == DosErrorCode::DriveNotReady));
    assert_eq!(regs, expected); // This is not a setter AX/CF failure or rollback.
    assert_eq!(dos.handles, handles);
    assert_eq!(host.handles, tokens);
    assert_eq!(host.file_set_write_time_calls, [(file, 0, 0x21)]);
    let state = host.file_for(file).unwrap();
    assert!(state.written);
    assert_eq!((state.status.unwrap().write_time, state.status.unwrap().write_date), (0, 0x21));
    host.file_status_error = None;
    dos.finish_external_int21(&mut memory, &mut host).unwrap();
}
