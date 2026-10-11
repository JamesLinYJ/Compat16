//! AH=3Fh checks owned file access even when CX is zero.

use super::*;
use super::super::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};

fn open_one_byte_file(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, mode: u8,
) -> (u16, DosHostFile) {
    let seed = host.file_create(b"READ.DAT", 0).unwrap();
    host.file_for(seed).unwrap().bytes = b"X".to_vec();
    host.file_close(seed).unwrap();
    memory.put(0x10100, b"READ.DAT\0");
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

fn read_without_io(
    dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory,
    handle: u16, count: u16, error: Option<DosErrorCode>,
) {
    dos.pending_input = Some(b'p');
    host.input = VecDeque::from([b'q']);
    let mut regs = Registers {
        eax: 0xaaaa_3f00, ebx: 0xbbbb_0000 | u32::from(handle),
        ecx: 0xcccc_0000 | u32::from(count), edx: 0xdddd_ffff,
        esi: 0xeeee_1234, edi: 0xffff_5678, eflags: 0xad7,
        ds: 0xffff, es: 0x4321, ..Default::default()
    };
    let mut expected = regs.clone();
    expected.set_ax(error.map_or(0, |code| code as u16));
    expected.set_carry(error.is_some());
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    assert!(host.file_read_calls.is_empty());
    assert_eq!(dos.pending_input, Some(b'p'));
    assert_eq!(host.input, VecDeque::from([b'q']));
    assert_eq!(host.stdin_poll_calls, 0);
    assert!(host.stdout.is_empty());
    assert!(host.stderr.is_empty());
}

#[test]
fn empty_read_rejects_write_only_before_buffer_access_or_host_io() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_one_byte_file(&mut dos, &mut host, &mut memory, 1);
    assert_eq!(host.last_open_access, Some(DosFileAccess::WriteOnly));
    let before = memory.0.clone();
    read_without_io(&mut dos, &mut host, &mut memory, handle, 0, Some(DosErrorCode::AccessDenied));
    assert_eq!(memory.0, before);
    assert_eq!(host.file_for(file).unwrap().cursor, 0);
    assert_eq!(host.file_for(file).unwrap().bytes, b"X");
}

#[test]
fn empty_read_accepts_readable_modes_without_buffer_access_or_host_io() {
    for mode in [0, 2, 0x40, 0xc2] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (handle, file) = open_one_byte_file(&mut dos, &mut host, &mut memory, mode);
        let before = memory.0.clone();
        read_without_io(&mut dos, &mut host, &mut memory, handle, 0, None);
        assert_eq!(memory.0, before);
        assert_eq!(host.file_for(file).unwrap().cursor, 0);
        assert_eq!(host.file_for(file).unwrap().bytes, b"X");
    }
}

#[test]
fn empty_read_duplicates_retain_access_mode_after_original_closes() {
    for mode in [0, 1, 2, 0xc1] {
        for forced in [false, true] {
            let mut dos = DosKernel::new(0x1000);
            let mut host = TestHost::default();
            let mut memory = TestMemory::new();
            let (handle, _) = open_one_byte_file(&mut dos, &mut host, &mut memory, mode);
            let mut regs = Registers::default();
            regs.set_ax(if forced { 0x4600 } else { 0x4500 });
            regs.set_bx(handle);
            regs.set_cx(0);
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
            assert!(!regs.carry());
            let alias = if forced { 0 } else { regs.ax() };
            assert_eq!(dos.file_table.file_open_mode(alias), Some(u16::from(mode)));
            regs.set_ax(0x3e00);
            regs.set_bx(handle);
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
            assert!(!regs.carry());
            let Handle::File(file) = dos.handles[&alias] else { panic!("expected alias"); };
            let before = memory.0.clone();
            let error = (mode & 7 == 1).then_some(DosErrorCode::AccessDenied);
            read_without_io(&mut dos, &mut host, &mut memory, alias, 0, error);
            assert_eq!(memory.0, before);
            assert_eq!(host.file_for(file).unwrap().cursor, 0);
            assert_eq!(host.file_for(file).unwrap().bytes, b"X");
        }
    }
}

#[test]
fn empty_read_ignores_guest_sft_access_mode_tampering() {
    for (mode, forged_mode) in [(1, 0_u16), (1, 2), (0, 1), (2, 1)] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        let (handle, file) = open_one_byte_file(&mut dos, &mut host, &mut memory, mode);
        // Publishing an SFT requires host metadata, unlike an empty read.
        host.file_for(file).unwrap().status = Some(DosFileStatus {
            short_name: *b"READ    DAT",
            size: 1,
            position: 0,
            attributes: 0,
            write_time: 0,
            write_date: ((2026 - 1980) << 9) | (10 << 5) | 11,
        });
        // Install the normal PSP JFT descriptor before publishing the SFT.
        memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
        dos.initialize_system_tables(&mut memory).unwrap();
        dos.refresh_system_tables(&mut memory, &mut host).unwrap();
        let before = memory.0.clone();
        let (_, index) = dos.file_table.live_handles().find(|(guest, _)| *guest == handle).unwrap();
        let offset = usize::from(SFT_OFFSET) + SFT_HEADER_BYTES
            + usize::from(index) * SFT_ENTRY_BYTES + 2;
        let address = guest_core::real_address(SYSTEM_SEGMENT, offset as u16).0;
        memory.put(address, &forged_mode.to_le_bytes());
        let error = (mode == 1).then_some(DosErrorCode::AccessDenied);
        read_without_io(&mut dos, &mut host, &mut memory, handle, 0, error);
        // The ordinary post-dispatch refresh restores the trusted projection.
        assert_eq!(memory.0, before);
        assert_eq!(dos.file_table.file_open_mode(handle), Some(u16::from(mode)));
        assert_eq!(host.file_for(file).unwrap().cursor, 0);
        assert_eq!(host.file_for(file).unwrap().bytes, b"X");
    }
}

#[test]
fn empty_read_preserves_invalid_handle_and_standard_device_behavior() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let before = memory.0.clone();
    read_without_io(&mut dos, &mut host, &mut memory, 99, 0, Some(DosErrorCode::InvalidHandle));
    for handle in [0, 1, 2] {
        read_without_io(&mut dos, &mut host, &mut memory, handle, 0, None);
    }
    assert_eq!(memory.0, before);
}

#[test]
fn nonempty_read_rejects_write_only_before_invalid_buffer_or_host_io() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (handle, file) = open_one_byte_file(&mut dos, &mut host, &mut memory, 1);
    let before = memory.0.clone();
    read_without_io(&mut dos, &mut host, &mut memory, handle, 1, Some(DosErrorCode::AccessDenied));
    assert_eq!(memory.0, before);
    assert_eq!(host.file_for(file).unwrap().cursor, 0);
    assert_eq!(host.file_for(file).unwrap().bytes, b"X");
}
