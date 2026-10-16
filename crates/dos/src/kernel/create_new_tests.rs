//! INT 21h/5Bh exclusive creation and shared JFT/SFT ownership regressions.

use super::*;

fn create(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    path: &[u8],
    attributes: u16,
) -> Registers {
    memory.put(0x10100, path);
    memory.put(0x10100 + path.len() as u32, &[0]);
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x5b00);
    regs.set_dx(0x100);
    regs.set_cx(attributes);
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    regs
}

#[test]
fn create_new_returns_read_write_inheritable_handle_and_preserves_registers() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"NEW.DAT\0");
    let mut regs = Registers {
        eax: 0xaaaa_5b00, ebx: 0xbbbb_1234, ecx: 0xcccc_0002,
        edx: 0xdddd_0100, esi: 0xeeee_5678, edi: 0xffff_9abc,
        eflags: 0xad7, ds: 0x1000, es: 0x4321, ..Default::default()
    };
    let mut expected = regs.clone();
    expected.set_ax(3);
    expected.set_carry(false);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert_eq!(regs, expected);
    assert!(dos.file_table.is_handle_inheritable(3));
    assert_eq!(host.attributes[b"NEW.DAT".as_slice()], 2);
    let Handle::File(file) = dos.handles[&3] else { panic!("expected file"); };
    host.file_write(file, b"data").unwrap();
    host.file_seek(file, 0, DosSeekOrigin::Start).unwrap();
    let mut bytes = [0; 4];
    assert_eq!(host.file_read(file, &mut bytes).unwrap(), 4);
    assert_eq!(&bytes, b"data");
}

#[test]
fn create_new_existing_file_preserves_contents_attributes_and_open_cursor() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let first = create(&mut dos, &mut host, &mut memory, b"KEEP.DAT", 2);
    let Handle::File(file) = dos.handles[&first.ax()] else { panic!("expected file"); };
    host.file_write(file, b"keep this").unwrap();
    host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
    let failed = create(&mut dos, &mut host, &mut memory, b"KEEP.DAT", 0x20);
    assert!(failed.carry());
    assert_eq!(failed.ax(), 80);
    assert_eq!(host.file_seek(file, 0, DosSeekOrigin::Current).unwrap(), 3);
    assert_eq!(host.file_for(file).unwrap().bytes, b"keep this");
    assert_eq!(host.attributes[b"KEEP.DAT".as_slice()], 2);
    assert_eq!(host.handles.len(), 1);
    assert!(!dos.file_table.is_handle_inheritable(4));
    let next = create(&mut dos, &mut host, &mut memory, b"NEXT.DAT", 0);
    assert!(!next.carry());
    assert_eq!(next.ax(), 4);
}

#[test]
fn create_new_host_failure_releases_reserved_sft_and_jft_slot() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    for error in [DosErrorCode::PathNotFound, DosErrorCode::AccessDenied, DosErrorCode::DiskFull] {
        host.fail_create_new = Some(error);
        let failed = create(&mut dos, &mut host, &mut memory, b"FAIL.DAT", 0);
        assert!(failed.carry());
        assert_eq!(failed.ax(), error as u16);
        assert!(!dos.handles.contains_key(&3));
        assert!(!dos.file_table.is_handle_inheritable(3));
        assert!(host.paths.is_empty());
    }
    host.fail_create_new = None;
    let created = create(&mut dos, &mut host, &mut memory, b"GOOD.DAT", 0);
    assert_eq!(created.ax(), 3);
    assert!(!created.carry());
}

#[test]
fn create_new_handle_exhaustion_precedes_host_side_effects() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    for index in 3..20 {
        let path = format!("F{index}.DAT");
        let created = create(&mut dos, &mut host, &mut memory, path.as_bytes(), 0);
        assert_eq!(created.ax(), index);
        assert!(!created.carry());
    }
    let calls = host.create_new_calls;
    let failed = create(&mut dos, &mut host, &mut memory, b"OVERFLOW.DAT", 0);
    assert!(failed.carry());
    assert_eq!(failed.ax(), 4);
    assert_eq!(host.create_new_calls, calls);
    assert!(!host.paths.contains_key(b"OVERFLOW.DAT".as_slice()));
}

#[test]
fn create_new_shared_sft_exhaustion_precedes_host_side_effects() {
    let mut dos = DosKernel::new(0x1000);
    let mut other = DosKernel::new(0x2000);
    assert!(other.file_table.inherit_from(&dos.file_table));
    // Occupy the shared SFT through another owner's mappings; this owner's
    // JFT still has a free handle 3, independent of the global SFT shortage.
    for handle in 3..255 {
        assert!(other.file_table.register_open(handle, 2).is_some());
    }
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let failed = create(&mut dos, &mut host, &mut memory, b"FULL.DAT", 0);
    assert!(failed.carry());
    assert_eq!(failed.ax(), 4);
    assert_eq!(host.create_new_calls, 0);
    assert!(host.paths.is_empty());
    drop(other);
    assert!(!create(&mut dos, &mut host, &mut memory, b"FREE.DAT", 0).carry());
}

#[test]
fn create_new_reuses_closed_standard_slot_as_a_file() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_ax(0x3e00);
    regs.set_bx(1);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let created = create(&mut dos, &mut host, &mut memory, b"OUTPUT.DAT", 0);
    assert_eq!(created.ax(), 1);
    assert!(matches!(dos.handles[&1], Handle::File(_)));
    regs.set_ax(0x0200);
    regs.set_dl(b'X');
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let Handle::File(file) = dos.handles[&1] else { panic!("expected file"); };
    assert_eq!(host.file_for(file).unwrap().bytes, b"X");
    assert!(host.stdout.is_empty());
}

#[test]
fn create_new_duplicate_and_child_share_cursor_but_own_closeable_tokens() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let created = create(&mut dos, &mut host, &mut memory, b"SHARED.DAT", 0);
    let mut regs = Registers::default();
    regs.set_ax(0x4500);
    regs.set_bx(created.ax());
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    let duplicate = regs.ax();
    let mut child = DosKernel::new(0x2000);
    child.inherit_handles_from(&dos, &mut host).unwrap();
    let Handle::File(original) = dos.handles[&created.ax()] else { panic!("expected file"); };
    let Handle::File(copy) = dos.handles[&duplicate] else { panic!("expected file"); };
    let Handle::File(inherited) = child.handles[&created.ax()] else { panic!("expected file"); };
    assert_ne!(original, copy);
    assert_ne!(original, inherited);
    host.file_write(inherited, b"child").unwrap();
    assert_eq!(host.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 5);
    child.close_all_handles_checked(&mut host).unwrap();
    regs.set_ax(0x3e00);
    regs.set_bx(created.ax());
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    host.file_write(copy, b" parent").unwrap();
    assert_eq!(host.file_for(copy).unwrap().bytes, b"child parent");
    dos.close_all_handles_checked(&mut host).unwrap();
    assert!(host.handles.is_empty());
}

#[test]
fn create_new_rejects_reused_host_identity_without_closing_its_owner() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let created = create(&mut dos, &mut host, &mut memory, b"OWNER.DAT", 0);
    let Handle::File(file) = dos.handles[&created.ax()] else { panic!("expected file"); };
    host.create_new_token_override = Some(file);
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x5b00);
    regs.set_dx(0x100);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))));
    assert!(!dos.file_table.is_handle_inheritable(4));
    assert_eq!(host.handles.len(), 1);
    host.file_write(file, b"still open").unwrap();
}

#[test]
fn create_new_invalid_path_memory_never_reaches_host() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers { ds: 0xffff, ..Default::default() };
    regs.set_ax(0x5b00);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::Memory(_))));
    assert_eq!(host.create_new_calls, 0);
    assert!(!dos.file_table.is_handle_inheritable(3));
    regs.ds = 0x1000;
    regs.set_dx(0x100);
    regs.set_ax(0x5b00);
    memory.put(0x10100, &[b'X'; 260]);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), 13);
    assert_eq!(host.create_new_calls, 0);
}

#[test]
fn create_new_is_not_a_protected_scalar_service() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut regs = Registers::default();
    regs.set_ax(0x5b00);
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(host.create_new_calls, 0);
}

#[test]
fn create_new_keeps_legacy_create_truncation_semantics() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let created = create(&mut dos, &mut host, &mut memory, b"TRUNC.DAT", 0);
    let Handle::File(file) = dos.handles[&created.ax()] else { panic!("expected file"); };
    host.file_write(file, b"discard").unwrap();
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3c00);
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
    assert!(!regs.carry());
    assert!(host.file_for(file).unwrap().bytes.is_empty());
    assert_eq!(host.create_new_calls, 1);
}

#[test]
fn create_new_corrupt_mcb_preflight_prevents_host_side_effects() {
    let psp = 0x1000;
    let mut dos = DosKernel::new(psp);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    let mut jft = [0xff; 20];
    jft[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(0x10018, &jft);
    dos.initialize_system_tables(&mut memory).unwrap();
    memory.put(0xfff0, b"X");
    memory.put(0x10100, b"NOFILE.DAT\0");
    let mut regs = Registers { ds: psp, ..Default::default() };
    regs.set_ax(0x5b00);
    regs.set_dx(0x100);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::InvalidMcbSignature { .. })));
    assert_eq!(host.create_new_calls, 0);
    assert!(host.paths.is_empty());
}
