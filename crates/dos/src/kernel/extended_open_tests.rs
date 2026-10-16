//! AX=6C00 request validation, truthful actions, and DOS handle ownership.

use super::*;

fn registers(mode: u16, action: u16, attributes: u16) -> Registers {
    let mut regs = Registers {
        eax: 0xaaaa_6c00, ebx: 0xbbbb_0000, ecx: 0xcccc_0000,
        edx: 0xdddd_0000, esi: 0xeeee_0100, edi: 0xffff_9abc,
        eflags: 0xad7, ds: 0x1000, es: 0x4321, ..Default::default()
    };
    regs.set_bx(mode);
    regs.set_dx(action);
    regs.set_cx(attributes);
    regs
}

fn call(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    mode: u16,
    action: u16,
    attributes: u16,
) -> Registers {
    let mut regs = registers(mode, action, attributes);
    assert_eq!(dos.interrupt(0x21, &mut regs, memory, host).unwrap(), DosAction::Continue);
    regs
}

fn fixture() -> (DosKernel, TestHost, TestMemory) {
    let dos = DosKernel::new(0x1000);
    let host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"TARGET.DAT\0");
    (dos, host, memory)
}

#[test]
fn extended_open_action_matrix_is_non_destructive_and_preserves_registers() {
    for exists in [false, true] {
        for action in [0x0001, 0x0010, 0x0011] {
            let (mut dos, mut host, mut memory) = fixture();
            let original = exists.then(|| {
                let file = host.file_create(b"TARGET.DAT", 2).unwrap();
                host.file_write(file, b"preserve").unwrap();
                host.file_seek(file, 3, DosSeekOrigin::Start).unwrap();
                file
            });
            let mut expected = registers(0x2042, action, 0x20);
            let result = call(&mut dos, &mut host, &mut memory, 0x2042, action, 0x20);
            let error = match (action, exists) {
                (0x0001, false) => Some(DosErrorCode::FileNotFound),
                (0x0010, true) => Some(DosErrorCode::FileExists),
                _ => None,
            };
            if let Some(error) = error {
                expected.set_ax(error as u16);
                expected.set_carry(true);
                assert!(!dos.handles.contains_key(&3));
                assert!(!dos.file_table.is_handle_inheritable(3));
            } else {
                expected.set_ax(3);
                expected.set_cx(if exists { 1 } else { 2 });
                expected.set_carry(false);
                assert!(dos.file_table.is_handle_inheritable(3));
            }
            assert_eq!(result, expected);
            assert_eq!(host.extended_open_calls.len(), 1);
            assert_eq!(host.extended_open_calls[0].0, b"TARGET.DAT");
            if let Some(file) = original {
                assert_eq!(host.file_for(file).unwrap().bytes, b"preserve");
                assert_eq!(host.file_for(file).unwrap().cursor, 3);
                assert_eq!(host.attributes[b"TARGET.DAT".as_slice()], 2);
            } else if !result.carry() {
                assert_eq!(host.attributes[b"TARGET.DAT".as_slice()], 0x20);
            } else {
                assert!(host.paths.is_empty());
            }
        }
    }
}

#[test]
fn extended_open_forwards_all_access_and_sharing_modes() {
    for (access_bits, access) in [
        (0, DosFileAccess::ReadOnly), (1, DosFileAccess::WriteOnly), (2, DosFileAccess::ReadWrite),
    ] {
        for (sharing_bits, sharing) in [
            (0x00, DosFileSharing::Compatibility), (0x10, DosFileSharing::DenyAll),
            (0x20, DosFileSharing::DenyWrite), (0x30, DosFileSharing::DenyRead),
            (0x40, DosFileSharing::DenyNone),
        ] {
            for flags in [0, 0x0080, 0x2000, 0x2080] {
                let (mut dos, mut host, mut memory) = fixture();
                host.file_create(b"TARGET.DAT", 2).unwrap();
                let mode = access_bits | sharing_bits | flags;
                // Existing-only ignores all of CX, including high bits.
                let result = call(&mut dos, &mut host, &mut memory, mode, 1, 0xffff);
                assert!(!result.carry());
                assert_eq!(result.cx(), 1);
                assert_eq!(host.extended_open_calls[0].1, DosFileOpenRequest {
                    access, sharing, disposition: DosFileDisposition::OpenExisting, attributes: 0,
                });
                assert_eq!(dos.file_table.is_handle_inheritable(result.ax()), flags & 0x80 == 0);
            }
        }
    }
}

#[test]
fn extended_open_rejects_invalid_words_and_unsupported_actions_before_host_call() {
    let invalid_modes = [3, 4, 5, 6, 7, 8, 0x50, 0x60, 0x70,
        0x100, 0x200, 0x400, 0x800, 0x1000, 0x8000, 0xffff];
    for mode in invalid_modes {
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, mode, 0x11, 0);
        assert_eq!(result.ax(), DosErrorCode::InvalidAccess as u16, "BX={mode:04x}");
        assert!(result.carry());
        assert!(host.extended_open_calls.is_empty());
    }
    for action in [0, 3, 4, 0xf, 0x13, 0x20, 0x21, 0x100, 0x101, 0x8001, 0xffff] {
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, 2, action, 0);
        assert_eq!(result.ax(), DosErrorCode::InvalidFunction as u16, "DX={action:04x}");
        assert!(result.carry());
        assert!(host.extended_open_calls.is_empty());
        assert!(host.paths.is_empty());
    }
    for mode in [0x4000, 0x4001, 0x4042, 0x6082] {
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, mode, 0x11, 0);
        assert_eq!(result.ax(), DosErrorCode::InvalidFunction as u16);
        assert!(host.extended_open_calls.is_empty());
    }
    for al in [1, 0xff] {
        let (mut dos, mut host, mut memory) = fixture();
        let mut regs = registers(2, 0x11, 0);
        regs.set_al(al);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), DosErrorCode::InvalidFunction as u16);
        assert!(host.extended_open_calls.is_empty());
    }
}

#[test]
fn extended_open_checks_creation_attributes_before_narrowing_to_a_byte() {
    for action in [0x10, 0x11] {
        for attributes in [0x08, 0x10, 0x40, 0x80, 0x100, 0x2000, 0x8000, 0xffff] {
            let (mut dos, mut host, mut memory) = fixture();
            let result = call(&mut dos, &mut host, &mut memory, 2, action, attributes);
            assert!(result.carry());
            assert_eq!(result.ax(), DosErrorCode::InvalidAccess as u16);
            assert!(host.extended_open_calls.is_empty());
            assert!(host.paths.is_empty());
        }
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, 1, action, 0x27);
        assert!(!result.carry());
        assert_eq!(host.extended_open_calls[0].1.attributes, 0x27);
    }
}

#[test]
fn extended_open_host_errors_release_reserved_slots_and_preserve_cx() {
    let (mut dos, mut host, mut memory) = fixture();
    for code in [DosErrorCode::InvalidFunction, DosErrorCode::PathNotFound,
        DosErrorCode::AccessDenied, DosErrorCode::SharingViolation, DosErrorCode::DiskFull] {
        host.extended_open_error = Some(code);
        let mut result = registers(2, 0x11, 0x22);
        result.set_carry(false);
        dos.interrupt(0x21, &mut result, &mut memory, &mut host).unwrap();
        assert_eq!(result.ax(), code as u16);
        assert_eq!(result.ecx, 0xcccc_0022);
        assert!(result.carry());
        assert!(!dos.handles.contains_key(&3));
        assert!(!dos.file_table.is_handle_inheritable(3));
        assert!(host.paths.is_empty());
    }
    host.extended_open_error = None;
    let result = call(&mut dos, &mut host, &mut memory, 2, 0x11, 0);
    assert_eq!(result.ax(), 3);
    assert_eq!(result.cx(), 2);
}

#[test]
fn extended_open_jft_and_shared_sft_exhaustion_precede_creation() {
    let (mut dos, mut host, mut memory) = fixture();
    for index in 3..20 {
        let result = call(&mut dos, &mut host, &mut memory, 2, 0x11, 0);
        assert_eq!(result.ax(), index);
    }
    let calls = host.extended_open_calls.len();
    memory.put(0x10100, b"OVERFLOW.DAT\0");
    let result = call(&mut dos, &mut host, &mut memory, 2, 0x10, 0);
    assert!(result.carry());
    assert_eq!(result.ax(), 4);
    assert_eq!(host.extended_open_calls.len(), calls);
    assert!(!host.paths.contains_key(b"OVERFLOW.DAT".as_slice()));

    let (mut dos, mut host, mut memory) = fixture();
    let mut other = DosKernel::new(0x2000);
    assert!(other.file_table.inherit_from(&dos.file_table));
    for handle in 3..255 {
        assert!(other.file_table.register_open(handle, 2).is_some());
    }
    let result = call(&mut dos, &mut host, &mut memory, 2, 0x10, 0);
    assert!(result.carry());
    assert_eq!(result.ax(), 4);
    assert!(host.extended_open_calls.is_empty());
    assert!(host.paths.is_empty());
    drop(other);
    assert_eq!(call(&mut dos, &mut host, &mut memory, 2, 0x10, 0).ax(), 3);
}

#[test]
fn extended_open_no_inherit_survives_duplication_and_inherited_tokens_are_distinct() {
    for no_inherit in [false, true] {
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, if no_inherit { 0x2082 } else { 0x2002 }, 0x10, 0);
        let mut regs = Registers::default();
        regs.set_ax(0x4500);
        regs.set_bx(result.ax());
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host).unwrap();
        let duplicate = regs.ax();
        assert_eq!(dos.file_table.is_handle_inheritable(duplicate), !no_inherit);
        let mut child = DosKernel::new(0x2000);
        child.inherit_handles_from(&dos, &mut host).unwrap();
        assert_eq!(child.handles.contains_key(&result.ax()), !no_inherit);
        assert_eq!(child.handles.contains_key(&duplicate), !no_inherit);
        let Handle::File(original) = dos.handles[&result.ax()] else { panic!("file"); };
        let Handle::File(copy) = dos.handles[&duplicate] else { panic!("file"); };
        assert_ne!(original, copy);
        if !no_inherit {
            let Handle::File(inherited) = child.handles[&result.ax()] else { panic!("file"); };
            assert_ne!(original, inherited);
            assert_ne!(copy, inherited);
            host.file_write(inherited, b"child").unwrap();
            assert_eq!(host.file_seek(copy, 0, DosSeekOrigin::Current).unwrap(), 5);
        }
        child.close_all_handles_checked(&mut host).unwrap();
        dos.close_all_handles_checked(&mut host).unwrap();
        assert!(host.handles.is_empty());
    }
}

#[test]
fn extended_open_reused_token_is_not_closed_or_attached_twice() {
    let (mut dos, mut host, mut memory) = fixture();
    let result = call(&mut dos, &mut host, &mut memory, 2, 0x11, 0);
    let Handle::File(file) = dos.handles[&result.ax()] else { panic!("file"); };
    host.extended_open_result_override = Some(DosFileOpenResult { file, outcome: DosFileOpenOutcome::Opened });
    let mut regs = registers(2, 1, 0);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::HostContractViolation(_))));
    assert_eq!(host.handles.len(), 1);
    assert!(!dos.file_table.is_handle_inheritable(4));
    host.file_write(file, b"still open").unwrap();
}

#[test]
fn extended_open_inconsistent_outcome_closes_or_retains_the_new_token() {
    for close_fails in [false, true] {
        let (mut dos, mut host, mut memory) = fixture();
        let file = host.file_create(b"TARGET.DAT", 0).unwrap();
        host.extended_open_result_override = Some(DosFileOpenResult { file, outcome: DosFileOpenOutcome::Created });
        host.file_close_error = close_fails.then_some(DosErrorCode::AccessDenied);
        let mut regs = registers(2, 1, 0);
        assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::HostContractViolation(_))));
        assert!(!dos.file_table.is_handle_inheritable(3));
        assert_eq!(host.handles.contains_key(&file), close_fails);
        assert_eq!(dos.orphan_file_handles.contains(&file), close_fails);
        host.file_close_error = None;
        dos.close_all_handles_checked(&mut host).unwrap();
        assert!(host.handles.is_empty());
    }
}

#[test]
fn extended_open_path_validation_uses_si_and_never_enters_scalar_route() {
    let (mut dos, mut host, mut memory) = fixture();
    let mut regs = registers(2, 0x11, 0);
    let before = regs.clone();
    assert_eq!(dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host).unwrap(), None);
    assert_eq!(regs, before);
    assert!(host.extended_open_calls.is_empty());
    regs.ds = 0xffff;
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::Memory(_))));
    assert!(host.extended_open_calls.is_empty());
    memory.put(0x10100, &[b'X'; 260]);
    let result = call(&mut dos, &mut host, &mut memory, 2, 0x11, 0);
    assert!(result.carry());
    assert_eq!(result.ax(), 13);
    assert!(host.extended_open_calls.is_empty());
    assert!(!dos.file_table.is_handle_inheritable(3));
}

#[test]
fn extended_open_read_only_creation_is_an_explicit_host_limit_without_mutation() {
    for action in [0x10, 0x11] {
        let (mut dos, mut host, mut memory) = fixture();
        let result = call(&mut dos, &mut host, &mut memory, 0, action, 0);
        assert!(result.carry());
        assert_eq!(result.ax(), DosErrorCode::InvalidFunction as u16);
        assert!(host.paths.is_empty());
        assert!(!dos.file_table.is_handle_inheritable(3));
    }
}

#[test]
fn extended_open_publishes_the_full_mode_in_the_shared_sft() {
    use super::super::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};
    let (mut dos, mut host, mut memory) = fixture();
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    let mut jft = [0xff; 20];
    jft[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(0x10018, &jft);
    dos.initialize_system_tables(&mut memory).unwrap();
    let file = host.file_create(b"TARGET.DAT", 0).unwrap();
    host.file_for(file).unwrap().status = Some(DosFileStatus {
        short_name: *b"TARGET  DAT", size: 0, position: 0,
        attributes: 0, write_time: 0, write_date: 0,
    });
    let mode = 0x20c2;
    let result = call(&mut dos, &mut host, &mut memory, mode, 1, 0xffff);
    assert!(!result.carry());
    let index = memory.read_u8(PhysAddr(0x10018 + u32::from(result.ax()))).unwrap();
    let offset = usize::from(SFT_OFFSET) + SFT_HEADER_BYTES + usize::from(index) * SFT_ENTRY_BYTES + 2;
    assert_eq!(memory.read_u16(guest_core::real_address(SYSTEM_SEGMENT, offset as u16)).unwrap(), mode);
}

#[test]
fn extended_open_corrupt_system_metadata_precedes_host_side_effects() {
    let (mut dos, mut host, mut memory) = fixture();
    memory.put(0x10032, &[20, 0, 0x18, 0, 0, 0x10]);
    let mut jft = [0xff; 20];
    jft[..3].copy_from_slice(&[0, 1, 2]);
    memory.put(0x10018, &jft);
    dos.initialize_system_tables(&mut memory).unwrap();
    memory.put(0xfff0, b"X");
    let mut regs = registers(2, 0x11, 0);
    assert!(matches!(dos.interrupt(0x21, &mut regs, &mut memory, &mut host), Err(DosError::InvalidMcbSignature { .. })));
    assert!(host.extended_open_calls.is_empty());
    assert!(host.paths.is_empty());
}
