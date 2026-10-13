//! AH=0Dh disk reset, AH=2Eh set verify, and AH=54h get verify.

use super::*;

fn filled(ah: u8, al: u8) -> Registers {
    Registers {
        eax: 0x1111_0000 | u32::from(ah) << 8 | u32::from(al),
        ebx: 0x2222_3333,
        ecx: 0x4444_5555,
        edx: 0x6666_7777,
        esp: 0x8888_9999,
        ebp: 0xaaaa_bbbb,
        esi: 0xcccc_dddd,
        edi: 0xeeee_ffff,
        eip: 0x1234_5678,
        eflags: 0xad7,
        cs: 0x1000,
        ds: 0x2000,
        es: 0x3000,
        ss: 0x4000,
        fs: 0x5000,
        gs: 0x6000,
    }
}

fn fail_then_query_cleared(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
) {
    let mut regs = filled(0x99, 0);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(regs.carry());
    let mut query = filled(0x59, 0);
    query.set_bx(0);
    dos.interrupt(0x21, &mut query, memory, host).unwrap();
    assert_eq!(query.ax(), DosErrorCode::InvalidFunction as u16);
}

#[test]
fn verify_flag_defaults_off_and_round_trips_without_other_register_changes() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();

    let mut get = filled(0x54, 0xab);
    get.set_carry(true);
    let mut expected = get.clone();
    expected.set_al(0);
    assert_eq!(
        dos.interrupt(0x21, &mut get, &mut memory, &mut host).unwrap(),
        DosAction::Continue
    );
    assert_eq!(get, expected);

    for al in [1_u8, 0xff, 0] {
        let mut set = filled(0x2e, al);
        set.set_carry(true);
        let expected = set.clone();
        assert_eq!(
            dos.interrupt(0x21, &mut set, &mut memory, &mut host).unwrap(),
            DosAction::Continue
        );
        assert_eq!(set, expected);

        let mut get = filled(0x54, 0xab);
        get.set_carry(true);
        let mut expected = get.clone();
        expected.set_al(u8::from(al != 0));
        assert_eq!(
            dos.interrupt(0x21, &mut get, &mut memory, &mut host).unwrap(),
            DosAction::Continue
        );
        assert_eq!(get, expected);
    }
}

#[test]
fn verify_and_disk_reset_clear_the_stored_error_and_use_the_scalar_route() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    fail_then_query_cleared(&mut dos, &mut host, &mut memory);

    let mut set = filled(0x2e, 1);
    assert_eq!(
        dos.interrupt_scalar(0x21, &mut set, &mut memory, &mut host).unwrap(),
        Some(DosAction::Continue)
    );
    let mut query = filled(0x59, 0);
    query.set_bx(0);
    dos.interrupt(0x21, &mut query, &mut memory, &mut host).unwrap();
    assert!(!query.carry());
    assert_eq!(query.ax(), 0);

    fail_then_query_cleared(&mut dos, &mut host, &mut memory);
    let mut reset = filled(0x0d, 0x5a);
    reset.set_carry(true);
    let expected = reset.clone();
    assert_eq!(
        dos.interrupt_scalar(0x21, &mut reset, &mut memory, &mut host).unwrap(),
        Some(DosAction::Continue)
    );
    assert_eq!(reset, expected);
    assert!(host.file_commit_calls.is_empty());
    let mut query = filled(0x59, 0);
    query.set_bx(0);
    dos.interrupt(0x21, &mut query, &mut memory, &mut host).unwrap();
    assert_eq!(query.ax(), 0);
}

#[test]
fn disk_reset_commits_each_owned_file_once_and_ignores_flush_errors() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let (first, first_file) = open_commit_file(&mut dos, &mut host, &mut memory, b"FIRST.DAT");
    let (_second, second_file) = open_commit_file(&mut dos, &mut host, &mut memory, b"SECOND.DAT");

    let mut dup = Registers::default();
    dup.set_ax(0x4500);
    dup.set_bx(first);
    dos.interrupt(0x21, &mut dup, &mut memory, &mut host).unwrap();
    assert!(!dup.carry());
    let copy = file_token(&dos, dup.ax());
    assert_ne!(copy, first_file);

    let orphan = DosHostFile(0x0d15);
    dos.orphan_file_handles.push(orphan);
    host.file_commit_error = Some(DosErrorCode::DiskFull);
    host.file_commit_calls.clear();

    let mut reset = filled(0x0d, 0x11);
    let expected = reset.clone();
    let handles = dos.handles.clone();
    assert_eq!(
        dos.interrupt(0x21, &mut reset, &mut memory, &mut host).unwrap(),
        DosAction::Continue
    );
    assert_eq!(reset, expected);
    assert_eq!(dos.handles, handles);
    assert_eq!(
        host.file_commit_calls,
        vec![first_file, second_file, copy, orphan]
    );

    let mut query = filled(0x59, 0);
    query.set_bx(0);
    dos.interrupt(0x21, &mut query, &mut memory, &mut host).unwrap();
    assert_eq!(query.ax(), 0);
}

#[test]
fn child_process_shares_the_verify_flag_with_its_parent() {
    let mut parent = DosKernel::new(0x400);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let mut set = filled(0x2e, 1);
    parent.interrupt(0x21, &mut set, &mut memory, &mut host).unwrap();

    let mut child = DosKernel::child_allocation_owner(&parent, 0x500);
    let mut get = filled(0x54, 0);
    child.interrupt(0x21, &mut get, &mut memory, &mut host).unwrap();
    assert_eq!(get.al(), 1);

    let mut clear = filled(0x2e, 0);
    child.interrupt(0x21, &mut clear, &mut memory, &mut host).unwrap();
    child
        .finish_child_process(&mut parent, &mut memory, &mut host, 0, 0x500)
        .unwrap();
    let mut get = filled(0x54, 0xff);
    parent.interrupt(0x21, &mut get, &mut memory, &mut host).unwrap();
    assert_eq!(get.al(), 0);
}

fn open_commit_file(
    dos: &mut DosKernel,
    host: &mut TestHost,
    memory: &mut TestMemory,
    path: &[u8],
) -> (u16, DosHostFile) {
    memory.put(0x10100, path);
    memory.put(0x10100 + path.len() as u32, &[0]);
    let mut regs = Registers { ds: 0x1000, ..Default::default() };
    regs.set_ax(0x3c00);
    regs.set_cx(0);
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, memory, host).unwrap();
    assert!(!regs.carry());
    (regs.ax(), file_token(dos, regs.ax()))
}

fn file_token(dos: &DosKernel, handle: u16) -> DosHostFile {
    let Handle::File(file) = dos.handles[&handle] else {
        panic!("expected file");
    };
    file
}
