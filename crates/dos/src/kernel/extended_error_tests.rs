//! INT 21h/AH=59h reports the last DOS failure and AH=6Ah commits like AH=68h.

use super::super::extended_error::ExtendedError;
use super::*;

fn open_missing(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory) -> Registers {
    memory.put(0x10100, b"MISSING.DAT\0");
    let mut regs = Registers {
        ds: 0x1000,
        ..Registers::default()
    };
    regs.set_ax(0x3d00);
    regs.set_dx(0x100);
    assert_eq!(
        dos.interrupt(0x21, &mut regs, memory, host).unwrap(),
        DosAction::Continue
    );
    assert!(regs.carry());
    assert_eq!(regs.ax(), DosErrorCode::FileNotFound as u16);
    regs
}

fn query(dos: &mut DosKernel, host: &mut TestHost, memory: &mut TestMemory, bx: u16) -> Registers {
    let mut regs = Registers {
        eax: 0x1111_5900,
        ebx: 0x2222_0000 | u32::from(bx),
        ecx: 0x3333_abcd,
        edx: 0x4444_5678,
        esi: 0x5555_1111,
        edi: 0x6666_2222,
        ebp: 0x7777_3333,
        esp: 0x8888_4444,
        eip: 0x9999_5555,
        eflags: 0xad7,
        cs: 0x1000,
        ds: 0x2000,
        es: 0x3000,
        ss: 0x4000,
        fs: 0x5000,
        gs: 0x6000,
    };
    assert_eq!(
        dos.interrupt(0x21, &mut regs, memory, host).unwrap(),
        DosAction::Continue
    );
    regs
}

fn assert_classified(regs: &Registers, code: u16) {
    let expected = if code == 0 {
        ExtendedError::NONE
    } else {
        ExtendedError::classify(code)
    };
    assert!(!regs.carry());
    assert_eq!(regs.ax(), expected.code);
    assert_eq!(regs.bh(), expected.class);
    assert_eq!(regs.bl(), expected.action);
    assert_eq!(regs.ch(), expected.locus);
}

#[test]
fn extended_error_is_empty_until_a_failed_call_and_survives_repeat_queries() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    let before = query(&mut dos, &mut host, &mut memory, 0);
    assert_classified(&before, 0);
    assert_eq!(before.cl(), 0xcd);
    assert_eq!(before.dx(), 0x5678);
    assert_eq!(before.es, 0x3000);
    assert_eq!(before.di(), 0x2222);
    assert_eq!(before.ds, 0x2000);

    open_missing(&mut dos, &mut host, &mut memory);
    let first = query(&mut dos, &mut host, &mut memory, 0);
    let second = query(&mut dos, &mut host, &mut memory, 0);
    assert_classified(&first, DosErrorCode::FileNotFound as u16);
    assert_eq!(first.ax(), second.ax());
    assert_eq!(first.bx(), second.bx());
    assert_eq!(first.cx(), second.cx());
    assert_eq!(first.cl(), 0xcd, "only CH is an extended-error output");
}

#[test]
fn successful_call_clears_extended_error_even_when_incoming_carry_is_set() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    open_missing(&mut dos, &mut host, &mut memory);

    let mut regs = Registers::default();
    regs.set_ax(0x3000);
    regs.set_carry(true);
    assert_eq!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap(),
        DosAction::Continue
    );
    assert_eq!(regs.al(), 5, "DOS 5 version report still completes");

    let cleared = query(&mut dos, &mut host, &mut memory, 0);
    assert_classified(&cleared, 0);
}

#[test]
fn nonzero_bx_replaces_the_stored_error_with_invalid_function() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    open_missing(&mut dos, &mut host, &mut memory);
    let rejected = query(&mut dos, &mut host, &mut memory, 1);
    assert!(rejected.carry());
    assert_eq!(rejected.ax(), DosErrorCode::InvalidFunction as u16);
    assert_eq!(
        rejected.bx(),
        1,
        "a rejected subfunction leaves BX unchanged"
    );
    let stored = query(&mut dos, &mut host, &mut memory, 0);
    assert_classified(&stored, DosErrorCode::InvalidFunction as u16);
}

#[test]
fn commit_aliases_return_invalid_handle_and_keep_the_host_cause() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"COMMIT.DAT\0");
    let mut regs = Registers {
        ds: 0x1000,
        ..Registers::default()
    };
    regs.set_ax(0x3c00);
    regs.set_cx(0);
    regs.set_dx(0x100);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert!(!regs.carry());
    let handle = regs.ax();

    for function in [0x68u8, 0x6a] {
        host.file_commit_error = Some(DosErrorCode::DiskFull);
        let mut regs = Registers {
            ds: 0x1000,
            ..Registers::default()
        };
        regs.set_ax(u16::from(function) << 8);
        regs.set_bx(handle);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), DosErrorCode::InvalidHandle as u16);
        let stored = query(&mut dos, &mut host, &mut memory, 0);
        assert_classified(&stored, DosErrorCode::DiskFull as u16);
    }
}

#[test]
fn protected_scalar_query_and_exec_failure_use_the_same_stored_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::new();
    open_missing(&mut dos, &mut host, &mut memory);
    let mut regs = Registers::default();
    regs.set_ax(0x5900);
    assert_eq!(
        dos.interrupt_scalar(0x21, &mut regs, &mut memory, &mut host)
            .unwrap(),
        Some(DosAction::Continue),
    );
    assert_classified(&regs, DosErrorCode::FileNotFound as u16);

    let mut child = DosKernel::new(0x1800);
    let mut child_regs = Registers::default();
    child_regs.set_ax(0x5900);
    child
        .interrupt(0x21, &mut child_regs, &mut memory, &mut host)
        .unwrap();
    assert_classified(&child_regs, 0);

    let mut failed = Registers::default();
    dos.complete_exec_failure(&mut failed, DosErrorCode::InsufficientMemory);
    assert!(failed.carry());
    assert_eq!(failed.ax(), DosErrorCode::InsufficientMemory as u16);
    let stored = query(&mut dos, &mut host, &mut memory, 0);
    assert_classified(&stored, DosErrorCode::InsufficientMemory as u16);
}
