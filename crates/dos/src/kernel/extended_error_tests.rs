use super::{
    DosKernel,
    tests::{TestHost, TestMemory},
};
use crate::{DosAction, DosErrorCode};
use guest_core::Registers;

fn query(dos: &mut DosKernel) -> Registers {
    let mut regs = Registers {
        eax: 0x1234_5900,
        ebx: 0x2345_abcd,
        ecx: 0x3456_78ef,
        edx: 0x4567_8901,
        esi: 0x5678_9abc,
        edi: 0x6789_abcd,
        ebp: 0x789a_bcde,
        esp: 0x89ab_cdef,
        eip: 0x9abc_def0,
        cs: 0x1111,
        ds: 0x2222,
        es: 0x3333,
        ss: 0x4444,
        fs: 0x5555,
        gs: 0x6666,
        eflags: 0xad57,
    };
    let before = regs.clone();
    assert_eq!(
        dos.interrupt(
            0x21,
            &mut regs,
            &mut TestMemory::new(),
            &mut TestHost::default()
        )
        .unwrap(),
        DosAction::Continue
    );
    let mut expected = before;
    expected.set_ax(regs.ax());
    expected.set_bx(regs.bx());
    expected.set_ch(regs.ch());
    expected.es = 0;
    expected.set_di(0);
    expected.set_carry(false);
    assert_eq!(
        regs, expected,
        "AH=59 changed a non-output register or flag"
    );
    regs
}

fn assert_error(dos: &mut DosKernel, code: u16, class: u8, action: u8, locus: u8) {
    let regs = query(dos);
    assert_eq!(
        (regs.ax(), regs.bh(), regs.bl(), regs.ch()),
        (code, class, action, locus)
    );
}

#[test]
fn extended_error_initial_query_and_repeat_queries_preserve_nonoutputs() {
    let mut dos = DosKernel::new(0x1000);
    assert_eq!(query(&mut dos).ax(), 0);
    let mut regs = Registers::default();
    dos.complete_exec_failure(&mut regs, DosErrorCode::InvalidFormat);
    assert_eq!(regs.ax(), 11);
    assert!(regs.carry());
    assert_error(&mut dos, 11, 9, 3, 1);
    assert_error(&mut dos, 11, 9, 3, 1);
}

#[test]
fn extended_error_real_open_records_missing_file_with_dos_classification() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"MISSING.TXT\0");
    let mut regs = Registers::default();
    regs.ds = 0x1000;
    regs.set_dx(0x100);
    regs.set_ax(0x3d00);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut TestHost::default())
        .unwrap();
    assert!(regs.carry());
    assert_eq!(regs.ax(), 2);
    assert_error(&mut dos, 2, 8, 3, 2);
}

#[test]
fn extended_error_failure_families_record_only_the_returned_failure() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    memory.put(0x10040, &super::DEFAULT_DOS_REPORTED_VERSION.to_le_bytes());
    let mut host = TestHost::default();
    for (ax, bx, cx, dx, code, class, action, locus) in [
        (0xff00, 0, 0, 0, 1, 7, 4, 1),
        (0x3e00, 0xffff, 0, 0, 6, 7, 4, 1),
        (0x5a00, 0, 0x8000, 0, 5, 3, 3, 1),
        (0x3800, 0, 0, 0xffff, 2, 8, 3, 2),
        (0x4b01, 0, 0, 0, 1, 7, 4, 1),
    ] {
        let mut regs = Registers::default();
        regs.set_ax(ax);
        regs.set_bx(bx);
        regs.set_cx(cx);
        regs.set_dx(dx);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert!(regs.carry());
        assert_eq!(regs.ax(), code);
        assert_error(&mut dos, code, class, action, locus);
    }
    // DOS version preserves incoming carry and returns AX=0005. It must not
    // overwrite error 1 with a fictitious access-denied result (5).
    let mut regs = Registers::default();
    regs.set_ax(0x3000);
    regs.set_carry(true);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(regs.ax(), 5);
    assert!(regs.carry());
    assert_error(&mut dos, 1, 7, 4, 1);
}

#[test]
fn extended_error_exec_tree_shares_state_and_psp_switch_does_not_clear_it() {
    let mut parent = DosKernel::new(0x1000);
    let mut child = DosKernel::child_allocation_owner(&parent, 0x2000);
    child.complete_service_failure(&mut Registers::default(), 18);
    assert_error(&mut parent, 18, 8, 3, 2);
    parent.complete_service_failure(&mut Registers::default(), 8);
    assert_error(&mut child, 8, 1, 4, 5);
    let mut regs = Registers::default();
    regs.set_ax(0x5000);
    regs.set_bx(0x3000);
    parent
        .interrupt(
            0x21,
            &mut regs,
            &mut TestMemory::new(),
            &mut TestHost::default(),
        )
        .unwrap();
    assert_error(&mut parent, 8, 1, 4, 5);
    assert_eq!(query(&mut DosKernel::new(0x4000)).ax(), 0);
}

#[test]
fn extended_error_unknown_external_codes_remain_exact_and_protected_query_has_no_pointer() {
    let mut dos = DosKernel::new(0x1000);
    dos.complete_service_failure(&mut Registers::default(), 0x1234);
    assert_error(&mut dos, 0x1234, 13, 4, 1);
    let mut regs = Registers::default();
    regs.ds = 0x0078;
    regs.set_ax(0x5900);
    assert_eq!(
        dos.interrupt_scalar(
            0x21,
            &mut regs,
            &mut TestMemory::new(),
            &mut TestHost::default()
        )
        .unwrap(),
        Some(DosAction::Continue)
    );
    assert_eq!((regs.ax(), regs.es, regs.di()), (0x1234, 0, 0));
}
