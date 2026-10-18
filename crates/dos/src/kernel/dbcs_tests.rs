use super::{
    DosKernel, dbcs_lead_byte_table,
    tests::{TestHost, TestMemory},
};
use crate::{DosAction, DosError};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

const SEGMENT: u16 = 0x1000;
const OFFSET: u16 = 0x0123;

fn registers() -> Registers {
    Registers {
        eax: 0x1234_6300,
        ebx: 0x2345_6789,
        ecx: 0x3456_789a,
        edx: 0x4567_89ab,
        esi: 0x5678_abcd,
        edi: 0x6789_bcde,
        ebp: 0x789a_cdef,
        esp: 0x89ab_def0,
        eip: 0x9abc_ef01,
        cs: 0x1111,
        ds: 0x2222,
        es: 0x3333,
        ss: 0x4444,
        fs: 0x5555,
        gs: 0x6666,
        eflags: 0xad57,
    }
}

#[test]
fn dbcs_tables_are_terminated_pairs_for_the_selected_codec() {
    assert_eq!(dbcs_lead_byte_table(CodePage::Cp437), [0, 0]);
    assert_eq!(dbcs_lead_byte_table(CodePage::Cp936), [0x81, 0xfe, 0, 0]);
}

#[test]
fn dbcs_6300_returns_registered_table_and_preserves_other_registers_and_error_state() {
    for code_page in [CodePage::Cp437, CodePage::Cp936] {
        let mut dos = DosKernel::new(0x1000);
        let mut memory = TestMemory::new();
        let mut host = TestHost::default();
        host.code_page = Some(code_page);
        let table = dbcs_lead_byte_table(code_page);
        memory.put(real_address(SEGMENT, OFFSET).0, &table);
        dos.set_dbcs_table_address(code_page, SEGMENT, OFFSET)
            .unwrap();
        let mut regs = registers();
        dos.complete_service_failure(&mut regs, 5);
        regs.set_ax(0x6300);
        let mut expected = regs.clone();
        expected.ds = SEGMENT;
        expected.set_si(OFFSET);
        expected.set_carry(false);
        assert_eq!(
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
                .unwrap(),
            DosAction::Continue
        );
        assert_eq!(regs, expected);
        let mut bytes = vec![0; table.len()];
        memory
            .read(real_address(regs.ds, regs.si()), &mut bytes)
            .unwrap();
        assert_eq!(bytes, table);
        regs.set_ax(0x5900);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert_eq!(
            regs.ax(),
            5,
            "successful DBCS lookup must not erase prior DOS error"
        );
    }
}

#[test]
fn dbcs_missing_or_mismatched_rom_fails_before_register_publication() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut regs = registers();
    let before = regs.clone();
    let mut host = TestHost::default();
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(regs, before);
    dos.set_dbcs_table_address(CodePage::Cp437, SEGMENT, OFFSET)
        .unwrap();
    memory.put(real_address(SEGMENT, OFFSET).0, &[0xff, 0]);
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostContractViolation(_))
    ));
    assert_eq!(regs, before);
    dos.set_dbcs_table_address(CodePage::Cp437, 0xffff, 0)
        .unwrap();
    assert!(matches!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host),
        Err(DosError::HostMemoryContractViolation { .. })
    ));
    assert_eq!(regs, before);
}

#[test]
fn dbcs_table_registration_checks_the_entire_segment_span() {
    let mut dos = DosKernel::new(0x1000);
    assert!(
        dos.set_dbcs_table_address(CodePage::Cp437, SEGMENT, 0xfffe)
            .is_ok()
    );
    assert!(
        dos.set_dbcs_table_address(CodePage::Cp437, SEGMENT, 0xffff)
            .is_err()
    );
    assert!(
        dos.set_dbcs_table_address(CodePage::Cp936, SEGMENT, 0xfffc)
            .is_ok()
    );
    assert!(
        dos.set_dbcs_table_address(CodePage::Cp936, SEGMENT, 0xfffd)
            .is_err()
    );
}

#[test]
fn dbcs_child_inherits_tables_but_an_independent_kernel_requires_installation() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    memory.put(real_address(SEGMENT, OFFSET).0, &[0, 0]);
    dos.set_dbcs_table_address(CodePage::Cp437, SEGMENT, OFFSET)
        .unwrap();
    let mut child = DosKernel::child_allocation_owner(&dos, 0x2000);
    let mut host = TestHost::default();
    let mut regs = registers();
    child
        .interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!((regs.ds, regs.si()), (SEGMENT, OFFSET));
    let mut independent = DosKernel::new(0x3000);
    let mut regs = registers();
    assert!(
        independent
            .interrupt(0x21, &mut regs, &mut memory, &mut host)
            .is_err()
    );
}

#[test]
fn dbcs_unimplemented_console_selectors_return_invalid_function_without_a_pointer() {
    for selector in [1, 2, 3, 0xff] {
        let mut regs = registers();
        regs.set_al(selector);
        let before = regs.clone();
        DosKernel::new(0x1000)
            .interrupt(
                0x21,
                &mut regs,
                &mut TestMemory::new(),
                &mut TestHost::default(),
            )
            .unwrap();
        let mut expected = before;
        expected.set_ax(1);
        expected.set_carry(true);
        assert_eq!(regs, expected);
    }
}
