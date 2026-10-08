use super::{MultiplexOutcome, dispatch};
use guest_core::Registers;

fn registers_with_ax(ax: u16) -> Registers {
    Registers {
        eax: 0x1357_0000 | u32::from(ax),
        ebx: 0x2468_ace0,
        ecx: 0x89ab_cdef,
        edx: 0xfedc_ba98,
        esp: 0x7654_3210,
        ebp: 0x1020_3040,
        esi: 0x5060_7080,
        edi: 0x90a0_b0c0,
        eip: 0xd0e0_f000,
        eflags: 0xa5a5_5a5b,
        cs: 0x1111,
        ds: 0x2222,
        es: 0x3333,
        ss: 0x4444,
        fs: 0x5555,
        gs: 0x6666,
    }
}

#[test]
fn unknown_and_uninstalled_multiplex_ids_preserve_every_register() {
    for ax in [0x1687, 0xa55a] {
        let mut regs = registers_with_ax(ax);
        let before = regs.clone();

        assert_eq!(dispatch(&mut regs), MultiplexOutcome::Unclaimed, "AX={ax:04X}");
        assert_eq!(regs, before, "unclaimed AX={ax:04X} changed guest state");
    }
}

#[test]
fn xms_installation_check_is_claimed_and_only_updates_al() {
    let mut regs = registers_with_ax(0x4300);
    let mut expected = regs.clone();
    expected.set_al(0x80);

    assert_eq!(dispatch(&mut regs), MultiplexOutcome::Handled);
    assert_eq!(regs, expected);
}

#[test]
fn xms_entry_query_is_claimed_and_returns_the_registered_rom_entry() {
    let mut regs = registers_with_ax(0x4310);
    let mut expected = regs.clone();
    expected.es = crate::XMS_ENTRY.segment;
    expected.set_bx(crate::XMS_ENTRY.offset);

    assert_eq!(dispatch(&mut regs), MultiplexOutcome::Handled);
    assert_eq!(regs, expected);
    assert_eq!(regs.es, 0xf000);
    assert_eq!(regs.bx(), 0x0100);
    assert_eq!(regs.ebx & 0xffff_0000, 0x2468_0000);
}

#[test]
fn dos_owned_services_are_not_silently_treated_as_absent_providers() {
    for ax in [0x1200, 0x122e, 0x12ff] {
        let mut regs = registers_with_ax(ax);
        let before = regs.clone();
        assert_eq!(dispatch(&mut regs), MultiplexOutcome::MissingDosService);
        assert_eq!(regs, before);
    }
}

#[test]
fn absent_optional_services_distinguish_probes_from_function_calls() {
    for ah in [0x10, 0x11, 0x14] {
        let mut probe = registers_with_ax(ah << 8);
        let before = probe.clone();
        assert_eq!(dispatch(&mut probe), MultiplexOutcome::Unclaimed);
        assert_eq!(probe, before);
        let mut call = registers_with_ax((ah << 8) | 1);
        let mut expected = call.clone();
        expected.set_ax(1);
        expected.set_carry(true);
        assert_eq!(dispatch(&mut call), MultiplexOutcome::Handled);
        assert_eq!(call, expected);
    }
}
