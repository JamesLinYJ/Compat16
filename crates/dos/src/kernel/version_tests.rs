use super::DosKernel;
use super::tests::TestMemory;
use guest_core::{GuestMemory, Registers, real_address};

#[test]
fn reported_dos_version_uses_live_current_psp_metadata() {
    let mut memory = TestMemory::new();
    let mut dos = DosKernel::new(0x1000);
    for version in [0x0005_u16, 0x0007, 0x1606, 0, 0xffff] {
        memory
            .write(real_address(0x1000, 0x40), &version.to_le_bytes())
            .unwrap();
        let mut regs = Registers {
            ds: 0x4321,
            es: 0x8765,
            ..Default::default()
        };
        regs.set_ax(0x3000);
        dos.dos_version(&mut regs, &memory).unwrap();
        assert_eq!((regs.ax(), regs.bx(), regs.cx()), (version, 0xff00, 0));
        assert_eq!((regs.ds, regs.es), (0x4321, 0x8765));
    }
    memory
        .write(real_address(0x1100, 0x40), &0x1f03_u16.to_le_bytes())
        .unwrap();
    dos.psp_segment = 0x1100;
    let mut regs = Registers::default();
    regs.set_ax(0x3001);
    dos.dos_version(&mut regs, &memory).unwrap();
    assert_eq!((regs.ax(), regs.bx()), (0x1f03, 0));
    regs.set_ax(0x3306);
    dos.extended_version(&mut regs);
    assert_eq!((regs.bx(), regs.dx()), (0x3205, 0));
}

#[test]
fn reported_dos_version_non_flag_selectors_return_oem_and_keep_high_registers() {
    let mut memory = TestMemory::new();
    memory
        .write(real_address(0x1000, 0x40), &7_u16.to_le_bytes())
        .unwrap();
    let mut regs = Registers {
        eax: 0xaabb_3042,
        ebx: 0xccdd_7f12,
        ecx: 0xeeff_1234,
        ..Default::default()
    };
    DosKernel::new(0x1000)
        .dos_version(&mut regs, &memory)
        .unwrap();
    assert_eq!(
        (regs.eax, regs.ebx, regs.ecx),
        (0xaabb_0007, 0xccdd_ff00, 0xeeff_0000)
    );
}

#[test]
fn reported_dos_version_checks_metadata_before_changing_results() {
    let memory = TestMemory::new();
    let mut regs = Registers {
        eax: 0x1234_3000,
        ebx: 0x5678_9abc,
        ecx: 0xdef0_1234,
        ..Default::default()
    };
    assert!(
        DosKernel::new(0xffff)
            .dos_version(&mut regs, &memory)
            .is_err()
    );
    assert_eq!(
        (regs.eax, regs.ebx, regs.ecx),
        (0x1234_3000, 0x5678_9abc, 0xdef0_1234)
    );
}
