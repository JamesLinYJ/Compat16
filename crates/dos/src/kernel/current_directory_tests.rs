//! AH=47h returns the DOS success AX used by legacy pathname scanners.

use super::*;

fn registers(drive: u8) -> Registers {
    Registers {
        eax: 0xabcd_4743,
        ebx: 0x1234_5678,
        ecx: 0x9876_5432,
        edx: 0x4321_0000 | u32::from(drive),
        esi: 0x1357_0200,
        edi: 0x2468_0300,
        ds: 0x1000,
        es: 0x4321,
        eflags: 0xad7,
        ..Default::default()
    }
}

#[test]
fn current_directory_success_returns_0100_for_root_default_and_explicit_drives() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    host.drive = 2;
    host.current_directories.insert(2, b"C:\\WORK".to_vec());
    let mut memory = TestMemory::new();
    for (drive, path) in [(0, b"WORK\0".as_slice()), (3, b"WORK\0"), (1, b"\0")] {
        memory.put(0x101ff, &[0xa5; 66]);
        let mut regs = registers(drive);
        let mut expected = regs.clone();
        expected.set_ax(0x0100);
        expected.set_carry(false);
        assert_eq!(
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
                .unwrap(),
            DosAction::Continue
        );
        assert_eq!(regs, expected);
        assert_eq!(&memory.0[0x10200..0x10200 + path.len()], path);
        assert_eq!(memory.0[0x101ff], 0xa5);
        assert!(
            memory.0[0x10200 + path.len()..0x10241]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }
}

#[test]
fn current_directory_invalid_drive_keeps_error_code_and_destination() {
    for drive in [4, 26, 27, 255] {
        let mut dos = DosKernel::new(0x1000);
        let mut host = TestHost::default();
        let mut memory = TestMemory::new();
        memory.put(0x10200, &[0xa5; 64]);
        let before = memory.0.clone();
        let mut regs = registers(drive);
        let mut expected = regs.clone();
        expected.set_ax(DosErrorCode::UnknownUnit as u16);
        expected.set_carry(true);
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert_eq!(regs, expected);
        assert_eq!(memory.0, before);
    }
}

#[test]
fn current_directory_short_destination_does_not_report_success_or_write() {
    let mut dos = DosKernel::new(0x1000);
    let mut host = TestHost::default();
    let mut memory = TestMemory::with_size(0x1023f);
    let before = memory.0.clone();
    let mut regs = registers(0);
    let expected = regs.clone();
    assert!(
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .is_err()
    );
    assert_eq!(regs, expected);
    assert_eq!(memory.0, before);
}
