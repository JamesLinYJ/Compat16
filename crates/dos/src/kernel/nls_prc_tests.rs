use super::{
    DosKernel, collating_table,
    tests::{TestHost, TestMemory},
    upper_case_table,
};
use crate::{DosAction, DosErrorCode};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

const SEGMENT: u16 = 0x1000;
const CALLBACK: u16 = 0x20;
const UPPERCASE: u16 = 0x100;
const COLLATING: u16 = 0x200;
const OUTPUT: u16 = 0x1000;

fn fixture() -> (DosKernel, TestMemory, TestHost) {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    memory.put(real_address(SEGMENT, CALLBACK).0, &[0xcb]);
    memory.put(
        real_address(SEGMENT, UPPERCASE).0,
        upper_case_table(CodePage::Cp936).unwrap(),
    );
    memory.put(
        real_address(SEGMENT, COLLATING).0,
        collating_table(CodePage::Cp936).unwrap(),
    );
    dos.set_case_map_address(CodePage::Cp936, SEGMENT, CALLBACK)
        .unwrap();
    dos.set_uppercase_table_address(CodePage::Cp936, SEGMENT, UPPERCASE)
        .unwrap();
    dos.set_collating_table_address(CodePage::Cp936, SEGMENT, COLLATING)
        .unwrap();
    let mut host = TestHost::default();
    host.code_page = Some(CodePage::Cp936);
    (dos, memory, host)
}

fn read(memory: &TestMemory, length: usize) -> Vec<u8> {
    let mut output = vec![0; length];
    memory
        .read(real_address(SEGMENT, OUTPUT), &mut output)
        .unwrap();
    output
}

#[test]
fn prc_legacy_current_explicit_and_extended_ids_return_verified_format_and_keep_tail() {
    for (ax, bx) in [(0x3800, 0), (0x3856, 0), (0x38ff, 86)] {
        let (mut dos, mut memory, mut host) = fixture();
        memory.put(real_address(SEGMENT, OUTPUT).0, &[0xcc; 32]);
        let mut regs = Registers {
            eax: 0xabcd_0000 | ax,
            ebx: 0xbcde_0000 | bx,
            ecx: 0x1234_5678,
            edx: 0x2345_0000 | u32::from(OUTPUT),
            ds: SEGMENT,
            eflags: 0x0203,
            ..Registers::default()
        };
        let before = regs.clone();
        assert_eq!(
            dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
                .unwrap(),
            DosAction::Continue
        );
        let mut expected_regs = before;
        expected_regs.set_ax(86);
        expected_regs.set_bx(86);
        expected_regs.set_carry(false);
        assert_eq!(regs, expected_regs);
        let mut expected = vec![0; 24];
        expected[0] = 2;
        expected[2] = b'\\';
        expected[7] = b',';
        expected[9] = b'.';
        expected[11] = b'-';
        expected[13] = b':';
        expected[16] = 2;
        expected[17] = 1;
        expected[18..22].copy_from_slice(&[CALLBACK as u8, 0, 0, 0x10]);
        expected[22] = b',';
        expected.extend_from_slice(&[0xcc; 8]);
        assert_eq!(read(&memory, 32), expected);
    }
}

#[test]
fn prc_extended_record_returns_country_code_page_and_callback_with_bounded_length() {
    let (mut dos, mut memory, mut host) = fixture();
    memory.put(real_address(SEGMENT, OUTPUT).0, &[0xcc; 48]);
    let mut regs = Registers {
        eax: 0x6501,
        ebx: 0xffff,
        ecx: 0xffff,
        edx: 0xffff,
        es: SEGMENT,
        edi: u32::from(OUTPUT),
        eflags: 0x202,
        ..Registers::default()
    };
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!((regs.ax(), regs.cx(), regs.carry()), (936, 41, false));
    let bytes = read(&memory, 48);
    assert_eq!(&bytes[..9], &[1, 38, 0, 86, 0, 0xa8, 3, 2, 0]);
    assert_eq!(bytes[9], b'\\');
    assert_eq!(bytes[24], 1);
    assert_eq!(&bytes[25..29], &[CALLBACK as u8, 0, 0, 0x10]);
    assert_eq!(&bytes[41..], &[0xcc; 7]);
    // Explicit queries are independent of the active code page, but the pair
    // itself must be backed by the installed PRC/936 profile.
    host.code_page = Some(CodePage::Cp437);
    regs.set_ax(0x6501);
    regs.set_bx(936);
    regs.set_dx(86);
    regs.set_cx(5);
    memory.put(real_address(SEGMENT, OUTPUT).0, &[0xcc; 48]);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(read(&memory, 8), [1, 2, 0, 86, 0, 0xcc, 0xcc, 0xcc]);
}

#[test]
fn prc_extended_table_queries_select_the_correct_immutable_records() {
    for (function, offset, length) in [
        (2, UPPERCASE, 128),
        (4, UPPERCASE, 128),
        (6, COLLATING, 256),
    ] {
        let (mut dos, mut memory, mut host) = fixture();
        let mut regs = Registers {
            eax: 0x6500 | function,
            ebx: 0xffff,
            ecx: 5,
            edx: 0xffff,
            es: SEGMENT,
            edi: u32::from(OUTPUT),
            ..Registers::default()
        };
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert!(!regs.carry());
        assert_eq!(regs.ax(), 936);
        assert_eq!(
            read(&memory, 5),
            [function as u8, offset as u8, (offset >> 8) as u8, 0, 0x10]
        );
        assert_eq!(
            memory.read_u16(real_address(SEGMENT, offset)).unwrap(),
            length
        );
    }
}

#[test]
fn prc_unknown_pairs_and_country_changes_fail_without_touching_the_buffer_or_profile() {
    let (mut dos, mut memory, mut host) = fixture();
    for (ax, bx, dx) in [
        (0x3801, 0, OUTPUT),
        (0x3800, 0, 0xffff),
        (0x6501, 936, 1),
        (0x6506, 437, 86),
    ] {
        memory.put(real_address(SEGMENT, OUTPUT).0, &[0xcc; 48]);
        let mut regs = Registers {
            eax: ax,
            ebx: bx,
            ecx: 41,
            edx: u32::from(dx),
            ds: SEGMENT,
            es: SEGMENT,
            edi: u32::from(OUTPUT),
            ..Registers::default()
        };
        dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap();
        assert_eq!(regs.ax(), DosErrorCode::FileNotFound as u16);
        assert!(regs.carry());
        assert_eq!(read(&memory, 48), [0xcc; 48]);
    }
    assert_eq!(host.code_page, Some(CodePage::Cp936));
}
