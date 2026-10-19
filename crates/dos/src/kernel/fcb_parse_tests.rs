use super::{
    DosKernel,
    tests::{TestHost, TestMemory},
};
use crate::{DosAction, DosError};
use guest_core::{GuestMemory, Registers, real_address};
use text_codec::CodePage;

const INPUT: u16 = 0x100;
const OUTPUT: u16 = 0x200;
const INITIAL: [u8; 16] = *b"\x02OLDNAME XYZ\xa1\xa2\xa3\xa4";

fn registers(flags: u8) -> Registers {
    Registers {
        eax: 0xaabb_2900 | u32::from(flags),
        ebx: 0xbbcc_1234,
        ecx: 0xccdd_2345,
        edx: 0xddee_3456,
        esi: 0xeeff_0100,
        edi: 0xffaa_0200,
        ebp: 0x1122_3344,
        ds: 0x1000,
        es: 0x1000,
        eflags: 0xad57,
        ..Default::default()
    }
}

fn call(input: &[u8], flags: u8, page: CodePage) -> (Registers, [u8; 37]) {
    let mut memory = TestMemory::new();
    memory.put(0x10100, input);
    memory.put(0x101ff, &[0xcc; 39]);
    memory.put(0x10200, &INITIAL);
    let mut host = TestHost::default();
    host.code_page = Some(page);
    let mut regs = registers(flags);
    assert_eq!(
        DosKernel::new(0x1000)
            .interrupt(0x21, &mut regs, &mut memory, &mut host)
            .unwrap(),
        DosAction::Continue
    );
    let mut fcb = [0; 37];
    memory
        .read(real_address(regs.es, OUTPUT), &mut fcb)
        .unwrap();
    let mut guard = [0; 1];
    memory
        .read(real_address(regs.es, OUTPUT - 1), &mut guard)
        .unwrap();
    assert_eq!(guard, [0xcc]);
    assert_eq!(&fcb[12..16], &[0; 4]);
    assert_eq!(&fcb[16..], &[0xcc; 21]);
    (regs, fcb)
}

#[test]
fn fcb_parse_builds_unopened_prefix_and_preserves_non_outputs() {
    let (regs, fcb) = call(b"c:readme.txt rest\r", 0, CodePage::Cp437);
    assert_eq!(&fcb[..12], b"\x03README  TXT");
    let mut expected = registers(0);
    expected.set_al(0);
    expected.set_si(INPUT + 12);
    assert_eq!(regs, expected);
}

#[test]
fn fcb_parse_preserve_bits_are_independent_for_absent_fields() {
    for flags in 0..16 {
        let (regs, fcb) = call(b"\r", flags, CodePage::Cp437);
        assert_eq!(regs.al(), 0);
        assert_eq!(regs.si(), INPUT);
        assert_eq!(fcb[0], if flags & 2 != 0 { INITIAL[0] } else { 0 });
        assert_eq!(
            &fcb[1..9],
            if flags & 4 != 0 {
                &INITIAL[1..9]
            } else {
                b"        "
            }
        );
        assert_eq!(
            &fcb[9..12],
            if flags & 8 != 0 {
                &INITIAL[9..12]
            } else {
                b"   "
            }
        );
    }
}

#[test]
fn fcb_parse_explicit_empty_extension_replaces_preserved_extension() {
    let (regs, fcb) = call(b".\0", 14, CodePage::Cp437);
    assert_eq!(&fcb[..9], &INITIAL[..9]);
    assert_eq!(&fcb[9..12], b"   ");
    assert_eq!(regs.si(), INPUT + 1);
    let (_, fcb) = call(b"new.\0", 14, CodePage::Cp437);
    assert_eq!(&fcb[..12], b"\x02NEW        ");
}

#[test]
fn fcb_parse_scans_blanks_and_only_one_optional_other_separator() {
    let (regs, _) = call(b" \t,one.txt\0", 0, CodePage::Cp437);
    assert_eq!(regs.si(), INPUT + 2);
    let (regs, fcb) = call(b" \t,one.txt\0", 1, CodePage::Cp437);
    assert_eq!(regs.si(), INPUT + 10);
    assert_eq!(&fcb[1..12], b"ONE     TXT");
    let (regs, fcb) = call(b"  , ,one.txt\0", 1, CodePage::Cp437);
    assert_eq!(regs.si(), INPUT + 4);
    assert_eq!(&fcb[1..12], b"           ");
}

#[test]
fn fcb_parse_expands_wildcards_and_consumes_truncated_components() {
    for (text, expected, status) in [
        (b"ab*cdefgh.xyz\0".as_slice(), b"AB??????XYZ".as_slice(), 1),
        (b"abcdefghij.abcdef\0", b"ABCDEFGHABC", 0),
        (b"a?.b?\0", b"A?      B? ", 1),
    ] {
        let (regs, fcb) = call(text, 0, CodePage::Cp437);
        assert_eq!(&fcb[1..12], expected);
        assert_eq!(regs.al(), status);
        assert_eq!(regs.si(), INPUT + (text.len() - 1) as u16);
    }
}

#[test]
fn fcb_parse_reports_invalid_drive_without_a_file_system_operation() {
    for (text, drive) in [
        (b"1:foo.bin\0".as_slice(), 0xf1),
        (b"z:foo.bin\0", 26),
        (b"@:foo.bin\0", 0),
    ] {
        let (regs, fcb) = call(text, 0, CodePage::Cp437);
        assert_eq!(regs.al(), 0xff);
        assert_eq!(fcb[0], drive);
        assert_eq!(&fcb[1..12], b"FOO     BIN");
        assert_eq!(regs.si(), INPUT + (text.len() - 1) as u16);
    }
}

#[test]
fn fcb_parse_uses_oem_uppercase_and_keeps_dbcs_trails_out_of_syntax() {
    let (_, fcb) = call(b"\x81a.txt\0", 0, CodePage::Cp437);
    assert_eq!(&fcb[1..12], b"\x9aA      TXT");
    let (regs, fcb) = call(b"\xa1\xa1a\x81\\b.t\x81?\0", 0, CodePage::Cp936);
    assert_eq!(regs.al(), 0);
    assert_eq!(&fcb[1..12], b"A\x81\\B    T\x81?");
}

#[test]
fn fcb_parse_never_leaves_half_a_dbcs_character_in_a_component() {
    let (regs, fcb) = call(b"aaaaaaa\x81\\x.ab\x81\\z\0", 0, CodePage::Cp936);
    assert_eq!(&fcb[1..12], b"AAAAAAA AB ");
    assert_eq!(regs.si(), INPUT + 16);
    assert_eq!(regs.al(), 0);
}

#[test]
fn fcb_parse_real_mode_input_and_output_keep_offset_wrap() {
    let mut memory = TestMemory::new();
    memory.put(0x1fffc, b"ab.t");
    memory.put(0x10000, b"xt\0");
    let mut regs = registers(0);
    regs.set_si(0xfffc);
    regs.es = 0x0800;
    regs.set_di(0xfff8);
    DosKernel::new(0x1000)
        .interrupt(0x21, &mut regs, &mut memory, &mut TestHost::default())
        .unwrap();
    let mut fcb = [0; 16];
    memory
        .read(real_address(0x0800, 0xfff8), &mut fcb[..8])
        .unwrap();
    memory.read(real_address(0x0800, 0), &mut fcb[8..]).unwrap();
    assert_eq!(&fcb[..12], b"\0AB      TXT");
    assert_eq!((regs.si(), regs.di(), regs.es), (2, 0xfff8, 0x0800));
}

#[test]
fn fcb_parse_bad_spans_leave_output_and_registers_unchanged() {
    for bad_output in [false, true] {
        let mut memory = TestMemory::new();
        memory.put(0x10100, b"ok.txt\0");
        memory.put(0x10200, &[0xa5; 16]);
        memory.put(0x1ffff, b"a");
        let mut regs = registers(0);
        if bad_output {
            regs.es = 0x1fff;
            regs.set_di(15);
        } else {
            regs.ds = 0x1fff;
            regs.set_si(15);
        }
        let before = regs.clone();
        assert!(
            DosKernel::new(0x1000)
                .interrupt(0x21, &mut regs, &mut memory, &mut TestHost::default())
                .is_err()
        );
        assert_eq!(regs, before);
        let mut bytes = [0; 16];
        memory
            .read(real_address(0x1000, OUTPUT), &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0xa5; 16]);
    }
}

#[test]
fn fcb_parse_unterminated_segment_is_bounded_and_does_not_publish_a_prefix() {
    let mut memory = TestMemory::new();
    memory.put(0x10000, &vec![b'a'; 0x10000]);
    memory.put(0x1200, &[0xa5; 16]);
    let mut regs = registers(0);
    regs.set_si(0);
    regs.es = 0x0100;
    let before = regs.clone();
    assert!(matches!(
        DosKernel::new(0x1000).interrupt(0x21, &mut regs, &mut memory, &mut TestHost::default()),
        Err(DosError::MalformedGuestInput(_))
    ));
    assert_eq!(regs, before);
    let mut bytes = [0; 16];
    memory
        .read(real_address(0x0100, OUTPUT), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0xa5; 16]);
}

#[test]
fn fcb_parse_invalid_drive_status_does_not_replace_the_extended_error() {
    let mut dos = DosKernel::new(0x1000);
    let mut memory = TestMemory::new();
    let mut host = TestHost::default();
    let mut regs = Registers::default();
    regs.set_ax(0xff00);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert!(regs.carry());
    memory.put(0x10100, b"z:file.txt\0");
    regs = registers(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(regs.al(), 0xff);
    assert!(regs.carry());
    regs.set_ax(0x5900);
    regs.set_bx(0);
    dos.interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert_eq!(regs.ax(), 1);
}
