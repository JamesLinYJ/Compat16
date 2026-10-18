use super::{DosKernel, TestHost, TestMemory};
use crate::DosErrorCode;
use guest_core::Registers;
use text_codec::CodePage;

fn registers() -> Registers {
    Registers {
        eax: 0x1234_6000,
        ebx: 0x1111_2222,
        ecx: 0x3333_4444,
        edx: 0x5555_6666,
        esi: 0x7777_0100,
        edi: 0x8888_0300,
        ds: 0x1000,
        es: 0x1000,
        eflags: 0xad57,
        ..Default::default()
    }
}
fn host(page: CodePage) -> TestHost {
    let mut host = TestHost::default();
    host.drive = 2;
    host.code_page = Some(page);
    host.current_directories
        .insert(2, b"C:\\WORK\\SUB".to_vec());
    host
}

#[test]
fn canonical_paths_are_lexical_and_preserve_registers_and_output_guards() {
    for (source, expected) in [
        (
            b"input.txt\0".as_slice(),
            b"C:\\WORK\\SUB\\INPUT.TXT\0".as_slice(),
        ),
        (b"c:/missing/../dir/file.txt\0", b"C:\\DIR\\FILE.TXT\0"),
        (b"..\\new.txt\0", b"C:\\WORK\\NEW.TXT\0"),
        (b".\\\0", b"C:\\WORK\\SUB\\\0"),
        (b"\\\0", b"C:\\\0"),
        (b"foo.\0", b"C:\\WORK\\SUB\\FOO\0"),
        (b"foo*zzz.longext\0", b"C:\\WORK\\SUB\\FOO?????.LON\0"),
        (b"nonexistentlong.txt\0", b"C:\\WORK\\SUB\\NONEXIST.TXT\0"),
    ] {
        let mut memory = TestMemory::new();
        memory.put(0x10100, source);
        memory.put(0x102ff, &[0xcc; 130]);
        let mut regs = registers();
        let mut expected_regs = regs.clone();
        expected_regs.set_ax(0x5c);
        expected_regs.set_carry(false);
        DosKernel::new(0x1000)
            .interrupt(0x21, &mut regs, &mut memory, &mut host(CodePage::Cp437))
            .unwrap();
        assert_eq!(regs, expected_regs);
        assert_eq!(&memory.0[0x10300..0x10300 + expected.len()], expected);
        assert_eq!(memory.0[0x102ff], 0xcc);
        assert!(
            memory.0[0x10300 + expected.len()..0x10381]
                .iter()
                .all(|b| *b == 0xcc)
        );
    }
}

#[test]
fn canonical_path_uses_existing_aliases_and_reparses_no_guest_output() {
    let mut host = host(CodePage::Cp437);
    host.short_names.insert(
        (b"C:\\WORK\\SUB\\".to_vec(), b"Long directory name".to_vec()),
        b"LONGDI~1".to_vec(),
    );
    host.short_names.insert(
        (
            b"C:\\WORK\\SUB\\LONGDI~1\\".to_vec(),
            b"LongFileName.txt".to_vec(),
        ),
        b"LONGFI~2.TXT".to_vec(),
    );
    let mut memory = TestMemory::new();
    memory.put(0x10100, b"Long directory name/LongFileName.txt\0");
    let mut regs = registers();
    regs.set_di(0x100);
    DosKernel::new(0x1000)
        .interrupt(0x21, &mut regs, &mut memory, &mut host)
        .unwrap();
    assert!(!regs.carry());
    let expected = b"C:\\WORK\\SUB\\LONGDI~1\\LONGFI~2.TXT\0";
    assert_eq!(&memory.0[0x10100..0x10100 + expected.len()], expected);
    assert_eq!(host.short_name_queries.len(), 2);
}

#[test]
fn canonical_path_dbcs_trail_slash_and_oem_case_stay_in_components() {
    for (page, source, expected) in [
        (
            CodePage::Cp437,
            b"\x81file.txt\0".as_slice(),
            b"C:\\WORK\\SUB\\\x9aFILE.TXT\0".as_slice(),
        ),
        (
            CodePage::Cp936,
            b"\x81\x5ca.txt\0",
            b"C:\\WORK\\SUB\\\x81\x5cA.TXT\0",
        ),
        (
            CodePage::Cp936,
            b"1234567\x81\x5c.txt\0",
            b"C:\\WORK\\SUB\\1234567.TXT\0",
        ),
    ] {
        let mut memory = TestMemory::new();
        memory.put(0x10100, source);
        let mut regs = registers();
        DosKernel::new(0x1000)
            .interrupt(0x21, &mut regs, &mut memory, &mut host(page))
            .unwrap();
        assert!(!regs.carry());
        assert_eq!(&memory.0[0x10300..0x10300 + expected.len()], expected);
    }
}

#[test]
fn canonical_path_errors_leave_output_unchanged_and_return_real_error() {
    for (source, code) in [
        (b"z:\\file.txt\0".as_slice(), DosErrorCode::PathNotFound),
        (b"C:\0", DosErrorCode::FileNotFound),
        (b"\\..\\file\0", DosErrorCode::PathNotFound),
        (b"\\\\server\\share\0", DosErrorCode::PathNotFound),
        (b"*\\child\0", DosErrorCode::PathNotFound),
        (b"bad.name.ext\0", DosErrorCode::FileNotFound),
        (b"\x81\0", DosErrorCode::PathNotFound),
    ] {
        let mut memory = TestMemory::new();
        memory.put(0x10100, source);
        memory.put(0x10300, &[0xcc; 128]);
        let before = memory.0.clone();
        let mut regs = registers();
        let mut expected = regs.clone();
        expected.set_ax(code as u16);
        expected.set_carry(true);
        DosKernel::new(0x1000)
            .interrupt(0x21, &mut regs, &mut memory, &mut host(CodePage::Cp936))
            .unwrap();
        assert_eq!(regs, expected);
        assert_eq!(memory.0, before);
    }
}

#[test]
fn canonical_path_short_output_fails_before_host_projection_or_writes() {
    let mut host = host(CodePage::Cp437);
    let mut memory = TestMemory::with_size(0x1037f);
    memory.put(0x10100, b"LongFileName.txt\0");
    let before = memory.0.clone();
    let mut regs = registers();
    let expected = regs.clone();
    assert!(
        DosKernel::new(0x1000)
            .interrupt(0x21, &mut regs, &mut memory, &mut host)
            .is_err()
    );
    assert_eq!(regs, expected);
    assert_eq!(memory.0, before);
    assert!(host.short_name_queries.is_empty());
}
