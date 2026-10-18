use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, protected: bool, page: u32) {
    let root = tempfile::tempdir().unwrap();
    let name = text_codec::decode(
        image::extended_open_filename(page == 936),
        text_codec::CodePage::try_from(page).unwrap(),
    )
    .unwrap();
    let input = root.path().join(name);
    std::fs::write(&input, b"open-ok").unwrap();
    let program = root.path().join(if protected {
        "EXTOPEN.EXE"
    } else {
        "EXTOPEN.COM"
    });
    std::fs::write(
        &program,
        image::extended_open_program(protected, page == 936),
    )
    .unwrap();
    run_with_dos_code_page(&program, page, engine);
    assert_eq!(std::fs::read(input).unwrap(), b"open-ok");
    assert!(!root.path().join("NEW.DAT").exists());
    assert!(!root.path().join("MISSING.DAT").exists());
}

#[test]
fn extended_open_native_jit_real_cp437() {
    verify("jit", false, 437);
}
#[test]
fn extended_open_native_interpreter_real_cp437() {
    verify("interpreter", false, 437);
}
#[test]
fn extended_open_native_jit_real_cp936() {
    verify("jit", false, 936);
}
#[test]
fn extended_open_native_interpreter_real_cp936() {
    verify("interpreter", false, 936);
}
#[test]
fn extended_open_native_jit_protected_cp437() {
    verify("jit", true, 437);
}
#[test]
fn extended_open_native_interpreter_protected_cp437() {
    verify("interpreter", true, 437);
}
#[test]
fn extended_open_native_jit_protected_cp936() {
    verify("jit", true, 936);
}
#[test]
fn extended_open_native_interpreter_protected_cp936() {
    verify("interpreter", true, 936);
}
