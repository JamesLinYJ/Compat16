use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, page: u32, protected: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join(if protected {
        "COUNTRY.EXE"
    } else {
        "COUNTRY.COM"
    });
    let prc = page == 936;
    std::fs::write(
        &program,
        if protected {
            image::country_program(prc)
        } else {
            image::country_com(prc)
        },
    )
    .unwrap();
    run_with_dos_code_page(&program, page, engine);
    let name = text_codec::decode(
        image::country_filename(prc),
        text_codec::CodePage::try_from(page).unwrap(),
    )
    .unwrap();
    assert_eq!(std::fs::read(root.path().join(name)).unwrap(), b"nls!");
}

#[test]
fn country_native_jit_real_cp437() {
    verify("jit", 437, false);
}
#[test]
fn country_native_interpreter_real_cp437() {
    verify("interpreter", 437, false);
}
#[test]
fn country_native_jit_real_cp936() {
    verify("jit", 936, false);
}
#[test]
fn country_native_interpreter_real_cp936() {
    verify("interpreter", 936, false);
}
#[test]
fn country_native_jit_protected_int_dos3call_cp437() {
    verify("jit", 437, true);
}
#[test]
fn country_native_interpreter_protected_int_dos3call_cp437() {
    verify("interpreter", 437, true);
}
#[test]
fn country_native_jit_protected_int_dos3call_cp936() {
    verify("jit", 936, true);
}
#[test]
fn country_native_interpreter_protected_int_dos3call_cp936() {
    verify("interpreter", 936, true);
}
