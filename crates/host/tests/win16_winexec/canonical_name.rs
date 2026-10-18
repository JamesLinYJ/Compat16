use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, protected: bool, page: u32) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("Long directory name");
    std::fs::create_dir(&directory).unwrap();
    let long = directory.join("Long file name.txt");
    std::fs::write(&long, b"one").unwrap();
    let oem = if page == 936 {
        b"\x81\\a.txt".as_slice()
    } else {
        b"\x81a.txt"
    };
    let oem = root
        .path()
        .join(text_codec::decode(oem, text_codec::CodePage::try_from(page).unwrap()).unwrap());
    std::fs::write(&oem, b"one").unwrap();
    let program = root
        .path()
        .join(if protected { "CANON.EXE" } else { "CANON.COM" });
    std::fs::write(
        &program,
        image::canonical_name_program(protected, page == 936),
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| run_with_dos_code_page(&program, page, engine));
    if let Err(error) = result {
        eprintln!("retained canonical-name fixture: {}", root.keep().display());
        std::panic::resume_unwind(error);
    }
    assert_eq!(std::fs::read(long).unwrap(), b"one");
    assert_eq!(std::fs::read(oem).unwrap(), b"one");
}
#[test]
fn canonical_name_native_jit_real_cp437() {
    verify("jit", false, 437);
}
#[test]
fn canonical_name_native_interpreter_real_cp437() {
    verify("interpreter", false, 437);
}
#[test]
fn canonical_name_native_jit_real_cp936() {
    verify("jit", false, 936);
}
#[test]
fn canonical_name_native_interpreter_real_cp936() {
    verify("interpreter", false, 936);
}
#[test]
fn canonical_name_native_jit_protected_cp437() {
    verify("jit", true, 437);
}
#[test]
fn canonical_name_native_interpreter_protected_cp437() {
    verify("interpreter", true, 437);
}
#[test]
fn canonical_name_native_jit_protected_cp936() {
    verify("jit", true, 936);
}
#[test]
fn canonical_name_native_interpreter_protected_cp936() {
    verify("interpreter", true, 936);
}
