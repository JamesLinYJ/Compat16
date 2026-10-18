use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, protected: bool, page: u32) {
    let root = tempfile::tempdir().unwrap();
    let mut inputs = Vec::new();
    for (letter, contents) in [(b'A', b"one".as_slice()), (b'B', b"three")] {
        let raw = image::fcb_search_filename(page == 936, letter);
        let name = text_codec::decode(&raw, text_codec::CodePage::try_from(page).unwrap()).unwrap();
        let path = root.path().join(name);
        std::fs::write(&path, contents).unwrap();
        inputs.push((path, contents));
    }
    let program = root.path().join(if protected {
        "FCBFIND.EXE"
    } else {
        "FCBFIND.COM"
    });
    std::fs::write(&program, image::fcb_search_program(protected, page == 936)).unwrap();
    let result = std::panic::catch_unwind(|| run_with_dos_code_page(&program, page, engine));
    if let Err(error) = result {
        eprintln!("retained FCB fixture: {}", root.keep().display());
        std::panic::resume_unwind(error);
    }
    for (path, expected) in inputs {
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
}

#[test]
fn fcb_search_native_jit_real_cp437() {
    verify("jit", false, 437);
}
#[test]
fn fcb_search_native_interpreter_real_cp437() {
    verify("interpreter", false, 437);
}
#[test]
fn fcb_search_native_jit_real_cp936() {
    verify("jit", false, 936);
}
#[test]
fn fcb_search_native_interpreter_real_cp936() {
    verify("interpreter", false, 936);
}
#[test]
fn fcb_search_native_jit_protected_cp437() {
    verify("jit", true, 437);
}
#[test]
fn fcb_search_native_interpreter_protected_cp437() {
    verify("interpreter", true, 437);
}
#[test]
fn fcb_search_native_jit_protected_cp936() {
    verify("jit", true, 936);
}
#[test]
fn fcb_search_native_interpreter_protected_cp936() {
    verify("interpreter", true, 936);
}
