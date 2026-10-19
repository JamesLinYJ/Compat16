use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, protected: bool, page: u32) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join(if protected {
        "FCBPARSE.EXE"
    } else {
        "FCBPARSE.COM"
    });
    std::fs::write(&program, image::fcb_parse_program(protected, page == 936)).unwrap();
    run_with_dos_code_page(&program, page, engine);
}

#[test]
fn fcb_parse_native_jit_real_cp437() {
    verify("jit", false, 437);
}
#[test]
fn fcb_parse_native_interpreter_real_cp437() {
    verify("interpreter", false, 437);
}
#[test]
fn fcb_parse_native_jit_real_cp936() {
    verify("jit", false, 936);
}
#[test]
fn fcb_parse_native_interpreter_real_cp936() {
    verify("interpreter", false, 936);
}
#[test]
fn fcb_parse_native_jit_protected_cp437() {
    verify("jit", true, 437);
}
#[test]
fn fcb_parse_native_interpreter_protected_cp437() {
    verify("interpreter", true, 437);
}
#[test]
fn fcb_parse_native_jit_protected_cp936() {
    verify("jit", true, 936);
}
#[test]
fn fcb_parse_native_interpreter_protected_cp936() {
    verify("interpreter", true, 936);
}
