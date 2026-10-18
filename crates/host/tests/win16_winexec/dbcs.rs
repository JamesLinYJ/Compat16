use super::{image, native::run_with_dos_code_page};

fn verify(engine: &str, page: u32, protected: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join(if protected {
        "DBCSTAB.EXE"
    } else {
        "DBCSTAB.COM"
    });
    let dbcs = page == 936;
    let bytes = if protected {
        image::dbcs_program(dbcs)
    } else {
        image::dbcs_com(dbcs)
    };
    std::fs::write(&program, bytes).unwrap();
    run_with_dos_code_page(&program, page, engine);
}

#[test]
fn dbcs_native_jit_real_com_cp437() {
    verify("jit", 437, false);
}
#[test]
fn dbcs_native_interpreter_real_com_cp437() {
    verify("interpreter", 437, false);
}
#[test]
fn dbcs_native_jit_real_com_cp936() {
    verify("jit", 936, false);
}
#[test]
fn dbcs_native_interpreter_real_com_cp936() {
    verify("interpreter", 936, false);
}
#[test]
fn dbcs_native_jit_protected_int_and_dos3call_cp437() {
    verify("jit", 437, true);
}
#[test]
fn dbcs_native_interpreter_protected_int_and_dos3call_cp437() {
    verify("interpreter", 437, true);
}
#[test]
fn dbcs_native_jit_protected_int_and_dos3call_cp936() {
    verify("jit", 936, true);
}
#[test]
fn dbcs_native_interpreter_protected_int_and_dos3call_cp936() {
    verify("interpreter", 936, true);
}
