use super::{image, native};

fn verify(engine: &str, protected: bool, selected: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join(if protected {
        "VERSION.EXE"
    } else {
        "VERSION.COM"
    });
    let version = if selected { 7 } else { 5 };
    let image = if protected {
        image::dos_version_program(version)
    } else {
        image::dos_version_com(version)
    };
    std::fs::write(&program, image).unwrap();
    if selected {
        native::run_with_dos_version(&program, 1252, engine, "7.00");
    } else {
        native::run_with_engine(&program, 1252, engine);
    }
}

#[test]
fn dos_version_native_jit_live_com_psp() {
    verify("jit", false, false);
}
#[test]
fn dos_version_native_interpreter_live_com_psp() {
    verify("interpreter", false, false);
}
#[test]
fn dos_version_native_jit_selected_com_psp() {
    verify("jit", false, true);
}
#[test]
fn dos_version_native_interpreter_selected_com_psp() {
    verify("interpreter", false, true);
}
#[test]
fn dos_version_native_jit_protected_int_and_dos3call() {
    verify("jit", true, true);
}
#[test]
fn dos_version_native_interpreter_protected_int_and_dos3call() {
    verify("interpreter", true, true);
}
