//! Exercise real COM and protected NE directory queries in each CPU engine.

use super::{image, native::run_with_engine};

fn verify(engine: &str, protected: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join(if protected {
        "CURDIR.EXE"
    } else {
        "CURDIR.COM"
    });
    let bytes = if protected {
        image::current_directory_program()
    } else {
        image::current_directory_com()
    };
    std::fs::write(&program, bytes).unwrap();
    run_with_engine(&program, 1252, engine);
}

#[test]
fn current_directory_native_jit_protected_int_and_dos3call() {
    verify("jit", true);
}

#[test]
fn current_directory_native_interpreter_protected_int_and_dos3call() {
    verify("interpreter", true);
}

#[test]
fn current_directory_native_jit_real_mode_com() {
    verify("jit", false);
}

#[test]
fn current_directory_native_interpreter_real_mode_com() {
    verify("interpreter", false);
}
