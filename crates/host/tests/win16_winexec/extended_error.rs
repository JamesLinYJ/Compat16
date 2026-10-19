use super::{image, native::run_with_engine};

fn verify(engine: &str, protected: bool) {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("DATA.DAT");
    std::fs::write(&input, b"read-only fixture").unwrap();
    let program = root.path().join(if protected {
        "ERRSTATE.EXE"
    } else {
        "ERRSTATE.COM"
    });
    let bytes = if protected {
        image::extended_error_program()
    } else {
        image::extended_error_com()
    };
    std::fs::write(&program, bytes).unwrap();
    let result = std::panic::catch_unwind(|| {
        run_with_engine(&program, 437, engine);
        assert_eq!(std::fs::read(&input).unwrap(), b"read-only fixture");
        assert!(!root.path().join("NOEXIST.C16").exists());
    });
    if let Err(failure) = result {
        eprintln!("retained extended-error fixture: {}", root.keep().display());
        std::panic::resume_unwind(failure);
    }
}
#[test]
fn extended_error_native_jit_real_com() {
    verify("jit", false);
}
#[test]
fn extended_error_native_interpreter_real_com() {
    verify("interpreter", false);
}
#[test]
fn extended_error_native_jit_protected_int_dos3call_and_hfile() {
    verify("jit", true);
}
#[test]
fn extended_error_native_interpreter_protected_int_dos3call_and_hfile() {
    verify("interpreter", true);
}
