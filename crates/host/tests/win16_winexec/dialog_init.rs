use super::{image, native::run_with_engine};

fn verify(engine: &str, handled: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("DLGINIT.EXE");
    std::fs::write(&program, image::private_dialog_init_program(handled)).unwrap();
    run_with_engine(&program, 1252, engine);
    let trace = std::fs::read_to_string(program.with_extension("io.log")).unwrap();
    let callback = trace
        .lines()
        .filter(|line| {
            line.contains("phase=guest-entry procedure=dlgproc") && line.contains("message=0110")
        })
        .count();
    assert_eq!(callback, usize::from(!handled));
}

#[test]
fn private_dialog_native_jit_forwards_init_through_default() {
    verify("jit", false);
}
#[test]
fn private_dialog_native_interpreter_forwards_init_through_default() {
    verify("interpreter", false);
}
#[test]
fn private_dialog_native_jit_keeps_class_handled_init() {
    verify("jit", true);
}
#[test]
fn private_dialog_native_interpreter_keeps_class_handled_init() {
    verify("interpreter", true);
}
