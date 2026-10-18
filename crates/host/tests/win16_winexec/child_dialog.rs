use super::{image, native::run_with_engine};
fn verify(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("CHILDDLG.EXE");
    std::fs::write(&program, image::child_dialog_program()).unwrap();
    run_with_engine(&program, 1252, engine);
}
#[test]
fn child_dialog_native_jit_parent_and_init_keep_the_same_hwnd() {
    verify("jit");
}
#[test]
fn child_dialog_native_interpreter_parent_and_init_keep_the_same_hwnd() {
    verify("interpreter");
}
