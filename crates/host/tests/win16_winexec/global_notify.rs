//! The native package executes the guest's own FAR callback in both engines.
use super::{image, native::run_with_engine};

fn verify(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("NOTIFY.EXE");
    let bytes = image::global_notify_program();
    formats::parse_ne(&bytes).unwrap();
    std::fs::write(&program, bytes).unwrap();
    run_with_engine(&program, 1252, engine);
}

#[test]
fn global_notify_native_jit_executes_veto_accept_and_unregister() {
    verify("jit");
}

#[test]
fn global_notify_native_interpreter_executes_veto_accept_and_unregister() {
    verify("interpreter");
}
