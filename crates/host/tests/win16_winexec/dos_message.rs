use super::{image, native::run_with_engine};

fn verify(engine: &str) {
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("MSGADDR.COM");
    std::fs::write(&program, image::dos_message_com()).unwrap();
    run_with_engine(&program, 437, engine);
}

#[test]
fn dos_message_native_jit_exchanges_addresses_and_calls_guest_provider() {
    verify("jit");
}
#[test]
fn dos_message_native_interpreter_exchanges_addresses_and_calls_guest_provider() {
    verify("interpreter");
}
