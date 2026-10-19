use super::{image, native::run_with_engine};

fn verify(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("OEMBMP.EXE");
    std::fs::write(&program, image::oem_bitmap_program()).unwrap();
    run_with_engine(&program, 1252, engine);
}

#[test]
fn oem_bitmap_native_jit_loads_legacy_and_module_resources() {
    verify("jit");
}

#[test]
fn oem_bitmap_native_interpreter_loads_legacy_and_module_resources() {
    verify("interpreter");
}
