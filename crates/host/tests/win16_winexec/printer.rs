use super::{image, native::run_with_engine};

fn verify(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("PRNMODE.EXE");
    std::fs::write(&program, image::default_printer_round_trip_program()).unwrap();
    run_with_engine(&program, 936, engine);
    let trace = std::fs::read_to_string(program.with_extension("io.log")).unwrap();
    let mut remaining = trace.as_str();
    for (module, api) in [
        ("COMMDLG", "PrintDlg"),
        ("GDI", "CreateIC"),
        ("GDI", "DeleteDC"),
        ("WINSPOOL", "DeviceCapabilities"),
        ("KERNEL", "GlobalFree"),
    ] {
        let event = format!("stage=dispatch-return module={module} name={api} ");
        let at = remaining
            .find(&event)
            .expect("guest must finish each native printer call");
        remaining = &remaining[at + event.len()..];
    }
}

#[test]
#[ignore = "requires a default printer; reads settings without showing a dialog or printing"]
fn wow_devmode_default_printer_native_jit_round_trip() {
    verify("jit");
}

#[test]
#[ignore = "requires a default printer; reads settings without showing a dialog or printing"]
fn wow_devmode_default_printer_native_interpreter_round_trip() {
    verify("interpreter");
}
