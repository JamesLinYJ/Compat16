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

fn verify_ext_device_mode(engine: &str) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("EXTMODE.EXE");
    std::fs::write(&program, image::ext_device_mode_round_trip_program()).unwrap();
    run_with_engine(&program, 936, engine);
    let trace = std::fs::read_to_string(program.with_extension("io.log")).unwrap();
    assert_eq!(
        trace
            .matches("stage=dispatch-return module=WINSPOOL name=ExtDeviceMode ")
            .count(),
        6
    );
    assert!(trace.contains("stage=dispatch-return module=GDI name=CreateIC "));
}

#[test]
#[ignore = "requires a default printer supporting landscape; no prompt, update or print job"]
fn ext_device_mode_default_printer_native_jit_query_copy_and_merge() {
    verify_ext_device_mode("jit");
}

#[test]
#[ignore = "requires a default printer supporting landscape; no prompt, update or print job"]
fn ext_device_mode_default_printer_native_interpreter_query_copy_and_merge() {
    verify_ext_device_mode("interpreter");
}
