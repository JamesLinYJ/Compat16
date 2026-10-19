//! Actual USER creates the hidden control; guest code reads its icon back.
use super::{image, native::run_with_engine};

fn verify(engine: &str, named_classes: bool) {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("NAMEDICO.EXE");
    let bytes = if named_classes {
        image::named_class_dialog_icon_program()
    } else {
        image::named_dialog_icon_program()
    };
    let module = formats::parse_ne(&bytes).unwrap();
    assert_eq!(module.resource_types.len(), 3);
    assert!(matches!(&module.resource_types[0].resources[0].id,
        formats::NeResourceId::Name(name) if name == b"\x82\xa0Icon"));
    std::fs::write(&program, bytes).unwrap();
    run_with_engine(&program, 932, engine);
    let trace = std::fs::read_to_string(program.with_extension("io.log")).unwrap();
    let mut remaining = trace.as_str();
    for api in ["CreateDialog", "SendDlgItemMessage", "DestroyWindow"] {
        let event = format!("stage=dispatch-return module=USER name={api} ");
        let offset = remaining
            .find(&event)
            .expect("guest must complete each native USER call");
        remaining = &remaining[offset + event.len()..];
    }
}

#[test]
fn named_dialog_icon_native_jit_reads_guest_icon_from_hidden_static() {
    verify("jit", false);
}

#[test]
fn named_dialog_icon_native_interpreter_reads_guest_icon_from_hidden_static() {
    verify("interpreter", false);
}

#[test]
fn dialog_class_names_native_jit_reads_icon_from_hidden_named_static() {
    verify("jit", true);
}

#[test]
fn dialog_class_names_native_interpreter_reads_icon_from_hidden_named_static() {
    verify("interpreter", true);
}
