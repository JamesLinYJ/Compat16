use super::compile_spec;

#[test]
fn explicit_void_is_preserved_and_conflicting_width_is_rejected() {
    let header = "# module=TEST source_module=test.dll\n";
    let valid = format!("{header}1 pascal -retvoid Notify()\n");
    let generated = compile_spec("TEST", "test.dll", "test.spec", &valid).unwrap();
    assert!(generated.contains("ExportReturnModifier::Void"));
    for width in ["-ret16", "-ret64"] {
        let invalid = format!("{header}1 pascal -retvoid {width} Notify()\n");
        assert!(compile_spec("TEST", "test.dll", "test.spec", &invalid).is_err());
    }
}
