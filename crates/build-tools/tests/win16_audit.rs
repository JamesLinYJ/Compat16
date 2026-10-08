use build_tools::{audit_win16_module, parse_spec};
use win16_abi::exports::{KERNEL_GET_VERSION, KERNEL_LOPEN};

#[test]
fn matching_declaration_reports_metadata_only_and_keeps_return_width_rust_owned() {
    let spec = parse_spec("3 pascal -ret16 GetVersion()", "KERNEL").unwrap();
    let report = audit_win16_module("KERNEL", &spec, &[KERNEL_GET_VERSION]);

    assert!(!report.has_differences());
    let tsv = report.to_tsv();
    assert!(tsv.contains("\nMATCH\tKERNEL\t3\t3\tGetVersion\tGetVersion\t"));
    assert!(tsv.contains("Dword(32-bit)"));
    assert!(tsv.contains("return width is shown from Rust metadata"));
    assert!(tsv.contains("no host implementation or service support is inferred"));
}

#[test]
fn mismatched_argument_slot_width_is_reported_as_a_difference() {
    let spec = parse_spec("85 pascal _lopen(word word)", "KERNEL").unwrap();
    let report = audit_win16_module("KERNEL", &spec, &[KERNEL_LOPEN]);

    assert!(report.has_differences());
    assert!(report.to_tsv().contains("MISMATCH"));
    assert!(report
        .to_tsv()
        .contains("argument 1 slot width differs: spec 2 bytes, Rust 4 bytes"));
}

#[test]
fn unknown_float_width_is_left_uncomparable() {
    let spec = parse_spec("85 pascal _lopen(float word)", "KERNEL").unwrap();
    let report = audit_win16_module("KERNEL", &spec, &[KERNEL_LOPEN]);

    assert!(report.has_differences());
    assert!(report.to_tsv().contains("UNCOMPARABLE"));
    assert!(report
        .to_tsv()
        .contains("argument 1 descriptor float has no width rule in this audit"));
}
