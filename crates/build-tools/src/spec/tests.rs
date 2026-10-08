use super::{generate_rust, parse_spec};
use crate::{ArgumentType, CallingConvention, ExportAttributes, ExportKind, Ordinal};

const REPRESENTATIVE: &str = include_str!("../../tests/fixtures/representative.spec");

#[test]
fn parses_numbered_auto_stub_variable_and_equate_records() {
    let module = parse_spec(REPRESENTATIVE, "KERNEL16").expect("fixture parses");
    assert_eq!(module.original_module_name, "KERNEL16");
    assert_eq!(module.exports.len(), 8);
    assert_eq!(module.exports[0].ordinal, Ordinal::Explicit(2));
    assert_eq!(module.exports[0].kind, ExportKind::Function);
    assert_eq!(module.exports[0].convention, Some(CallingConvention::Pascal));
    assert_eq!(
        module.exports[0].arguments,
        vec![ArgumentType::Word, ArgumentType::SegmentPointer]
    );
    assert_eq!(
        module.exports[0].implementation_name.as_deref(),
        Some("ExitKernel16")
    );
    assert!(module.exports[0]
        .flags
        .attributes
        .contains(ExportAttributes::RET16));
    assert_eq!(module.exports[1].ordinal, Ordinal::Explicit(3));
    assert_eq!(module.exports[1].kind, ExportKind::Stub);
    assert_eq!(module.exports[2].ordinal, Ordinal::Explicit(113));
    assert_eq!(module.exports[2].kind, ExportKind::Equate);
    assert_eq!(module.exports[2].values, vec!["3".to_owned()]);
    assert_eq!(module.exports[3].kind, ExportKind::Variable);
    assert_eq!(
        module.exports[3].values,
        vec![
            "0x00020021".to_owned(),
            "0x00000000".to_owned(),
            "0x000000c0".to_owned(),
            "0x46000000".to_owned()
        ]
    );
    assert_eq!(module.exports[4].ordinal, Ordinal::Automatic);
    assert_eq!(module.exports[4].convention, Some(CallingConvention::Stdcall));
    assert!(module.exports[4].flags.arch_win32);
    assert_eq!(module.exports[5].convention, Some(CallingConvention::Cdecl));
    assert_eq!(module.exports[5].arguments[1], ArgumentType::Int64);
    assert_eq!(module.exports[6].convention, Some(CallingConvention::Varargs));
    assert!(module.exports[6]
        .flags
        .attributes
        .contains(ExportAttributes::RET16));
    assert_eq!(
        module.exports[7].arguments,
        vec![ArgumentType::Float, ArgumentType::Pointer]
    );
}

#[test]
fn generated_metadata_is_deterministic_and_keeps_original_module_name() {
    let module = parse_spec(REPRESENTATIVE, "Original.Module16").expect("fixture parses");
    let first = generate_rust(&module);
    assert_eq!(first, generate_rust(&module));
    assert!(first.contains("original_module_name: \"Original.Module16\""));
    assert!(first.contains("Ordinal::Automatic"));
    assert!(first.contains("ExportKind::Stub"));
    assert!(first.ends_with("};\n"));
}

#[test]
fn rejects_unknown_lines_flags_descriptors_and_duplicate_ordinals() {
    let unsupported = include_str!("../../tests/fixtures/unsupported.spec");
    let fixture_error = parse_spec(unsupported, "TEST").expect_err("unknown flag rejected");
    assert_eq!(fixture_error.line, 2);
    for source in [
        "1 mystery Foo()\n",
        "1 pascal -future-flag Foo()\n",
        "1 pascal Foo(nearptr)\n",
        "1 stub First\n1 stub Second\n",
        "65536 stub TooLarge\n",
    ] {
        assert!(parse_spec(source, "TEST").is_err(), "accepted {source:?}");
    }
}

#[test]
fn reports_the_source_line_for_malformed_entries() {
    let error = parse_spec("# comment\n\n9 pascal MissingClose(word\n", "TEST")
        .expect_err("unterminated declaration rejected");
    assert_eq!(error.line, 3);
}
