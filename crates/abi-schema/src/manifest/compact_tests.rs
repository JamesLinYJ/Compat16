use std::collections::BTreeMap;

use super::{compact, *};

const ROOT: &str = r#"
version = 2
groups = ["sample.toml"]
types = ["types.toml"]
[defaults]
architecture = "win16"
ordinal_source = "explicit"
[source_notes]
spec = "Preserved historical evidence"
types = "Preserved type evidence"
[[modules]]
id = "KERNEL"
source_module = "krnl386.exe"
"#;

const TYPES: &str = r#"
[defaults]
evidence = [{ source = "compiled-baseline", note_ref = "types" }]
[types.Word]
value = { kind = "integer", bits = 16, signedness = "unknown" }
declaration_encoding = "word"
[types.Byte]
value = { kind = "integer", bits = 8, signedness = "unknown" }
declaration_encoding = "word"
[types.FarPointer]
value = { kind = "far16_16", role = "far_pointer" }
declaration_encoding = "pointer"
"#;

const GROUP: &str = r#"
module = "KERNEL"
defaults = { attributes = ["ret16"] }
[sources]
spec = { path = "specs/kernel.spec", note = "spec" }
[[exports]]
ordinal = 1
name = "Example"
binding = { rust_id = "Example", id_value = 17, constant = "EXAMPLE" }
evidence = [{ source = "spec", line = 2 }]
[exports.call]
returns = "void"
params = [{ name = "value", type = "Byte" }]
"#;

fn decode(root: &str, group: &str, types: &str) -> Result<ValidatedCatalog, ManifestError> {
    let root = toml::from_str::<compact::Root>(root)
        .map_err(|e| ManifestError::new("catalog.toml", e.to_string()))?;
    let groups = BTreeMap::from([(
        "sample.toml".into(),
        toml::from_str::<compact::CompactGroup>(group)
            .map_err(|e| ManifestError::new("sample.toml", e.to_string()))?,
    )]);
    let types = BTreeMap::from([(
        "types.toml".into(),
        toml::from_str::<compact::CompactTypes>(types)
            .map_err(|e| ManifestError::new("types.toml", e.to_string()))?,
    )]);
    let (catalog, groups, types) = compact::normalize(root, groups, types)?;
    validate_catalog(catalog, groups, types)
}

#[test]
fn compact_bound_contract_expands_exact_semantics_and_evidence() {
    let catalog = decode(ROOT, GROUP, TYPES).unwrap();
    assert_eq!(catalog.catalog().version, SCHEMA_VERSION);
    let export = catalog.exports().next().unwrap().1;
    assert_eq!(export.ordinal_source, OrdinalSource::Explicit);
    assert_eq!(export.architecture, Architecture::Win16);
    assert_eq!(export.name.as_deref(), Some("Example"));
    assert_eq!(export.declared_name, "Example");
    assert_eq!(export.binding.as_ref().unwrap().id_value, 17);
    assert_eq!(
        export.evidence,
        vec![Evidence {
            source: "specs/kernel.spec".into(),
            line: Some(2),
            note: Some("Preserved historical evidence".into())
        }]
    );
    let abi = export.entry.abi().unwrap();
    assert_eq!(
        abi.cleanup(),
        Some(StackCleanup {
            callee_pop_bytes: 2,
            caller_pop_bytes: 0
        })
    );
    let signature = abi.signature().unwrap();
    assert_eq!(signature.returns, ReturnValue::Void);
    assert_eq!(signature.parameters[0].slot_bytes, 2);
    assert_eq!(
        catalog
            .resolve_type(&signature.parameters[0].value)
            .runtime_argument_kind(),
        Some(RuntimeArgumentKind::Byte)
    );
    assert_eq!(
        export.declaration.abi.as_ref().unwrap().return_modifier,
        ReturnModifier::Ret16
    );
    assert_eq!(
        catalog.types()["Byte"].evidence[0].note.as_deref(),
        Some("Preserved type evidence")
    );
}

#[test]
fn compact_defaults_have_finite_precedence_and_empty_arrays_clear() {
    let root = ROOT.replace(
        "ordinal_source = \"explicit\"",
        "ordinal_source = \"explicit\"\nattributes = ['ret64']",
    ) + "\n[modules.defaults]\narchitecture = 'win32_only'\nordinal_source = 'assigned'\nconvention = 'cdecl'\nattributes = ['ret16']\n";
    let group = r#"
module = "KERNEL"
defaults = { architecture = "win16", attributes = ["private"] }
[[exports]]
ordinal = 1
name = "Inherited"
[[exports]]
ordinal = 2
name = "Cleared"
ordinal_source = "explicit"
decl = { attributes = [], args = [] }
[[exports]]
ordinal = 3
name = "Explicit"
architecture = "unknown"
decl = { attributes = ["ret64"], type = "pascal" }
"#;
    let catalog = decode(&root, group, TYPES).unwrap();
    let exports: Vec<_> = catalog.exports().map(|(_, export)| export).collect();
    assert_eq!(exports[0].architecture, Architecture::Win16);
    assert_eq!(exports[0].ordinal_source, OrdinalSource::Assigned);
    assert_eq!(
        exports[0].declaration.declaration_type,
        DeclarationType::Cdecl
    );
    assert_eq!(exports[0].declaration.attributes, vec![Attribute::Private]);
    assert!(exports[1].declaration.attributes.is_empty());
    assert_eq!(exports[1].ordinal_source, OrdinalSource::Explicit);
    assert_eq!(exports[2].architecture, Architecture::Unknown);
    assert_eq!(exports[2].declaration.attributes, vec![Attribute::Ret64]);
    assert_eq!(
        exports[2].declaration.declaration_type,
        DeclarationType::Pascal
    );
}

#[test]
fn compact_group_empty_attributes_clear_root_and_module_defaults() {
    let root = ROOT.to_owned() + "\n[modules.defaults]\nattributes = ['ret16']\n";
    let group = "module = 'KERNEL'\ndefaults = { attributes = [] }\n[[exports]]\nordinal = 1\nname = 'Empty'";
    assert!(
        decode(&root, group, TYPES)
            .unwrap()
            .exports()
            .next()
            .unwrap()
            .1
            .declaration
            .attributes
            .is_empty()
    );
}

#[test]
fn compact_encoding_exceptions_and_whole_args_overrides_are_metadata_only() {
    let group = GROUP.replace(
        "type = \"Byte\"",
        "type = \"FarPointer\", encoding = \"long\"",
    );
    let catalog = decode(ROOT, &group, TYPES).unwrap();
    let export = catalog.exports().next().unwrap().1;
    assert_eq!(
        export.declaration.abi.as_ref().unwrap().arguments,
        vec![ArgumentEncoding::Long]
    );
    assert_eq!(
        export.entry.abi().unwrap().signature().unwrap().parameters[0].slot_bytes,
        4
    );
    assert!(matches!(
        catalog.resolve_type(&export.entry.abi().unwrap().signature().unwrap().parameters[0].value),
        ValueType::Far16_16 {
            role: FarPointerRole::FarPointer,
            direction: Direction::Unknown,
            nullability: Nullability::Unknown
        }
    ));
    let cleared = group.replace(
        "name = \"Example\"",
        "name = \"Example\"\ndecl = { args = [] }",
    );
    let cleared = decode(ROOT, &cleared, TYPES).unwrap();
    let export = cleared.exports().next().unwrap().1;
    assert!(
        export
            .declaration
            .abi
            .as_ref()
            .unwrap()
            .arguments
            .is_empty()
    );
    assert_eq!(
        export
            .entry
            .abi()
            .unwrap()
            .signature()
            .unwrap()
            .parameters
            .len(),
        1
    );
}

#[test]
fn compact_legacy_signatures_and_register_flags_do_not_make_calls() {
    let group = r#"
module = "KERNEL"
[[exports]]
ordinal = 1
name = "OnlyMetadata"
decl = { args = ["word"], attributes = ["register"] }
[[exports]]
ordinal = 2
name = "Stub"
kind = "stub"
"#;
    let catalog = decode(ROOT, group, TYPES).unwrap();
    for (_, export) in catalog.exports() {
        assert!(matches!(export.entry.abi(), Some(Abi::Unknown)));
    }
    assert_eq!(
        catalog
            .exports()
            .next()
            .unwrap()
            .1
            .declaration
            .abi
            .as_ref()
            .unwrap()
            .knowledge,
        SignatureKnowledge::Known
    );
    let missing_call = GROUP.split("[exports.call]").next().unwrap();
    assert!(
        decode(ROOT, missing_call, TYPES)
            .unwrap_err()
            .message
            .contains("explicit call")
    );
}

#[test]
fn compact_missing_refs_unknown_fields_and_versions_fail() {
    for group in [
        GROUP.replace("type = \"Byte\"", "type = \"Missing\""),
        GROUP.replace("source = \"spec\"", "source = \"missing\""),
        GROUP.replace("note = \"spec\"", "note = \"missing\""),
        GROUP.replace(
            "returns = \"void\"",
            "returns = \"void\"\nunrecognized = true",
        ),
    ] {
        assert!(decode(ROOT, &group, TYPES).is_err());
    }
    assert!(decode(&ROOT.replace("version = 2", "version = 3"), GROUP, TYPES).is_err());
    assert!(
        decode(
            ROOT,
            GROUP,
            &TYPES.replace("note_ref = \"types\"", "note_ref = \"missing\"")
        )
        .is_err()
    );
}

#[test]
fn compact_aliases_inherit_type_encoding_and_keep_independent_evidence() {
    let types =
        TYPES.to_owned() + "\n[types.Alias]\nvalue = {kind='named', name='Byte'}\nevidence = []\n";
    let group = GROUP.replace("type = \"Byte\"", "type = \"Alias\"");
    let catalog = decode(ROOT, &group, &types).unwrap();
    assert!(catalog.types()["Alias"].evidence.is_empty());
    assert!(!catalog.types()["Byte"].evidence.is_empty());
    assert_eq!(
        catalog
            .exports()
            .next()
            .unwrap()
            .1
            .declaration
            .abi
            .as_ref()
            .unwrap()
            .arguments,
        vec![ArgumentEncoding::Word]
    );
    let cyclic = types.replace("name='Byte'", "name='Alias'");
    assert!(
        decode(ROOT, &group, &cyclic)
            .unwrap_err()
            .message
            .contains("cycle")
    );
}

#[test]
fn compact_missing_type_encoding_requires_an_explicit_metadata_override() {
    let types = TYPES.replace("declaration_encoding = \"word\"", "");
    assert!(
        decode(ROOT, GROUP, &types)
            .unwrap_err()
            .message
            .contains("encoding")
    );
    let override_parameter =
        GROUP.replace("type = \"Byte\"", "type = \"Byte\", encoding = \"long\"");
    assert!(decode(ROOT, &override_parameter, &types).is_ok());
    let override_arguments = GROUP.replace(
        "name = \"Example\"",
        "name = \"Example\"\ndecl = { args = [] }",
    );
    assert!(decode(ROOT, &override_arguments, &types).is_ok());
}

#[test]
fn compact_data_payloads_and_ordinal_only_names_preserve_distinctions() {
    let group = r#"
module = "KERNEL"
[[exports]]
ordinal = 1
name = "Variable"
kind = "variable"
values = [0, 4294967295]
[[exports]]
ordinal = 2
name = "Equate"
kind = "equate"
value = -1
[[exports]]
ordinal = 3
name = "Internal"
ordinal_only = true
declared_name = "Historical"
"#;
    let catalog = decode(ROOT, group, TYPES).unwrap();
    let exports: Vec<_> = catalog.exports().map(|(_, export)| export).collect();
    assert!(matches!(&exports[0].entry, Entry::Variable { values } if values == &[0, u32::MAX]));
    assert!(matches!(exports[1].entry, Entry::Equate { value: -1 }));
    assert_eq!(exports[2].name, None);
    assert_eq!(exports[2].declared_name, "Historical");
    assert!(decode(ROOT, &group.replace("value = -1", "values = []"), TYPES).is_err());
    assert!(
        decode(
            ROOT,
            &group.replace(
                "values = [0, 4294967295]",
                "values = []\ncall = { returns = 'void' }"
            ),
            TYPES
        )
        .is_err()
    );
}

#[test]
fn compact_call_kinds_stay_explicit_and_unknown_returns_cannot_bind() {
    let variable = GROUP.replace(
        "returns = \"void\"",
        "kind = 'variable_stack'\nconvention = 'varargs'\nreturns = 'dword'",
    );
    let catalog = decode(ROOT, &variable, TYPES).unwrap();
    assert!(matches!(
        catalog.exports().next().unwrap().1.entry.abi(),
        Some(Abi::VariableStack { .. })
    ));
    let register = GROUP
        .replace(
            "returns = \"void\"",
            "kind = 'register_context'\nreturns = 'register_context'",
        )
        .replace("params = [{ name = \"value\", type = \"Byte\" }]", "");
    let catalog = decode(ROOT, &register, TYPES).unwrap();
    assert_eq!(
        catalog
            .exports()
            .next()
            .unwrap()
            .1
            .entry
            .abi()
            .unwrap()
            .fixed_stack_bytes(),
        Some(0)
    );
    assert!(
        decode(
            ROOT,
            &GROUP.replace("returns = \"void\"", "returns = 'unknown'"),
            TYPES
        )
        .is_err()
    );
    assert!(decode(ROOT, &GROUP.replace("returns = \"void\"", ""), TYPES).is_err());
}

#[test]
fn compact_unknown_type_slots_are_never_guessed_and_bounds_still_apply() {
    let types = TYPES.replace(
        "kind = \"integer\", bits = 8, signedness = \"unknown\"",
        "kind = \"unknown\"",
    );
    let unbound = GROUP.replace(
        "binding = { rust_id = \"Example\", id_value = 17, constant = \"EXAMPLE\" }",
        "",
    );
    assert!(
        decode(ROOT, &unbound, &types)
            .unwrap_err()
            .message
            .contains("no known slot")
    );
    assert!(
        decode(
            ROOT,
            &unbound.replace("type = \"Byte\"", "type = \"Byte\", slot_bytes = 2"),
            &types
        )
        .is_ok()
    );
    assert!(
        decode(
            ROOT,
            &GROUP.replace("type = \"Byte\"", "type = \"Byte\", slot_bytes = 4"),
            TYPES
        )
        .is_err()
    );
    let params = (0..1025)
        .map(|i| format!("{{name='p{i}',type='Byte'}}"))
        .collect::<Vec<_>>()
        .join(",");
    let oversized = GROUP.replace(
        "params = [{ name = \"value\", type = \"Byte\" }]",
        &format!("params = [{params}]"),
    );
    assert!(
        decode(ROOT, &oversized, TYPES)
            .unwrap_err()
            .message
            .contains("parameter limit")
    );
}

#[test]
fn compact_deep_type_references_are_iterative_and_missing_targets_fail() {
    let mut types = TYPES.to_owned();
    for i in 0..512 {
        let next = if i == 511 {
            "Byte".into()
        } else {
            format!("T{}", i + 1)
        };
        types.push_str(&format!(
            "\n[types.T{i}]\nvalue = {{kind='named',name='{next}'}}\n"
        ));
    }
    let group = GROUP.replace("type = \"Byte\"", "type = \"T0\"");
    assert!(decode(ROOT, &group, &types).is_ok());
    assert!(
        decode(
            ROOT,
            &group,
            &types.replace("name='Byte'", "name='Missing'")
        )
        .is_err()
    );
}

#[test]
fn compact_unknown_argument_knowledge_requires_an_explicit_declaration() {
    let group = "module = 'KERNEL'\n[[exports]]\nordinal = 1\nname = 'UnknownArgument'\ndecl = { args = ['unknown'] }";
    assert!(
        decode(ROOT, group, TYPES)
            .unwrap_err()
            .message
            .contains("known declaration signature")
    );
    let explicit = group.replace(
        "args = ['unknown']",
        "args = ['unknown'], knowledge = 'unknown'",
    );
    assert!(matches!(
        decode(ROOT, &explicit, TYPES)
            .unwrap()
            .exports()
            .next()
            .unwrap()
            .1
            .entry
            .abi(),
        Some(Abi::Unknown)
    ));
}

#[test]
fn compact_oversized_inherited_metadata_is_rejected_before_expansion() {
    let root = ROOT.replace("Preserved historical evidence", &"n".repeat(16 * 1024 + 1));
    assert!(
        decode(&root, GROUP, TYPES)
            .unwrap_err()
            .message
            .contains("16 KiB")
    );
    let duplicate_defaults = GROUP.replace(
        "attributes = [\"ret16\"]",
        "attributes = ['ret16', 'ret16']",
    );
    assert!(
        decode(ROOT, &duplicate_defaults, TYPES)
            .unwrap_err()
            .message
            .contains("duplicate inherited")
    );
    let evidence = (0..65)
        .map(|_| "{source='compiled-baseline',note_ref='types'}")
        .collect::<Vec<_>>()
        .join(",");
    let types = TYPES.replace(
        "evidence = [{ source = \"compiled-baseline\", note_ref = \"types\" }]",
        &format!("evidence = [{evidence}]"),
    );
    assert!(
        decode(ROOT, GROUP, &types)
            .unwrap_err()
            .message
            .contains("64 records")
    );
}
