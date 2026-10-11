use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

fn decode_value<T: serde::de::DeserializeOwned>(value: toml::Value) -> Result<T, toml::de::Error> {
    value.try_into()
}

fn fixture() -> (Catalog, BTreeMap<String, Group>, BTreeMap<String, SharedTypes>) {
    let catalog = Catalog {
        version: 1,
        modules: vec![Module { id: "KERNEL".into(), source_module: "krnl386.exe".into(), aliases: vec![] }],
        name_resolutions: vec![],
        groups: vec!["memory.toml".into()],
        types: vec![],
    };
    let export: Export = toml::from_str(r#"
module = "KERNEL"
ordinal = 1
ordinal_source = "explicit"
declared_name = "Example"
name = "Example"
aliases = []
architecture = "win16"
evidence = [{ source = "previous.spec", line = 1 }]

[declaration]
declaration_type = "pascal"
attributes = ["ret16"]
architecture_constraints = []
[declaration.abi]
calling_convention = "pascal"
knowledge = "known"
arguments = ["word"]
return_modifier = "ret16"

[entry]
kind = "function"
[entry.abi]
kind = "fixed_stack"
[entry.abi.signature]
calling_convention = "pascal"
returns = "void"
parameters = [{ name = "value", slot_bytes = 2, value = { kind = "integer", bits = 8, signedness = "unknown" } }]

[binding]
rust_id = "Example"
id_value = 0
constant = "EXAMPLE"
"#).unwrap();
    (catalog, BTreeMap::from([("memory.toml".into(), Group { version: 1, exports: vec![export] })]), BTreeMap::new())
}

fn export_mut(groups: &mut BTreeMap<String, Group>) -> &mut Export {
    &mut groups.get_mut("memory.toml").unwrap().exports[0]
}

fn signature_mut(export: &mut Export) -> &mut Signature {
    let Entry::Function { abi } = &mut export.entry else { panic!("fixture function"); };
    match abi {
        Abi::FixedStack { signature } | Abi::VariableStack { signature }
        | Abi::RegisterContext { signature } => signature,
        Abi::Unknown => panic!("fixture semantic signature"),
    }
}

#[test]
fn byte_value_uses_word_slot_and_void_is_not_legacy_return_hint() {
    let (catalog, groups, types) = fixture();
    let validated = validate_catalog(catalog, groups, types).unwrap();
    let (_, export) = validated.exports().next().unwrap();
    let abi = export.entry.abi().unwrap();
    assert_eq!(abi.fixed_stack_bytes(), Some(2));
    assert_eq!(abi.cleanup(), Some(StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 }));
    assert_eq!(abi.signature().unwrap().returns, ReturnValue::Void);
    assert_eq!(export.declaration.abi.as_ref().unwrap().return_modifier, ReturnModifier::Ret16);
    assert_eq!(export.declaration.attribute_bits(), crate::ExportAttributes::RET16);
}

#[test]
fn serde_rejects_unknown_fields_and_variants_at_every_layer() {
    let (catalog, groups, _) = fixture();
    let mut catalog = toml::Value::try_from(&catalog).unwrap();
    catalog.as_table_mut().unwrap().insert("includes".into(), toml::Value::Array(vec![]));
    assert!(decode_value::<Catalog>(catalog).is_err());
    let mut group = toml::Value::try_from(&groups["memory.toml"]).unwrap();
    group["exports"][0]["entry"]["abi"]["signature"]["parameters"][0]["value"].as_table_mut().unwrap().insert("mystery".into(), true.into());
    assert!(decode_value::<Group>(group).is_err());
    assert!(toml::from_str::<ValueType>(r#"kind = "native_pointer""#).is_err());
    assert!(toml::from_str::<Catalog>("version = 1\nversion = 1\nmodules = []\ngroups = []\ntypes = []\nname_resolutions = []").is_err());
}

#[test]
fn unknown_abi_is_metadata_only() {
    let (catalog, mut groups, types) = fixture();
    let export = export_mut(&mut groups);
    export.entry = Entry::Function { abi: Abi::Unknown };
    assert!(validate_catalog(catalog.clone(), groups.clone(), types.clone()).is_err());
    export_mut(&mut groups).binding = None;
    assert!(validate_catalog(catalog, groups, types).is_ok());
}

#[test]
fn duplicate_ordinals_names_aliases_and_rust_ids_are_global() {
    for change in 0..4 {
        let (mut catalog, mut groups, types) = fixture();
        let mut duplicate = groups["memory.toml"].exports[0].clone();
        match change {
            0 => { duplicate.name = Some("Other".into()); },
            1 => { duplicate.ordinal = 2; duplicate.name = Some("EXAMPLE".into()); },
            2 => { duplicate.ordinal = 2; duplicate.name = Some("Other".into()); duplicate.aliases = vec!["example".into()]; },
            _ => { duplicate.ordinal = 2; duplicate.name = Some("Other".into()); },
        }
        catalog.groups.push("files.toml".into());
        groups.insert("files.toml".into(), Group { version: 1, exports: vec![duplicate] });
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn module_aliases_use_runtime_suffix_and_case_rules() {
    let (mut catalog, groups, types) = fixture();
    catalog.modules.push(Module { id: "OTHER".into(), source_module: "other.dll".into(), aliases: vec!["KrNl386.DLL".into()] });
    assert!(validate_catalog(catalog, groups, types).is_err());
}

#[test]
fn safe_paths_and_exact_file_membership_are_required() {
    for path in ["../memory.toml", "/memory.toml", "a/../memory.toml", "a//memory.toml", "C:memory.toml", "a\\memory.toml", "./memory.toml", "a./memory.toml", "memory.TOML", "catalog.toml", "Catalog.toml"] {
        let (mut catalog, mut groups, types) = fixture();
        let group = groups.remove("memory.toml").unwrap();
        catalog.groups = vec![path.into()];
        groups.insert(path.into(), group);
        assert!(validate_catalog(catalog, groups, types).is_err(), "{path}");
    }
    let (catalog, mut groups, types) = fixture();
    groups.insert("unreferenced.toml".into(), Group { version: 1, exports: vec![] });
    assert!(validate_catalog(catalog, groups, types).is_err());
}

#[test]
fn schema_versions_are_checked_on_all_documents() {
    let (mut catalog, groups, types) = fixture();
    catalog.version = 2;
    assert!(validate_catalog(catalog, groups, types).is_err());
    let (catalog, mut groups, types) = fixture();
    groups.get_mut("memory.toml").unwrap().version = 2;
    assert!(validate_catalog(catalog, groups, types).is_err());
    let (mut catalog, groups, _) = fixture();
    catalog.types.push("types.toml".into());
    let types = BTreeMap::from([("types.toml".into(), SharedTypes { version: 2, types: vec![] })]);
    assert!(validate_catalog(catalog, groups, types).is_err());
}

#[test]
fn named_types_resolve_and_reject_missing_or_cyclic_references() {
    let (mut catalog, mut groups, _) = fixture();
    catalog.types.push("types.toml".into());
    signature_mut(export_mut(&mut groups)).parameters[0].value = ValueType::Named { name: "BYTE".into() };
    let named = NamedType { name: "BYTE".into(), value: ValueType::Integer { bits: 8, signedness: Signedness::Unknown }, evidence: vec![] };
    let mut types = BTreeMap::from([("types.toml".into(), SharedTypes { version: 1, types: vec![named] })]);
    assert!(validate_catalog(catalog.clone(), groups.clone(), types.clone()).is_ok());
    types.get_mut("types.toml").unwrap().types[0].value = ValueType::Named { name: "MISSING".into() };
    assert!(validate_catalog(catalog.clone(), groups.clone(), types.clone()).is_err());
    types.get_mut("types.toml").unwrap().types[0].value = ValueType::Named { name: "BYTE".into() };
    assert!(validate_catalog(catalog, groups, types).is_err());
}

#[test]
fn invalid_rust_identifiers_never_become_generated_code() {
    for bad in ["bad::path", "impl", "gen", "_", "1name", "x();", "r#type"] {
        let (catalog, mut groups, types) = fixture();
        export_mut(&mut groups).binding.as_mut().unwrap().rust_id = bad.into();
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn parameter_width_and_signature_errors_are_rejected() {
    for change in 0..5 {
        let (catalog, mut groups, types) = fixture();
        let signature = signature_mut(export_mut(&mut groups));
        match change {
            0 => signature.parameters[0].slot_bytes = 4,
            1 => signature.parameters[0].value = ValueType::Integer { bits: 32, signedness: Signedness::Signed },
            2 => signature.returns = ReturnValue::Unknown,
            3 => signature.parameters[0].value = ValueType::Unknown,
            _ => signature.calling_convention = CallingConvention::Stdcall,
        }
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn far_pointer_unknown_direction_and_nullability_stay_unknown() {
    let (catalog, mut groups, types) = fixture();
    let parameter = &mut signature_mut(export_mut(&mut groups)).parameters[0];
    parameter.slot_bytes = 4;
    parameter.value = ValueType::Far16_16 { role: FarPointerRole::FarPointer, direction: Direction::Unknown, nullability: Nullability::Unknown };
    let validated = validate_catalog(catalog, groups, types).unwrap();
    let (_, export) = validated.exports().next().unwrap();
    let encoded = toml::to_string(&export.entry.abi().unwrap().signature().unwrap().parameters[0].value).unwrap();
    assert!(encoded.contains("direction = \"unknown\""));
    assert!(encoded.contains("nullability = \"unknown\""));
}

#[test]
fn variable_and_register_abis_preserve_cleanup_shape() {
    let (catalog, mut groups, types) = fixture();
    let export = export_mut(&mut groups);
    let mut signature = export.entry.abi().unwrap().signature().unwrap().clone();
    signature.calling_convention = CallingConvention::Varargs;
    export.entry = Entry::Function { abi: Abi::VariableStack { signature } };
    let validated = validate_catalog(catalog.clone(), groups.clone(), types.clone()).unwrap();
    assert_eq!(validated.exports().next().unwrap().1.entry.abi().unwrap().cleanup(), None);
    let export = export_mut(&mut groups);
    let mut signature = export.entry.abi().unwrap().signature().unwrap().clone();
    signature.calling_convention = CallingConvention::Pascal;
    signature.parameters.clear();
    signature.returns = ReturnValue::RegisterContext;
    export.entry = Entry::Function { abi: Abi::RegisterContext { signature } };
    let validated = validate_catalog(catalog, groups, types).unwrap();
    assert_eq!(validated.exports().next().unwrap().1.entry.abi().unwrap().cleanup(), Some(StackCleanup { caller_pop_bytes: 0, callee_pop_bytes: 0 }));
}

#[test]
fn data_and_equates_cannot_acquire_function_bindings() {
    for entry in [Entry::Variable { values: vec![0, u32::MAX] }, Entry::Equate { value: -1 }] {
        let (catalog, mut groups, types) = fixture();
        let export = export_mut(&mut groups);
        export.declaration.declaration_type = match &entry { Entry::Variable { .. } => DeclarationType::Variable, _ => DeclarationType::Equate };
        export.declaration.abi = None;
        export.entry = entry;
        assert!(validate_catalog(catalog.clone(), groups.clone(), types.clone()).is_err());
        export_mut(&mut groups).binding = None;
        assert!(validate_catalog(catalog, groups, types).is_ok());
    }
}

struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("abi-schema-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[test]
fn rooted_loader_rejects_unreferenced_group_files() {
    let root = TempRoot::new();
    let (catalog, groups, _) = fixture();
    fs::write(root.0.join("catalog.toml"), toml::to_string(&catalog).unwrap()).unwrap();
    fs::write(root.0.join("memory.toml"), toml::to_string(&groups["memory.toml"]).unwrap()).unwrap();
    assert!(load_catalog(&root.0).is_ok());
    fs::write(root.0.join("forgotten.toml"), "version = 1\nexports = []\n").unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("not referenced"));
}

#[test]
fn grouping_does_not_change_logical_export_identity() {
    let (mut catalog, mut groups, types) = fixture();
    let original = groups.remove("memory.toml").unwrap();
    catalog.groups = vec!["drawing/any-name.toml".into()];
    groups.insert(catalog.groups[0].clone(), original);
    let validated = validate_catalog(catalog, groups, types).unwrap();
    let (path, export) = validated.exports().next().unwrap();
    assert_eq!(path, "drawing/any-name.toml");
    assert_eq!((&*export.module, export.ordinal), ("KERNEL", 1));
}

#[test]
fn historical_name_collisions_require_explicit_valid_precedence() {
    let (mut catalog, mut groups, types) = fixture();
    let mut collision = groups["memory.toml"].exports[0].clone();
    collision.ordinal = 595;
    collision.name = Some("EXAMPLE".into());
    collision.binding = None;
    groups.get_mut("memory.toml").unwrap().exports.push(collision);
    assert!(validate_catalog(catalog.clone(), groups.clone(), types.clone()).is_err());
    catalog.name_resolutions.push(NameResolution { module: "KERNEL".into(), name: "Example".into(), ordinal: 1 });
    let validated = validate_catalog(catalog.clone(), groups.clone(), types.clone()).unwrap();
    assert_eq!(validated.exports().count(), 2);
    catalog.name_resolutions[0].ordinal = 7;
    assert!(validate_catalog(catalog, groups, types).is_err());
}

#[test]
fn oversized_source_documents_are_rejected_before_parsing() {
    let root = TempRoot::new();
    fs::write(root.0.join("catalog.toml"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("1 MiB"));
}

#[test]
fn far_pointer_annotations_are_explicit_and_strict() {
    assert!(toml::from_str::<ValueType>("kind = \"far16_16\"\nrole = \"far_pointer\"").is_err());
    assert!(toml::from_str::<ValueType>("kind = \"far16_16\"\nrole = \"callback\"\ndirection = \"unknown\"\nnullability = \"unknown\"").is_err());
}

#[test]
fn cdecl_cleanup_uses_caller_and_same_canonical_slot_sum() {
    let (catalog, mut groups, types) = fixture();
    let export = export_mut(&mut groups);
    signature_mut(export).calling_convention = CallingConvention::Cdecl;
    let validated = validate_catalog(catalog, groups, types).unwrap();
    assert_eq!(validated.exports().next().unwrap().1.entry.abi().unwrap().cleanup(), Some(StackCleanup { caller_pop_bytes: 2, callee_pop_bytes: 0 }));
}

#[cfg(unix)]
#[test]
fn catalog_symlinks_are_rejected() {
    use std::os::unix::fs::symlink;
    let root = TempRoot::new();
    symlink("missing.toml", root.0.join("catalog.toml")).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("symlink"));
}

#[test]
fn historical_hints_never_select_or_constrain_runtime_abi() {
    let (catalog, mut groups, types) = fixture();
    let export = export_mut(&mut groups);
    // An old stub can acquire a verified bridge. Its unknown declaration
    // arguments and convention remain evidence, not the active call contract.
    export.declaration.declaration_type = DeclarationType::Stub;
    let hints = export.declaration.abi.as_mut().unwrap();
    hints.calling_convention = None;
    hints.knowledge = SignatureKnowledge::Unknown;
    hints.arguments = vec![ArgumentEncoding::Unknown];
    let abi = export.entry.abi().unwrap().clone();
    export.entry = Entry::Stub { abi };
    let validated = validate_catalog(catalog, groups, types).unwrap();
    let (_, export) = validated.exports().next().unwrap();
    let abi = export.entry.abi().unwrap();
    assert_eq!(abi.cleanup(), Some(StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 }));
    assert_eq!(abi.signature().unwrap().returns, ReturnValue::Void);
}

#[test]
fn semantic_signature_rejects_legacy_fields() {
    let (catalog, groups, _) = fixture();
    let mut group = toml::Value::try_from(&groups["memory.toml"]).unwrap();
    group["exports"][0]["entry"]["abi"]["signature"].as_table_mut().unwrap().insert("return_modifier".into(), "ret16".into());
    assert!(decode_value::<Group>(group).is_err());
    assert!(toml::to_string(&catalog).unwrap().contains("name_resolutions"));
}

#[test]
fn byte_word_and_dword_runtime_decoder_kinds_remain_distinct() {
    for (bits, kind, slot) in [(8, RuntimeArgumentKind::Byte, 2), (16, RuntimeArgumentKind::Word, 2), (32, RuntimeArgumentKind::Dword, 4)] {
        for signedness in [Signedness::Unknown, Signedness::Signed, Signedness::Unsigned] {
            let value = ValueType::Integer { bits, signedness };
            assert_eq!(value.runtime_argument_kind(), Some(kind));
            assert_eq!(kind.slot_bytes(), slot);
        }
    }
}

#[test]
fn register_context_return_and_argument_shapes_must_agree() {
    for return_kind in [ReturnValue::Void, ReturnValue::Word, ReturnValue::Dword, ReturnValue::FarPointer, ReturnValue::Unknown] {
        let (catalog, mut groups, types) = fixture();
        let export = export_mut(&mut groups);
        let mut signature = export.entry.abi().unwrap().signature().unwrap().clone();
        signature.parameters.clear();
        signature.returns = return_kind;
        export.entry = Entry::Function { abi: Abi::RegisterContext { signature } };
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
    for variable in [false, true] {
        let (catalog, mut groups, types) = fixture();
        let export = export_mut(&mut groups);
        let mut signature = export.entry.abi().unwrap().signature().unwrap().clone();
        signature.returns = ReturnValue::RegisterContext;
        export.entry = Entry::Function { abi: if variable {
            signature.calling_convention = CallingConvention::Varargs;
            Abi::VariableStack { signature }
        } else { Abi::FixedStack { signature } } };
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn register_context_rejects_unsupported_conventions() {
    for convention in [CallingConvention::Unknown, CallingConvention::Stdcall, CallingConvention::Thiscall, CallingConvention::Varargs] {
        let (catalog, mut groups, types) = fixture();
        let export = export_mut(&mut groups);
        export.entry = Entry::Function { abi: Abi::RegisterContext { signature: Signature {
            calling_convention: convention, parameters: vec![], returns: ReturnValue::RegisterContext,
        } } };
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn known_pointer_annotations_cannot_contradict_the_runtime_role() {
    for value in [
        ValueType::Far16_16 { role: FarPointerRole::NullableFarString, direction: Direction::Unknown, nullability: Nullability::NonNull },
        ValueType::Far16_16 { role: FarPointerRole::FarOutputBuffer, direction: Direction::In, nullability: Nullability::Unknown },
    ] {
        let (catalog, mut groups, types) = fixture();
        let parameter = &mut signature_mut(export_mut(&mut groups)).parameters[0];
        parameter.slot_bytes = 4;
        parameter.value = value;
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn loader_validates_root_index_before_opening_missing_group_files() {
    let root = TempRoot::new();
    let (mut catalog, _, _) = fixture();
    catalog.groups = vec!["missing.toml".into(), "MISSING.toml".into()];
    fs::write(root.0.join("catalog.toml"), toml::to_string(&catalog).unwrap()).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("duplicate"));
    catalog.groups = (0..256).map(|i| format!("missing{i}.toml")).collect();
    fs::write(root.0.join("catalog.toml"), toml::to_string(&catalog).unwrap()).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("file limit"));
}

#[cfg(unix)]
#[test]
fn literal_backslash_filename_cannot_alias_an_indexed_path() {
    let root = TempRoot::new();
    let (mut catalog, groups, _) = fixture();
    catalog.groups = vec!["a/b.toml".into()];
    fs::create_dir(root.0.join("a")).unwrap();
    fs::write(root.0.join("catalog.toml"), toml::to_string(&catalog).unwrap()).unwrap();
    fs::write(root.0.join("a/b.toml"), toml::to_string(&groups["memory.toml"]).unwrap()).unwrap();
    fs::write(root.0.join(r"a\b.toml"), "version = 1\nexports = []\n").unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("safe relative"));
}

#[cfg(unix)]
#[test]
fn non_regular_catalog_entries_are_rejected_without_reading() {
    use std::os::unix::net::UnixListener;
    let root = TempRoot::new();
    let _socket = UnixListener::bind(root.0.join("socket.toml")).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("regular files"));
}

#[test]
fn numeric_binding_discriminants_are_unique_and_generated_names_reserved() {
    let (catalog, mut groups, types) = fixture();
    let mut duplicate = groups["memory.toml"].exports[0].clone();
    duplicate.ordinal = 2;
    duplicate.name = Some("Other".into());
    let binding = duplicate.binding.as_mut().unwrap();
    binding.rust_id = "Other".into();
    binding.constant = "OTHER".into();
    groups.get_mut("memory.toml").unwrap().exports.push(duplicate);
    assert!(validate_catalog(catalog, groups, types).unwrap_err().message.contains("numeric discriminant"));
    for constant in ["EXPORTS", "WIN16_DECODER_KEYS"] {
        let (catalog, mut groups, types) = fixture();
        let binding = export_mut(&mut groups).binding.as_mut().unwrap();
        binding.constant = constant.into();
        assert!(validate_catalog(catalog, groups, types).is_err());
    }
}

#[test]
fn binding_rejects_a_second_editable_dispatch_identity() {
    let (catalog, groups, _) = fixture();
    let mut group = toml::Value::try_from(&groups["memory.toml"]).unwrap();
    group["exports"][0]["binding"].as_table_mut().unwrap().insert("decoder".into(), "Unregistered".into());
    assert!(decode_value::<Group>(group).is_err());
    assert_eq!(catalog.version, SCHEMA_VERSION);
}

#[test]
fn module_lookup_matches_canonical_source_and_explicit_alias_spellings() {
    let (mut catalog, groups, types) = fixture();
    catalog.modules[0].aliases.push("legacy.mod".into());
    let validated = validate_catalog(catalog, groups, types).unwrap();
    for stem in ["KERNEL", "krnl386", "legacy"] {
        for suffix in ["", ".DLL", ".EXE", ".DRV", ".MOD"] {
            let name = format!("{stem}{suffix}");
            for spelling in [name.to_ascii_uppercase(), name.to_ascii_lowercase()] {
                assert_eq!(validated.module(&spelling).map(|module| module.id.as_str()), Some("KERNEL"), "{spelling}");
            }
        }
    }
}

#[test]
fn module_lookup_does_not_normalize_paths_whitespace_or_multiple_suffixes() {
    let (catalog, groups, types) = fixture();
    let validated = validate_catalog(catalog, groups, types).unwrap();
    for name in ["", "OTHER", "KERNEL.DLL.EXE", "KERNEL.COM", " KERNEL", "KERNEL ", "path/KERNEL.DLL", r"path\KERNEL.DLL", "KÉRNEL"] {
        assert!(validated.module(name).is_none(), "{name}");
    }
}

#[test]
fn toml_optional_fields_round_trip_without_null_literals() {
    let (_, groups, _) = fixture();
    let original = &groups["memory.toml"];
    let encoded = toml::to_string(original).unwrap();
    let decoded: Group = toml::from_str(&encoded).unwrap();
    assert_eq!(&decoded, original);
    assert_eq!(decoded.exports[0].link_name, None);
    assert_eq!(decoded.exports[0].evidence[0].note, None);
    assert!(!encoded.contains("null"));
}

#[test]
fn toml_loader_accepts_comments_but_rejects_json_documents_and_paths() {
    let root = TempRoot::new();
    let (mut catalog, groups, _) = fixture();
    fs::write(root.0.join("catalog.toml"), format!("# Guest ABI catalog\n{}", toml::to_string(&catalog).unwrap())).unwrap();
    fs::write(root.0.join("memory.toml"), toml::to_string(&groups["memory.toml"]).unwrap()).unwrap();
    assert!(load_catalog(&root.0).is_ok());
    fs::write(root.0.join("catalog.toml"), r#"{"version":1,"modules":[],"name_resolutions":[],"groups":[],"types":[]}"#).unwrap();
    assert!(load_catalog(&root.0).is_err());
    catalog.groups = vec!["memory.json".into()];
    fs::write(root.0.join("catalog.toml"), toml::to_string(&catalog).unwrap()).unwrap();
    assert!(load_catalog(&root.0).unwrap_err().message.contains("safe relative .toml"));
}

#[test]
fn toml_root_requires_explicit_arrays_and_typed_integers() {
    assert!(toml::from_str::<Catalog>("version = 1\nmodules = []\ngroups = []\ntypes = []").is_err());
    assert!(toml::from_str::<Catalog>("version = '1'\nmodules = []\nname_resolutions = []\ngroups = []\ntypes = []").is_err());
}
