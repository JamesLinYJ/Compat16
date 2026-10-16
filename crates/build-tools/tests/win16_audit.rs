//! Manifest/compiler integration regressions. Independent SDK facts live in
//! win16_sdk_contracts.rs and are deliberately not generated from this fixture.
use std::collections::BTreeMap;
use std::path::Path;

use build_tools::{audit_win16_module, manifest::*};
use win16_abi::exports::{
    KERNEL_GET_VERSION, KERNEL_LOPEN, Win16ExportAbiKind, Win16ExportDescriptor,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind, export_descriptors,
};
use win16_abi::{ArgumentKind, StackCleanup};

fn version_export() -> Export {
    Export {
        module: "KERNEL".to_owned(), ordinal: 3, ordinal_source: OrdinalSource::Explicit,
        declared_name: "GetVersion".to_owned(), name: Some("GetVersion".to_owned()),
        aliases: vec![], link_name: None, import_library_name: None,
        architecture: Architecture::Win16,
        declaration: DeclarationEvidence {
            declaration_type: DeclarationType::Pascal,
            attributes: vec![Attribute::Ret16], architecture_constraints: vec![],
            abi: Some(DeclarationAbiEvidence {
                calling_convention: Some(CallingConvention::Pascal),
                knowledge: SignatureKnowledge::Known, arguments: vec![],
                return_modifier: ReturnModifier::Ret16,
            }),
        },
        entry: Entry::Function { abi: Abi::FixedStack { signature: Signature {
            calling_convention: CallingConvention::Pascal,
            parameters: vec![], returns: ReturnValue::Dword,
        } } },
        binding: Some(Binding {
            rust_id: "KernelGetVersion".to_owned(),
            id_value: KERNEL_GET_VERSION.id as u32,
            constant: "KERNEL_GET_VERSION".to_owned(),
        }),
        evidence: vec![],
    }
}

fn open_export() -> Export {
    let mut export = version_export();
    export.ordinal = 85;
    export.declared_name = "_lopen".to_owned();
    export.name = Some("_lopen".to_owned());
    export.binding = Some(Binding {
        rust_id: "KernelLopen".to_owned(), id_value: KERNEL_LOPEN.id as u32,
        constant: "KERNEL_LOPEN".to_owned(),
    });
    signature_mut(&mut export).returns = ReturnValue::Word;
    signature_mut(&mut export).parameters = vec![
        Parameter {
            name: "path".to_owned(), slot_bytes: 4,
            value: ValueType::Far16_16 {
                role: FarPointerRole::FarString,
                direction: Direction::Unknown, nullability: Nullability::Unknown,
            },
        },
        Parameter {
            name: "mode".to_owned(), slot_bytes: 2,
            value: ValueType::Integer { bits: 16, signedness: Signedness::Signed },
        },
    ];
    export
}

fn signature_mut(export: &mut Export) -> &mut Signature {
    let Entry::Function { abi: Abi::FixedStack { signature } } = &mut export.entry else {
        panic!("fixture fixed function");
    };
    signature
}

fn catalog(exports: Vec<Export>) -> ValidatedCatalog {
    validate_catalog(
        Catalog {
            version: SCHEMA_VERSION,
            modules: vec![Module {
                id: "KERNEL".to_owned(), source_module: "krnl386.exe".to_owned(),
                aliases: vec!["kernel16".to_owned()],
            }],
            name_resolutions: vec![], groups: vec!["kernel.toml".to_owned()], types: vec![],
        },
        BTreeMap::from([("kernel.toml".to_owned(), Group { version: SCHEMA_VERSION, exports })]),
        BTreeMap::new(),
    ).unwrap()
}

fn report(exports: Vec<Export>, descriptors: &[Win16ExportDescriptor]) -> build_tools::Win16AuditReport {
    audit_win16_module(&catalog(exports), "KERNEL", descriptors).unwrap()
}

#[test]
fn canonical_return_and_arguments_do_not_come_from_historical_hints() {
    // Ret16 and an empty historical argument list intentionally disagree with
    // the canonical Dword return and _lopen's verified parameter list.
    let report = report(vec![version_export(), open_export()], &[KERNEL_GET_VERSION, KERNEL_LOPEN]);
    assert!(!report.has_differences());
    let tsv = report.to_tsv();
    assert!(tsv.contains("\nMATCH\tKERNEL\t3\t3\tGetVersion\tGetVersion\t"));
    assert!(tsv.contains("no host implementation or service support is inferred"));
    assert!(tsv.contains("Independent SDK facts are tested separately"));
    assert!(tsv.contains("exact_matches=2 declared_only=0 differences=0"));
    assert_eq!(tsv, report.to_tsv());
}

#[test]
fn return_cleanup_convention_and_abi_differences_are_reported() {
    let mut changed = KERNEL_GET_VERSION;
    changed.return_kind = Win16ReturnKind::Word;
    changed.abi_kind = Win16ExportAbiKind::RegisterContext;
    changed.calling_convention = win16_abi::exports::ExportCallingConvention::Cdecl;
    changed.stack_cleanup = Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 2, caller_pop_bytes: 2,
    });
    let report = report(vec![version_export()], &[changed]);
    assert!(report.has_differences());
    for label in ["return kind", "ABI kind", "calling convention", "stack cleanup"] {
        assert!(report.to_tsv().contains(&format!("{label} differs")));
    }
}

#[test]
fn same_width_byte_kind_and_pointer_semantics_are_not_interchangeable() {
    let mut changed = open_export();
    signature_mut(&mut changed).parameters[1].value = ValueType::Integer {
        bits: 8, signedness: Signedness::Signed,
    };
    signature_mut(&mut changed).parameters[0].value = ValueType::Far16_16 {
        role: FarPointerRole::FarOutputBuffer,
        direction: Direction::Unknown, nullability: Nullability::Unknown,
    };
    let report = report(vec![changed], &[KERNEL_LOPEN]);
    assert!(report.has_differences());
    let tsv = report.to_tsv();
    assert!(tsv.contains("parameter 2 value kind differs"));
    assert!(tsv.contains("parameter 1 semantic role differs"));
    assert!(!tsv.contains("slot bytes differs"));
}

#[test]
fn parameter_names_widths_and_counts_are_checked() {
    let mut changed = open_export();
    signature_mut(&mut changed).parameters[0] = Parameter {
        name: "changed".to_owned(), slot_bytes: 2,
        value: ValueType::Integer { bits: 16, signedness: Signedness::Unknown },
    };
    signature_mut(&mut changed).parameters.pop();
    let report = report(vec![changed], &[KERNEL_LOPEN]);
    assert!(report.has_differences());
    for label in ["parameter count", "parameter 1 name", "parameter 1 value kind", "parameter 1 slot bytes", "parameter 1 semantic role", "stack cleanup"] {
        assert!(report.to_tsv().contains(&format!("{label} differs")));
    }
}

#[test]
fn unknown_unbound_signature_does_not_claim_missing_runtime_support() {
    let mut export = version_export();
    export.entry = Entry::Function { abi: Abi::Unknown };
    export.binding = None;
    let declared = report(vec![export.clone()], &[]);
    assert!(!declared.has_differences());
    assert!(declared.to_tsv().contains("DECLARED_ONLY"));
    let unexpected = report(vec![export], &[KERNEL_GET_VERSION]);
    assert!(unexpected.has_differences());
    assert!(unexpected.to_tsv().contains("unbound declaration unexpectedly has a compiled runtime descriptor"));
}

#[test]
fn missing_extra_and_duplicate_descriptors_are_differences() {
    let missing = report(vec![version_export()], &[]);
    assert!(missing.has_differences());
    assert!(missing.to_tsv().contains("MANIFEST_ONLY"));
    let extra = report(vec![], &[KERNEL_GET_VERSION]);
    assert!(extra.has_differences());
    assert!(extra.to_tsv().contains("RUNTIME_ONLY"));
    let duplicate = report(vec![version_export()], &[KERNEL_GET_VERSION, KERNEL_GET_VERSION]);
    assert!(duplicate.has_differences());
    assert!(duplicate.to_tsv().contains("AMBIGUOUS"));
}

#[test]
fn identity_changes_cannot_pass_using_a_name_or_binding_fallback() {
    for change in 0..4 {
        let mut export = version_export();
        match change {
            0 => export.ordinal += 1,
            1 => export.name = Some("GETVERSION".to_owned()),
            2 => export.binding.as_mut().unwrap().rust_id.push_str("Changed"),
            _ => export.binding.as_mut().unwrap().id_value += 1,
        }
        let report = report(vec![export], &[KERNEL_GET_VERSION]);
        assert!(report.has_differences());
        assert!(report.to_tsv().contains("MISMATCH"));
    }
}

#[test]
fn module_lookup_uses_shared_alias_rules_and_rejects_unknown_modules() {
    let catalog = catalog(vec![version_export()]);
    for module in ["kernel", "KrNl386.DLL", "kernel16.drv"] {
        assert!(!audit_win16_module(&catalog, module, &[KERNEL_GET_VERSION]).unwrap().has_differences());
    }
    for module in ["missing", "../KERNEL", "KERNEL "] {
        assert!(audit_win16_module(&catalog, module, &[KERNEL_GET_VERSION]).is_err());
    }
}

#[test]
fn named_types_resolve_to_the_same_runtime_contract() {
    let catalog = catalog(vec![open_export()]);
    let mut root = catalog.catalog().clone();
    root.types.push("types.toml".to_owned());
    let mut groups = catalog.groups().clone();
    signature_mut(&mut groups.get_mut("kernel.toml").unwrap().exports[0]).parameters[1].value = ValueType::Named { name: "MODE".to_owned() };
    let catalog = validate_catalog(root, groups, BTreeMap::from([("types.toml".to_owned(), SharedTypes {
        version: SCHEMA_VERSION,
        types: vec![NamedType {
            name: "MODE".to_owned(),
            value: ValueType::Integer { bits: 16, signedness: Signedness::Signed },
            evidence: vec![],
        }],
    })])).unwrap();
    assert!(!audit_win16_module(&catalog, "KERNEL", &[KERNEL_LOPEN]).unwrap().has_differences());
}

#[test]
fn checked_in_catalog_agrees_with_the_compiled_runtime_contracts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../abi");
    let catalog = load_catalog(&root).unwrap();
    for module in &catalog.catalog().modules {
        let report = audit_win16_module(&catalog, &module.id, export_descriptors()).unwrap();
        assert!(!report.has_differences(), "{}", report.to_tsv());
    }
    // Every runtime descriptor must also have a declared logical module.
    for descriptor in export_descriptors() {
        assert!(catalog.module(descriptor.module()).is_some());
    }
}

#[test]
fn fixed_fixture_still_exercises_distinct_runtime_argument_and_pointer_kinds() {
    assert_eq!(KERNEL_LOPEN.parameters[0].kind, ArgumentKind::Dword);
    assert_eq!(KERNEL_LOPEN.parameters[0].parameter_type, Win16ParameterType::FarString);
    assert_eq!(KERNEL_LOPEN.parameters[1].kind, ArgumentKind::Word);
    assert_eq!(KERNEL_LOPEN.parameters[1].parameter_type, Win16ParameterType::SignedScalar);
}
