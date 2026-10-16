//! Independent compiled-ABI capture for spec migration review. This consumes
//! the public catalog, not spec text or generated Rust, and changes no runtime
//! behavior. Declaration hints deliberately remain separate from descriptors.

use super::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Write;

macro_rules! labels {
    ($function:ident, $ty:ident, $($variant:ident),+ $(,)?) => {
        fn $function(value: $ty) -> &'static str {
            match value { $($ty::$variant => stringify!($variant),)+ }
        }
    };
}

labels!(architecture, ExportArchitecture, Win16, Win32Only, Unknown);
labels!(entry_kind, ExportEntryKind, Function, Stub, Variable, Equate, Extern, Forward, Unknown);
labels!(signature, ExportSignatureKind, Known, Unknown);
labels!(declaration_type, ExportDeclarationType,
    Variable, Pascal, Equate, Stub, Stdcall, Cdecl, Varargs, Thiscall, Extern, Unknown);
labels!(convention, ExportCallingConvention, Pascal, Stdcall, Cdecl, Varargs, Thiscall, Unknown);
labels!(argument_type, ExportArgumentType,
    Word, SignedWord, SegmentedPointer, SegmentedString, Long, Pointer, String,
    WideString, Int64, Int128, Float, Double, Unknown);
labels!(return_modifier, ExportReturnModifier, Void, Unspecified, Ret16, Ret64, Ret16AndRet64, Unknown);
labels!(ordinal_source, ExportOrdinalSource, Explicit, Assigned);
labels!(argument_kind, ArgumentKind, Byte, Word, Dword);
labels!(parameter_type, Win16ParameterType,
    Scalar, SignedScalar, FarString, FarPointer, FarStringOrChar, ResourceName,
    AtomName, ClassName, NullableFarString, FarBuffer, FarOutputBuffer);
labels!(return_kind, Win16ReturnKind, Word, Dword, FarPointer, RegisterContext, Void);
labels!(abi_kind, Win16ExportAbiKind, Stack, VariableStack, RegisterContext);
labels!(runtime_state, Win16VariableRuntimeState, InitialWords, Unspecified);
labels!(selector_equate, Win16RuntimeSelectorEquate,
    RomBios, VideoA000, OptionRomC000, OptionRomD000, VideoB000, VideoB800,
    ConventionalZero, OptionRomE000, BiosData, BiosRomF000, FlatCode, FlatData);

fn data_source(declaration: &'static ExportMetadata) -> Value {
    match lookup_data_export_source(declaration) {
        None => Value::Null,
        Some(Win16DataExportSource::VariableWords { words, runtime_state: state }) => json!({
            "kind": "VariableWords", "words": words, "runtime_state": runtime_state(state),
        }),
        Some(Win16DataExportSource::Equate(source)) => match source {
            Win16EquateValueSource::Literal(value) => json!({"kind": "Literal", "value": value}),
            Win16EquateValueSource::CurrentWinFlags => json!({"kind": "CurrentWinFlags"}),
            Win16EquateValueSource::RuntimeSelector(selector) => json!({
                "kind": "RuntimeSelector", "selector": selector_equate(selector),
            }),
        },
    }
}

fn descriptor_value(descriptor: &Win16ExportDescriptor) -> Value {
    let cleanup = match descriptor.stack_cleanup {
        Win16ExportStackCleanup::Variable => json!({"kind": "Variable"}),
        Win16ExportStackCleanup::Fixed(cleanup) => json!({
            "kind": "Fixed", "callee_pop_bytes": cleanup.callee_pop_bytes,
            "caller_pop_bytes": cleanup.caller_pop_bytes,
        }),
    };
    json!({
        "module": descriptor.module(), "ordinal": descriptor.ordinal(), "name": descriptor.name(),
        // Debug is used only to label one fieldless Rust identity, never to
        // serialize or parse an ABI structure. ABI fields below are explicit.
        "rust_id": format!("{:?}", descriptor.id),
        "id_value": descriptor.id as u32,
        "abi_kind": abi_kind(descriptor.abi_kind),
        "calling_convention": convention(descriptor.calling_convention),
        "return_kind": return_kind(descriptor.return_kind), "stack_cleanup": cleanup,
        "parameters": descriptor.parameters.iter().map(|parameter| json!({
            "name": parameter.name, "kind": argument_kind(parameter.kind),
            "role": parameter_type(parameter.parameter_type),
        })).collect::<Vec<_>>(),
    })
}

fn declaration_value(declaration: &'static ExportMetadata) -> Value {
    let descriptor = (declaration.architecture == ExportArchitecture::Win16)
        .then(|| lookup_export(declaration.module.as_bytes(), ExportLookupTarget::Ordinal(declaration.ordinal)))
        .flatten();
    json!({
        "module": declaration.module, "source_module": declaration.source_module,
        "ordinal": declaration.ordinal, "ordinal_source": ordinal_source(declaration.ordinal_source),
        "name": declaration.name, "declared_name": declaration.declared_name,
        "link_name": declaration.link_name, "import_library_name": declaration.import_library_name,
        "kind": entry_kind(declaration.kind), "declaration_type": declaration_type(declaration.declaration_type),
        "architecture": architecture(declaration.architecture),
        "flags": {"bits": declaration.flags.bits(), "architecture_constraints": declaration.flags.architecture_constraints},
        "declaration_abi_hints": declaration.abi.map(|abi| json!({
            "calling_convention": abi.calling_convention.map(convention),
            "signature": signature(abi.signature), "return_modifier": return_modifier(abi.return_modifier),
            "arguments": abi.arguments.iter().copied().map(argument_type).collect::<Vec<_>>(),
        })),
        "variable_values": declaration.variable_values, "equate_value": declaration.equate_value,
        "data_source": data_source(declaration),
        "descriptor_present": descriptor.is_some(),
        // A declaration's name may be shadowed by an earlier ordinal under
        // ASCII-insensitive lookup (USER.595 OLDEXITWINDOWS resolves USER.2).
        "name_lookup_ordinal": (declaration.architecture == ExportArchitecture::Win16)
            .then(|| declaration.name.and_then(|name| {
                lookup_export_metadata(declaration.module.as_bytes(), ExportLookupTarget::Name(name.as_bytes()))
                    .map(|entry| entry.ordinal)
            })).flatten(),
        "source": {"spec_path": declaration.source.spec_path, "line": declaration.source.line},
    })
}

fn assert_resolution(
    declaration: &'static ExportMetadata,
    descriptor: Option<&'static Win16ExportDescriptor>,
    module: &str,
    target: ExportLookupTarget<'_>,
) {
    assert_eq!(lookup_export_metadata(module.as_bytes(), target), Some(declaration),
        "metadata lookup differs for {module} {target:?}");
    assert_eq!(lookup_export(module.as_bytes(), target), descriptor,
        "descriptor lookup differs for {module} {target:?}");
    assert_eq!(resolve_export(module.as_bytes(), target), Some(ExportResolution {
        declaration,
        descriptor,
        state: if descriptor.is_some() {
            ExportImplementationState::BoundToRequest
        } else {
            ExportImplementationState::DeclaredOnly
        },
    }), "joined resolution differs for {module} {target:?}");
}

fn module_spellings(declaration: &ExportMetadata) -> BTreeSet<String> {
    // The current resolver strips exactly one of these four suffixes from
    // imports and source_module, then compares ASCII case-insensitively. In
    // particular KERNEL also accepts krnl386, and driver modules accept .DRV.
    let suffixes = [".EXE", ".DLL", ".DRV", ".MOD"];
    let source = declaration.source_module;
    let source_stem = suffixes.iter().find_map(|suffix| {
        let start = source.len().checked_sub(suffix.len())?;
        source.get(start..)?.eq_ignore_ascii_case(suffix).then(|| &source[..start])
    }).unwrap_or(source);
    let mut spellings = BTreeSet::from([source.to_owned(), source.to_ascii_lowercase()]);
    for stem in [declaration.module, source_stem] {
        for suffix in ["", ".EXE", ".DLL", ".DRV", ".MOD"] {
            let module = format!("{stem}{suffix}");
            spellings.insert(module.to_ascii_lowercase());
            spellings.insert(module.to_ascii_uppercase());
        }
    }
    spellings
}

fn expected_named_declaration(module: &str, name: &str) -> Option<&'static ExportMetadata> {
    let selected = declarations::NAME_RESOLUTIONS.iter()
        .find(|&&(candidate, alias, _)| candidate == module && alias.eq_ignore_ascii_case(name))
        .map(|&(_, _, ordinal)| ordinal);
    WIN16_EXPORTS.iter().flat_map(|group| group.iter()).find(|candidate| {
        candidate.architecture == ExportArchitecture::Win16
            && candidate.module == module
            && match selected {
                Some(ordinal) => candidate.ordinal == ordinal,
                None => candidate.name.is_some_and(|candidate_name| candidate_name.eq_ignore_ascii_case(name)),
            }
    })
}

// Normalize only container order and the two intentional provenance changes.
// All semantic fields, including enum discriminants, remain in the comparison.
fn comparable_baseline(mut document: Value) -> Value {
    let declarations = document["declarations"].as_array_mut()
        .expect("baseline declarations must be an array");
    for declaration in declarations.iter_mut() {
        let source = declaration["source"].as_object_mut()
            .expect("baseline declaration source must be an object");
        source.remove("spec_path");
        source.remove("line");
    }
    declarations.sort_by_cached_key(Value::to_string);
    document["descriptors"].as_array_mut()
        .expect("baseline descriptors must be an array")
        .sort_by_cached_key(Value::to_string);
    document
}

#[test]
fn baseline_comparison_ignores_only_provenance_and_top_level_order() {
    let original = json!({
        "declarations": [
            {"ordinal": 2, "source": {"spec_path": "old.spec", "line": 3}, "flags": 4},
            {"ordinal": 1, "source": {"spec_path": "old.spec", "line": 2}, "flags": 0},
        ],
        "descriptors": [{"id_value": 1, "parameters": ["first", "second"]}, {"id_value": 2}],
        "counts": {"declarations": 2},
    });
    let mut reordered = original.clone();
    reordered["declarations"].as_array_mut().unwrap().reverse();
    reordered["descriptors"].as_array_mut().unwrap().reverse();
    reordered["declarations"][0]["source"] = json!({"spec_path": "groups/new.toml", "line": 0});
    assert_eq!(comparable_baseline(original.clone()), comparable_baseline(reordered));
    for changed in [
        { let mut value = original.clone(); value["declarations"][0]["flags"] = json!(0); value },
        { let mut value = original.clone(); value["descriptors"][0]["id_value"] = json!(3); value },
        { let mut value = original.clone(); value["descriptors"][0]["parameters"].as_array_mut().unwrap().reverse(); value },
        { let mut value = original.clone(); value["counts"]["declarations"] = json!(3); value },
    ] {
        assert_ne!(comparable_baseline(original.clone()), comparable_baseline(changed));
    }
}

/// Run explicitly with ABI_BASELINE_PATH pointing to a retained JSON artifact.
/// Set ABI_BASELINE_REFERENCE to compare a retained pre-migration artifact.
/// No timestamps, host paths, or native addresses are included. Sorting fixes
/// traversal order; JSON numbers and null preserve widths/absence unambiguously.
#[test]
#[ignore = "explicit pre-migration compiled ABI artifact capture"]
fn capture_compiled_abi_baseline() {
    let output = std::env::var_os("ABI_BASELINE_PATH")
        .expect("set ABI_BASELINE_PATH to the output JSON file");
    let mut declarations: Vec<_> = WIN16_EXPORTS.iter().flat_map(|group| group.iter()).collect();
    declarations.sort_by_key(|entry| (entry.module, entry.ordinal, entry.source_module, entry.source.line));
    assert_eq!(declarations.len(), 3196, "pre-migration declaration count changed");
    let mut descriptors: Vec<_> = export_descriptors().iter().collect();
    descriptors.sort_by_key(|entry| (entry.module(), entry.ordinal()));
    let mut identities = BTreeSet::new();
    for descriptor in &descriptors {
        assert!(identities.insert((descriptor.module(), descriptor.ordinal())), "duplicate descriptor identity");
        assert_eq!(lookup_export(descriptor.module().as_bytes(), ExportLookupTarget::Ordinal(descriptor.ordinal())), Some(*descriptor));
        let named_declaration = expected_named_declaration(descriptor.module(), descriptor.name());
        let named_descriptor = named_declaration.and_then(|declaration| {
            export_descriptors().iter().find(|candidate| {
                candidate.module() == declaration.module && candidate.ordinal() == declaration.ordinal
            })
        });
        assert_eq!(lookup_export_metadata(descriptor.module().as_bytes(), ExportLookupTarget::Name(descriptor.name().as_bytes())), named_declaration);
        assert_eq!(lookup_export(descriptor.module().as_bytes(), ExportLookupTarget::Name(descriptor.name().as_bytes())), named_descriptor);
    }
    let mut active_identities = BTreeSet::new();
    let mut spelling_checked_modules = BTreeSet::new();
    for declaration in &declarations {
        if declaration.architecture == ExportArchitecture::Win16 {
            assert!(active_identities.insert((declaration.module, declaration.ordinal)), "duplicate active declaration identity");
            // Select the expected descriptor independently from the enumerated
            // catalog. None must stay None for every unbound declaration.
            let expected = export_descriptors().iter().find(|descriptor| {
                descriptor.module() == declaration.module && descriptor.ordinal() == declaration.ordinal
            });
            // Name collisions use the catalog's explicit choice, independently
            // of physical TOML grouping and sorted artifact order.
            let named_declaration = declaration.name.map(|name| {
                expected_named_declaration(declaration.module, name)
                    .expect("named declaration must occur in the public catalog")
            });
            // All rows exercise canonical ordinal/name resolution. Module
            // normalization is shared across rows, so exhaust its spelling
            // cross-product once per logical module, rather than multiplying
            // thousands of linear catalog lookups on debug ARM64 builds.
            let spellings = if spelling_checked_modules.insert(declaration.module) {
                module_spellings(declaration)
            } else {
                BTreeSet::from([declaration.module.to_owned()])
            };
            for module in spellings {
                assert_resolution(declaration, expected, &module, ExportLookupTarget::Ordinal(declaration.ordinal));
                if let (Some(name), Some(named_declaration)) = (declaration.name, named_declaration) {
                    let named_descriptor = export_descriptors().iter().find(|descriptor| {
                        descriptor.module() == named_declaration.module && descriptor.ordinal() == named_declaration.ordinal
                    });
                    assert_resolution(named_declaration, named_descriptor, &module, ExportLookupTarget::Name(name.as_bytes()));
                    let lower_name = name.to_ascii_lowercase();
                    assert_resolution(named_declaration, named_descriptor, &module, ExportLookupTarget::Name(lower_name.as_bytes()));
                }
            }
        }
    }
    // Explicit compatibility aliases in the current public lookup contract.
    // Check both metadata and descriptor resolution so this is not a guessed
    // relationship inferred from declaration text or spelling.
    let aliases = [("GDI", 104, "RectVisibleOld"), ("GDI", 181, "RectInRegionOld")];
    for &(module, ordinal, name) in &aliases {
        let metadata = lookup_export_metadata(module.as_bytes(), ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!((metadata.module, metadata.ordinal), (module, ordinal));
        let expected = export_descriptors().iter().find(|descriptor| {
            descriptor.module() == module && descriptor.ordinal() == ordinal
        });
        for spelling in module_spellings(metadata) {
            assert_resolution(metadata, expected, &spelling, ExportLookupTarget::Name(name.as_bytes()));
            assert_resolution(metadata, expected, &spelling, ExportLookupTarget::Name(name.to_ascii_lowercase().as_bytes()));
        }
        assert_eq!(lookup_export_metadata(b"USER", ExportLookupTarget::Name(name.as_bytes())), None,
            "GDI compatibility aliases must remain module-scoped");
    }
    // Preserve the actual compiled result, including known differences from
    // old spec hints. Never "correct" a descriptor using declaration modifiers.
    let close_window = lookup_export(b"USER", ExportLookupTarget::Name(b"CloseWindow")).unwrap();
    assert_eq!(close_window.return_kind, Win16ReturnKind::Void);
    let declaration_only_count = declarations.iter().filter(|entry| {
        entry.architecture == ExportArchitecture::Win16 && !identities.contains(&(entry.module, entry.ordinal))
    }).count();
    let document = json!({
        "schema_version": 1,
        "scope": "Compiled declaration and request-descriptor contracts; not runtime implementation coverage",
        "counts": {"declarations": declarations.len(), "active_win16_declarations": active_identities.len(),
            "descriptors": descriptors.len(), "active_declarations_without_descriptor": declaration_only_count},
        "lookup_contract": {"ascii_case_insensitive": true, "module_suffixes": [".EXE", ".DLL", ".DRV", ".MOD"],
            "module_names": "canonical module or source_module with conventional suffix removed",
            "compatibility_name_aliases": aliases.iter().map(|&(module, ordinal, name)| json!({
                "module": module, "ordinal": ordinal, "name": name,
            })).collect::<Vec<_>>()},
        "declarations": declarations.into_iter().map(declaration_value).collect::<Vec<_>>(),
        "descriptors": descriptors.into_iter().map(descriptor_value).collect::<Vec<_>>(),
    });
    if let Some(reference) = std::env::var_os("ABI_BASELINE_REFERENCE") {
        let reference = std::fs::File::open(reference).expect("open retained ABI baseline");
        let expected: Value = serde_json::from_reader(reference).expect("read retained ABI baseline");
        assert_eq!(comparable_baseline(document.clone()), comparable_baseline(expected),
            "compiled ABI changed beyond catalog provenance and collection order");
    }
    let path = std::path::PathBuf::from(output);
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).expect("create baseline artifact directory");
    }
    let mut file = std::fs::File::create(path).expect("create ABI baseline artifact");
    serde_json::to_writer_pretty(&mut file, &document).expect("write ABI baseline JSON");
    file.write_all(b"\n").expect("finish ABI baseline JSON");
    file.sync_all().expect("flush ABI baseline artifact");
    println!("Compiled ABI baseline captured: {}", document["counts"]);
}
