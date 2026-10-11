use std::collections::BTreeMap;

use abi_schema::manifest::*;
use crate::compile_catalog;

fn export(ordinal: u16) -> Export {
    Export {
        module: "TEST".into(), ordinal, ordinal_source: OrdinalSource::Explicit,
        declared_name: format!("Example{ordinal}"), name: Some(format!("Example{ordinal}")),
        aliases: vec![], link_name: None, import_library_name: None,
        architecture: Architecture::Win16,
        declaration: DeclarationEvidence {
            declaration_type: DeclarationType::Pascal, attributes: vec![Attribute::Ret16],
            architecture_constraints: vec![], abi: Some(DeclarationAbiEvidence {
                calling_convention: Some(CallingConvention::Pascal), knowledge: SignatureKnowledge::Known,
                arguments: vec![ArgumentEncoding::Word], return_modifier: ReturnModifier::Ret16,
            }),
        },
        entry: Entry::Function { abi: Abi::FixedStack { signature: Signature {
            calling_convention: CallingConvention::Cdecl,
            parameters: vec![Parameter { name: "byte".into(), slot_bytes: 2,
                value: ValueType::Integer { bits: 8, signedness: Signedness::Signed } }],
            returns: ReturnValue::Void,
        } } },
        binding: Some(Binding { id_value: u32::from(ordinal), rust_id: format!("Example{ordinal}"), constant: format!("EXAMPLE_{ordinal}") }),
        evidence: vec![],
    }
}

fn validate(exports: Vec<Export>, types: Vec<NamedType>, resolutions: Vec<NameResolution>) -> ValidatedCatalog {
    validate_catalog(Catalog {
        version: SCHEMA_VERSION,
        modules: vec![Module { id: "TEST".into(), source_module: "test.dll".into(), aliases: vec!["test_alias".into()] }],
        name_resolutions: resolutions, groups: vec!["group.toml".into()], types: vec!["types.toml".into()],
    }, BTreeMap::from([("group.toml".into(), Group { version: SCHEMA_VERSION, exports })]),
    BTreeMap::from([("types.toml".into(), SharedTypes { version: SCHEMA_VERSION, types })])).unwrap()
}

fn signature(export: &mut Export) -> &mut Signature {
    let Entry::Function { abi: Abi::FixedStack { signature } } = &mut export.entry else { panic!("fixture signature"); };
    signature
}

#[test]
fn semantic_signature_controls_byte_signedness_return_and_cleanup() {
    let validated = validate(vec![export(1)], vec![], vec![]);
    let generated = compile_catalog(&validated);
    assert_eq!(generated, compile_catalog(&validated));
    assert!(generated.bindings.contains("kind: ArgumentKind::Byte, parameter_type: Win16ParameterType::SignedScalar"));
    assert!(generated.bindings.contains("calling_convention: ExportCallingConvention::Cdecl"));
    assert!(generated.bindings.contains("return_kind: Win16ReturnKind::Void"));
    assert!(generated.bindings.contains("callee_pop_bytes: 0, caller_pop_bytes: 2"));
    assert!(!generated.bindings.contains("ExportCallingConvention::Pascal"));
    assert!(generated.metadata.contains("Some(ExportCallingConvention::Pascal)"));
    assert!(generated.metadata.contains("ExportReturnModifier::Ret16"));
    assert!(generated.metadata.contains("source_module: \"test.dll\""));
    assert!(generated.metadata.contains("spec_path: \"group.toml\", line: 0"));
    assert!(generated.bindings.contains("(Win16ExportId::Example1, \"Example1\")"));
}

#[test]
fn named_types_resolve_structurally_and_preserve_far_roles() {
    let roles = [FarPointerRole::FarString, FarPointerRole::FarPointer, FarPointerRole::FarStringOrChar,
        FarPointerRole::ResourceName, FarPointerRole::AtomName, FarPointerRole::ClassName,
        FarPointerRole::NullableFarString, FarPointerRole::FarBuffer, FarPointerRole::FarOutputBuffer];
    let mut entry = export(1);
    signature(&mut entry).parameters = roles.iter().enumerate().map(|(i, role)| Parameter {
        name: format!("p{i}"), slot_bytes: 4, value: ValueType::Far16_16 {
            role: *role, direction: Direction::Unknown, nullability: Nullability::Unknown,
        },
    }).collect();
    signature(&mut entry).parameters.push(Parameter { name: "named".into(), slot_bytes: 2,
        value: ValueType::Named { name: "ALIAS".into() } });
    let types = vec![NamedType { name: "ALIAS".into(), value: ValueType::Named { name: "BYTE".into() }, evidence: vec![] },
        NamedType { name: "BYTE".into(), value: ValueType::Integer { bits: 8, signedness: Signedness::Unsigned }, evidence: vec![] }];
    let generated = compile_catalog(&validate(vec![entry], types, vec![]));
    for role in roles { assert!(generated.bindings.contains(&format!("Win16ParameterType::{role:?}"))); }
    assert!(generated.bindings.contains("name: \"named\", kind: ArgumentKind::Byte, parameter_type: Win16ParameterType::Scalar"));
    assert!(generated.bindings.contains("caller_pop_bytes: 38"));
}

#[test]
fn unknown_entries_and_data_remain_metadata_only() {
    let mut unknown = export(1);
    unknown.entry = Entry::Function { abi: Abi::Unknown };
    unknown.binding = None;
    let mut variable = export(2);
    variable.entry = Entry::Variable { values: vec![0, u32::MAX, 42] };
    variable.binding = None;
    variable.declaration = DeclarationEvidence { declaration_type: DeclarationType::Variable, attributes: vec![], architecture_constraints: vec![], abi: None };
    let mut equate = variable.clone();
    equate.ordinal = 3;
    equate.name = None;
    equate.entry = Entry::Equate { value: -1 };
    equate.declaration.declaration_type = DeclarationType::Equate;
    let generated = compile_catalog(&validate(vec![unknown, variable, equate], vec![], vec![]));
    assert!(!generated.bindings.contains("pub const EXAMPLE_"));
    assert!(generated.metadata.contains("ExportEntryKind::Function"));
    assert!(generated.metadata.contains("variable_values: &[0, 4294967295, 42]"));
    assert!(generated.metadata.contains("equate_value: Some(-1)"));
}

#[test]
fn names_are_escaped_and_collisions_have_explicit_tables() {
    let mut first = export(1);
    first.name = Some("Name\"\\\n".into());
    first.aliases = vec!["Shared".into()];
    signature(&mut first).parameters[0].name = "value\"\\\n".into();
    let mut second = export(2);
    second.aliases = vec!["shared".into()];
    let resolution = NameResolution { module: "TEST".into(), name: "SHARED".into(), ordinal: 2 };
    let generated = compile_catalog(&validate(vec![first, second], vec![], vec![resolution]));
    assert!(generated.metadata.contains(r#"Some("Name\"\\\n")"#));
    assert!(generated.bindings.contains(r#"name: "value\"\\\n""#));
    assert!(generated.metadata.contains("(\"TEST\", \"test_alias\")"));
    assert!(generated.metadata.contains("(\"TEST\", 1, \"Shared\")"));
    assert!(generated.metadata.contains("(\"TEST\", \"SHARED\", 2)"));
}

#[test]
fn variable_and_register_context_have_distinct_cleanup() {
    let mut variable = export(1);
    let mut sig = signature(&mut variable).clone();
    sig.calling_convention = CallingConvention::Varargs;
    variable.entry = Entry::Function { abi: Abi::VariableStack { signature: sig } };
    let mut registers = export(2);
    let mut sig = signature(&mut registers).clone();
    sig.parameters.clear();
    sig.returns = ReturnValue::RegisterContext;
    registers.entry = Entry::Function { abi: Abi::RegisterContext { signature: sig } };
    let generated = compile_catalog(&validate(vec![variable, registers], vec![], vec![]));
    assert!(generated.bindings.contains("Win16ExportAbiKind::VariableStack"));
    assert!(generated.bindings.contains("stack_cleanup: Win16ExportStackCleanup::Variable"));
    assert!(generated.bindings.contains("Win16ExportAbiKind::RegisterContext"));
    assert!(generated.bindings.contains("callee_pop_bytes: 0, caller_pop_bytes: 0"));
}

#[test]
fn explicit_discriminants_and_descriptor_order_survive_group_reordering() {
    let first = export(1);
    let second = export(2);
    let forward = compile_catalog(&validate(vec![first.clone(), second.clone()], vec![], vec![]));
    let reverse = compile_catalog(&validate(vec![second, first], vec![], vec![]));
    assert_eq!(forward.bindings, reverse.bindings);
    assert!(forward.bindings.contains("Example1 = 1,"));
    assert!(forward.bindings.contains("Example2 = 2,"));
}
