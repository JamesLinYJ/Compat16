//! Rust fragments generated only from a completely validated catalog.

use abi_schema::manifest::{Abi, Entry, Export, Signedness, ValidatedCatalog, ValueType};
use std::fmt::Write;

/// Include `metadata` in the declaration module and `bindings` in the module
/// containing the public Win16 descriptor types. Neither fragment executes code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedCatalog {
    pub metadata: String,
    pub bindings: String,
}

/// Render deterministic, escaped Rust data. Physical manifest grouping does not
/// select runtime semantics: only a bound export's canonical signature does.
/// Binding identifiers have already been checked by `ValidatedCatalog`.
pub fn compile_catalog(catalog: &ValidatedCatalog) -> GeneratedCatalog {
    GeneratedCatalog {
        metadata: metadata(catalog),
        bindings: bindings(catalog),
    }
}

fn string(value: &str) -> String { format!("{value:?}") }
fn optional(value: Option<&str>) -> String {
    value.map_or_else(|| "None".into(), |value| format!("Some({})", string(value)))
}

fn metadata(catalog: &ValidatedCatalog) -> String {
    let mut out = String::from("// Generated from the validated ABI catalog.\n");
    for (index, module) in catalog.catalog().modules.iter().enumerate() {
        writeln!(out, "static MODULE_{index}: &[ExportMetadata] = &[").unwrap();
        for (path, export) in catalog.exports().filter(|(_, export)| export.module == module.id) {
            metadata_entry(&mut out, path, &module.source_module, export);
        }
        out.push_str("];\n");
    }
    out.push_str("pub static WIN16_EXPORTS: &[&[ExportMetadata]] = &[\n");
    for index in 0..catalog.catalog().modules.len() { writeln!(out, "MODULE_{index},").unwrap(); }
    out.push_str("];\n");
    out.push_str("pub(super) const MODULE_ALIASES: &[(&str, &str)] = &[\n");
    for module in &catalog.catalog().modules {
        for alias in &module.aliases {
            writeln!(out, "({}, {}),", string(&module.id), string(alias)).unwrap();
        }
    }
    out.push_str("];\npub(super) const EXPORT_ALIASES: &[(&str, u16, &str)] = &[\n");
    for (_, export) in catalog.exports() {
        for alias in &export.aliases {
            writeln!(out, "({}, {}, {}),", string(&export.module), export.ordinal, string(alias)).unwrap();
        }
    }
    out.push_str("];\npub(super) const NAME_RESOLUTIONS: &[(&str, &str, u16)] = &[\n");
    for resolution in &catalog.catalog().name_resolutions {
        writeln!(out, "({}, {}, {}),", string(&resolution.module), string(&resolution.name), resolution.ordinal).unwrap();
    }
    out.push_str("];\n");
    out
}

fn metadata_entry(out: &mut String, path: &str, source_module: &str, export: &Export) {
    let (kind, values, equate) = match &export.entry {
        Entry::Function { .. } => ("Function", &[][..], None),
        Entry::Stub { .. } => ("Stub", &[][..], None),
        Entry::Variable { values } => ("Variable", values.as_slice(), None),
        Entry::Equate { value } => ("Equate", &[][..], Some(*value)),
        Entry::Extern => ("Extern", &[][..], None),
        Entry::Forward => ("Forward", &[][..], None),
    };
    writeln!(out, "ExportMetadata {{ module: {}, source_module: {}, ordinal: {}, ordinal_source: ExportOrdinalSource::{:?}, name: {}, declared_name: {}, link_name: {}, import_library_name: {}, kind: ExportEntryKind::{kind}, declaration_type: ExportDeclarationType::{:?},",
        string(&export.module), string(source_module), export.ordinal, export.ordinal_source,
        optional(export.name.as_deref()), string(&export.declared_name), optional(export.link_name.as_deref()),
        optional(export.import_library_name.as_deref()), export.declaration.declaration_type).unwrap();
    // These are explicitly historical declaration hints. Descriptors below do
    // not read this record, so a retained legacy hint cannot change callability.
    if let Some(abi) = &export.declaration.abi {
        let convention = abi.calling_convention.map_or_else(|| "None".into(), |c| format!("Some(ExportCallingConvention::{c:?})"));
        writeln!(out, "abi: Some(ExportAbiMetadata {{ calling_convention: {convention}, signature: ExportSignatureKind::{:?}, arguments: &[", abi.knowledge).unwrap();
        for argument in &abi.arguments { writeln!(out, "ExportArgumentType::{argument:?},").unwrap(); }
        writeln!(out, "], return_modifier: ExportReturnModifier::{:?} }}),", abi.return_modifier).unwrap();
    } else { out.push_str("abi: None,\n"); }
    writeln!(out, "flags: ExportFlags {{ attributes: ExportAttributes::from_bits_retain({}), architecture_constraints: &[", export.declaration.attribute_bits().bits()).unwrap();
    for constraint in &export.declaration.architecture_constraints { writeln!(out, "{},", string(constraint)).unwrap(); }
    writeln!(out, "] }}, architecture: ExportArchitecture::{:?}, variable_values: &{:?}, equate_value: {:?}, source: ExportSourceLocation {{ spec_path: {}, line: 0 }} }},", export.architecture, values, equate, string(path)).unwrap();
}

fn bindings(catalog: &ValidatedCatalog) -> String {
    let mut exports: Vec<_> = catalog.exports().filter_map(|(_, export)| export.binding.as_ref().map(|binding| (export, binding))).collect();
    exports.sort_by_key(|(_, binding)| binding.id_value);
    let mut out = String::from("// Generated from canonical semantic signatures, not declaration hints.\n#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]\npub enum Win16ExportId {\n");
    for (_, binding) in &exports { writeln!(out, "{} = {},", binding.rust_id, binding.id_value).unwrap(); }
    out.push_str("}\nimpl Win16ExportId {\npub const fn module(self) -> &'static str { match self {\n");
    for (export, binding) in &exports { writeln!(out, "Self::{} => {},", binding.rust_id, string(&export.module)).unwrap(); }
    out.push_str("} }\npub const fn ordinal(self) -> u16 { match self {\n");
    for (export, binding) in &exports { writeln!(out, "Self::{} => {},", binding.rust_id, export.ordinal).unwrap(); }
    out.push_str("} }\npub const fn name(self) -> &'static str { match self {\n");
    for (export, binding) in &exports { writeln!(out, "Self::{} => {},", binding.rust_id, string(export.name.as_deref().unwrap_or(&export.declared_name))).unwrap(); }
    out.push_str("} }\n}\n");
    for (export, binding) in &exports {
        let abi = export.entry.abi().expect("validated callable binding");
        let signature = abi.signature().expect("validated known signature");
        let kind = match abi { Abi::FixedStack { .. } => "Stack", Abi::VariableStack { .. } => "VariableStack", Abi::RegisterContext { .. } => "RegisterContext", Abi::Unknown => unreachable!("validated binding") };
        writeln!(out, "pub const {}: Win16ExportDescriptor = Win16ExportDescriptor {{ id: Win16ExportId::{}, abi_kind: Win16ExportAbiKind::{kind}, parameters: &[", binding.constant, binding.rust_id).unwrap();
        for parameter in &signature.parameters {
            let value = catalog.resolve_type(&parameter.value);
            let role = match value {
                ValueType::Integer { signedness: Signedness::Signed, .. } => "SignedScalar".to_owned(),
                ValueType::Integer { .. } => "Scalar".to_owned(),
                ValueType::Far16_16 { role, .. } => format!("{role:?}"),
                _ => unreachable!("validated runtime parameter"),
            };
            writeln!(out, "Win16Parameter {{ name: {}, kind: ArgumentKind::{:?}, parameter_type: Win16ParameterType::{role} }},", string(&parameter.name), value.runtime_argument_kind().expect("validated runtime parameter")).unwrap();
        }
        writeln!(out, "], calling_convention: ExportCallingConvention::{:?}, return_kind: Win16ReturnKind::{:?},", signature.calling_convention, signature.returns).unwrap();
        if let Some(cleanup) = abi.cleanup() {
            writeln!(out, "stack_cleanup: Win16ExportStackCleanup::Fixed(StackCleanup {{ callee_pop_bytes: {}, caller_pop_bytes: {} }}),", cleanup.callee_pop_bytes, cleanup.caller_pop_bytes).unwrap();
        } else { out.push_str("stack_cleanup: Win16ExportStackCleanup::Variable,\n"); }
        out.push_str("};\n");
    }
    out.push_str("const EXPORTS: &[Win16ExportDescriptor] = &[\n");
    for (_, binding) in &exports { writeln!(out, "{},", binding.constant).unwrap(); }
    out.push_str("];\npub const WIN16_DECODER_KEYS: &[(Win16ExportId, &str)] = &[\n");
    for (_, binding) in &exports {
        writeln!(out, "(Win16ExportId::{}, {}),", binding.rust_id, string(&binding.rust_id)).unwrap();
    }
    out.push_str("];\n");
    out
}
