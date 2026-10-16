//! Compare a validated semantic manifest with the compiled Win16 descriptors.
//!
//! This is an integration consistency check, not an independent ABI authority.
//! Historical declaration hints never determine a runtime signature, and a
//! descriptor match does not establish host implementation or service support.

use std::fmt::{Debug, Write as _};

use abi_schema::manifest::{
    Abi, CallingConvention, Export, FarPointerRole, ManifestError, ReturnValue,
    RuntimeArgumentKind, Signedness, ValidatedCatalog, ValueType,
};
use win16_abi::exports::{
    ExportCallingConvention, Win16ExportAbiKind, Win16ExportDescriptor,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind,
};
use win16_abi::{ArgumentKind, StackCleanup};

/// Audit one module, accepting the shared schema's module names and aliases.
///
/// All declarations are retained in the report. An unbound declaration is
/// `DECLARED_ONLY`, not a missing implementation. Only manifest bindings are
/// expected to have runtime descriptors; unexpected descriptors are differences.
/// The descriptor slice may contain the complete runtime catalog.
pub fn audit_win16_module(
    catalog: &ValidatedCatalog,
    module_name: &str,
    descriptors: &[Win16ExportDescriptor],
) -> Result<Win16AuditReport, ManifestError> {
    let module = catalog.module(module_name).ok_or_else(|| ManifestError {
        location: "module".to_owned(),
        message: format!("unknown catalog module {module_name:?}"),
    })?;
    let indices = descriptors
        .iter()
        .enumerate()
        .filter_map(|(index, descriptor)| {
            descriptor.module().eq_ignore_ascii_case(&module.id).then_some(index)
        })
        .collect::<Vec<_>>();
    let mut used = vec![false; descriptors.len()];
    let mut rows = Vec::new();
    let mut declarations = 0;
    let mut bindings = 0;

    for (path, export) in catalog.exports().filter(|(_, export)| export.module == module.id) {
        declarations += 1;
        bindings += usize::from(export.binding.is_some());
        let mut candidates = indices.iter().copied()
            .filter(|&index| descriptors[index].ordinal() == export.ordinal)
            .collect::<Vec<_>>();
        // A binding/name fallback exposes changed ordinals without treating a
        // same-named unbound declaration as a second runtime binding.
        if candidates.is_empty() {
            if let Some(binding) = &export.binding {
                candidates = indices.iter().copied()
                    .filter(|&index| descriptors[index].id as u32 == binding.id_value)
                    .collect();
                if candidates.is_empty() {
                    candidates = indices.iter().copied()
                        .filter(|&index| descriptors[index].name().eq_ignore_ascii_case(export_name(export)))
                        .collect();
                }
            }
        }
        let row = match candidates.as_slice() {
            [index] if !used[*index] => {
                used[*index] = true;
                compare_export(catalog, path, export, &descriptors[*index])
            }
            [] => {
                let bound = export.binding.is_some();
                AuditRow::manifest(
                    if bound { AuditStatus::ManifestOnly } else { AuditStatus::DeclaredOnly },
                    path,
                    export,
                    if bound {
                        "manifest binding has no compiled descriptor"
                    } else {
                        "declaration has no runtime binding; no host implementation or service support is inferred"
                    }.to_owned(),
                )
            }
            _ => AuditRow::manifest(
                AuditStatus::Ambiguous,
                path,
                export,
                "multiple or already-matched compiled descriptors; identity is not unique".to_owned(),
            ),
        };
        rows.push(row);
    }
    for &index in &indices {
        if !used[index] {
            rows.push(AuditRow::runtime(&descriptors[index]));
        }
    }
    Ok(Win16AuditReport {
        module_name: module.id.clone(),
        declarations,
        bindings,
        descriptors: indices.len(),
        rows,
    })
}

/// Stable TSV output, with canonical signatures separate from legacy evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16AuditReport {
    module_name: String,
    declarations: usize,
    bindings: usize,
    descriptors: usize,
    rows: Vec<AuditRow>,
}

impl Win16AuditReport {
    pub fn has_differences(&self) -> bool {
        self.rows.iter().any(|row| row.status.is_difference())
    }

    pub fn to_tsv(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "# Manifest/compiled ABI consistency only; no host implementation or service support is inferred.");
        let _ = writeln!(output, "# Historical declaration hints are provenance, not a runtime signature. Independent SDK facts are tested separately.");
        let _ = writeln!(
            output,
            "# module={} manifest_declarations={} manifest_bindings={} rust_descriptors={}",
            tsv_field(&self.module_name), self.declarations, self.bindings, self.descriptors
        );
        output.push_str("status\tmodule\tmanifest_ordinal\trust_ordinal\tmanifest_name\trust_name\tmanifest_binding\trust_binding\tmanifest_abi\trust_abi\tsource\tdetail\n");
        for row in &self.rows {
            let fields = [
                row.status.as_str(), self.module_name.as_str(),
                row.manifest_ordinal.as_str(), row.rust_ordinal.as_str(),
                row.manifest_name.as_str(), row.rust_name.as_str(),
                row.manifest_binding.as_str(), row.rust_binding.as_str(),
                row.manifest_abi.as_str(), row.rust_abi.as_str(),
                row.source.as_str(), row.detail.as_str(),
            ];
            output.push_str(&fields.into_iter().map(tsv_field).collect::<Vec<_>>().join("\t"));
            output.push('\n');
        }
        let differences = self.rows.iter().filter(|row| row.status.is_difference()).count();
        let matches = self.rows.iter().filter(|row| row.status == AuditStatus::Match).count();
        let declared = self.rows.iter().filter(|row| row.status == AuditStatus::DeclaredOnly).count();
        let _ = writeln!(output, "# summary rows={} exact_matches={} declared_only={} differences={}", self.rows.len(), matches, declared, differences);
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditStatus { Match, DeclaredOnly, Mismatch, ManifestOnly, RuntimeOnly, Ambiguous }

impl AuditStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "MATCH",
            Self::DeclaredOnly => "DECLARED_ONLY",
            Self::Mismatch => "MISMATCH",
            Self::ManifestOnly => "MANIFEST_ONLY",
            Self::RuntimeOnly => "RUNTIME_ONLY",
            Self::Ambiguous => "AMBIGUOUS",
        }
    }

    const fn is_difference(self) -> bool {
        !matches!(self, Self::Match | Self::DeclaredOnly)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditRow {
    status: AuditStatus,
    manifest_ordinal: String,
    rust_ordinal: String,
    manifest_name: String,
    rust_name: String,
    manifest_binding: String,
    rust_binding: String,
    manifest_abi: String,
    rust_abi: String,
    source: String,
    detail: String,
}

impl AuditRow {
    fn manifest(status: AuditStatus, path: &str, export: &Export, detail: String) -> Self {
        Self {
            status,
            manifest_ordinal: export.ordinal.to_string(),
            rust_ordinal: "-".to_owned(),
            manifest_name: export_name(export).to_owned(),
            rust_name: "-".to_owned(),
            manifest_binding: export.binding.as_ref().map_or_else(|| "-".to_owned(), |binding| format!("{}:{}", binding.rust_id, binding.id_value)),
            rust_binding: "-".to_owned(),
            manifest_abi: export.entry.abi().map_or_else(|| "non-callable data".to_owned(), |abi| format!("{abi:?}")),
            rust_abi: "-".to_owned(),
            source: path.to_owned(),
            detail,
        }
    }

    fn runtime(descriptor: &Win16ExportDescriptor) -> Self {
        Self {
            status: AuditStatus::RuntimeOnly,
            manifest_ordinal: "-".to_owned(),
            rust_ordinal: descriptor.ordinal().to_string(),
            manifest_name: "-".to_owned(),
            rust_name: descriptor.name().to_owned(),
            manifest_binding: "-".to_owned(),
            rust_binding: format!("{:?}:{}", descriptor.id, descriptor.id as u32),
            manifest_abi: "-".to_owned(),
            rust_abi: format!("{descriptor:?}"),
            source: "-".to_owned(),
            detail: "compiled descriptor has no matching manifest binding".to_owned(),
        }
    }
}

fn export_name(export: &Export) -> &str {
    export.name.as_deref().unwrap_or(&export.declared_name)
}

fn compare_export(
    catalog: &ValidatedCatalog,
    path: &str,
    export: &Export,
    descriptor: &Win16ExportDescriptor,
) -> AuditRow {
    let mut details = Vec::new();
    compare("module", &export.module.as_str(), &descriptor.module(), &mut details);
    compare("ordinal", &export.ordinal, &descriptor.ordinal(), &mut details);
    compare("name", &export_name(export), &descriptor.name(), &mut details);
    if let Some(binding) = &export.binding {
        compare("binding Rust id", &binding.rust_id, &format!("{:?}", descriptor.id), &mut details);
        compare("binding discriminant", &binding.id_value, &(descriptor.id as u32), &mut details);
        // The shared validator guarantees bound signatures are known and have
        // types representable by the runtime. Never consult declaration hints.
        let abi = export.entry.abi().expect("validated callable binding");
        let signature = abi.signature().expect("validated known binding signature");
        let expected_kind = match abi {
            Abi::FixedStack { .. } => Win16ExportAbiKind::Stack,
            Abi::VariableStack { .. } => Win16ExportAbiKind::VariableStack,
            Abi::RegisterContext { .. } => Win16ExportAbiKind::RegisterContext,
            Abi::Unknown => unreachable!("validated known binding ABI"),
        };
        compare("ABI kind", &expected_kind, &descriptor.abi_kind, &mut details);
        compare("calling convention", &runtime_convention(signature.calling_convention), &descriptor.calling_convention, &mut details);
        compare("return kind", &runtime_return(signature.returns), &Some(descriptor.return_kind), &mut details);
        let cleanup = abi.cleanup().map_or(Win16ExportStackCleanup::Variable, |cleanup| {
            Win16ExportStackCleanup::Fixed(StackCleanup {
                callee_pop_bytes: cleanup.callee_pop_bytes,
                caller_pop_bytes: cleanup.caller_pop_bytes,
            })
        });
        compare("stack cleanup", &cleanup, &descriptor.stack_cleanup, &mut details);
        compare("parameter count", &signature.parameters.len(), &descriptor.parameters.len(), &mut details);
        for (index, (expected, actual)) in signature.parameters.iter().zip(descriptor.parameters).enumerate() {
            let value = catalog.resolve_type(&expected.value);
            compare(&format!("parameter {} name", index + 1), &expected.name.as_str(), &actual.name, &mut details);
            compare(&format!("parameter {} value kind", index + 1), &runtime_kind(value), &Some(actual.kind), &mut details);
            compare(&format!("parameter {} slot bytes", index + 1), &expected.slot_bytes, &slot_bytes(actual.kind), &mut details);
            compare(&format!("parameter {} semantic role", index + 1), &runtime_role(value), &Some(actual.parameter_type), &mut details);
        }
    } else {
        details.push("unbound declaration unexpectedly has a compiled runtime descriptor".to_owned());
    }
    let status = if details.is_empty() { AuditStatus::Match } else { AuditStatus::Mismatch };
    let mut row = AuditRow::manifest(status, path, export, if details.is_empty() {
        "binding identity and complete representable semantic signature agree".to_owned()
    } else { details.join("; ") });
    row.rust_ordinal = descriptor.ordinal().to_string();
    row.rust_name = descriptor.name().to_owned();
    row.rust_binding = format!("{:?}:{}", descriptor.id, descriptor.id as u32);
    row.rust_abi = format!("{descriptor:?}");
    row
}

fn compare<T: Debug + PartialEq>(label: &str, expected: &T, actual: &T, details: &mut Vec<String>) {
    if expected != actual {
        details.push(format!("{label} differs: manifest {expected:?}, Rust {actual:?}"));
    }
}

fn runtime_convention(value: CallingConvention) -> ExportCallingConvention {
    match value {
        CallingConvention::Pascal => ExportCallingConvention::Pascal,
        CallingConvention::Cdecl => ExportCallingConvention::Cdecl,
        CallingConvention::Stdcall => ExportCallingConvention::Stdcall,
        CallingConvention::Varargs => ExportCallingConvention::Varargs,
        CallingConvention::Thiscall => ExportCallingConvention::Thiscall,
        CallingConvention::Unknown => ExportCallingConvention::Unknown,
    }
}

fn runtime_return(value: ReturnValue) -> Option<Win16ReturnKind> {
    Some(match value {
        ReturnValue::Word => Win16ReturnKind::Word,
        ReturnValue::Dword => Win16ReturnKind::Dword,
        ReturnValue::FarPointer => Win16ReturnKind::FarPointer,
        ReturnValue::RegisterContext => Win16ReturnKind::RegisterContext,
        ReturnValue::Void => Win16ReturnKind::Void,
        ReturnValue::Unknown => return None,
    })
}

fn runtime_kind(value: &ValueType) -> Option<ArgumentKind> {
    value.runtime_argument_kind().map(|kind| match kind {
        RuntimeArgumentKind::Byte => ArgumentKind::Byte,
        RuntimeArgumentKind::Word => ArgumentKind::Word,
        RuntimeArgumentKind::Dword => ArgumentKind::Dword,
    })
}

fn slot_bytes(kind: ArgumentKind) -> u16 {
    match kind { ArgumentKind::Byte | ArgumentKind::Word => 2, ArgumentKind::Dword => 4 }
}

fn runtime_role(value: &ValueType) -> Option<Win16ParameterType> {
    Some(match value {
        ValueType::Integer { signedness: Signedness::Signed, .. } => Win16ParameterType::SignedScalar,
        ValueType::Integer { .. } => Win16ParameterType::Scalar,
        ValueType::Far16_16 { role, .. } => match role {
            FarPointerRole::FarString => Win16ParameterType::FarString,
            FarPointerRole::FarPointer => Win16ParameterType::FarPointer,
            FarPointerRole::FarStringOrChar => Win16ParameterType::FarStringOrChar,
            FarPointerRole::ResourceName => Win16ParameterType::ResourceName,
            FarPointerRole::AtomName => Win16ParameterType::AtomName,
            FarPointerRole::ClassName => Win16ParameterType::ClassName,
            FarPointerRole::NullableFarString => Win16ParameterType::NullableFarString,
            FarPointerRole::FarBuffer => Win16ParameterType::FarBuffer,
            FarPointerRole::FarOutputBuffer => Win16ParameterType::FarOutputBuffer,
            FarPointerRole::Unknown => return None,
        },
        _ => return None,
    })
}

fn tsv_field(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\t', "\\t").replace('\r', "\\r").replace('\n', "\\n")
}
