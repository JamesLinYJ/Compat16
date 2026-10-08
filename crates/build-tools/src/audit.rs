//! Read-only comparison of export-specification metadata with the Win16 ABI catalog.
//!
//! This module checks declarations only. A catalog match says nothing about
//! whether the runtime has a host implementation for the export.

use std::fmt::Write as _;

use win16_abi::exports::{
    ExportCallingConvention, Win16ExportAbiKind, Win16ExportDescriptor, Win16ReturnKind,
};
use win16_abi::ArgumentKind;

use crate::{
    ArgumentType, CallingConvention, ExportAttributes, ExportKind, Ordinal, SpecEntry, SpecModule,
};

/// Compare one parsed reference module against the project's typed descriptors.
///
/// `module_name` must be the canonical module identity used by the descriptors
/// (for example `USER`). The descriptor slice can contain the complete catalog;
/// entries from other modules are ignored.
pub fn audit_win16_module(
    module_name: &str,
    spec: &SpecModule,
    descriptors: &[Win16ExportDescriptor],
) -> Win16AuditReport {
    let module_name = module_name.to_owned();
    let catalog_indices = descriptors
        .iter()
        .enumerate()
        .filter_map(|(index, descriptor)| {
            descriptor
                .module()
                .eq_ignore_ascii_case(&module_name)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let mut used_catalog = vec![false; descriptors.len()];
    let mut rows = Vec::new();

    for entry in &spec.exports {
        let ordinal_candidates = match entry.ordinal {
            Ordinal::Explicit(ordinal) => catalog_indices
                .iter()
                .copied()
                .filter(|&index| descriptors[index].ordinal() == ordinal)
                .collect::<Vec<_>>(),
            Ordinal::Automatic => Vec::new(),
        };

        if ordinal_candidates.len() == 1 {
            let index = ordinal_candidates[0];
            used_catalog[index] = true;
            rows.push(compare_entry(entry, &descriptors[index], true));
            continue;
        }

        if ordinal_candidates.len() > 1 {
            rows.push(uncomparable_spec_row(
                entry,
                format!(
                    "multiple Rust descriptors use ordinal {} in module {module_name}",
                    ordinal_text(entry.ordinal)
                ),
            ));
            continue;
        }

        let name_candidates = catalog_indices
            .iter()
            .copied()
            .filter(|&index| {
                descriptors[index]
                    .name()
                    .eq_ignore_ascii_case(&entry.export_name)
            })
            .collect::<Vec<_>>();
        match name_candidates.as_slice() {
            [index] => {
                used_catalog[*index] = true;
                rows.push(compare_entry(entry, &descriptors[*index], false));
            }
            [] => rows.push(spec_only_row(entry)),
            _ => rows.push(uncomparable_spec_row(
                entry,
                format!(
                    "name matches {} Rust descriptors; an ordinal match is required to disambiguate",
                    name_candidates.len()
                ),
            )),
        }
    }

    for index in catalog_indices {
        if !used_catalog[index] {
            rows.push(catalog_only_row(&descriptors[index]));
        }
    }

    let catalog_descriptors = descriptors
        .iter()
        .filter(|descriptor| descriptor.module().eq_ignore_ascii_case(&module_name))
        .count();
    Win16AuditReport {
        module_name,
        spec_declarations: spec.exports.len(),
        catalog_descriptors,
        rows,
    }
}

/// A stable, tab-separated report for reviewing ABI metadata differences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16AuditReport {
    module_name: String,
    spec_declarations: usize,
    catalog_descriptors: usize,
    rows: Vec<AuditRow>,
}

impl Win16AuditReport {
    /// True when any declaration is different, missing, extra, or not
    /// comparable. The CLI uses this to return a nonzero exit status.
    pub fn has_differences(&self) -> bool {
        self.rows
            .iter()
            .any(|row| row.status != AuditStatus::Match)
    }

    /// Render a reviewable TSV report. The header explicitly limits the
    /// result to ABI metadata and does not describe runtime implementation.
    pub fn to_tsv(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(
            output,
            "# ABI metadata comparison only; no host implementation or service support is inferred."
        );
        let _ = writeln!(
            output,
            "# module={} spec_declarations={} rust_descriptors={}",
            tsv_field(&self.module_name),
            self.spec_declarations,
            self.catalog_descriptors
        );
        output.push_str(
            "status\tmodule\tspec_ordinal\trust_ordinal\tspec_name\trust_name\tspec_convention\trust_convention\tspec_arguments\trust_parameters\tspec_flags\trust_return_kind\tsource_line\tdetail\n",
        );
        for row in &self.rows {
            let fields = [
                row.status.as_str().to_owned(),
                self.module_name.clone(),
                row.spec_ordinal.clone(),
                row.rust_ordinal.clone(),
                row.spec_name.clone(),
                row.rust_name.clone(),
                row.spec_convention.clone(),
                row.rust_convention.clone(),
                row.spec_arguments.clone(),
                row.rust_parameters.clone(),
                row.spec_flags.clone(),
                row.rust_return_kind.clone(),
                row.source_line.clone(),
                row.detail.clone(),
            ];
            for (index, value) in fields.iter().enumerate() {
                if index > 0 {
                    output.push('\t');
                }
                output.push_str(&tsv_field(value));
            }
            output.push('\n');
        }

        let differences = self
            .rows
            .iter()
            .filter(|row| row.status != AuditStatus::Match)
            .count();
        let _ = writeln!(
            output,
            "# summary rows={} exact_matches={} differences={}",
            self.rows.len(),
            self.rows.len().saturating_sub(differences),
            differences
        );
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditStatus {
    Match,
    NameCaseDifference,
    Mismatch,
    SpecOnly,
    CatalogOnly,
    Uncomparable,
}

impl AuditStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "MATCH",
            Self::NameCaseDifference => "NAME_CASE_DIFFERENCE",
            Self::Mismatch => "MISMATCH",
            Self::SpecOnly => "SPEC_ONLY",
            Self::CatalogOnly => "CATALOG_ONLY",
            Self::Uncomparable => "UNCOMPARABLE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuditRow {
    status: AuditStatus,
    spec_ordinal: String,
    rust_ordinal: String,
    spec_name: String,
    rust_name: String,
    spec_convention: String,
    rust_convention: String,
    spec_arguments: String,
    rust_parameters: String,
    spec_flags: String,
    rust_return_kind: String,
    source_line: String,
    detail: String,
}

fn compare_entry(
    entry: &SpecEntry,
    descriptor: &Win16ExportDescriptor,
    ordinal_matched: bool,
) -> AuditRow {
    let mut mismatch = false;
    let mut uncomparable = false;
    let mut name_case_difference = false;
    let mut details = Vec::new();

    match entry.ordinal {
        Ordinal::Explicit(spec_ordinal) if spec_ordinal != descriptor.ordinal() => {
            mismatch = true;
            details.push(format!(
                "ordinal differs: spec {spec_ordinal}, Rust {}",
                descriptor.ordinal()
            ));
        }
        Ordinal::Automatic => {
            uncomparable = true;
            details.push("automatic spec ordinal cannot be compared with the Rust ordinal".to_owned());
        }
        Ordinal::Explicit(_) => {}
    }
    if !ordinal_matched && matches!(entry.ordinal, Ordinal::Explicit(_)) {
        mismatch = true;
    }

    if entry.export_name != descriptor.name() {
        if entry
            .export_name
            .eq_ignore_ascii_case(descriptor.name())
        {
            name_case_difference = true;
            details.push(format!(
                "name differs only by case: spec {:?}, Rust {:?}",
                entry.export_name,
                descriptor.name()
            ));
        } else {
            mismatch = true;
            details.push(format!(
                "name differs: spec {:?}, Rust {:?}",
                entry.export_name,
                descriptor.name()
            ));
        }
    }

    if entry.kind != ExportKind::Function {
        mismatch = true;
        details.push(format!(
            "spec declaration kind is {:?}; the Rust catalog entry is a callable ABI descriptor",
            entry.kind
        ));
    } else {
        compare_calling_convention(entry, descriptor, &mut mismatch, &mut uncomparable, &mut details);
        let spec_register = entry.flags.attributes.contains(ExportAttributes::REGISTER);
        let rust_register = descriptor.abi_kind == Win16ExportAbiKind::RegisterContext;
        if spec_register != rust_register {
            mismatch = true;
            details.push(format!(
                "register-context flag differs: spec {spec_register}, Rust {rust_register}"
            ));
        }
        compare_arguments(entry, descriptor, &mut mismatch, &mut uncomparable, &mut details);
    }

    if entry.flags.attributes.contains(ExportAttributes::RET16) {
        details.push(
            "spec has -ret16; return width is shown from Rust metadata and is not inferred from this flag"
                .to_owned(),
        );
    }

    let status = if mismatch {
        AuditStatus::Mismatch
    } else if uncomparable {
        AuditStatus::Uncomparable
    } else if name_case_difference {
        AuditStatus::NameCaseDifference
    } else {
        AuditStatus::Match
    };

    AuditRow {
        status,
        spec_ordinal: ordinal_text(entry.ordinal),
        rust_ordinal: descriptor.ordinal().to_string(),
        spec_name: entry.export_name.clone(),
        rust_name: descriptor.name().to_owned(),
        spec_convention: entry
            .convention
            .map(|convention| convention.as_spec_name().to_owned())
            .unwrap_or_else(|| "-".to_owned()),
        rust_convention: rust_convention(descriptor.calling_convention),
        spec_arguments: format_spec_arguments(&entry.arguments),
        rust_parameters: format_rust_parameters(descriptor),
        spec_flags: format_spec_flags(entry),
        rust_return_kind: format_rust_return_kind(descriptor.return_kind),
        source_line: entry.source_line.to_string(),
        detail: if details.is_empty() {
            "ordinal, name, convention, register mode, and comparable argument slot widths agree".to_owned()
        } else {
            details.join("; ")
        },
    }
}

fn compare_calling_convention(
    entry: &SpecEntry,
    descriptor: &Win16ExportDescriptor,
    mismatch: &mut bool,
    uncomparable: &mut bool,
    details: &mut Vec<String>,
) {
    let Some(spec_convention) = entry.convention else {
        *uncomparable = true;
        details.push("spec declaration has no comparable calling convention".to_owned());
        return;
    };
    let expected_convention = match spec_convention {
        CallingConvention::Pascal => ExportCallingConvention::Pascal,
        CallingConvention::Cdecl => ExportCallingConvention::Cdecl,
        CallingConvention::Stdcall => ExportCallingConvention::Stdcall,
        CallingConvention::Varargs => ExportCallingConvention::Varargs,
    };
    if descriptor.calling_convention != expected_convention {
        *mismatch = true;
        details.push(format!(
            "calling convention differs: spec {}, Rust {}",
            spec_convention.as_spec_name(),
            rust_convention(descriptor.calling_convention)
        ));
    }
}

fn compare_arguments(
    entry: &SpecEntry,
    descriptor: &Win16ExportDescriptor,
    mismatch: &mut bool,
    uncomparable: &mut bool,
    details: &mut Vec<String>,
) {
    if entry.arguments.len() != descriptor.parameters.len() {
        *mismatch = true;
        details.push(format!(
            "argument count differs: spec {}, Rust {}",
            entry.arguments.len(),
            descriptor.parameters.len()
        ));
        return;
    }

    for (index, (spec_argument, rust_parameter)) in entry
        .arguments
        .iter()
        .zip(descriptor.parameters)
        .enumerate()
    {
        let Some(spec_width) = spec_slot_width(*spec_argument) else {
            *uncomparable = true;
            details.push(format!(
                "argument {} descriptor {} has no width rule in this audit",
                index + 1,
                spec_argument.as_spec_name()
            ));
            continue;
        };
        let rust_width = rust_slot_width(rust_parameter.kind);
        if spec_width != rust_width {
            *mismatch = true;
            details.push(format!(
                "argument {} slot width differs: spec {spec_width} bytes, Rust {rust_width} bytes",
                index + 1
            ));
        }
    }
}

fn spec_only_row(entry: &SpecEntry) -> AuditRow {
    AuditRow {
        status: AuditStatus::SpecOnly,
        spec_ordinal: ordinal_text(entry.ordinal),
        rust_ordinal: "-".to_owned(),
        spec_name: entry.export_name.clone(),
        rust_name: "-".to_owned(),
        spec_convention: entry
            .convention
            .map(|convention| convention.as_spec_name().to_owned())
            .unwrap_or_else(|| "-".to_owned()),
        rust_convention: "-".to_owned(),
        spec_arguments: format_spec_arguments(&entry.arguments),
        rust_parameters: "-".to_owned(),
        spec_flags: format_spec_flags(entry),
        rust_return_kind: "-".to_owned(),
        source_line: entry.source_line.to_string(),
        detail: "reference declaration has no matching Rust ABI descriptor; this does not state runtime support".to_owned(),
    }
}

fn uncomparable_spec_row(entry: &SpecEntry, detail: String) -> AuditRow {
    let mut row = spec_only_row(entry);
    row.status = AuditStatus::Uncomparable;
    row.detail = detail;
    row
}

fn catalog_only_row(descriptor: &Win16ExportDescriptor) -> AuditRow {
    AuditRow {
        status: AuditStatus::CatalogOnly,
        spec_ordinal: "-".to_owned(),
        rust_ordinal: descriptor.ordinal().to_string(),
        spec_name: "-".to_owned(),
        rust_name: descriptor.name().to_owned(),
        spec_convention: "-".to_owned(),
        rust_convention: rust_convention(descriptor.calling_convention),
        spec_arguments: "-".to_owned(),
        rust_parameters: format_rust_parameters(descriptor),
        spec_flags: "-".to_owned(),
        rust_return_kind: format_rust_return_kind(descriptor.return_kind),
        source_line: "-".to_owned(),
        detail: "Rust ABI descriptor has no matching reference declaration; this does not state runtime support".to_owned(),
    }
}

fn ordinal_text(ordinal: Ordinal) -> String {
    match ordinal {
        Ordinal::Explicit(value) => value.to_string(),
        Ordinal::Automatic => "@".to_owned(),
    }
}

fn spec_slot_width(argument: ArgumentType) -> Option<usize> {
    match argument {
        ArgumentType::Word | ArgumentType::SignedWord => Some(2),
        ArgumentType::Long
        | ArgumentType::Pointer
        | ArgumentType::String
        | ArgumentType::SegmentPointer
        | ArgumentType::SegmentString
        | ArgumentType::WideString => Some(4),
        ArgumentType::Int64 => Some(8),
        // No Win16 stack width is assigned to `float` by this audit; leave it
        // for manual review rather than guessing.
        ArgumentType::Float => None,
    }
}

fn rust_slot_width(argument: ArgumentKind) -> usize {
    match argument {
        ArgumentKind::Byte | ArgumentKind::Word => 2,
        ArgumentKind::Dword => 4,
    }
}

fn format_spec_arguments(arguments: &[ArgumentType]) -> String {
    if arguments.is_empty() {
        return "-".to_owned();
    }
    arguments
        .iter()
        .map(|argument| match spec_slot_width(*argument) {
            Some(width) => format!("{}:{width}B", argument.as_spec_name()),
            None => format!("{}:?", argument.as_spec_name()),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_rust_parameters(descriptor: &Win16ExportDescriptor) -> String {
    if descriptor.parameters.is_empty() {
        return "-".to_owned();
    }
    descriptor
        .parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}:{:?}:{:?}:{}B",
                parameter.name,
                parameter.kind,
                parameter.parameter_type,
                rust_slot_width(parameter.kind)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn rust_convention(convention: ExportCallingConvention) -> String {
    match convention {
        ExportCallingConvention::Pascal => "pascal".to_owned(),
        ExportCallingConvention::Cdecl => "cdecl".to_owned(),
        ExportCallingConvention::Stdcall => "stdcall".to_owned(),
        ExportCallingConvention::Varargs => "varargs".to_owned(),
        ExportCallingConvention::Thiscall => "thiscall".to_owned(),
        ExportCallingConvention::Unknown => "unknown".to_owned(),
    }
}

fn format_rust_return_kind(kind: Win16ReturnKind) -> String {
    match kind {
        Win16ReturnKind::Word => "Word(16-bit)".to_owned(),
        Win16ReturnKind::Dword => "Dword(32-bit)".to_owned(),
        Win16ReturnKind::FarPointer => "FarPointer(32-bit)".to_owned(),
        Win16ReturnKind::RegisterContext => "RegisterContext".to_owned(),
        Win16ReturnKind::Void => "Void".to_owned(),
    }
}

fn format_spec_flags(entry: &SpecEntry) -> String {
    let mut flags = Vec::new();
    if entry.flags.attributes.contains(ExportAttributes::RET16) {
        flags.push("ret16");
    }
    if entry.flags.attributes.contains(ExportAttributes::REGISTER) {
        flags.push("register");
    }
    if entry.flags.attributes.contains(ExportAttributes::STACK_PROLOG) {
        flags.push("stack_prolog");
    }
    if entry.flags.attributes.contains(ExportAttributes::NO_RELAY) {
        flags.push("no_relay");
    }
    if entry.flags.attributes.contains(ExportAttributes::PRIVATE) {
        flags.push("private");
    }
    if entry.flags.arch_win32 {
        flags.push("arch_win32");
    }
    if flags.is_empty() {
        "-".to_owned()
    } else {
        flags.join(",")
    }
}

fn tsv_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
