use abi_schema::ExportAttributes;

use crate::model::{
    Architecture, ArgumentType, CallingConvention, DeclarationType, EntryKind, OrdinalSource,
    ReturnModifier, SignatureKind, SpecEntry, SpecModule,
};

pub(crate) fn render_spec(module: &SpecModule) -> String {
    let mut output = String::from("&[\n");
    for entry in &module.entries {
        output.push_str("    entry!(");
        output.push_str(&render_entry(module, entry));
        output.push_str("),\n");
    }
    output.push(']');
    output
}

fn render_entry(module: &SpecModule, entry: &SpecEntry) -> String {
    let arguments = vec![
        rust_string(&module.module),
        entry.ordinal.to_string(),
        ordinal_source(entry.ordinal_source).to_owned(),
        render_export_name(entry),
        rust_string(&entry.declared_name),
        optional_string(entry.link_name.as_deref()),
        if entry.flags.attributes.contains(ExportAttributes::NONAME) {
            format!("Some({})", rust_string(&entry.declared_name))
        } else {
            "None".to_owned()
        },
        entry_kind(entry.kind).to_owned(),
        declaration_type(entry.declaration_type).to_owned(),
        render_abi(entry),
        entry.flags.attributes.bits().to_string(),
        architecture_constraints(&entry.flags.architecture_constraints),
        architecture(entry.architecture).to_owned(),
        u32_slice(&entry.variable_values),
        entry
            .equate_value
            .map_or_else(|| "None".to_owned(), |value| format!("Some({value})")),
        rust_string(&module.source_module),
        rust_string(&module.spec_path),
        entry.line.to_string(),
        rust_string(&entry.raw),
    ];
    arguments.join(", ")
}

fn render_export_name(entry: &SpecEntry) -> String {
    // `-noname` suppresses the public name but retains the declared token for imports.
    if entry.flags.attributes.contains(ExportAttributes::NONAME)
        || entry.flags.attributes.contains(ExportAttributes::ORDINAL)
    {
        "None".to_owned()
    } else {
        format!("Some({})", rust_string(&entry.declared_name))
    }
}

fn render_abi(entry: &SpecEntry) -> String {
    let Some(signature_kind) = entry.signature_kind else {
        return "None".to_owned();
    };
    let convention = entry.calling_convention.map_or_else(
        || "None".to_owned(),
        |value| format!("Some({})", convention(value)),
    );
    let signature = match signature_kind {
        SignatureKind::Known => "ExportSignatureKind::Known",
        SignatureKind::Unknown => "ExportSignatureKind::Unknown",
    };
    let arguments = entry
        .arguments
        .iter()
        .copied()
        .map(argument_type)
        .collect::<Vec<_>>()
        .join(", ");
    let return_modifier = match entry.flags.return_modifier() {
        ReturnModifier::Void => "ExportReturnModifier::Void",
        ReturnModifier::Unspecified => "ExportReturnModifier::Unspecified",
        ReturnModifier::Ret16 => "ExportReturnModifier::Ret16",
        ReturnModifier::Ret64 => "ExportReturnModifier::Ret64",
        ReturnModifier::Ret16AndRet64 => "ExportReturnModifier::Ret16AndRet64",
    };
    format!("Some(abi({convention}, {signature}, &[{arguments}], {return_modifier}))")
}

fn architecture_constraints(constraints: &[&str]) -> String {
    let values = constraints
        .iter()
        .map(|constraint| rust_string(constraint))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{values}]")
}

fn u32_slice(values: &[u32]) -> String {
    let values = values
        .iter()
        .map(|value| format!("0x{value:08x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{values}]")
}

fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(
        || "None".to_owned(),
        |value| format!("Some({})", rust_string(value)),
    )
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn ordinal_source(source: OrdinalSource) -> &'static str {
    match source {
        OrdinalSource::Explicit => "ExportOrdinalSource::Explicit",
        OrdinalSource::Assigned => "ExportOrdinalSource::Assigned",
    }
}

fn entry_kind(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Function => "ExportEntryKind::Function",
        EntryKind::Stub => "ExportEntryKind::Stub",
        EntryKind::Variable => "ExportEntryKind::Variable",
        EntryKind::Equate => "ExportEntryKind::Equate",
        EntryKind::Extern => "ExportEntryKind::Extern",
        EntryKind::Forward => "ExportEntryKind::Forward",
    }
}

fn declaration_type(declaration: DeclarationType) -> &'static str {
    match declaration {
        DeclarationType::Variable => "ExportDeclarationType::Variable",
        DeclarationType::Pascal => "ExportDeclarationType::Pascal",
        DeclarationType::Equate => "ExportDeclarationType::Equate",
        DeclarationType::Stub => "ExportDeclarationType::Stub",
        DeclarationType::Stdcall => "ExportDeclarationType::Stdcall",
        DeclarationType::Cdecl => "ExportDeclarationType::Cdecl",
        DeclarationType::Varargs => "ExportDeclarationType::Varargs",
        DeclarationType::Thiscall => "ExportDeclarationType::Thiscall",
        DeclarationType::Extern => "ExportDeclarationType::Extern",
    }
}

fn architecture(value: Architecture) -> &'static str {
    match value {
        Architecture::Win16 => "ExportArchitecture::Win16",
        Architecture::Win32Only => "ExportArchitecture::Win32Only",
    }
}

fn convention(value: CallingConvention) -> &'static str {
    match value {
        CallingConvention::Pascal => "ExportCallingConvention::Pascal",
        CallingConvention::Cdecl => "ExportCallingConvention::Cdecl",
        CallingConvention::Stdcall => "ExportCallingConvention::Stdcall",
        CallingConvention::Varargs => "ExportCallingConvention::Varargs",
        CallingConvention::Thiscall => "ExportCallingConvention::Thiscall",
    }
}

fn argument_type(value: ArgumentType) -> &'static str {
    match value {
        ArgumentType::Word => "ExportArgumentType::Word",
        ArgumentType::SignedWord => "ExportArgumentType::SignedWord",
        ArgumentType::SegmentPointer => "ExportArgumentType::SegmentedPointer",
        ArgumentType::SegmentString => "ExportArgumentType::SegmentedString",
        ArgumentType::Long => "ExportArgumentType::Long",
        ArgumentType::Pointer => "ExportArgumentType::Pointer",
        ArgumentType::String => "ExportArgumentType::String",
        ArgumentType::WideString => "ExportArgumentType::WideString",
        ArgumentType::Int64 => "ExportArgumentType::Int64",
        ArgumentType::Int128 => "ExportArgumentType::Int128",
        ArgumentType::Float => "ExportArgumentType::Float",
        ArgumentType::Double => "ExportArgumentType::Double",
        ArgumentType::Unknown => "ExportArgumentType::Unknown",
    }
}
