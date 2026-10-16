//! Compact TOML authoring version 2. This module expands authoring defaults and
//! references into the version-1 semantic IR; generators consume only that IR.
//! Declaration defaults reconstruct consumed declaration metadata, never callability.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::model::*;
use super::validate::ManifestError;

pub const AUTHORING_VERSION: u32 = 2;
type Result<T> = std::result::Result<T, ManifestError>;

// The complete current expanded catalog is only a few MiB. This conservative
// allocation-accounting budget leaves headroom while bounding inherited text,
// container entries and temporary clones, not only compact input bytes.
const MAX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_CONSTRAINTS: usize = 64;

struct Budget {
    remaining: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            remaining: MAX_EXPANDED_BYTES,
        }
    }
    fn charge(&mut self, bytes: usize, location: &str) -> Result<()> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            error(
                location,
                "expanded normalization allocation budget exceeded",
            )
        })?;
        Ok(())
    }
    fn text(&mut self, text: &str, location: &str) -> Result<()> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(error(location, "authoring text exceeds 16 KiB limit"));
        }
        self.charge(text.len(), location)
    }
    fn entries<T>(&mut self, count: usize, location: &str) -> Result<()> {
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| error(location, "normalization allocation size overflow"))?;
        self.charge(bytes, location)
    }
}

fn attributes(values: &[Attribute], location: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.flag().bits()) {
            return Err(error(location, "duplicate inherited declaration attribute"));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Root {
    pub version: u32,
    pub defaults: RootDefaults,
    pub modules: Vec<CompactModule>,
    #[serde(default)]
    pub name_resolutions: Vec<NameResolution>,
    pub groups: Vec<String>,
    pub types: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootDefaults {
    architecture: Architecture,
    ordinal_source: OrdinalSource,
    #[serde(default = "pascal")]
    convention: CallingConvention,
    #[serde(default)]
    attributes: Vec<Attribute>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactModule {
    id: String,
    source_module: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    defaults: Defaults,
}

impl Root {
    pub fn catalog(&self) -> Catalog {
        Catalog {
            version: SCHEMA_VERSION,
            modules: self
                .modules
                .iter()
                .map(|module| Module {
                    id: module.id.clone(),
                    source_module: module.source_module.clone(),
                    aliases: module.aliases.clone(),
                })
                .collect(),
            name_resolutions: self.name_resolutions.clone(),
            groups: self.groups.clone(),
            types: self.types.clone(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactGroup {
    module: Option<String>,
    #[serde(default)]
    defaults: Defaults,
    pub exports: Vec<CompactExport>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    architecture: Option<Architecture>,
    ordinal_source: Option<OrdinalSource>,
    convention: Option<CallingConvention>,
    attributes: Option<Vec<Attribute>>,
}

#[derive(Clone)]
struct EffectiveDefaults {
    architecture: Architecture,
    ordinal_source: OrdinalSource,
    convention: CallingConvention,
    attributes: Vec<Attribute>,
}
impl EffectiveDefaults {
    fn apply(&mut self, overrides: &Defaults) {
        if let Some(value) = overrides.architecture {
            self.architecture = value;
        }
        if let Some(value) = overrides.ordinal_source {
            self.ordinal_source = value;
        }
        if let Some(value) = overrides.convention {
            self.convention = value;
        }
        if let Some(value) = &overrides.attributes {
            self.attributes = value.clone();
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    #[default]
    Function,
    Stub,
    Variable,
    Equate,
    Extern,
    Forward,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactExport {
    module: Option<String>,
    ordinal: u16,
    ordinal_source: Option<OrdinalSource>,
    name: String,
    #[serde(default)]
    ordinal_only: bool,
    declared_name: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    link_name: Option<String>,
    import_library_name: Option<String>,
    architecture: Option<Architecture>,
    #[serde(default)]
    kind: Kind,
    #[serde(default)]
    decl: Declaration,
    binding: Option<Binding>,
    call: Option<Call>,
    values: Option<Vec<u32>>,
    value: Option<i32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    #[serde(rename = "type")]
    declaration_type: Option<DeclarationType>,
    attributes: Option<Vec<Attribute>>,
    args: Option<Vec<ArgumentEncoding>>,
    knowledge: Option<SignatureKnowledge>,
    #[serde(default, alias = "constraints")]
    architecture_constraints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CallKind {
    #[default]
    FixedStack,
    VariableStack,
    RegisterContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    #[serde(default)]
    kind: CallKind,
    convention: Option<CallingConvention>,
    returns: ReturnValue,
    #[serde(default)]
    params: Vec<Param>,
}
fn pascal() -> CallingConvention {
    CallingConvention::Pascal
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Param {
    name: String,
    #[serde(rename = "type")]
    type_name: String,
    slot_bytes: Option<u16>,
    /// Historical encoding exception, never a semantic slot or decoder kind.
    encoding: Option<ArgumentEncoding>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactTypes {
    pub types: BTreeMap<String, TypeDefinition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TypeDefinition {
    value: CompactValue,
    declaration_encoding: Option<ArgumentEncoding>,
    slot_bytes: Option<u16>,
}

/// Only authoring permits omitted pointer annotations. Their default is
/// explicitly Unknown, never a guessed direction or nullable contract.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CompactValue {
    Unknown,
    Integer {
        bits: u16,
        signedness: Signedness,
    },
    Float {
        bits: u16,
    },
    Far16_16 {
        role: FarPointerRole,
        direction: Option<Direction>,
        nullability: Option<Nullability>,
    },
    LinearPointer {
        bits: u16,
        role: LinearPointerRole,
        direction: Option<Direction>,
        nullability: Option<Nullability>,
    },
    Named {
        name: String,
    },
}

impl CompactValue {
    fn normalize(self) -> ValueType {
        match self {
            Self::Unknown => ValueType::Unknown,
            Self::Integer { bits, signedness } => ValueType::Integer { bits, signedness },
            Self::Float { bits } => ValueType::Float { bits },
            Self::Far16_16 {
                role,
                direction,
                nullability,
            } => ValueType::Far16_16 {
                role,
                direction: direction.unwrap_or(Direction::Unknown),
                nullability: nullability.unwrap_or(Nullability::Unknown),
            },
            Self::LinearPointer {
                bits,
                role,
                direction,
                nullability,
            } => ValueType::LinearPointer {
                bits,
                role,
                direction: direction.unwrap_or(Direction::Unknown),
                nullability: nullability.unwrap_or(Nullability::Unknown),
            },
            Self::Named { name } => ValueType::Named { name },
        }
    }
}

struct TypeDefaultsResolved {
    encoding: Option<ArgumentEncoding>,
    slot_bytes: Option<u16>,
}

pub(super) fn normalize(
    root: Root,
    group_files: BTreeMap<String, CompactGroup>,
    type_files: BTreeMap<String, CompactTypes>,
) -> Result<(
    Catalog,
    BTreeMap<String, Group>,
    BTreeMap<String, SharedTypes>,
)> {
    if root.version != AUTHORING_VERSION {
        return Err(error("catalog.toml", "unsupported schema version"));
    }
    if group_files
        .values()
        .map(|group| group.exports.len())
        .sum::<usize>()
        > 16_384
    {
        return Err(error("catalog.toml", "catalog export limit exceeded"));
    }
    if type_files
        .values()
        .map(|file| file.types.len())
        .sum::<usize>()
        > 4096
    {
        return Err(error("catalog.toml", "shared type limit exceeded"));
    }
    let mut budget = Budget::new();
    attributes(&root.defaults.attributes, "catalog.toml")?;
    for module in &root.modules {
        if let Some(values) = &module.defaults.attributes {
            attributes(values, "catalog.toml")?;
        }
        budget.charge(std::mem::size_of::<Module>() + 128, "catalog.toml")?;
        budget.entries::<String>(module.aliases.len(), "catalog.toml")?;
        for text in std::iter::once(&module.id)
            .chain(std::iter::once(&module.source_module))
            .chain(&module.aliases)
        {
            budget.text(text, "catalog.toml")?;
        }
    }
    for path in root.groups.iter().chain(&root.types) {
        budget.text(path, "catalog.toml")?;
    }
    for resolution in &root.name_resolutions {
        budget.charge(std::mem::size_of::<NameResolution>(), "catalog.toml")?;
        budget.text(&resolution.module, "catalog.toml")?;
        budget.text(&resolution.name, "catalog.toml")?;
    }
    let catalog = root.catalog();
    let root_defaults = EffectiveDefaults {
        architecture: root.defaults.architecture,
        ordinal_source: root.defaults.ordinal_source,
        convention: root.defaults.convention,
        attributes: root.defaults.attributes.clone(),
    };
    let mut expanded_types = BTreeMap::new();
    let mut type_defaults = BTreeMap::new();
    let mut values = BTreeMap::new();
    for (path, file) in type_files {
        let mut types = Vec::new();
        for (name, definition) in file.types {
            budget.charge(
                std::mem::size_of::<NamedType>() + std::mem::size_of::<ValueType>() + 256,
                &path,
            )?;
            for _ in 0..3 {
                budget.text(&name, &path)?;
            }
            let value = definition.value.normalize();
            if let ValueType::Named { name } = &value {
                budget.text(name, &path)?;
                budget.text(name, &path)?;
            }
            if values.insert(name.clone(), value.clone()).is_some() {
                return Err(error(&path, "duplicate shared type"));
            }
            type_defaults.insert(
                name.clone(),
                TypeDefaultsResolved {
                    encoding: definition.declaration_encoding,
                    slot_bytes: definition.slot_bytes,
                },
            );
            types.push(NamedType {
                name,
                value,
                evidence: Vec::new(),
            });
        }
        expanded_types.insert(
            path,
            SharedTypes {
                version: SCHEMA_VERSION,
                types,
            },
        );
    }
    // Validate every type reference/cycle before group expansion, including
    // unused definitions, without recursive descent through a type chain.
    for name in values.keys() {
        resolve(name, &values, "types")?;
    }
    let mut expanded_groups = BTreeMap::new();
    for (path, group) in group_files {
        if let Some(values) = &group.defaults.attributes {
            attributes(values, &path)?;
        }
        let mut exports = Vec::new();
        for export in group.exports {
            let location = format!("{path}:ordinal {}", export.ordinal);
            budget.charge(std::mem::size_of::<Export>() + 256, &location)?;
            budget.text(
                export
                    .module
                    .as_deref()
                    .or(group.module.as_deref())
                    .ok_or_else(|| {
                        error(
                            &location,
                            "export requires a logical module or group module default",
                        )
                    })?,
                &location,
            )?;
            budget.text(
                export.declared_name.as_deref().unwrap_or(&export.name),
                &location,
            )?;
            budget.entries::<String>(export.aliases.len(), &location)?;
            budget.entries::<String>(export.decl.architecture_constraints.len(), &location)?;
            if let Some(values) = &export.values {
                budget.entries::<u32>(values.len(), &location)?;
            }
            for text in std::iter::once(&export.name)
                .chain(&export.aliases)
                .chain(export.link_name.iter())
                .chain(export.import_library_name.iter())
            {
                budget.text(text, &location)?;
            }
            if export.decl.architecture_constraints.len() > MAX_CONSTRAINTS {
                return Err(error(
                    &location,
                    "architecture constraint count limit exceeded",
                ));
            }
            for text in &export.decl.architecture_constraints {
                budget.text(text, &location)?;
            }
            if let Some(binding) = &export.binding {
                budget.text(&binding.rust_id, &location)?;
                budget.text(&binding.constant, &location)?;
            }
            if let Some(values) = &export.decl.attributes {
                attributes(values, &location)?;
            }
            // Root/module/group lists were checked for duplicate flags above;
            // each has at most the finite Attribute variant count.
            budget.charge(4 * 16 * std::mem::size_of::<Attribute>(), &location)?;
            let module = export
                .module
                .or_else(|| group.module.clone())
                .ok_or_else(|| {
                    error(
                        &location,
                        "export requires a logical module or group module default",
                    )
                })?;
            let declared_name = export.declared_name.unwrap_or_else(|| export.name.clone());
            let mut defaults = root_defaults.clone();
            if let Some(module) = root.modules.iter().find(|candidate| candidate.id == module) {
                defaults.apply(&module.defaults);
            }
            defaults.apply(&group.defaults);
            if export.binding.is_some() && export.call.is_none() {
                return Err(error(
                    &location,
                    "binding requires an explicit call contract",
                ));
            }
            if !matches!(export.kind, Kind::Function | Kind::Stub)
                && (export.call.is_some() || export.binding.is_some())
            {
                return Err(error(
                    &location,
                    "data and forward exports cannot declare a call or binding",
                ));
            }
            let convention = export
                .call
                .as_ref()
                .and_then(|call| call.convention)
                .unwrap_or(defaults.convention);
            let declaration_type =
                export
                    .decl
                    .declaration_type
                    .unwrap_or_else(|| match export.kind {
                        Kind::Function => match convention {
                            CallingConvention::Pascal => DeclarationType::Pascal,
                            CallingConvention::Cdecl => DeclarationType::Cdecl,
                            CallingConvention::Stdcall => DeclarationType::Stdcall,
                            CallingConvention::Varargs => DeclarationType::Varargs,
                            CallingConvention::Thiscall => DeclarationType::Thiscall,
                            CallingConvention::Unknown => DeclarationType::Unknown,
                        },
                        Kind::Stub => DeclarationType::Stub,
                        Kind::Variable => DeclarationType::Variable,
                        Kind::Equate => DeclarationType::Equate,
                        Kind::Extern | Kind::Forward => DeclarationType::Extern,
                    });
            let attributes = export.decl.attributes.unwrap_or(defaults.attributes);
            let explicit_arguments = export.decl.args.is_some();
            let mut arguments = Vec::new();
            let abi = if let Some(call) = export.call {
                if call.params.len() > 1024 {
                    return Err(error(&location, "signature parameter limit exceeded"));
                }
                let mut parameters = Vec::new();
                for parameter in call.params {
                    budget.charge(
                        std::mem::size_of::<Parameter>()
                            + std::mem::size_of::<ArgumentEncoding>()
                            + 32,
                        &location,
                    )?;
                    budget.text(&parameter.name, &location)?;
                    budget.text(&parameter.type_name, &location)?;
                    let defaults =
                        resolve_defaults(&parameter.type_name, &values, &type_defaults, &location)?;
                    let value = resolve(&parameter.type_name, &values, &location)?;
                    let slot_bytes = parameter
                        .slot_bytes
                        .or(defaults.slot_bytes)
                        .or_else(|| default_slot(value))
                        .ok_or_else(|| {
                            error(
                                &location,
                                "parameter type has no known slot; specify slot_bytes",
                            )
                        })?;
                    if !explicit_arguments {
                        arguments.push(parameter.encoding.or(defaults.encoding).ok_or_else(
                            || {
                                error(
                                    &location,
                                    format!(
                                        "type {} needs a declaration encoding default or override",
                                        parameter.type_name
                                    ),
                                )
                            },
                        )?);
                    }
                    parameters.push(Parameter {
                        name: parameter.name,
                        slot_bytes,
                        value: ValueType::Named {
                            name: parameter.type_name,
                        },
                    });
                }
                let signature = Signature {
                    calling_convention: convention,
                    parameters,
                    returns: call.returns,
                };
                match call.kind {
                    CallKind::FixedStack => Abi::FixedStack { signature },
                    CallKind::VariableStack => Abi::VariableStack { signature },
                    CallKind::RegisterContext => Abi::RegisterContext { signature },
                }
            } else {
                Abi::Unknown
            };
            let arguments = export.decl.args.unwrap_or(arguments);
            if arguments.len() > 1024 {
                return Err(error(&location, "declaration argument limit exceeded"));
            }
            budget.charge(
                arguments
                    .len()
                    .checked_mul(std::mem::size_of::<ArgumentEncoding>())
                    .ok_or_else(|| error(&location, "argument allocation size overflow"))?,
                &location,
            )?;
            let declaration_abi = if matches!(export.kind, Kind::Function | Kind::Stub) {
                let knowledge = export.decl.knowledge.unwrap_or_else(|| {
                    if matches!(export.kind, Kind::Stub) {
                        SignatureKnowledge::Unknown
                    } else {
                        SignatureKnowledge::Known
                    }
                });
                Some(DeclarationAbiEvidence {
                    calling_convention: declaration_convention(declaration_type),
                    knowledge,
                    arguments,
                    return_modifier: modifier(&attributes),
                })
            } else {
                if explicit_arguments || export.decl.knowledge.is_some() {
                    return Err(error(
                        &location,
                        "data declarations cannot carry argument or signature hints",
                    ));
                }
                None
            };
            let entry = match (export.kind, export.values, export.value) {
                (Kind::Function, None, None) => Entry::Function { abi },
                (Kind::Stub, None, None) => Entry::Stub { abi },
                (Kind::Variable, Some(values), None) => Entry::Variable { values },
                (Kind::Equate, None, Some(value)) => Entry::Equate { value },
                (Kind::Extern, None, None) => Entry::Extern,
                (Kind::Forward, None, None) => Entry::Forward,
                _ => return Err(error(&location, "entry kind and data payload disagree")),
            };
            exports.push(Export {
                module,
                ordinal: export.ordinal,
                ordinal_source: export.ordinal_source.unwrap_or(defaults.ordinal_source),
                declared_name,
                name: if export.ordinal_only {
                    None
                } else {
                    Some(export.name)
                },
                aliases: export.aliases,
                link_name: export.link_name,
                import_library_name: export.import_library_name,
                architecture: export.architecture.unwrap_or(defaults.architecture),
                declaration: DeclarationEvidence {
                    declaration_type,
                    attributes,
                    architecture_constraints: export.decl.architecture_constraints,
                    abi: declaration_abi,
                },
                entry,
                binding: export.binding,
                evidence: Vec::new(),
            });
        }
        expanded_groups.insert(
            path,
            Group {
                version: SCHEMA_VERSION,
                exports,
            },
        );
    }
    Ok((catalog, expanded_groups, expanded_types))
}

fn error(location: &str, message: impl Into<String>) -> ManifestError {
    ManifestError::new(location, message)
}

fn resolve<'a>(
    name: &'a str,
    types: &'a BTreeMap<String, ValueType>,
    location: &str,
) -> Result<&'a ValueType> {
    let mut name = name;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(name) {
            return Err(error(
                location,
                format!("shared type reference cycle at {name}"),
            ));
        }
        let value = types
            .get(name)
            .ok_or_else(|| error(location, format!("unknown shared type {name}")))?;
        match value {
            ValueType::Named { name: next } => name = next,
            _ => return Ok(value),
        }
    }
}
fn resolve_defaults(
    name: &str,
    values: &BTreeMap<String, ValueType>,
    defaults: &BTreeMap<String, TypeDefaultsResolved>,
    location: &str,
) -> Result<TypeDefaultsResolved> {
    let mut name = name;
    let mut visited = BTreeSet::new();
    let mut result = TypeDefaultsResolved {
        encoding: None,
        slot_bytes: None,
    };
    loop {
        if !visited.insert(name) {
            return Err(error(
                location,
                format!("shared type reference cycle at {name}"),
            ));
        }
        let value = values
            .get(name)
            .ok_or_else(|| error(location, format!("unknown shared type {name}")))?;
        let current = &defaults[name];
        result.encoding = result.encoding.or(current.encoding);
        result.slot_bytes = result.slot_bytes.or(current.slot_bytes);
        match value {
            ValueType::Named { name: next } => name = next,
            _ => return Ok(result),
        }
    }
}

fn default_slot(value: &ValueType) -> Option<u16> {
    match value {
        ValueType::Integer { bits, .. }
        | ValueType::Float { bits }
        | ValueType::LinearPointer { bits, .. } => Some((bits / 8).max(2)),
        ValueType::Far16_16 { .. } => Some(4),
        ValueType::Unknown | ValueType::Named { .. } => None,
    }
}
fn declaration_convention(declaration: DeclarationType) -> Option<CallingConvention> {
    match declaration {
        DeclarationType::Pascal => Some(CallingConvention::Pascal),
        DeclarationType::Cdecl => Some(CallingConvention::Cdecl),
        DeclarationType::Stdcall => Some(CallingConvention::Stdcall),
        DeclarationType::Varargs => Some(CallingConvention::Varargs),
        DeclarationType::Thiscall => Some(CallingConvention::Thiscall),
        _ => None,
    }
}
fn modifier(attributes: &[Attribute]) -> ReturnModifier {
    if attributes.contains(&Attribute::Retvoid) {
        return ReturnModifier::Void;
    }
    match (
        attributes.contains(&Attribute::Ret16),
        attributes.contains(&Attribute::Ret64),
    ) {
        (false, false) => ReturnModifier::Unspecified,
        (true, false) => ReturnModifier::Ret16,
        (false, true) => ReturnModifier::Ret64,
        (true, true) => ReturnModifier::Ret16AndRet64,
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn inherited_text_is_charged_before_an_expanded_clone() {
        let mut budget = Budget { remaining: 8 };
        assert!(
            budget
                .text("a long repeated module name", "test")
                .unwrap_err()
                .message
                .contains("allocation budget")
        );
    }

    #[test]
    fn allocation_accounting_rejects_integer_overflow() {
        let mut budget = Budget::new();
        assert!(
            budget
                .entries::<String>(usize::MAX, "test")
                .unwrap_err()
                .message
                .contains("overflow")
        );
    }

    #[test]
    fn excessive_text_and_duplicate_defaults_fail_without_expansion() {
        let mut budget = Budget::new();
        assert!(
            budget
                .text(&"x".repeat(MAX_TEXT_BYTES + 1), "test")
                .unwrap_err()
                .message
                .contains("16 KiB")
        );
        assert!(attributes(&[Attribute::Ret16, Attribute::Ret16], "test").is_err());
    }
}
