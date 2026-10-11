use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::de::DeserializeOwned;

use super::model::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestError {
    pub location: String,
    pub message: String,
}

impl ManifestError {
    fn new(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self { location: location.into(), message: message.into() }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}
impl std::error::Error for ManifestError {}

/// Bounds keep accidental giant documents and include trees out of builds.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOML_FILES: usize = 256;
const MAX_DIRECTORY_DEPTH: usize = 16;
const MAX_EXPORTS: usize = 16_384;
const MAX_SHARED_TYPES: usize = 4096;
const MAX_PARAMETERS: usize = 1024;

type Result<T> = std::result::Result<T, ManifestError>;

/// Immutable after validation. Ordering follows the explicit root index, then
/// each group's declaration order, independently of filesystem enumeration.
#[derive(Clone, Debug)]
pub struct ValidatedCatalog {
    catalog: Catalog,
    groups: BTreeMap<String, Group>,
    types: BTreeMap<String, NamedType>,
}

impl ValidatedCatalog {
    pub fn catalog(&self) -> &Catalog { &self.catalog }
    pub fn groups(&self) -> &BTreeMap<String, Group> { &self.groups }
    pub fn types(&self) -> &BTreeMap<String, NamedType> { &self.types }
    /// Resolve a guest import module using the same normalization used to
    /// validate canonical identities, source filenames and explicit aliases.
    /// Comparison is ASCII case-insensitive and strips exactly one conventional
    /// .DLL, .EXE, .DRV or .MOD suffix; paths and whitespace are not normalized.
    pub fn module(&self, name: &str) -> Option<&Module> {
        let key = module_key(name);
        self.catalog.modules.iter().find(|module| {
            std::iter::once(&module.id)
                .chain(std::iter::once(&module.source_module))
                .chain(&module.aliases)
                .any(|candidate| module_key(candidate) == key)
        })
    }
    pub fn exports(&self) -> impl Iterator<Item = (&str, &Export)> {
        self.catalog.groups.iter().flat_map(|path| {
            self.groups[path].exports.iter().map(move |export| (path.as_str(), export))
        })
    }
    pub fn resolve_type<'a>(&'a self, value: &'a ValueType) -> &'a ValueType {
        let mut value = value;
        while let ValueType::Named { name } = value {
            value = &self.types[name].value;
        }
        value
    }
}

/// Load `root/catalog.toml`. Every TOML file below this dedicated catalog root
/// must be indexed. Symlinks, traversal and ambiguous platform path spellings
/// are rejected before reads; nested includes are deliberately unsupported.
pub fn load_catalog(root: &Path) -> Result<ValidatedCatalog> {
    let mut files = BTreeSet::new();
    collect_files(root, root, &mut files)?;
    let catalog: Catalog = read_toml(root, "catalog.toml")?;
    validate_index(&catalog)?;
    let mut groups = BTreeMap::new();
    let mut types = BTreeMap::new();
    let mut expected = BTreeSet::from(["catalog.toml".to_owned()]);
    for path in &catalog.groups {
        validate_path(path)?;
        if !expected.insert(path.clone()) { return Err(ManifestError::new(path, "file indexed more than once")); }
        groups.insert(path.clone(), read_toml(root, path)?);
    }
    for path in &catalog.types {
        validate_path(path)?;
        if !expected.insert(path.clone()) { return Err(ManifestError::new(path, "file indexed more than once")); }
        types.insert(path.clone(), read_toml(root, path)?);
    }
    if let Some(path) = files.difference(&expected).next() {
        return Err(ManifestError::new(path, "TOML file is not referenced by catalog.toml"));
    }
    validate_catalog(catalog, groups, types)
}

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeSet<String>) -> Result<()> {
    let meta = fs::symlink_metadata(directory).map_err(|e| ManifestError::new(directory.display().to_string(), e.to_string()))?;
    if meta.file_type().is_symlink() { return Err(ManifestError::new(directory.display().to_string(), "symlinks are not allowed in the catalog")); }
    if directory.strip_prefix(root).map_or(usize::MAX, |path| path.components().count()) > MAX_DIRECTORY_DEPTH {
        return Err(ManifestError::new(directory.display().to_string(), "catalog directory nesting limit exceeded"));
    }
    for item in fs::read_dir(directory).map_err(|e| ManifestError::new(directory.display().to_string(), e.to_string()))? {
        let item = item.map_err(|e| ManifestError::new(directory.display().to_string(), e.to_string()))?;
        let path = item.path();
        let kind = item.file_type().map_err(|e| ManifestError::new(path.display().to_string(), e.to_string()))?;
        if kind.is_symlink() { return Err(ManifestError::new(path.display().to_string(), "symlinks are not allowed in the catalog")); }
        if kind.is_dir() { collect_files(root, &path, files)?; }
        else if !kind.is_file() { return Err(ManifestError::new(path.display().to_string(), "catalog entries must be regular files or directories")); }
        else if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("toml")) {
            let relative = path.strip_prefix(root).map_err(|e| ManifestError::new(path.display().to_string(), e.to_string()))?;
            let relative = relative.components().map(|component| {
                component.as_os_str().to_str().ok_or_else(|| ManifestError::new(path.display().to_string(), "non-UTF-8 catalog path"))
            }).collect::<Result<Vec<_>>>()?.join("/");
            validate_path(&relative)?;
            files.insert(relative);
            if files.len() > MAX_TOML_FILES { return Err(ManifestError::new("catalog.toml", "catalog TOML file limit exceeded")); }
        }
    }
    Ok(())
}

fn read_toml<T: DeserializeOwned>(root: &Path, path: &str) -> Result<T> {
    validate_path(path)?;
    let file = fs::File::open(root.join(path)).map_err(|e| ManifestError::new(path, e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).map_err(|e| ManifestError::new(path, e.to_string()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES { return Err(ManifestError::new(path, "catalog document exceeds 1 MiB limit; split physical groups")); }
    let text = std::str::from_utf8(&bytes).map_err(|e| ManifestError::new(path, e.to_string()))?;
    toml::from_str(text).map_err(|e| ManifestError::new(path, e.to_string()))
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || !path.ends_with(".toml") || path.contains(['\\', ':', '\0'])
        || path.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.ends_with([' ', '.']))
    {
        return Err(ManifestError::new(path, "expected a safe relative .toml path without traversal"));
    }
    Ok(())
}

/// Validate already-parsed documents. Exact indexed membership is required;
/// callers cannot accidentally omit a group or silently supply unused groups.
pub fn validate_catalog(
    catalog: Catalog,
    groups: BTreeMap<String, Group>,
    type_files: BTreeMap<String, SharedTypes>,
) -> Result<ValidatedCatalog> {
    validate_index(&catalog)?;
    if groups.values().map(|group| group.exports.len()).sum::<usize>() > MAX_EXPORTS {
        return Err(ManifestError::new("catalog.toml", "catalog export limit exceeded"));
    }
    if type_files.values().map(|file| file.types.len()).sum::<usize>() > MAX_SHARED_TYPES {
        return Err(ManifestError::new("catalog.toml", "shared type limit exceeded"));
    }
    exact_files("groups", &catalog.groups, groups.keys())?;
    exact_files("types", &catalog.types, type_files.keys())?;
    let mut module_ids = BTreeSet::new();
    let mut module_names = BTreeMap::new();
    for module in &catalog.modules {
        nonempty(&module.id, "module id")?;
        if !module_ids.insert(module.id.clone()) { return Err(ManifestError::new(&module.id, "duplicate module id")); }
        let mut local = BTreeSet::new();
        for name in std::iter::once(&module.id).chain(std::iter::once(&module.source_module)).chain(&module.aliases) {
            nonempty(name, &module.id)?;
            let normalized = module_key(name);
            // Canonical name and source filename may normalize identically.
            if !local.insert(normalized.clone()) { continue; }
            if let Some(previous) = module_names.insert(normalized, &module.id) {
                return Err(ManifestError::new(&module.id, format!("module name or alias conflicts with {previous}")));
            }
        }
        let mut aliases = BTreeSet::new();
        for alias in &module.aliases {
            if !aliases.insert(module_key(alias)) { return Err(ManifestError::new(&module.id, "duplicate module alias")); }
        }
    }
    let mut types = BTreeMap::new();
    for (path, file) in type_files {
        version(&path, file.version)?;
        for named in file.types {
            identifier(&named.name, &path)?;
            validate_evidence(&named.evidence, &path)?;
            if types.insert(named.name.clone(), named).is_some() { return Err(ManifestError::new(path, "duplicate shared type")); }
        }
    }
    for (name, named) in &types {
        resolve(&named.value, &types, &mut BTreeSet::from([name.as_str()]), name)?;
    }
    let mut ordinals = BTreeSet::new();
    let mut names: BTreeMap<(String, String), Vec<u16>> = BTreeMap::new();
    let mut rust_ids = BTreeSet::new();
    let mut constants = BTreeSet::new();
    let mut id_values = BTreeSet::new();
    for (path, group) in &groups {
        version(path, group.version)?;
        for export in &group.exports {
            let location = format!("{path}:{}!{}", export.module, export.ordinal);
            if !module_ids.contains(&export.module) { return Err(ManifestError::new(&location, "unknown logical module")); }
            if !ordinals.insert((&export.module, export.ordinal)) { return Err(ManifestError::new(&location, "duplicate module/ordinal")); }
            nonempty(&export.declared_name, &location)?;
            let mut local_names = BTreeSet::new();
            for name in export.name.iter().chain(&export.aliases) {
                nonempty(name, &location)?;
                if !local_names.insert(name.to_ascii_lowercase()) { return Err(ManifestError::new(&location, "duplicate name or alias on one export")); }
                names.entry((export.module.clone(), name.to_ascii_lowercase())).or_default().push(export.ordinal);
            }
            let mut attributes = BTreeSet::new();
            for attribute in &export.declaration.attributes {
                if !attributes.insert(attribute.flag().bits()) { return Err(ManifestError::new(&location, "duplicate export attribute")); }
            }
            validate_evidence(&export.evidence, &location)?;
            validate_entry(export, &types, &location)?;
            if let Some(binding) = &export.binding {
                for id in [&binding.rust_id, &binding.constant] { identifier(id, &location)?; }
                if ["EXPORTS", "WIN16_DECODER_KEYS"].contains(&binding.constant.as_str()) {
                    return Err(ManifestError::new(&location, "binding constant conflicts with a generated catalog identifier"));
                }
                if !rust_ids.insert(&binding.rust_id) || !constants.insert(&binding.constant) || !id_values.insert(binding.id_value) { return Err(ManifestError::new(&location, "duplicate Rust binding id, constant, or numeric discriminant")); }
                if export.architecture != Architecture::Win16 { return Err(ManifestError::new(&location, "runtime binding requires Win16 architecture")); }
                let abi = export.entry.abi().ok_or_else(|| ManifestError::new(&location, "data or forward export cannot bind a decoder"))?;
                if matches!(abi, Abi::Unknown) { return Err(ManifestError::new(&location, "unknown ABI cannot bind a decoder")); }
                let signature = abi.signature().ok_or_else(|| ManifestError::new(&location, "binding requires a semantic signature"))?;
                if signature.returns == ReturnValue::Unknown { return Err(ManifestError::new(&location, "binding requires a verified runtime return shape")); }
                for parameter in &signature.parameters {
                    if parameter.name.is_empty() { return Err(ManifestError::new(&location, "binding requires parameter names")); }
                    let value = resolve(&parameter.value, &types, &mut BTreeSet::new(), &location)?;
                    let runtime_slot = value.runtime_argument_kind().map(RuntimeArgumentKind::slot_bytes);
                    if runtime_slot != Some(parameter.slot_bytes) { return Err(ManifestError::new(&location, "value kind does not preserve the runtime parameter slot")); }
                    if !matches!(value, ValueType::Integer { bits: 8 | 16 | 32, .. } | ValueType::Far16_16 { role: FarPointerRole::FarString | FarPointerRole::FarPointer | FarPointerRole::FarStringOrChar | FarPointerRole::ResourceName | FarPointerRole::AtomName | FarPointerRole::ClassName | FarPointerRole::NullableFarString | FarPointerRole::FarBuffer | FarPointerRole::FarOutputBuffer, .. }) {
                        return Err(ManifestError::new(&location, "parameter cannot be represented by the existing runtime descriptor"));
                    }
                }
            }
        }
    }
    let mut resolutions = BTreeMap::new();
    for resolution in &catalog.name_resolutions {
        let key = (resolution.module.clone(), resolution.name.to_ascii_lowercase());
        let candidates = names.get(&key).ok_or_else(|| ManifestError::new("catalog.toml", "name resolution does not identify an exported name"))?;
        if candidates.len() < 2 || !candidates.contains(&resolution.ordinal) {
            return Err(ManifestError::new("catalog.toml", "name resolution must select an ordinal participating in a real name collision"));
        }
        if resolutions.insert(key, resolution.ordinal).is_some() { return Err(ManifestError::new("catalog.toml", "duplicate name resolution")); }
    }
    for (key, candidates) in names {
        if candidates.len() > 1 && !resolutions.contains_key(&key) {
            return Err(ManifestError::new(format!("{}!{}", key.0, key.1), "duplicate export name or alias requires explicit name resolution"));
        }
    }
    Ok(ValidatedCatalog { catalog, groups, types })
}

fn validate_index(catalog: &Catalog) -> Result<()> {
    version("catalog.toml", catalog.version)?;
    if catalog.groups.len() + catalog.types.len() + 1 > MAX_TOML_FILES {
        return Err(ManifestError::new("catalog.toml", "catalog TOML file limit exceeded"));
    }
    let mut paths = BTreeSet::new();
    for path in catalog.groups.iter().chain(&catalog.types) {
        validate_path(path)?;
        if path.eq_ignore_ascii_case("catalog.toml") || !paths.insert(path.to_ascii_lowercase()) {
            return Err(ManifestError::new(path, "duplicate or reserved catalog path"));
        }
    }
    Ok(())
}

fn exact_files<'a>(label: &str, expected: &[String], actual: impl Iterator<Item = &'a String>) -> Result<()> {
    let expected: BTreeSet<_> = expected.iter().collect();
    let actual: BTreeSet<_> = actual.collect();
    if expected != actual { return Err(ManifestError::new(label, "indexed files do not match supplied documents")); }
    Ok(())
}

fn version(location: &str, value: u32) -> Result<()> {
    if value != SCHEMA_VERSION { return Err(ManifestError::new(location, format!("unsupported schema version {value}"))); }
    Ok(())
}

fn nonempty(value: &str, location: &str) -> Result<()> {
    if value.trim().is_empty() || value.contains('\0') { return Err(ManifestError::new(location, "empty or NUL-containing name")); }
    Ok(())
}

fn module_key(value: &str) -> String {
    let value = value.to_ascii_uppercase();
    for suffix in [".DLL", ".EXE", ".DRV", ".MOD"] {
        if let Some(base) = value.strip_suffix(suffix) { return base.to_owned(); }
    }
    value
}

fn identifier(value: &str, location: &str) -> Result<()> {
    // Restrict generated identifiers to the unambiguous ASCII Rust subset.
    const KEYWORDS: &[&str] = &["as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "gen", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "union"];
    let mut bytes = value.bytes();
    if value == "_" || KEYWORDS.contains(&value)
        || !bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(ManifestError::new(location, format!("invalid Rust identifier {value:?}")));
    }
    Ok(())
}

fn validate_evidence(evidence: &[Evidence], location: &str) -> Result<()> {
    for item in evidence {
        nonempty(&item.source, location)?;
        if item.line == Some(0) { return Err(ManifestError::new(location, "source line numbers are one-based")); }
    }
    Ok(())
}

fn resolve<'a>(value: &'a ValueType, types: &'a BTreeMap<String, NamedType>, visiting: &mut BTreeSet<&'a str>, location: &str) -> Result<&'a ValueType> {
    let mut value = value;
    while let ValueType::Named { name } = value {
        if !visiting.insert(name) { return Err(ManifestError::new(location, format!("shared type reference cycle at {name}"))); }
        value = &types.get(name).ok_or_else(|| ManifestError::new(location, format!("unknown shared type {name}")))?.value;
    }
    match value {
        ValueType::Far16_16 { role: FarPointerRole::NullableFarString, nullability: Nullability::NonNull, .. } => Err(ManifestError::new(location, "nullable string role contradicts non-null annotation")),
        ValueType::Far16_16 { role: FarPointerRole::FarOutputBuffer, direction: Direction::In, .. } => Err(ManifestError::new(location, "output buffer role contradicts input-only annotation")),
        ValueType::Integer { bits, .. } if ![8, 16, 32, 64, 128].contains(bits) => Err(ManifestError::new(location, "unsupported integer value width")),
        ValueType::Float { bits } if ![32, 64].contains(bits) => Err(ManifestError::new(location, "unsupported floating-point value width")),
        ValueType::LinearPointer { bits, .. } if *bits != 32 => Err(ManifestError::new(location, "declaration linear pointers must retain their 32-bit encoding")),
        _ => Ok(value),
    }
}

fn validate_entry(export: &Export, types: &BTreeMap<String, NamedType>, location: &str) -> Result<()> {
    validate_declaration(&export.declaration, &export.entry, location)?;
    let Some(abi) = export.entry.abi() else { return Ok(()); };
    let Some(signature) = abi.signature() else { return Ok(()); };
    if matches!(abi, Abi::RegisterContext { .. }) != (signature.returns == ReturnValue::RegisterContext) {
        return Err(ManifestError::new(location, "register-context argument and return contracts must agree"));
    }
    match abi {
        Abi::RegisterContext { .. } if !matches!(signature.calling_convention, CallingConvention::Pascal | CallingConvention::Cdecl) => return Err(ManifestError::new(location, "register-context ABI requires a supported Pascal or Cdecl convention")),
        Abi::FixedStack { .. } if !matches!(signature.calling_convention, CallingConvention::Pascal | CallingConvention::Cdecl) => return Err(ManifestError::new(location, "fixed stack runtime ABI requires Pascal or Cdecl")),
        Abi::VariableStack { .. } if signature.calling_convention != CallingConvention::Varargs => return Err(ManifestError::new(location, "variable stack requires Varargs")),
        Abi::RegisterContext { .. } if !signature.parameters.is_empty() => return Err(ManifestError::new(location, "register-context ABI cannot contain stack parameters")),
        _ => {}
    }
    if signature.parameters.len() > MAX_PARAMETERS { return Err(ManifestError::new(location, "signature parameter limit exceeded")); }
    let mut parameter_names = BTreeSet::new();
    for parameter in &signature.parameters {
        nonempty(&parameter.name, location)?;
        if !parameter_names.insert(&parameter.name) { return Err(ManifestError::new(location, "duplicate parameter name")); }
        if ![2, 4, 8, 16].contains(&parameter.slot_bytes) { return Err(ManifestError::new(location, "unsupported semantic stack slot width")); }
        let value = resolve(&parameter.value, types, &mut BTreeSet::new(), location)?;
        let value_bytes = match value {
            ValueType::Unknown => None,
            ValueType::Integer { bits, .. } | ValueType::Float { bits } | ValueType::LinearPointer { bits, .. } => Some(bits / 8),
            ValueType::Far16_16 { .. } => Some(4),
            ValueType::Named { .. } => unreachable!("resolved named type"),
        };
        if value_bytes.is_some_and(|bytes| bytes > parameter.slot_bytes) { return Err(ManifestError::new(location, "value width exceeds encoded slot")); }
    }
    if matches!(abi, Abi::FixedStack { .. }) && abi.fixed_stack_bytes().is_none() { return Err(ManifestError::new(location, "fixed argument area exceeds 65535 bytes")); }
    Ok(())
}

// Check the retained historical document for internal consistency, entirely
// independently of the callable semantic ABI. In particular no old argument
// encoding, convention, register flag or return hint constrains a descriptor.
fn validate_declaration(declaration: &DeclarationEvidence, entry: &Entry, location: &str) -> Result<()> {
    let declaration_matches = match entry {
        Entry::Function { .. } => matches!(declaration.declaration_type, DeclarationType::Pascal | DeclarationType::Cdecl | DeclarationType::Stdcall | DeclarationType::Varargs | DeclarationType::Thiscall),
        Entry::Stub { .. } => declaration.declaration_type == DeclarationType::Stub,
        Entry::Variable { .. } => declaration.declaration_type == DeclarationType::Variable,
        Entry::Equate { .. } => declaration.declaration_type == DeclarationType::Equate,
        Entry::Extern | Entry::Forward => declaration.declaration_type == DeclarationType::Extern,
    };
    if !declaration_matches { return Err(ManifestError::new(location, "entry kind disagrees with historical declaration type")); }
    if entry.abi().is_some() != declaration.abi.is_some() { return Err(ManifestError::new(location, "historical function declaration requires ABI evidence; data does not")); }
    let Some(abi) = &declaration.abi else { return Ok(()); };
    if abi.arguments.len() > MAX_PARAMETERS { return Err(ManifestError::new(location, "declaration argument limit exceeded")); }
    if abi.knowledge == SignatureKnowledge::Known && abi.arguments.contains(&ArgumentEncoding::Unknown) {
        return Err(ManifestError::new(location, "known declaration signature contains an unknown encoding"));
    }
    let declared_convention = match declaration.declaration_type {
        DeclarationType::Pascal => Some(CallingConvention::Pascal),
        DeclarationType::Cdecl => Some(CallingConvention::Cdecl),
        DeclarationType::Stdcall => Some(CallingConvention::Stdcall),
        DeclarationType::Varargs => Some(CallingConvention::Varargs),
        DeclarationType::Thiscall => Some(CallingConvention::Thiscall),
        _ => None,
    };
    if abi.calling_convention != declared_convention { return Err(ManifestError::new(location, "historical calling convention disagrees with declaration type")); }
    let expected_modifier = if declaration.attributes.contains(&Attribute::Retvoid) {
        ReturnModifier::Void
    } else {
        match (declaration.attributes.contains(&Attribute::Ret16), declaration.attributes.contains(&Attribute::Ret64)) {
            (false, false) => ReturnModifier::Unspecified,
            (true, false) => ReturnModifier::Ret16,
            (false, true) => ReturnModifier::Ret64,
            (true, true) => ReturnModifier::Ret16AndRet64,
        }
    };
    if abi.return_modifier != expected_modifier { return Err(ManifestError::new(location, "historical return modifier disagrees with declaration attributes")); }
    Ok(())
}
