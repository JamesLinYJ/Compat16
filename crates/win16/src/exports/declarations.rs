//! Typed guest DLL declarations generated from this crate's module specifications.
//!
//! The specification records ABI information; dispatch and host semantics are
//! implemented by typed Rust bridges. Unknown signatures remain non-callable.

pub use abi_schema::ExportAttributes;

use super::ExportLookupTarget;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportArchitecture {
    /// Declaration belongs to a Win16 module and is active in the Win16 table.
    Win16,
    /// Win32 spec or a Win32-only row embedded in a Win16 spec.
    Win32Only,
    /// Reserved for declarations whose architecture cannot be established.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportEntryKind {
    Function,
    Stub,
    Variable,
    Equate,
    Extern,
    Forward,
    Unknown,
}

/// Whether a declaration exposes a callable ABI signature. Stub records may
/// omit their optional argument list; that differs from an explicitly empty
/// `()` signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportSignatureKind {
    Known,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportDeclarationType {
    Variable,
    Pascal,
    Equate,
    Stub,
    Stdcall,
    Cdecl,
    Varargs,
    Thiscall,
    Extern,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportCallingConvention {
    Pascal,
    Stdcall,
    Cdecl,
    Varargs,
    Thiscall,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportArgumentType {
    Word,
    SignedWord,
    SegmentedPointer,
    SegmentedString,
    Long,
    Pointer,
    String,
    WideString,
    Int64,
    Int128,
    Float,
    Double,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportReturnModifier {
    /// The declaration explicitly specifies no return value.
    Void,
    /// No explicit return-width modifier occurs in the declaration.
    Unspecified,
    Ret16,
    Ret64,
    Ret16AndRet64,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExportOrdinalSource {
    Explicit,
    Assigned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExportFlags {
    pub attributes: ExportAttributes,
    /// Raw architecture constraints such as win32, retained separately from
    /// the Win16/Win32-only classification.
    pub architecture_constraints: &'static [&'static str],
}

impl ExportFlags {
    pub const fn bits(self) -> u16 {
        self.attributes.bits()
    }

    pub const fn contains(self, attributes: ExportAttributes) -> bool {
        self.attributes.contains(attributes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExportAbiMetadata {
    pub calling_convention: Option<ExportCallingConvention>,
    pub signature: ExportSignatureKind,
    pub arguments: &'static [ExportArgumentType],
    /// A modifier only; absence is not a guessed return type or width.
    pub return_modifier: ExportReturnModifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExportSourceLocation {
    /// Project specification path used for a build-time diagnostic.
    pub spec_path: &'static str,
    pub line: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExportMetadata {
    /// Canonical guest import module name; KERNEL normalizes krnl386 to KERNEL.
    pub module: &'static str,
    /// Guest module file name, including its DLL, EXE, driver, or module suffix.
    pub source_module: &'static str,
    pub ordinal: u16,
    pub ordinal_source: ExportOrdinalSource,
    /// Name available to imports. None means ordinal-only or unnamed.
    pub name: Option<&'static str>,
    /// Token used as the declared name before export-name flags are applied.
    pub declared_name: &'static str,
    /// Native/internal target name when one was explicitly declared.
    pub link_name: Option<&'static str>,
    /// Import-library alias preserved for `-noname` declarations.
    pub import_library_name: Option<&'static str>,
    pub kind: ExportEntryKind,
    pub declaration_type: ExportDeclarationType,
    pub abi: Option<ExportAbiMetadata>,
    pub flags: ExportFlags,
    pub architecture: ExportArchitecture,
    /// Initial data values from a variable record, not a complete runtime
    /// initialization policy.
    pub variable_values: &'static [u32],
    /// Literal equate value from the declaration. Runtime initialization or
    /// capability policy may replace it; this is not necessarily guest state.
    pub equate_value: Option<i32>,
    pub source: ExportSourceLocation,
}

const fn abi(
    calling_convention: Option<ExportCallingConvention>,
    signature: ExportSignatureKind,
    arguments: &'static [ExportArgumentType],
    return_modifier: ExportReturnModifier,
) -> ExportAbiMetadata {
    ExportAbiMetadata { calling_convention, signature, arguments, return_modifier }
}

macro_rules! entry {
    ($module:literal, $ordinal:literal, $ordinal_source:expr, $name:expr,
     $declared_name:literal, $link_name:expr, $import_library_name:expr,
     $kind:expr, $declaration_type:expr, $abi:expr, $flag_bits:literal,
     $architecture_constraints:expr, $architecture:expr, $variable_values:expr,
     $equate_value:expr, $source_module:literal, $spec_path:literal,
     $line:literal, $raw:literal) => {
        ExportMetadata {
            module: $module,
            source_module: $source_module,
            ordinal: $ordinal,
            ordinal_source: $ordinal_source,
            name: $name,
            declared_name: $declared_name,
            link_name: $link_name,
            import_library_name: $import_library_name,
            kind: $kind,
            declaration_type: $declaration_type,
            abi: $abi,
            flags: ExportFlags {
                attributes: ExportAttributes::from_bits_retain($flag_bits),
                architecture_constraints: $architecture_constraints,
            },
            architecture: $architecture,
            variable_values: $variable_values,
            equate_value: $equate_value,
            source: ExportSourceLocation { spec_path: $spec_path, line: $line },
        }
    };
}

include!(concat!(env!("OUT_DIR"), "/win16_exports.rs"));

pub(super) const fn export_name(module: &str, ordinal: u16) -> &'static str {
    let declaration = declaration(module, ordinal);
    match declaration.name {
        Some(name) => name,
        None => declaration.declared_name,
    }
}

pub(super) const fn calling_convention(module: &str, ordinal: u16)
    -> ExportCallingConvention {
    let abi = match declaration(module, ordinal).abi {
        Some(abi) => abi,
        None => panic!("data exports cannot bind a request decoder"),
    };
    match abi.calling_convention {
        Some(convention) => convention,
        None => panic!("request binding requires a declared calling convention"),
    }
}

pub(super) const fn checked_parameters(
    module: &str,
    ordinal: u16,
    kind: super::Win16ExportAbiKind,
    parameters: &'static [super::Win16Parameter],
) -> &'static [super::Win16Parameter] {
    let declaration = declaration(module, ordinal);
    let abi = match declaration.abi {
        Some(abi) => abi,
        None => panic!("request binding requires a function declaration"),
    };
    assert!(matches!(abi.signature, ExportSignatureKind::Known),
        "unknown signatures cannot bind request decoders");
    if matches!(kind, super::Win16ExportAbiKind::RegisterContext) {
        assert!(declaration.flags.contains(ExportAttributes::REGISTER)
            && parameters.is_empty()
            && abi.arguments.is_empty(),
            "register-context binding must match the module specification");
        return parameters;
    }
    assert!(parameters.len() == abi.arguments.len(),
        "bridge parameter count differs from the module specification");
    let mut index = 0;
    while index < parameters.len() {
        let expected_word = match abi.arguments[index] {
            ExportArgumentType::Word | ExportArgumentType::SignedWord => true,
            ExportArgumentType::SegmentedPointer | ExportArgumentType::SegmentedString
            | ExportArgumentType::Long | ExportArgumentType::Pointer
            | ExportArgumentType::String | ExportArgumentType::WideString
            | ExportArgumentType::Float => false,
            _ => panic!("request binding does not support this encoded argument width"),
        };
        let actual_word = matches!(parameters[index].kind,
            crate::ArgumentKind::Byte | crate::ArgumentKind::Word);
        assert!(expected_word == actual_word,
            "bridge parameter width differs from the module specification");
        index += 1;
    }
    parameters
}

const fn declaration(module: &str, ordinal: u16) -> &'static ExportMetadata {
    let mut group = 0;
    while group < WIN16_EXPORTS.len() {
        let entries = WIN16_EXPORTS[group];
        if !entries.is_empty() && same_module(entries[0].module, module) {
            let mut index = 0;
            while index < entries.len() {
                if entries[index].ordinal == ordinal
                    && matches!(entries[index].architecture, ExportArchitecture::Win16) {
                    return &entries[index];
                }
                index += 1;
            }
            break;
        }
        group += 1;
    }
    panic!("request binding has no module specification declaration")
}

const fn same_module(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() { return false; }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] { return false; }
        index += 1;
    }
    true
}

/// Look up active Win16 declaration metadata by the same module/name rules used
/// by the implemented descriptor catalog, including explicit compatibility
/// names. A hit describes ABI metadata only; aliases return the canonical row.
pub fn lookup_export_metadata(
    module: &[u8],
    target: ExportLookupTarget<'_>,
) -> Option<&'static ExportMetadata> {
    WIN16_EXPORTS.iter().flat_map(|chunk| chunk.iter()).find(|entry| {
        matches!(entry.architecture, ExportArchitecture::Win16)
            && metadata_module_matches(module, entry)
            && match target {
                ExportLookupTarget::Ordinal(ordinal) => entry.ordinal == ordinal,
                ExportLookupTarget::Name(name) => {
                    entry.name.is_some_and(|export_name| {
                        name.eq_ignore_ascii_case(export_name.as_bytes())
                    }) || compatibility_name_matches(name, entry)
                }
            }
    })
}

fn compatibility_name_matches(name: &[u8], entry: &ExportMetadata) -> bool {
    // Earlier project specifications exposed these names at the same ordinals.
    // Keep them callable without replacing the independently verified SDK names
    // or introducing duplicate declarations. Scope every alias to its module.
    const ALIASES: &[(&str, u16, &[u8])] = &[
        ("GDI", 104, b"RectVisibleOld"),
        ("GDI", 181, b"RectInRegionOld"),
    ];
    ALIASES.iter().any(|&(module, ordinal, alias)| {
        entry.module == module && entry.ordinal == ordinal && name.eq_ignore_ascii_case(alias)
    })
}

fn metadata_module_matches(import_name: &[u8], entry: &ExportMetadata) -> bool {
    let normalized = strip_module_suffix(import_name);
    normalized.eq_ignore_ascii_case(entry.module.as_bytes())
        || normalized.eq_ignore_ascii_case(strip_module_suffix(entry.source_module.as_bytes()))
}

fn strip_module_suffix(module: &[u8]) -> &[u8] {
    [b".EXE".as_slice(), b".DLL", b".DRV", b".MOD"]
        .into_iter()
        .find_map(|suffix| {
            let start = module.len().checked_sub(suffix.len())?;
            module[start..]
                .eq_ignore_ascii_case(suffix)
                .then_some(&module[..start])
        })
        .unwrap_or(module)
}
