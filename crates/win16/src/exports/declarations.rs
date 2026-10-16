//! Typed guest DLL declarations generated from the validated ABI catalog.
//!
//! Historical declaration hints remain available to metadata consumers; runtime
//! descriptors use canonical semantic signatures. Host bridges stay handwritten.

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
    /// Catalog group path used for a build-time diagnostic; line is zero for TOML.
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

include!(concat!(env!("OUT_DIR"), "/win16_exports.rs"));

/// Look up active Win16 declaration metadata by the same module/name rules used
/// by the implemented descriptor catalog, including explicit compatibility
/// names. A hit describes ABI metadata only; aliases return the canonical row.
pub fn lookup_export_metadata(
    module: &[u8],
    target: ExportLookupTarget<'_>,
) -> Option<&'static ExportMetadata> {
    let canonical_module = WIN16_EXPORTS.iter().flat_map(|chunk| chunk.iter())
        .find(|entry| metadata_module_matches(module, entry))?.module;
    // Explicit choices make legacy name collisions independent of the physical
    // grouping or traversal order of TOML files.
    let target = match target {
        ExportLookupTarget::Name(name) => NAME_RESOLUTIONS.iter()
            .find(|&&(module, alias, _)| module == canonical_module
                && name.eq_ignore_ascii_case(alias.as_bytes()))
            .map_or(target, |&(_, _, ordinal)| ExportLookupTarget::Ordinal(ordinal)),
        target => target,
    };
    WIN16_EXPORTS.iter().flat_map(|chunk| chunk.iter()).find(|entry| {
        matches!(entry.architecture, ExportArchitecture::Win16)
            && entry.module == canonical_module
            && match target {
                ExportLookupTarget::Ordinal(ordinal) => entry.ordinal == ordinal,
                ExportLookupTarget::Name(name) => {
                    entry.name.is_some_and(|export_name| {
                        name.eq_ignore_ascii_case(export_name.as_bytes())
                    }) || EXPORT_ALIASES.iter().any(|&(module, ordinal, alias)| {
                        entry.module == module && entry.ordinal == ordinal
                            && name.eq_ignore_ascii_case(alias.as_bytes())
                    })
                }
            }
    })
}

fn metadata_module_matches(import_name: &[u8], entry: &ExportMetadata) -> bool {
    let normalized = strip_module_suffix(import_name);
    normalized.eq_ignore_ascii_case(strip_module_suffix(entry.module.as_bytes()))
        || normalized.eq_ignore_ascii_case(strip_module_suffix(entry.source_module.as_bytes()))
        || MODULE_ALIASES.iter().any(|&(module, alias)| {
            entry.module == module
                && normalized.eq_ignore_ascii_case(strip_module_suffix(alias.as_bytes()))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixed_canonical_module_names_follow_import_normalization() {
        // Use an artificial copy so the real catalog remains unchanged. A
        // canonical module ID may itself contain a conventional suffix.
        let mut entry = *WIN16_EXPORTS.iter().flat_map(|group| group.iter())
            .next().expect("catalog contains declarations");
        entry.module = "CANON.DLL";
        entry.source_module = "physical.exe";
        for name in [b"CANON".as_slice(), b"canon.dll", b"CaNoN.ExE", b"CANON.DRV", b"canon.mod", b"physical", b"PHYSICAL.EXE"] {
            assert!(metadata_module_matches(name, &entry), "{name:?}");
        }
        assert!(!metadata_module_matches(b"CANON.DLL.DLL", &entry));
        assert!(!metadata_module_matches(b"different", &entry));
    }
}
