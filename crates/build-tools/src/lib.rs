#![forbid(unsafe_code)]

mod audit;
mod probe;
mod vga_probe;
pub mod spec;

pub use audit::{audit_win16_module, Win16AuditReport};
pub use probe::{
    dos_probe_bytes, probe_file_contents, probe_file_name, ProbeBuildError, ProbeFormat,
};
pub use vga_probe::{vga_probe_bytes, VGA_PROBE_FILE_CONTENTS, VGA_PROBE_FILE_NAME};
pub use spec::{generate_rust, parse_spec, SpecEntry, SpecModule, SpecParseError};
pub use abi_schema::ExportAttributes;

/// Compile-time metadata types referenced by files emitted by [`generate_rust`].
///
/// These are records only. Function entries do not imply that a Win16 service
/// has been implemented or that a guest call can be dispatched successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordinal {
    Explicit(u16),
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Function,
    Stub,
    Variable,
    Equate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Pascal,
    Cdecl,
    Stdcall,
    Varargs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentType {
    Word,
    SignedWord,
    Long,
    Pointer,
    String,
    SegmentPointer,
    SegmentString,
    Int64,
    Float,
    WideString,
}

impl CallingConvention {
    pub const fn as_spec_name(self) -> &'static str {
        match self {
            Self::Pascal => "pascal",
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Varargs => "varargs",
        }
    }
}

impl ArgumentType {
    pub const fn as_spec_name(self) -> &'static str {
        match self {
            Self::Word => "word",
            Self::SignedWord => "s_word",
            Self::Long => "long",
            Self::Pointer => "ptr",
            Self::String => "str",
            Self::SegmentPointer => "segptr",
            Self::SegmentString => "segstr",
            Self::Int64 => "int64",
            Self::Float => "float",
            Self::WideString => "wstr",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportFlags {
    pub attributes: ExportAttributes,
    /// Architecture constraint metadata is not encoded in export attributes.
    pub arch_win32: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedExport {
    pub ordinal: Ordinal,
    pub kind: ExportKind,
    pub export_name: &'static str,
    pub implementation_name: Option<&'static str>,
    pub convention: Option<CallingConvention>,
    pub arguments: &'static [ArgumentType],
    pub flags: ExportFlags,
    /// Numeric initializer tokens for `variable` and `equate` records.
    pub values: &'static [&'static str],
    pub source_line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratedModule {
    /// Original module name, preserved exactly as supplied to the generator.
    pub original_module_name: &'static str,
    pub exports: &'static [GeneratedExport],
}
