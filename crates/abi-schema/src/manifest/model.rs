use serde::{Deserialize, Serialize};

use crate::ExportAttributes;

pub const SCHEMA_VERSION: u32 = 1;

/// Paths are relative to the directory containing `catalog.toml`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub modules: Vec<Module>,
    pub name_resolutions: Vec<NameResolution>,
    pub groups: Vec<String>,
    pub types: Vec<String>,
}

/// An explicitly retained historical collision in case-insensitive import
/// names. Ordinal identity and the losing declaration's name remain intact.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NameResolution {
    pub module: String,
    pub name: String,
    pub ordinal: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub id: String,
    pub source_module: String,
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub version: u32,
    pub exports: Vec<Export>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SharedTypes {
    pub version: u32,
    pub types: Vec<NamedType>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedType {
    pub name: String,
    pub value: ValueType,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub module: String,
    pub ordinal: u16,
    pub ordinal_source: OrdinalSource,
    pub declared_name: String,
    pub name: Option<String>,
    pub aliases: Vec<String>,
    pub link_name: Option<String>,
    pub import_library_name: Option<String>,
    pub architecture: Architecture,
    pub declaration: DeclarationEvidence,
    pub entry: Entry,
    pub binding: Option<Binding>,
    pub evidence: Vec<Evidence>,
}

/// Historical declaration metadata, retained for lossless migration and
/// inspection. Generating a callable descriptor must never consult these hints.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclarationEvidence {
    pub declaration_type: DeclarationType,
    pub attributes: Vec<Attribute>,
    pub architecture_constraints: Vec<String>,
    pub abi: Option<DeclarationAbiEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclarationAbiEvidence {
    pub calling_convention: Option<CallingConvention>,
    pub knowledge: SignatureKnowledge,
    pub arguments: Vec<ArgumentEncoding>,
    pub return_modifier: ReturnModifier,
}

/// These records are provenance only and never select a decoder or host path.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: String,
    pub line: Option<u32>,
    pub note: Option<String>,
}

/// References registered Rust-side dispatch keys, never arbitrary Rust source.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub rust_id: String,
    /// Stable existing Rust discriminant, independent of guest ordinal/order.
    pub id_value: u32,
    pub constant: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entry {
    Function { abi: Abi },
    /// Historical declaration classification; a verified binding may exist.
    Stub { abi: Abi },
    Variable { values: Vec<u32> },
    Equate { value: i32 },
    Extern,
    Forward,
}

impl Entry {
    pub fn abi(&self) -> Option<&Abi> {
        match self {
            Self::Function { abi } | Self::Stub { abi } => Some(abi),
            _ => None,
        }
    }
}

/// Unknown describes runtime callability. Historical declaration arguments
/// live exclusively in DeclarationEvidence, not in a guessed runtime signature.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Abi {
    Unknown,
    FixedStack { signature: Signature },
    VariableStack { signature: Signature },
    RegisterContext { signature: Signature },
}

impl Abi {
    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Unknown => None,
            Self::FixedStack { signature } | Self::VariableStack { signature }
            | Self::RegisterContext { signature } => Some(signature),
        }
    }

    /// The total fixed argument area, not including any return address.
    pub fn fixed_stack_bytes(&self) -> Option<u16> {
        match self {
            Self::FixedStack { signature } => signature.parameters.iter().try_fold(0u16, |n, p| {
                n.checked_add(p.slot_bytes)
            }),
            Self::RegisterContext { .. } => Some(0),
            Self::Unknown | Self::VariableStack { .. } => None,
        }
    }

    /// Derived from the canonical signature; never a second editable number.
    pub fn cleanup(&self) -> Option<StackCleanup> {
        let bytes = self.fixed_stack_bytes()?;
        if matches!(self, Self::RegisterContext { .. }) {
            return Some(StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: 0 });
        }
        match self.signature()?.calling_convention {
            CallingConvention::Pascal => Some(StackCleanup { callee_pop_bytes: bytes, caller_pop_bytes: 0 }),
            CallingConvention::Cdecl => Some(StackCleanup { callee_pop_bytes: 0, caller_pop_bytes: bytes }),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackCleanup {
    pub callee_pop_bytes: u16,
    pub caller_pop_bytes: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub calling_convention: CallingConvention,
    pub parameters: Vec<Parameter>,
    pub returns: ReturnValue,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    pub name: String,
    /// Physical guest stack slot size. A byte value can occupy a word slot.
    pub slot_bytes: u16,
    pub value: ValueType,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueType {
    Unknown,
    Integer { bits: u16, signedness: Signedness },
    Float { bits: u16 },
    Far16_16 { role: FarPointerRole, direction: Direction, nullability: Nullability },
    /// A declaration-level linear pointer whose pointed-to contract is unknown.
    LinearPointer { bits: u16, role: LinearPointerRole, direction: Direction, nullability: Nullability },
    Named { name: String },
}

macro_rules! enums {
    ($($name:ident { $($variant:ident),* $(,)? })*) => { $(
        #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),* }
    )*};
}

enums! {
    OrdinalSource { Explicit, Assigned }
    Architecture { Win16, Win32Only, Unknown }
    SignatureKnowledge { Known, Unknown }
    DeclarationType { Variable, Pascal, Equate, Stub, Stdcall, Cdecl, Varargs, Thiscall, Extern, Unknown }
    CallingConvention { Pascal, Stdcall, Cdecl, Varargs, Thiscall, Unknown }
    ArgumentEncoding { Word, SignedWord, SegmentedPointer, SegmentedString, Long, Pointer, String, WideString, Int64, Int128, Float, Double, Unknown }
    ReturnModifier { Void, Unspecified, Ret16, Ret64, Ret16AndRet64, Unknown }
    ReturnValue { Unknown, Word, Dword, FarPointer, RegisterContext, Void }
    RuntimeArgumentKind { Byte, Word, Dword }
    Signedness { Unsigned, Signed, Unknown }
    FarPointerRole { Unknown, FarString, FarPointer, FarStringOrChar, ResourceName, AtomName, ClassName, NullableFarString, FarBuffer, FarOutputBuffer }
    LinearPointerRole { Unknown, Pointer, String, WideString }
    Direction { Unknown, In, Out, InOut }
    Nullability { Unknown, Nullable, NonNull }
    Attribute { NoRelay, Noname, Ret16, Ret64, Register, Private, Ordinal, StackProlog, LegacyI386, Forwarded, Retvoid }
}

impl Attribute {
    pub const fn flag(self) -> ExportAttributes {
        match self {
            Self::NoRelay => ExportAttributes::NO_RELAY,
            Self::Noname => ExportAttributes::NONAME,
            Self::Ret16 => ExportAttributes::RET16,
            Self::Ret64 => ExportAttributes::RET64,
            Self::Register => ExportAttributes::REGISTER,
            Self::Private => ExportAttributes::PRIVATE,
            Self::Ordinal => ExportAttributes::ORDINAL,
            Self::StackProlog => ExportAttributes::STACK_PROLOG,
            Self::LegacyI386 => ExportAttributes::LEGACY_I386,
            Self::Forwarded => ExportAttributes::FORWARDED,
            Self::Retvoid => ExportAttributes::RETVOID,
        }
    }
}

impl DeclarationEvidence {
    pub fn attribute_bits(&self) -> ExportAttributes {
        self.attributes.iter().fold(ExportAttributes::empty(), |bits, attribute| bits | attribute.flag())
    }
}

impl ValueType {
    /// Existing runtime value decoder kind. Resolve Named values first. This
    /// preserves Byte versus Word even though both occupy a two-byte slot.
    pub fn runtime_argument_kind(&self) -> Option<RuntimeArgumentKind> {
        match self {
            Self::Integer { bits: 8, .. } => Some(RuntimeArgumentKind::Byte),
            Self::Integer { bits: 16, .. } => Some(RuntimeArgumentKind::Word),
            Self::Integer { bits: 32, .. } | Self::Far16_16 { .. } => Some(RuntimeArgumentKind::Dword),
            _ => None,
        }
    }
}

impl RuntimeArgumentKind {
    pub const fn slot_bytes(self) -> u16 {
        match self {
            Self::Byte | Self::Word => 2,
            Self::Dword => 4,
        }
    }
}
