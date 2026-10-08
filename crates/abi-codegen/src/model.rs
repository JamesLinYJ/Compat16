use abi_schema::ExportAttributes;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OrdinalSource {
    Explicit,
    Assigned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Function,
    Stub,
    Variable,
    Equate,
    Extern,
    Forward,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeclarationType {
    Variable,
    Pascal,
    Equate,
    Stub,
    Stdcall,
    Cdecl,
    Varargs,
    Thiscall,
    Extern,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallingConvention {
    Pascal,
    Cdecl,
    Stdcall,
    Varargs,
    Thiscall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArgumentType {
    Word,
    SignedWord,
    SegmentPointer,
    SegmentString,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReturnModifier {
    Void,
    Unspecified,
    Ret16,
    Ret64,
    Ret16AndRet64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureKind {
    Known,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Architecture {
    Win16,
    Win32Only,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Flags {
    pub attributes: ExportAttributes,
    pub architecture_constraints: Vec<&'static str>,
}

impl Flags {
    pub fn return_modifier(&self) -> ReturnModifier {
        if self.attributes.contains(ExportAttributes::RETVOID) {
            return ReturnModifier::Void;
        }
        match (
            self.attributes.contains(ExportAttributes::RET16),
            self.attributes.contains(ExportAttributes::RET64),
        ) {
            (false, false) => ReturnModifier::Unspecified,
            (true, false) => ReturnModifier::Ret16,
            (false, true) => ReturnModifier::Ret64,
            (true, true) => ReturnModifier::Ret16AndRet64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpecEntry {
    pub ordinal: u16,
    pub ordinal_source: OrdinalSource,
    pub declared_name: String,
    pub link_name: Option<String>,
    pub kind: EntryKind,
    pub declaration_type: DeclarationType,
    pub calling_convention: Option<CallingConvention>,
    pub signature_kind: Option<SignatureKind>,
    pub arguments: Vec<ArgumentType>,
    pub flags: Flags,
    pub architecture: Architecture,
    pub variable_values: Vec<u32>,
    pub equate_value: Option<i32>,
    pub line: usize,
    pub raw: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpecModule {
    pub module: String,
    pub source_module: String,
    pub spec_path: String,
    pub entries: Vec<SpecEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OrdinalToken {
    Explicit(u16),
    Automatic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedEntry {
    pub ordinal: OrdinalToken,
    pub declared_name: String,
    pub link_name: Option<String>,
    pub kind: EntryKind,
    pub declaration_type: DeclarationType,
    pub calling_convention: Option<CallingConvention>,
    pub signature_kind: Option<SignatureKind>,
    pub arguments: Vec<ArgumentType>,
    pub flags: Flags,
    pub architecture: Architecture,
    pub variable_values: Vec<u32>,
    pub equate_value: Option<i32>,
    pub line: usize,
    pub raw: String,
}
