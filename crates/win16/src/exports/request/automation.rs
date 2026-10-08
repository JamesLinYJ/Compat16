//! Owned Win16 OLE Automation, NLS, and type-library call arguments.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16AutomationFamily {
    Ole2Disp,
    Ole2Nls,
    TypeLib,
}

/// An argument after its ABI width and any guest string/buffer input have
/// been checked. `GuestAddress` contains only the original selector:offset
/// bits; callers must validate it before reading or writing guest memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16AutomationArgument {
    Word(u16),
    Dword(u32),
    GuestAddress(u32),
    AnsiString(Vec<u8>),
    NullableAnsiString(Option<Vec<u8>>),
    /// Counted Win16 `OLECHAR16` input copied as owned ANSI/DBCS bytes.
    /// `None` preserves a null FAR source for the BSTR null-source forms.
    CountedBstrBytes(Option<Vec<u8>>),
    CountedAnsiString { bytes: Vec<u8>, declared_count: i16, is_null: bool },
    ExactBytes(Option<Vec<u8>>),
}

/// The native adapter selects the documented operation by family and source
/// ordinal. This keeps export identity independent from runtime and host ABI
/// types while preserving the precise Win16 stack values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16AutomationCall {
    pub family: Win16AutomationFamily,
    pub ordinal: u16,
    pub arguments: Vec<Win16AutomationArgument>,
}
