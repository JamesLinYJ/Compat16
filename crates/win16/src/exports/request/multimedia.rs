//! Owned argument values for the Win16 multimedia-family export bridge.

/// One argument decoded according to the inventory's Win16 declaration.
/// `GuestFarPointer` is an address token in emulated memory, never a native
/// pointer. Runtime code may validate it through the selector table and copy
/// a bounded buffer before creating a host request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MultimediaArgument {
    Byte(u8),
    Word(u16),
    SignedWord(i16),
    Dword(u32),
    SignedDword(i32),
    GuestFarPointer(u32),
    AnsiString(Vec<u8>),
}

/// Identity and owned arguments for one known-signature Win16 multimedia
/// export. Ordinal remains authoritative; `name` is optional for ordinal-only
/// declarations. The module and name values point only into the static Rust
/// inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16MultimediaCall {
    pub module: &'static str,
    pub ordinal: u16,
    pub name: Option<&'static str>,
    pub arguments: Vec<Win16MultimediaArgument>,
}
