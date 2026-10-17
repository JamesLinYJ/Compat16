//! Decoded arguments for GDI exports that were previously declaration-only.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiInternalArg {
    Word(u16),
    Dword(u32),
    /// Guest 16:16 address. It is not a host pointer.
    Far(u32),
    Ansi(Option<Vec<u8>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16GdiInternalRequest {
    pub ordinal: u16,
    pub arguments: Vec<Win16GdiInternalArg>,
}
