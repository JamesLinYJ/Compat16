//! Remaining USER exports. Guest slots stay scalar values; a far pointer is
//! the raw 16:16 dword and is never a host address.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16UserDeclaredCall {
    pub ordinal: u16,
    pub slots: Vec<u32>,
}
