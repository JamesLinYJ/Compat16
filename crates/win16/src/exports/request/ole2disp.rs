//! Owned arguments for guest-local Win16 OLE2DISP operations.

/// One scalar or checked owned input to an OLE2DISP guest operation.
///
/// `GuestAddress` always contains guest FAR bits. It is never a host pointer;
/// runtime handlers validate it through the selector table before access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16Ole2DispArgument {
    Word(u16),
    Dword(u32),
    GuestAddress(u32),
    AnsiString(Vec<u8>),
    NullableAnsiString(Option<Vec<u8>>),
    /// Counted Win16 OLECHAR bytes copied from the guest, preserving null.
    CountedBstrBytes(Option<Vec<u8>>),
    /// An exact, bounded guest input range such as the SAFEARRAY bounds list.
    ExactBytes(Option<Vec<u8>>),
}

/// A checked OLE2DISP call. The decoder emits only the supported guest-local
/// BSTR, VARIANT, and SAFEARRAY ordinals; native conversion and COM APIs are
/// deliberately outside this request family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16Ole2DispCall {
    pub ordinal: u16,
    pub arguments: Vec<Win16Ole2DispArgument>,
}
