//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelStringsRequest {
    /// Checked ANSI byte count excluding NUL, with zero for a null input.
    /// DBCS lead and trail bytes each contribute one to the Win16 word result.
    StringLength { byte_count: u16 },

    /// Copy a checked source string to the raw guest destination FAR pointer.
    /// The runtime validates and commits the guest write after sizing it.
    StringCopy {
        destination: u32,
        source: Option<Vec<u8>>,
    },

    /// Append a checked source string to a raw guest destination FAR pointer.
    StringConcat { destination: u32, source: Vec<u8> },
}
