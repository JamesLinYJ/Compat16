//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelStringsRequest {
    /// Return a bounded NUL-terminated string length. A null input is retained
    /// as `None` and has the Win16 zero result.
    StringLength { text: Option<Vec<u8>> },

    /// Copy a checked source string to the raw guest destination FAR pointer.
    /// The runtime validates and commits the guest write after sizing it.
    StringCopy {
        destination: u32,
        source: Option<Vec<u8>>,
    },

    /// Append a checked source string to a raw guest destination FAR pointer.
    StringConcat { destination: u32, source: Vec<u8> },
}
