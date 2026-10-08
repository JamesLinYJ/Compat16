//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserTextRequest {
    /// Register a checked nullable ANSI clipboard format name and return its
    /// Win16 WORD format identifier.
    RegisterClipboardFormat { name: Option<Vec<u8>> },

    /// Copy a clipboard format's name to an output FAR pointer. The runtime
    /// receives the raw guest address and signed count for write preflight;
    /// the decoder does not read the output memory.
    GetClipboardFormatName {
        format: u16,
        output: u32,
        count: i16,
    },

    MessageBox {
        owner: u16,
        text: Option<Vec<u8>>,
        caption: Option<Vec<u8>>,
        style: u16,
    },
}
