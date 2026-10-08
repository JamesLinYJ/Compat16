use super::Win16OutputBuffer;

/// Fully formatted USER output. `bytes` includes its terminating NUL and is
/// bounded by the Win16 formatter's 1024-byte output area.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16UserStringFormatRequest {
    pub output: Win16OutputBuffer,
    pub bytes: Vec<u8>,
    pub return_length: u16,
}
