use std::fmt;

/// A supported Windows legacy code page.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CodePage {
    /// United States OEM (IBM PC) code page.
    Cp437,
    /// Simplified Chinese Windows code page, using the GBK mapping.
    Cp936,
}

impl CodePage {
    pub const CP437: Self = Self::Cp437;
    pub const CP936: Self = Self::Cp936;

    /// Return the numeric Windows code-page identifier.
    pub const fn number(self) -> u16 {
        match self {
            Self::Cp437 => 437,
            Self::Cp936 => 936,
        }
    }

    /// Strictly decode bytes using this code page.
    pub fn decode(self, bytes: &[u8]) -> Result<String, TextError> {
        crate::decode(bytes, self)
    }

    /// Strictly encode Unicode text using this code page.
    pub fn encode(self, text: &str) -> Result<Vec<u8>, TextError> {
        crate::encode(text, self)
    }
}

impl TryFrom<u16> for CodePage {
    type Error = TextError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from(u32::from(value))
    }
}

impl TryFrom<u32> for CodePage {
    type Error = TextError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            437 => Ok(Self::Cp437),
            936 => Ok(Self::Cp936),
            other => Err(TextError::UnsupportedCodePage(other)),
        }
    }
}

/// Errors from strict code-page conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextError {
    UnsupportedCodePage(u32),
    /// Input contains bytes that are not a valid sequence in the selected page.
    MalformedInput {
        code_page: CodePage,
        /// Present for character-boundary iteration, where the byte position is known.
        byte_index: Option<usize>,
    },
    /// A CP936 lead byte was the final byte in the supplied input.
    IncompleteSequence { code_page: CodePage, byte_index: usize },
    /// At least one Unicode character cannot be represented in the selected page.
    UnrepresentableText { code_page: CodePage },
    /// The caller pushed data after declaring the stream finished.
    StreamFinished,
    /// A previous malformed stream push made the decoder unusable.
    StreamFailed,
    /// The required output buffer size cannot be represented by `usize`.
    OutputTooLarge,
    /// Reserving the required output memory failed.
    AllocationFailed,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCodePage(code_page) => {
                write!(f, "unsupported Windows code page {code_page}")
            }
            Self::MalformedInput { code_page, byte_index } => match byte_index {
                Some(index) => write!(
                    f,
                    "malformed input sequence for code page {} at byte offset {index}",
                    code_page.number()
                ),
                None => write!(
                    f,
                    "malformed input sequence for code page {} at an unspecified byte offset",
                    code_page.number()
                ),
            },
            Self::IncompleteSequence { code_page, byte_index } => write!(
                f,
                "incomplete input sequence for code page {} at byte offset {byte_index}",
                code_page.number()
            ),
            Self::UnrepresentableText { code_page } => write!(
                f,
                "text contains characters that cannot be represented in code page {}",
                code_page.number()
            ),
            Self::StreamFinished => f.write_str("text decoder stream is already finished"),
            Self::StreamFailed => {
                f.write_str("text decoder stream cannot continue after an earlier decoding error")
            }
            Self::OutputTooLarge => {
                f.write_str("decoded text output exceeds the addressable buffer size")
            }
            Self::AllocationFailed => f.write_str("unable to allocate text conversion output"),
        }
    }
}

impl std::error::Error for TextError {}
