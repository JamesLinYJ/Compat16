use std::iter::FusedIterator;
use std::ops::Range;

use encoding_rs::GBK;
use oem_cp::Cp437;

use crate::codepage::{CodePage, TextError};

/// One Unicode character together with the byte range that encoded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedCharacter {
    pub byte_range: Range<usize>,
    pub character: char,
}

impl EncodedCharacter {
    /// Whether this character is exactly one standalone ASCII byte.
    ///
    /// In CP936, a valid double-byte character may contain ASCII-valued bytes
    /// such as `0x5c` in its trail position. Its range has length two, so it
    /// cannot be mistaken for a path separator or wildcard by callers.
    pub fn is_standalone_ascii(&self, byte: u8) -> bool {
        self.byte_range.end.checked_sub(self.byte_range.start) == Some(1)
            && self.character == char::from(byte)
    }
}

/// Lazy, strict iteration over decoded characters and their source byte ranges.
pub struct EncodedCharacters<'a> {
    bytes: &'a [u8],
    code_page: CodePage,
    offset: usize,
    failed: bool,
}

/// Iterate over characters in encoded data without losing their byte ranges.
///
/// Each CP936 pair is emitted as one character with a two-byte range. Malformed
/// or truncated data yields one error item and terminates the iterator.
pub fn encoded_characters(bytes: &[u8], code_page: CodePage) -> EncodedCharacters<'_> {
    EncodedCharacters {
        bytes,
        code_page,
        offset: 0,
        failed: false,
    }
}

impl Iterator for EncodedCharacters<'_> {
    type Item = Result<EncodedCharacter, TextError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        let byte_index = self.offset;
        let &first = self.bytes.get(byte_index)?;
        match self.code_page {
            CodePage::Cp437 => {
                self.offset += 1;
                Some(Ok(EncodedCharacter {
                    byte_range: byte_index..self.offset,
                    character: char::from(Cp437::from(first)),
                }))
            }
            CodePage::Cp936 if is_gbk_lead(first) => {
                let trail_index = byte_index + 1;
                let Some(&trail) = self.bytes.get(trail_index) else {
                    self.failed = true;
                    return Some(Err(TextError::IncompleteSequence {
                        code_page: self.code_page,
                        byte_index,
                    }));
                };
                if !is_gbk_trail(trail) {
                    self.failed = true;
                    return Some(Err(TextError::MalformedInput {
                        code_page: self.code_page,
                        byte_index: Some(byte_index),
                    }));
                }

                let end = trail_index + 1;
                match decode_one_gbk_character(&self.bytes[byte_index..end], byte_index) {
                    Ok(character) => {
                        self.offset = end;
                        Some(Ok(EncodedCharacter {
                            byte_range: byte_index..end,
                            character,
                        }))
                    }
                    Err(error) => {
                        self.failed = true;
                        Some(Err(error))
                    }
                }
            }
            CodePage::Cp936 => {
                let end = byte_index + 1;
                match decode_one_gbk_character(&self.bytes[byte_index..end], byte_index) {
                    Ok(character) => {
                        self.offset = end;
                        Some(Ok(EncodedCharacter {
                            byte_range: byte_index..end,
                            character,
                        }))
                    }
                    Err(error) => {
                        self.failed = true;
                        Some(Err(error))
                    }
                }
            }
        }
    }
}

impl FusedIterator for EncodedCharacters<'_> {}

pub(crate) fn decode_one_gbk_character(
    bytes: &[u8],
    byte_index: usize,
) -> Result<char, TextError> {
    let decoded = GBK
        .decode_without_bom_handling_and_without_replacement(bytes)
        .ok_or(TextError::MalformedInput {
            code_page: CodePage::Cp936,
            byte_index: Some(byte_index),
        })?;
    let mut characters = decoded.chars();
    let first = characters.next().ok_or(TextError::MalformedInput {
        code_page: CodePage::Cp936,
        byte_index: Some(byte_index),
    })?;
    if characters.next().is_some() {
        return Err(TextError::MalformedInput {
            code_page: CodePage::Cp936,
            byte_index: Some(byte_index),
        });
    }
    Ok(first)
}

pub(crate) const fn is_gbk_lead(byte: u8) -> bool {
    byte >= 0x81 && byte <= 0xfe
}

pub(crate) const fn is_gbk_trail(byte: u8) -> bool {
    byte >= 0x40 && byte <= 0xfe && byte != 0x7f
}
