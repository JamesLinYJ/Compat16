//! Strict, byte-aware text conversion for DOS and Win16 code pages.
#![forbid(unsafe_code)]

mod cells;
mod characters;
mod codepage;
mod convert;
mod detection;
mod dos_tables;
mod name;
mod stream;

pub use cells::{decode_text_row, CellRole, DecodedCell};
pub use characters::{encoded_characters, EncodedCharacter, EncodedCharacters};
pub use codepage::{CodePage, TextError};
pub use convert::{decode, encode};
pub use detection::{detect_ansi_code_page, TextEncodingConflict, TextEncodingEvidence, TextEncodingSelection};
pub use dos_tables::{DosCodePageTables, dos_code_page_tables};
pub use name::uppercase_oem_name;
pub use stream::StreamDecoder;

#[cfg(test)]
mod tests;
