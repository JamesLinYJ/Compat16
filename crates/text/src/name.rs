use crate::codepage::{CodePage, TextError};
use crate::convert::encode;
use crate::characters::encoded_characters;

/// Uppercase an OEM-encoded name without changing its byte length or
/// uppercasing ASCII-valued trail bytes inside CP936 characters.
///
/// A supported DOS profile uses its actual OEM mapping, shared with the guest
/// NLS table. Other encodings retain the existing Unicode conversion fallback;
/// this fallback does not claim to implement that code page's DOS NLS profile.
/// Each fallback source character is decoded independently. Its uppercase form
/// is encoded back only when uppercase produces exactly one character, that
/// character is representable, and its encoded byte count matches the source
/// character. Otherwise the original byte sequence is retained. Invalid or
/// truncated source bytes return an error.
pub fn uppercase_oem_name(bytes: &[u8], code_page: CodePage) -> Result<Vec<u8>, TextError> {
    let mut output = Vec::new();
    output
        .try_reserve(bytes.len())
        .map_err(|_| TextError::AllocationFailed)?;

    if let Some(tables) = crate::dos_code_page_tables(code_page) {
        if code_page.dbcs_lead_byte_ranges().is_empty() {
            output.extend(bytes.iter().map(|&byte| tables.uppercase_byte(byte)));
        } else {
            for item in encoded_characters(bytes, code_page) {
                let item = item?;
                let source = &bytes[item.byte_range];
                if source.len() == 1 {
                    output.push(tables.uppercase_byte(source[0]));
                } else {
                    output.extend_from_slice(source);
                }
            }
        }
        return Ok(output);
    }

    for item in encoded_characters(bytes, code_page) {
        let item = item?;
        let source = &bytes[item.byte_range.clone()];
        let mut uppercase_chars = item.character.to_uppercase();
        let uppercase_character = match (uppercase_chars.next(), uppercase_chars.next()) {
            (Some(character), None) => character,
            _ => {
                output.extend_from_slice(source);
                continue;
            }
        };

        if uppercase_character == item.character {
            output.extend_from_slice(source);
            continue;
        }

        let mut uppercase_buffer = [0; 4];
        let uppercase_text = uppercase_character.encode_utf8(&mut uppercase_buffer);
        match encode(uppercase_text, code_page) {
            Ok(encoded) if encoded.len() == source.len() => output.extend_from_slice(&encoded),
            Ok(_) | Err(TextError::UnrepresentableText { .. }) => {
                output.extend_from_slice(source)
            }
            Err(error) => return Err(error),
        }
    }

    Ok(output)
}
