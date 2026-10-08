use std::borrow::Cow;

use encoding_rs::GBK;
use oem_cp::code_table::{DECODING_TABLE_CP437, ENCODING_TABLE_CP437};

use crate::codepage::{CodePage, TextError};

/// Strictly decode a byte slice using the selected code page.
pub fn decode(bytes: &[u8], code_page: CodePage) -> Result<String, TextError> {
    match code_page {
        CodePage::Cp437 => Ok(oem_cp::decode_string_complete_table(
            bytes,
            &DECODING_TABLE_CP437,
        )),
        CodePage::Cp936 => GBK
            .decode_without_bom_handling_and_without_replacement(bytes)
            .map(Cow::into_owned)
            .ok_or(TextError::MalformedInput {
                code_page,
                byte_index: None,
            }),
    }
}

/// Strictly encode Unicode text using the selected code page.
pub fn encode(text: &str, code_page: CodePage) -> Result<Vec<u8>, TextError> {
    match code_page {
        CodePage::Cp437 => oem_cp::encode_string_checked(text, &ENCODING_TABLE_CP437)
            .ok_or(TextError::UnrepresentableText { code_page }),
        CodePage::Cp936 => {
            let (bytes, _encoding, had_errors) = GBK.encode(text);
            if had_errors {
                Err(TextError::UnrepresentableText { code_page })
            } else {
                Ok(bytes.into_owned())
            }
        }
    }
}
