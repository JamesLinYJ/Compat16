//! OEM character boundaries keep DBCS trail punctuation inside its character.
use crate::DosErrorCode;
use text_codec::{CodePage, EncodedCharacter};

fn characters(bytes: &[u8], page: CodePage) -> Result<Vec<EncodedCharacter>, DosErrorCode> {
    text_codec::encoded_characters(bytes, page)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DosErrorCode::PathNotFound)
}

pub(super) fn split(
    bytes: &[u8],
    page: CodePage,
) -> Result<(bool, bool, Vec<Vec<u8>>), DosErrorCode> {
    let chars = characters(bytes, page)?;
    let separator =
        |c: &EncodedCharacter| c.is_standalone_ascii(b'\\') || c.is_standalone_ascii(b'/');
    let mut parts = Vec::new();
    let mut start = 0;
    for c in &chars {
        if separator(c) {
            parts.push(bytes[start..c.byte_range.start].to_vec());
            start = c.byte_range.end;
        }
    }
    parts.push(bytes[start..].to_vec());
    Ok((
        chars.first().is_some_and(separator),
        chars.last().is_some_and(separator),
        parts,
    ))
}

pub(super) fn normalize_component(
    bytes: &[u8],
    page: CodePage,
) -> Result<(Vec<u8>, bool), DosErrorCode> {
    let upper =
        text_codec::uppercase_oem_name(bytes, page).map_err(|_| DosErrorCode::PathNotFound)?;
    let chars = characters(&upper, page)?;
    let mut base = Vec::new();
    let mut extension = Vec::new();
    let mut dotted = false;
    let mut full = false;
    let mut wildcard = false;
    for c in chars {
        let text = &upper[c.byte_range.clone()];
        if c.is_standalone_ascii(b'.') {
            if dotted || base.is_empty() {
                return Err(DosErrorCode::FileNotFound);
            }
            dotted = true;
            full = false;
            continue;
        }
        if text.len() == 1
            && (text[0] <= b' '
                || matches!(
                    text[0],
                    b':' | b';'
                        | b','
                        | b'='
                        | b'+'
                        | b'"'
                        | b'['
                        | b']'
                        | b'<'
                        | b'>'
                        | b'|'
                        | b'/'
                        | b'\\'
                ))
        {
            return Err(DosErrorCode::FileNotFound);
        }
        let (field, capacity) = if dotted {
            (&mut extension, 3)
        } else {
            (&mut base, 8)
        };
        wildcard |= c.is_standalone_ascii(b'*') || c.is_standalone_ascii(b'?');
        if full {
            continue;
        }
        if c.is_standalone_ascii(b'*') {
            field.resize(capacity, b'?');
            full = true;
        } else if field.len() + text.len() <= capacity {
            field.extend_from_slice(text);
        } else {
            full = true;
        }
    }
    if base.is_empty() {
        return Err(DosErrorCode::FileNotFound);
    }
    if !extension.is_empty() {
        base.push(b'.');
        base.extend_from_slice(&extension);
    }
    Ok((base, wildcard))
}
