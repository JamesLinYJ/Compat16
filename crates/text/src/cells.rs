use crate::characters::encoded_characters;
use crate::codepage::{CodePage, TextError};

/// Which byte cell of a CP936 double-byte character this output cell occupies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CellRole {
    /// A character encoded in one byte, including CP437 characters.
    Single,
    /// The first byte of a CP936 character. `DecodedCell::character` holds it.
    Lead,
    /// The second byte of a CP936 character. Its `character` is `None` because
    /// the Unicode scalar is already attached to the lead cell.
    Trail,
}

/// Decoded content corresponding to one original byte cell in a text row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedCell {
    pub byte_index: usize,
    pub character: Option<char>,
    pub role: CellRole,
}

/// Decode one fixed-width text row while preserving the original byte-cell map.
///
/// The returned vector always has the same length as `bytes`. A valid CP936
/// pair occupies a lead cell containing its Unicode character and a trail cell
/// containing `None`. A lead byte at the end of the row is an error; rows are
/// never joined to complete a character across a row boundary.
pub fn decode_text_row(bytes: &[u8], code_page: CodePage) -> Result<Vec<DecodedCell>, TextError> {
    let mut cells = Vec::new();
    cells
        .try_reserve(bytes.len())
        .map_err(|_| TextError::AllocationFailed)?;
    for item in encoded_characters(bytes, code_page) {
        let item = item?;
        match item.byte_range.end.checked_sub(item.byte_range.start) {
            Some(1) => cells.push(DecodedCell {
                byte_index: item.byte_range.start,
                character: Some(item.character),
                role: CellRole::Single,
            }),
            Some(2) => {
                cells.push(DecodedCell {
                    byte_index: item.byte_range.start,
                    character: Some(item.character),
                    role: CellRole::Lead,
                });
                cells.push(DecodedCell {
                    byte_index: item.byte_range.start + 1,
                    character: None,
                    role: CellRole::Trail,
                });
            }
            _ => {
                return Err(TextError::MalformedInput {
                    code_page,
                    byte_index: Some(item.byte_range.start),
                });
            }
        }
    }
    Ok(cells)
}
