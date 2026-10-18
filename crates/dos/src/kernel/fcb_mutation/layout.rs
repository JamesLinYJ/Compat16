use super::super::{directory, fcb, state::DosSearchPattern};
use crate::{DosCallAddressSpace, DosError, DosErrorCode, DosSpanPolicy};
use text_codec::CodePage;

pub(super) struct Request {
    pub drive: u8,
    pub attributes: u8,
    old: [u8; 11],
    new: Option<[u8; 11]>,
}
impl Request {
    pub fn read(
        memory: &mut impl DosCallAddressSpace,
        segment: u16,
        offset: u16,
        rename: bool,
    ) -> Result<Self, DosError> {
        let pointer = memory.resolve_caller_pointer(segment, offset)?;
        let mut prefix = [0; 7];
        memory.read_caller_range(pointer, 0, &mut prefix[..1], DosSpanPolicy::OffsetWrap)?;
        let skip = if prefix[0] == 0xff {
            memory.read_caller_range(pointer, 0, &mut prefix, DosSpanPolicy::OffsetWrap)?;
            7
        } else {
            0
        };
        let mut body = [0; 28];
        let length = if rename { 28 } else { 12 };
        memory.read_caller_range(
            pointer,
            skip,
            &mut body[..length],
            DosSpanPolicy::OffsetWrap,
        )?;
        let mut old = [0; 11];
        old.copy_from_slice(&body[1..12]);
        let new = if rename {
            let mut new = [0; 11];
            new.copy_from_slice(&body[17..28]);
            Some(new)
        } else {
            None
        };
        Ok(Self {
            drive: body[0],
            attributes: if skip == 0 { 0 } else { prefix[6] },
            old,
            new,
        })
    }
    pub fn patterns(
        &self,
        page: CodePage,
    ) -> Result<(DosSearchPattern, Option<DosSearchPattern>), DosErrorCode> {
        // Like TransFCB, validate the destination before doing any filesystem
        // work. The five reserved bytes (including offset 10h) are not a drive.
        let new = self
            .new
            .as_ref()
            .map(|name| parse(name, page))
            .transpose()?;
        Ok((parse(&self.old, page)?, new))
    }
}

fn parse(fields: &[u8; 11], page: CodePage) -> Result<DosSearchPattern, DosErrorCode> {
    for field in [&fields[..8], &fields[8..]] {
        let mut padded = false;
        for character in text_codec::encoded_characters(field, page) {
            let character = character.map_err(|_| DosErrorCode::PathNotFound)?;
            if character.is_standalone_ascii(b' ') {
                padded = true;
                continue;
            }
            if padded
                || (character.byte_range.len() == 1 && field[character.byte_range.start] < b' ')
                || [b';', b',', b'=', b'+', b'[', b']']
                    .iter()
                    .any(|&c| character.is_standalone_ascii(c))
            {
                return Err(DosErrorCode::PathNotFound);
            }
        }
    }
    if fields[..8].iter().all(|b| *b == b' ') {
        return Err(DosErrorCode::PathNotFound);
    }
    fcb::pattern(fields, page).map_err(|_| DosErrorCode::PathNotFound)
}

pub(super) fn substitute(
    template: DosSearchPattern,
    source: &[u8],
    page: CodePage,
) -> Result<Vec<u8>, DosErrorCode> {
    let (old_name, old_extension) =
        directory::short_name_fields(source, page).ok_or(DosErrorCode::InvalidData)?;
    let mut name = template.name;
    let mut extension = template.extension;
    for (field, old) in [
        (name.as_mut_slice(), old_name.as_slice()),
        (extension.as_mut_slice(), old_extension.as_slice()),
    ] {
        for (byte, &original) in field.iter_mut().zip(old) {
            if *byte == b'?' {
                *byte = original;
            }
        }
    }
    let base = name
        .iter()
        .rposition(|b| *b != b' ')
        .map_or(0, |last| last + 1);
    let ext = extension
        .iter()
        .rposition(|b| *b != b' ')
        .map_or(0, |last| last + 1);
    let mut result = name[..base].to_vec();
    if ext != 0 {
        result.push(b'.');
        result.extend_from_slice(&extension[..ext]);
    }
    if result == b"." || result == b".." {
        return Err(DosErrorCode::AccessDenied);
    }
    // Question marks substitute byte positions, as DOS NEW_RENAME does. A
    // mixed template must still produce a complete valid OEM host filename.
    directory::short_name_fields(&result, page).ok_or(DosErrorCode::PathNotFound)?;
    Ok(result)
}
