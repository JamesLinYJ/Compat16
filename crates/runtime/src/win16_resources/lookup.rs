//! Named and ordinal resource identity shared by FindResource and
//! SetResourceHandler.
//!
//! An NE integer id is the low 15 bits of the type or name word. Bit 15 marks
//! the word as an integer, so a caller id and the stored ordinal still match
//! when either side already has that flag set.
//!
//! FindResource additionally reads type 15 (the name table) from the module
//! image when the caller passed a string. Each record is a byte length, a
//! type word, an id word, and C strings. A set bit 15 on a word means the
//! corresponding C string is present; the low 15 bits remain the directory
//! ordinal. The scan uses those image bytes, which is the default loader's
//! copy of the table.

use formats::{NeModule, NeResourceId};
use win16_abi::Win16ResourceName;

use super::decimal_resource_id;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

const RT_NAME_TABLE: u16 = 15;
const NE_INTEGER_ID_FLAG: u16 = 0x8000;
const NAME_TABLE_HEADER_BYTES: usize = 6;

#[derive(Clone, Copy)]
pub(super) enum ResourceQuery<'a> {
    Ordinal(u16),
    Name(&'a [u8]),
}

impl<'a> ResourceQuery<'a> {
    pub(super) fn from_name(name: &'a Win16ResourceName) -> Self {
        match name {
            Win16ResourceName::Id(id) => Self::Ordinal(*id),
            Win16ResourceName::Name(bytes) => match decimal_resource_id(bytes) {
                Some(id) => Self::Ordinal(id),
                None => Self::Name(bytes),
            },
        }
    }

    fn is_name(self) -> bool {
        matches!(self, Self::Name(_))
    }
}

pub(super) fn ordinals_match(stored: u16, requested: u16) -> bool {
    stored & !NE_INTEGER_ID_FLAG == requested & !NE_INTEGER_ID_FLAG
}

pub(super) fn stored_id_matches(
    stored: &NeResourceId,
    requested: ResourceQuery<'_>,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    match requested {
        ResourceQuery::Ordinal(id) => Ok(matches!(stored,
            NeResourceId::Numeric(value) if ordinals_match(*value, id))),
        ResourceQuery::Name(name) => match stored {
            NeResourceId::Numeric(_) => Ok(false),
            NeResourceId::Name(value) => Ok(host.win16_ansi_compare(name, value, true)? == 0),
        },
    }
}

/// Resolve a string name or type through every type-15 resource, in directory
/// order. Both-ordinal queries do not consult the table. The returned words
/// are the record's type and id, including any integer-id flag.
pub(super) fn name_table_ordinals(
    definition: &NeModule,
    image: &[u8],
    resource_type: ResourceQuery<'_>,
    name: ResourceQuery<'_>,
    host: &mut impl RuntimeHost,
) -> Result<Option<(u16, u16)>, RuntimeError> {
    if !resource_type.is_name() && !name.is_name() {
        return Ok(None);
    }
    for entry in &definition.resource_types {
        let NeResourceId::Numeric(type_id) = entry.id else {
            continue;
        };
        if !ordinals_match(type_id, RT_NAME_TABLE) {
            continue;
        }
        for resource in &entry.resources {
            let end = resource
                .file_offset
                .checked_add(resource.byte_length)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 name-table resource extent overflowed",
                    )
                })?;
            let Some(source) = image.get(resource.file_offset..end) else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 name-table resource is outside its module image",
                ));
            };
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(source.len()).map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 name-table resource cannot be copied",
                )
            })?;
            bytes.extend_from_slice(source);
            if let Some(found) = scan_name_table(&bytes, resource_type, name, host)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn scan_name_table(
    bytes: &[u8],
    resource_type: ResourceQuery<'_>,
    name: ResourceQuery<'_>,
    host: &mut impl RuntimeHost,
) -> Result<Option<(u16, u16)>, RuntimeError> {
    let mut offset = 0_usize;
    while let Some(header_end) = offset.checked_add(2) {
        let Some(header) = bytes.get(offset..header_end) else {
            break;
        };
        let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
        if length == 0 || length < NAME_TABLE_HEADER_BYTES {
            break;
        }
        let Some(end) = offset.checked_add(length) else {
            break;
        };
        let Some(record) = bytes.get(offset..end) else {
            break;
        };
        let type_word = u16::from_le_bytes([record[2], record[3]]);
        let id_word = u16::from_le_bytes([record[4], record[5]]);
        if entry_matches(
            type_word,
            id_word,
            &record[NAME_TABLE_HEADER_BYTES..],
            resource_type,
            name,
            host,
        )? {
            return Ok(Some((type_word, id_word)));
        }
        offset = end;
    }
    Ok(None)
}

fn entry_matches(
    type_word: u16,
    id_word: u16,
    strings: &[u8],
    resource_type: ResourceQuery<'_>,
    name: ResourceQuery<'_>,
    host: &mut impl RuntimeHost,
) -> Result<bool, RuntimeError> {
    let type_ok = if type_word & NE_INTEGER_ID_FLAG != 0 {
        let ResourceQuery::Name(requested) = resource_type else {
            return Ok(false);
        };
        let Some(stored) = c_string(strings, 0) else {
            return Ok(false);
        };
        host.win16_ansi_compare(requested, stored, true)? == 0
    } else {
        match resource_type {
            ResourceQuery::Name(_) => false,
            ResourceQuery::Ordinal(id) => ordinals_match(type_word, id),
        }
    };
    if !type_ok {
        return Ok(false);
    }
    if id_word & NE_INTEGER_ID_FLAG != 0 {
        let ResourceQuery::Name(requested) = name else {
            return Ok(false);
        };
        let Some(type_string) = c_string(strings, 0) else {
            return Ok(false);
        };
        let Some(name_at) = type_string.len().checked_add(1) else {
            return Ok(false);
        };
        let Some(stored) = c_string(strings, name_at) else {
            return Ok(false);
        };
        Ok(host.win16_ansi_compare(requested, stored, true)? == 0)
    } else {
        Ok(match name {
            ResourceQuery::Name(_) => false,
            ResourceQuery::Ordinal(id) => ordinals_match(id_word, id),
        })
    }
}

fn c_string(bytes: &[u8], start: usize) -> Option<&[u8]> {
    let rest = bytes.get(start..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    Some(&rest[..end])
}
