//! Startup-time text evidence found in an NE executable's structured resources.
//!
//! This keeps resource-derived byte samples separate from code and image data.
//! Version resources are returned as checked ranges into the original file so
//! the runtime can query them with the shared Win16 ANSI version codec; this
//! crate must not depend on `compat`.

use crate::{NeModule, NeResourceId, NeStringTable};
use std::ops::Range;

const RT_STRING: u16 = 6;
const RT_FONT: u16 = 8;
const RT_VERSION: u16 = 16;
const STRING_SLOTS_PER_BLOCK: u16 = 16;
const MAX_STRING_BLOCK_ID: u16 = (u16::MAX / STRING_SLOTS_PER_BLOCK) + 1;

const FNT_VERSION_OFFSET: usize = 0;
const FNT_SIZE_OFFSET: usize = 2;
const FNT_CHARSET_OFFSET: usize = 85;
const FNT_FIXED_HEADER_LENGTH: usize = FNT_CHARSET_OFFSET + 1;

/// Owned metadata and ANSI samples gathered only from selected NE resources.
///
/// `version_resource_ranges` are validated byte ranges into the `bytes` slice
/// passed to [`collect_ne_text_profile`]. They preserve every structurally
/// addressable RT_VERSION candidate, including conflicting candidates, for
/// later parsing by the shared Win16 version-information codec.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NeTextProfile {
    pub version_resource_ranges: Vec<Range<usize>>,
    pub font_charsets: Vec<u8>,
    /// Nonempty raw ANSI payloads from parsed RT_STRING slots, without length
    /// prefixes. No code page has been selected or applied to these bytes.
    pub strings: Vec<Vec<u8>>,
}

/// Collect bounded text-encoding evidence from a parsed NE module.
///
/// Missing, malformed, or unaddressable resources contribute no evidence and
/// do not make the executable unusable. `NeModule` is the parsed image type in
/// this crate; all resource offsets are rechecked against `bytes` here.
pub fn collect_ne_text_profile(bytes: &[u8], image: &NeModule) -> NeTextProfile {
    let mut profile = NeTextProfile::default();
    collect_version_ranges(bytes, image, &mut profile);
    collect_font_charsets(bytes, image, &mut profile);
    collect_string_samples(bytes, image, &mut profile);
    profile
}

fn collect_version_ranges(bytes: &[u8], image: &NeModule, profile: &mut NeTextProfile) {
    for resource_type in &image.resource_types {
        if resource_type.id != NeResourceId::Numeric(RT_VERSION) {
            continue;
        }
        for resource in &resource_type.resources {
            let Some(range) =
                checked_resource_range(bytes, resource.file_offset, resource.byte_length)
            else {
                continue;
            };
            if range.is_empty() || profile.version_resource_ranges.try_reserve(1).is_err() {
                continue;
            }
            profile.version_resource_ranges.push(range);
        }
    }
}

fn collect_font_charsets(bytes: &[u8], image: &NeModule, profile: &mut NeTextProfile) {
    for resource_type in &image.resource_types {
        if resource_type.id != NeResourceId::Numeric(RT_FONT) {
            continue;
        }
        for resource in &resource_type.resources {
            let Some(range) =
                checked_resource_range(bytes, resource.file_offset, resource.byte_length)
            else {
                continue;
            };
            let Some(charset) = fnt_charset(bytes.get(range).unwrap_or_default()) else {
                continue;
            };
            if profile.font_charsets.try_reserve(1).is_ok() {
                profile.font_charsets.push(charset);
            }
        }
    }
}

fn collect_string_samples(bytes: &[u8], image: &NeModule, profile: &mut NeTextProfile) {
    let Ok(strings) = NeStringTable::from_module(bytes, image) else {
        return;
    };

    // There are 4096 addressable RT_STRING block IDs. This fixed bitset keeps
    // duplicate resource IDs from weighting the same first-selected block
    // more than once, while all slot contents still come from NeStringTable.
    let mut visited_blocks = [false; MAX_STRING_BLOCK_ID as usize];
    for resource_type in &image.resource_types {
        if resource_type.id != NeResourceId::Numeric(RT_STRING) {
            continue;
        }
        for resource in &resource_type.resources {
            let NeResourceId::Numeric(block_id) = &resource.id else {
                continue;
            };
            if *block_id == 0 || *block_id > MAX_STRING_BLOCK_ID {
                continue;
            }
            let block_index = usize::from(*block_id - 1);
            let Some(visited) = visited_blocks.get_mut(block_index) else {
                continue;
            };
            if *visited {
                continue;
            }
            *visited = true;

            let Some(first_id) = block_index.checked_mul(usize::from(STRING_SLOTS_PER_BLOCK))
            else {
                continue;
            };
            for slot in 0..usize::from(STRING_SLOTS_PER_BLOCK) {
                let Some(id) = first_id
                    .checked_add(slot)
                    .and_then(|id| u16::try_from(id).ok())
                else {
                    continue;
                };
                let Ok(Some(sample)) = strings.get(id) else {
                    continue;
                };
                if !sample.is_empty() && !push_sample(&mut profile.strings, sample) {
                    return;
                }
            }
        }
    }
}

fn push_sample(samples: &mut Vec<Vec<u8>>, sample: &[u8]) -> bool {
    if samples.try_reserve(1).is_err() {
        return false;
    }
    let mut owned = Vec::new();
    if owned.try_reserve_exact(sample.len()).is_err() {
        return false;
    }
    owned.extend_from_slice(sample);
    samples.push(owned);
    true
}

fn checked_resource_range(bytes: &[u8], offset: usize, length: usize) -> Option<Range<usize>> {
    let end = offset.checked_add(length)?;
    bytes.get(offset..end)?;
    Some(offset..end)
}

fn fnt_charset(resource: &[u8]) -> Option<u8> {
    // Windows 3.1 Programmer's Reference, Volume 4, Font File Format defines
    // an RT_FONT component as an FNT FONTINFO record. This guest record is a
    // packed little-endian byte layout, not a host LOGFONT or UTF-16 structure;
    // formats has no FNT codec to reuse, so read only the checked fields needed
    // for evidence instead of casting the bytes to a host structure.
    let header = resource.get(..FNT_FIXED_HEADER_LENGTH)?;
    let version = read_le_u16(header, FNT_VERSION_OFFSET)?;
    if !matches!(version, 0x0200 | 0x0300) {
        return None;
    }
    let declared_size = usize::try_from(read_le_u32(header, FNT_SIZE_OFFSET)?).ok()?;
    if !(FNT_FIXED_HEADER_LENGTH..=resource.len()).contains(&declared_size) {
        return None;
    }
    header.get(FNT_CHARSET_OFFSET).copied()
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([*field.first()?, *field.get(1)?]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *field.first()?,
        *field.get(1)?,
        *field.get(2)?,
        *field.get(3)?,
    ]))
}
