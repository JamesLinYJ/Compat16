//! Checked lookup for integer identifiers in NE `RT_STRING` resources.
//!
//! A string-table resource contains sixteen byte-length-prefixed strings. Its
//! numeric resource ID is the one-based block number `((string_id >> 4) + 1)`;
//! the low four bits select a string inside that block. This follows the
//! Microsoft Windows 3.1 Programmer's Reference, Volume 4, resource format;
//! `LoadStringA` uses the same block selection. The returned bytes remain in
//! the module's original ANSI encoding; code-page conversion belongs to the
//! Win16 ABI layer.

use crate::ne_load::extract_ne_resource;
use crate::{FormatError, NeModule, NeResourceId};
use std::collections::{BTreeMap, btree_map::Entry};

const RT_STRING: u16 = 6;
const STRINGS_PER_BLOCK: u16 = 16;
const STRINGS_PER_BLOCK_USIZE: usize = STRINGS_PER_BLOCK as usize;
const MAX_STRING_BLOCK_ID: u16 = (u16::MAX / STRINGS_PER_BLOCK) + 1;

/// Raw ANSI string resources indexed by their 16-bit Win16 string IDs.
///
/// The source NE image is needed only while this value is constructed. String
/// slices returned by [`get`](Self::get) borrow this owned table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NeStringTable {
    blocks: BTreeMap<u16, Result<Vec<u8>, FormatError>>,
    unaddressable_errors: Vec<FormatError>,
}

impl NeStringTable {
    /// Extract all numeric `RT_STRING` blocks from an already parsed NE module.
    ///
    /// Resource bytes are copied out of `image`; the image itself is not
    /// retained. A block's range and contents are checked when a string from
    /// that block is requested, so damaged, unused string blocks do not stop
    /// the rest of the NE module from loading. Missing string-table resources
    /// are valid and produce an empty table. Named and out-of-range block IDs
    /// cannot be selected by Win16 `LoadString`; their errors are retained in
    /// [`unaddressable_errors`](Self::unaddressable_errors).
    pub fn from_module(image: &[u8], module: &NeModule) -> Result<Self, FormatError> {
        let mut blocks = BTreeMap::new();
        let mut unaddressable_errors = Vec::new();

        for resource_type in &module.resource_types {
            if resource_type.id != NeResourceId::Numeric(RT_STRING) {
                continue;
            }

            for resource in &resource_type.resources {
                let NeResourceId::Numeric(block_id) = resource.id else {
                    unaddressable_errors
                        .try_reserve(1)
                        .map_err(|_| FormatError::AllocationFailed)?;
                    unaddressable_errors.push(FormatError::InvalidNe(
                        "RT_STRING resource has a named ID and cannot be selected by LoadString",
                    ));
                    continue;
                };
                if block_id == 0 || block_id > MAX_STRING_BLOCK_ID {
                    unaddressable_errors
                        .try_reserve(1)
                        .map_err(|_| FormatError::AllocationFailed)?;
                    unaddressable_errors.push(FormatError::InvalidNe(
                        "RT_STRING block ID is outside the 16-bit string ID range",
                    ));
                    continue;
                }

                match blocks.entry(block_id) {
                    Entry::Vacant(entry) => {
                        // Preserve failures with the first matching block so
                        // only a later lookup of one of its IDs reports the
                        // damaged resource.
                        entry.insert(extract_ne_resource(image, resource));
                    }
                    // FindResource selects the first matching entry in the
                    // resource table. Later duplicate IDs are not consulted.
                    Entry::Occupied(_) => {}
                }
            }
        }

        Ok(Self {
            blocks,
            unaddressable_errors,
        })
    }

    /// Return raw ANSI bytes, absence, or the error in the selected string block.
    pub fn get(&self, id: u16) -> Result<Option<&[u8]>, FormatError> {
        let block_id = (id >> 4) + 1;
        let Some(block) = self.blocks.get(&block_id) else {
            return Ok(None);
        };
        let block = block.as_ref().map_err(|error| error.clone())?;
        get_string_from_block(block, usize::from(id & 0x000f)).map(Some)
    }

    /// Errors for string resources that `LoadString` cannot address by a
    /// 16-bit numeric string ID, such as named resources or invalid block IDs.
    pub fn unaddressable_errors(&self) -> &[FormatError] {
        &self.unaddressable_errors
    }
}

fn get_string_from_block(block: &[u8], requested: usize) -> Result<&[u8], FormatError> {
    let mut offset = 0_usize;
    let mut selected = None;

    for index in 0..STRINGS_PER_BLOCK_USIZE {
        let length = usize::from(*block.get(offset).ok_or(FormatError::InvalidNe(
            "RT_STRING block is truncated before all 16 strings",
        ))?);
        offset = offset
            .checked_add(1)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let end = offset
            .checked_add(length)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let value = block.get(offset..end).ok_or(FormatError::InvalidNe(
            "RT_STRING string length exceeds its resource block",
        ))?;
        if index == requested {
            selected = Some(value);
        }
        offset = end;
    }

    // Trailing bytes are resource-alignment padding. The NE resource length is
    // expressed in shifted alignment units.
    selected.ok_or(FormatError::InvalidNe(
        "RT_STRING block does not contain the requested string slot",
    ))
}
