//! Owned lookup for Win16 NE group-icon/cursor and image resources.
//!
//! An `RT_GROUP_ICON` resource contains an icon directory whose entries name
//! separate `RT_ICON` resources. The host USER adapter can pass the directory
//! bytes to `LookupIconIdFromDirectoryEx` to select an entry for the current
//! display, then use [`icon_image`](Self::icon_image) to obtain that entry's
//! image bytes. This module stays independent of host handles and display
//! metrics.

use crate::ne_load::extract_ne_resource;
use crate::{FormatError, NeModule, NeResource, NeResourceId};

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_CURSOR: u16 = 1;
const RT_GROUP_CURSOR: u16 = 12;
const GROUP_IMAGE_HEADER_LENGTH: usize = 6;
const GROUP_IMAGE_ENTRY_LENGTH: usize = 14;
const CURSOR_HOTSPOT_PREFIX_LENGTH: usize = 4;

/// Owns the icon resources needed to bridge Win16 icon lookup to Windows USER.
///
/// The source executable is required only during construction. Resource
/// payloads are copied and no guest or host pointers are retained. When the NE
/// resource table contains duplicate IDs, the first matching resource wins,
/// matching the order used by resource lookup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NeIconResourceTable {
    resources: NeGroupedImageResources,
}

/// Owns the NE resources needed to bridge Win16 cursor lookup to Windows USER.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NeCursorResourceTable {
    resources: NeGroupedImageResources,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NeGroupedImageResources {
    groups: Vec<StoredResource>,
    images: Vec<StoredResource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredResource {
    id: NeResourceId,
    data: Result<Vec<u8>, FormatError>,
}

impl NeIconResourceTable {
    /// Copy numeric and named `RT_GROUP_ICON` resources and numeric `RT_ICON`
    /// resources from an already parsed NE module.
    ///
    /// Invalid resource ranges remain attached to their resource and are
    /// reported only when that resource is requested. This lets an unrelated
    /// damaged icon remain unused without preventing other resources from
    /// being read. Missing icon resource types are valid.
    pub fn from_module(image: &[u8], module: &NeModule) -> Result<Self, FormatError> {
        Ok(Self {
            resources: NeGroupedImageResources::from_module(
                image,
                module,
                RT_GROUP_ICON,
                RT_ICON,
            )?,
        })
    }

    /// Return the checked raw group-directory bytes for a numeric or named
    /// icon resource ID. Named IDs are matched ASCII case-insensitively, as
    /// Win16 NE `FindResource` does; their stored bytes are left unchanged.
    ///
    /// The directory preserves its original entry metadata and icon IDs. A
    /// host USER adapter can use Windows `LookupIconIdFromDirectoryEx` to pick
    /// the image matching the active display metrics.
    pub fn group_icon(&self, id: &NeResourceId) -> Result<Option<Vec<u8>>, FormatError> {
        self.resources.group_directory(id, 1, "RT_GROUP_ICON")
    }

    /// Return owned bytes for the numeric `RT_ICON` resource named by a group
    /// icon directory entry.
    pub fn icon_image(&self, id: u16) -> Result<Option<Vec<u8>>, FormatError> {
        self.resources.image(id, 0, "RT_ICON image")
    }
}

impl NeCursorResourceTable {
    /// Copy numeric and named `RT_GROUP_CURSOR` resources and numeric
    /// `RT_CURSOR` resources from an already parsed NE module.
    pub fn from_module(image: &[u8], module: &NeModule) -> Result<Self, FormatError> {
        Ok(Self {
            resources: NeGroupedImageResources::from_module(
                image,
                module,
                RT_GROUP_CURSOR,
                RT_CURSOR,
            )?,
        })
    }

    /// Return checked raw cursor-group directory bytes for a numeric or named
    /// cursor resource ID. The group directory keeps its hotspot and size
    /// metadata for Windows `LookupIconIdFromDirectoryEx`.
    pub fn group_cursor(&self, id: &NeResourceId) -> Result<Option<Vec<u8>>, FormatError> {
        self.resources.group_directory(id, 2, "RT_GROUP_CURSOR")
    }

    /// Return owned `RT_CURSOR` resource bytes, including the four-byte
    /// little-endian hotspot prefix required by `CreateIconFromResourceEx` for
    /// a cursor (`fIcon = FALSE`).
    pub fn cursor_image(&self, id: u16) -> Result<Option<Vec<u8>>, FormatError> {
        self.resources.image(
            id,
            CURSOR_HOTSPOT_PREFIX_LENGTH,
            "RT_CURSOR hotspot prefix",
        )
    }
}

impl NeGroupedImageResources {
    fn from_module(
        image: &[u8],
        module: &NeModule,
        group_resource_type: u16,
        image_resource_type: u16,
    ) -> Result<Self, FormatError> {
        let mut resources = Self::default();

        for resource_type in &module.resource_types {
            if resource_type.id == NeResourceId::Numeric(group_resource_type) {
                for resource in &resource_type.resources {
                    store_first(image, resource, &mut resources.groups)?;
                }
            } else if resource_type.id == NeResourceId::Numeric(image_resource_type) {
                for resource in &resource_type.resources {
                    if matches!(&resource.id, NeResourceId::Numeric(_)) {
                        store_first(image, resource, &mut resources.images)?;
                    }
                }
            }
        }

        Ok(resources)
    }

    fn group_directory(
        &self,
        id: &NeResourceId,
        expected_kind: u16,
        resource_type_name: &'static str,
    ) -> Result<Option<Vec<u8>>, FormatError> {
        let Some(resource) = find_resource(&self.groups, id) else {
            return Ok(None);
        };
        let bytes = resource.data.as_ref().map_err(|error| error.clone())?;
        validate_group_directory(bytes, expected_kind, resource_type_name)?;
        clone_bytes(bytes).map(Some)
    }

    fn image(
        &self,
        id: u16,
        minimum_length: usize,
        context: &'static str,
    ) -> Result<Option<Vec<u8>>, FormatError> {
        let Some(resource) = self
            .images
            .iter()
            .find(|resource| resource.id == NeResourceId::Numeric(id))
        else {
            return Ok(None);
        };
        let bytes = resource.data.as_ref().map_err(|error| error.clone())?;
        if bytes.len() < minimum_length {
            return Err(FormatError::Truncated {
                context,
                offset: 0,
                needed: minimum_length,
            });
        }
        clone_bytes(bytes).map(Some)
    }
}

fn store_first(
    image: &[u8],
    resource: &NeResource,
    resources: &mut Vec<StoredResource>,
) -> Result<(), FormatError> {
    if resources.iter().any(|stored| stored.id == resource.id) {
        return Ok(());
    }

    resources.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
    resources.push(StoredResource {
        id: resource.id.clone(),
        data: extract_ne_resource(image, resource),
    });
    Ok(())
}

fn find_resource<'a>(resources: &'a [StoredResource], id: &NeResourceId) -> Option<&'a StoredResource> {
    resources
        .iter()
        .find(|resource| resource_ids_match(&resource.id, id))
}

fn resource_ids_match(left: &NeResourceId, right: &NeResourceId) -> bool {
    match (left, right) {
        (NeResourceId::Numeric(left), NeResourceId::Numeric(right)) => left == right,
        (NeResourceId::Name(left), NeResourceId::Name(right)) => {
            left.eq_ignore_ascii_case(right)
        }
        _ => false,
    }
}

fn clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| FormatError::AllocationFailed)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn validate_group_directory(
    bytes: &[u8],
    expected_kind: u16,
    resource_type_name: &'static str,
) -> Result<(), FormatError> {
    let reserved = read_u16(bytes, 0, "group icon/cursor reserved field")?;
    let kind = read_u16(bytes, 2, "group icon/cursor type field")?;
    let count = usize::from(read_u16(bytes, 4, "group icon/cursor entry count")?);

    if reserved != 0 || kind != expected_kind || count == 0 {
        return Err(FormatError::InvalidNe(match resource_type_name {
            "RT_GROUP_ICON" => "RT_GROUP_ICON has an invalid directory header",
            "RT_GROUP_CURSOR" => "RT_GROUP_CURSOR has an invalid directory header",
            _ => "group icon/cursor resource has an invalid directory header",
        }));
    }

    let entries_length = count
        .checked_mul(GROUP_IMAGE_ENTRY_LENGTH)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let required_length = GROUP_IMAGE_HEADER_LENGTH
        .checked_add(entries_length)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if bytes.len() < required_length {
        return Err(FormatError::Truncated {
            context: "group icon/cursor directory entries",
            offset: GROUP_IMAGE_HEADER_LENGTH,
            needed: entries_length,
        });
    }

    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, FormatError> {
    let end = offset
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let value = bytes
        .get(offset..end)
        .ok_or(FormatError::Truncated {
            context,
            offset,
            needed: 2,
        })?;
    let low = *value.first().ok_or(FormatError::Truncated {
        context,
        offset,
        needed: 2,
    })?;
    let high = *value.get(1).ok_or(FormatError::Truncated {
        context,
        offset,
        needed: 2,
    })?;
    Ok(u16::from_le_bytes([low, high]))
}
