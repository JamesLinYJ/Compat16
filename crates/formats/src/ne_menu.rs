//! Owned parsing for standard Win16 `RT_MENU` resources.
//!
//! Microsoft documents the modern menu-template header and item fields in
//! [`MENUITEMTEMPLATEHEADER`] and [`MENUITEMTEMPLATE`], and the menu-option
//! meanings/values in [`AppendMenuA`]. Those pages describe `mtString` as
//! `WCHAR`; they do not establish Win16 string encoding. The supported 3.0+
//! Win16 layout uses WORD flags and 8-bit NUL-terminated item labels. This
//! parser stores label bytes unchanged as owned ANSI data. The `MF_POPUP`
//! (`0x0010`), `MF_END` (`0x0080`), and `MF_SEPARATOR` (`0x0800`) values follow
//! the Windows menu flags; `MF_END` terminates a list and is stripped from
//! stored item flags.
//!
//! Callers must select this parser using the NE target version; version-0 bytes
//! alone cannot reliably distinguish every pre-3.0 menu from a 3.0+ template.
//! This parser does not support the pre-3.0 byte-flag layout or version-1
//! extended templates.
//!
//! [`MENUITEMTEMPLATEHEADER`]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplateheader
//! [`MENUITEMTEMPLATE`]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplate
//! [`AppendMenuA`]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-appendmenua
//!
//! The size, nesting, and item-count ceilings below are parser resource limits,
//! not Win16 ABI limits. Text remains in its original ANSI byte encoding and
//! owns no guest or host handles.

use crate::ne_load::extract_ne_resource;
use crate::{FormatError, NeModule, NeResourceId};

const MENU_HEADER_LENGTH: usize = 4;
const MAX_MENU_RESOURCE_BYTES: usize = 1024 * 1024;
const MAX_POPUP_NESTING_DEPTH: usize = 32;
const MAX_TOTAL_MENU_ITEMS: usize = 4096;

const MF_POPUP: u16 = 0x0010;
const MF_END: u16 = 0x0080;
const MF_SEPARATOR: u16 = 0x0800;
const RT_MENU: u16 = 4;

/// An owned menu tree decoded from a version-0 standard Win16 `RT_MENU`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16Menu {
    pub items: Vec<Win16MenuItem>,
}

/// One item in a Win16 menu list. Flags preserve the original option bits
/// except `MF_END`, which marks the end of the containing list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MenuItem {
    /// A submenu item and the menu list opened by it.
    Popup {
        flags: u16,
        text: Vec<u8>,
        menu: Win16Menu,
    },
    /// A command item. Text is raw ANSI bytes without its terminating NUL.
    Item {
        flags: u16,
        id: u16,
        text: Vec<u8>,
    },
    /// A separator identified by `MF_SEPARATOR`. The serialized command ID is
    /// retained although the menu API ignores it. Pre-3.0 empty-label/ID-zero
    /// patterns are not inferred because that layout is unsupported here.
    Separator {
        flags: u16,
        id: u16,
    },
}

/// Owned numeric and named `RT_MENU` resources from an NE module.
///
/// Resource bytes are copied while the table is built, but parsed only when
/// requested. Damaged or unsupported menu resources remain attached to their
/// IDs and do not prevent unrelated resources or menus from being used. An NE
/// module with no `RT_MENU` resources produces an empty table, including when
/// its expected Windows version predates 3.0.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NeMenuResourceTable {
    resources: Vec<StoredMenuResource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredMenuResource {
    id: NeResourceId,
    bytes: Result<Vec<u8>, FormatError>,
}

impl NeMenuResourceTable {
    /// Copy each distinct numeric or named `RT_MENU` resource from `image`.
    ///
    /// Standard menu parsing is selected only when
    /// `module.header.expected_windows_version` is at least `0x0300`. For
    /// older targets, querying a present menu returns an explicit unsupported
    /// format error; construction itself still succeeds so an application that
    /// never uses its menu can continue loading. Resource-range errors are
    /// retained until that resource is requested. Allocation failures while
    /// constructing this table are returned immediately.
    pub fn from_module(image: &[u8], module: &NeModule) -> Result<Self, FormatError> {
        let mut resources = Vec::new();
        let supports_standard_menu = module.header.expected_windows_version >= 0x0300;

        for resource_type in &module.resource_types {
            if resource_type.id != NeResourceId::Numeric(RT_MENU) {
                continue;
            }

            for resource in &resource_type.resources {
                if resources
                    .iter()
                    .any(|stored: &StoredMenuResource| resource_ids_match(&stored.id, &resource.id))
                {
                    continue;
                }

                resources.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
                let id = try_clone_resource_id(&resource.id)?;
                let bytes = if !supports_standard_menu {
                    Err(FormatError::UnsupportedNeFeature(
                        "pre-3.0 RT_MENU byte-flag template",
                    ))
                } else if resource.byte_length > MAX_MENU_RESOURCE_BYTES {
                    Err(FormatError::InvalidNe(
                        "RT_MENU resource exceeds the 1 MiB parser limit",
                    ))
                } else {
                    match extract_ne_resource(image, resource) {
                        Err(FormatError::AllocationFailed) => {
                            return Err(FormatError::AllocationFailed);
                        }
                        result => result,
                    }
                };
                resources.push(StoredMenuResource { id, bytes });
            }
        }

        Ok(Self { resources })
    }

    /// Parse and return an owned menu by numeric resource ID or raw ANSI name.
    ///
    /// Named IDs are matched ASCII case-insensitively, while the stored name
    /// bytes are never decoded or rewritten. When duplicate IDs exist, the
    /// first resource-table entry wins. A damaged, oversized, or unsupported
    /// resource reports its typed error only when selected.
    pub fn get(&self, id: &NeResourceId) -> Result<Option<Win16Menu>, FormatError> {
        let Some(resource) = self
            .resources
            .iter()
            .find(|resource| resource_ids_match(&resource.id, id))
        else {
            return Ok(None);
        };

        let bytes = resource.bytes.as_ref().map_err(|error| error.clone())?;
        parse_win16_menu(bytes).map(Some)
    }
}

fn try_clone_resource_id(id: &NeResourceId) -> Result<NeResourceId, FormatError> {
    match id {
        NeResourceId::Numeric(id) => Ok(NeResourceId::Numeric(*id)),
        NeResourceId::Name(name) => {
            let mut copy = Vec::new();
            copy.try_reserve_exact(name.len())
                .map_err(|_| FormatError::AllocationFailed)?;
            copy.extend_from_slice(name);
            Ok(NeResourceId::Name(copy))
        }
    }
}

pub(super) fn resource_ids_match(left: &NeResourceId, right: &NeResourceId) -> bool {
    match (left, right) {
        (NeResourceId::Numeric(left), NeResourceId::Numeric(right)) => left == right,
        (NeResourceId::Name(left), NeResourceId::Name(right)) => {
            left.eq_ignore_ascii_case(right)
        }
        _ => false,
    }
}

/// Parse a standard Win16 `RT_MENU` resource into an owned menu tree.
///
/// The caller must first select this parser using the NE target version;
/// version-0 bytes alone cannot reliably identify every pre-3.0 menu. This
/// accepts the Windows 3.0+ standard menu-template format only. The second
/// header word is the byte offset from the fixed header's end to the first
/// item; skipped bytes are checked against the input bounds. Nonzero versions
/// are returned as unsupported features rather than being interpreted as this
/// format. Resource inputs larger than 1 MiB, popup nesting deeper than 32
/// levels (root is level 0), or trees containing more than 4096 total items
/// are rejected. All input reads, offset arithmetic, and owned allocations are
/// checked. Parsing stops at the outer list's `MF_END`; any trailing resource
/// bytes are ignored.
pub fn parse_win16_menu(bytes: &[u8]) -> Result<Win16Menu, FormatError> {
    if bytes.len() > MAX_MENU_RESOURCE_BYTES {
        return Err(FormatError::InvalidNe(
            "RT_MENU resource exceeds the 1 MiB parser limit",
        ));
    }

    let mut parser = MenuParser {
        bytes,
        offset: 0,
        total_items: 0,
    };

    let version = parser.read_u16("RT_MENU template version")?;
    let extension_length = usize::from(parser.read_u16("RT_MENU header size")?);
    if version != 0 {
        return Err(FormatError::UnsupportedNeFeature(
            "nonzero RT_MENU template version",
        ));
    }
    let items_offset = MENU_HEADER_LENGTH
        .checked_add(extension_length)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if items_offset > bytes.len() {
        return Err(FormatError::Truncated {
            context: "RT_MENU header extension",
            offset: MENU_HEADER_LENGTH,
            needed: extension_length,
        });
    }
    parser.offset = items_offset;

    parser.parse_menu(0)
}

struct MenuParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    total_items: usize,
}

impl MenuParser<'_> {
    fn parse_menu(&mut self, nesting_depth: usize) -> Result<Win16Menu, FormatError> {
        if nesting_depth > MAX_POPUP_NESTING_DEPTH {
            return Err(FormatError::InvalidNe(
                "RT_MENU popup nesting exceeds the 32-level parser limit",
            ));
        }

        let mut items = Vec::new();
        loop {
            let serialized_flags = self.read_u16("RT_MENU item flags")?;
            let ends_menu = serialized_flags & MF_END != 0;
            let flags = serialized_flags & !MF_END;

            self.total_items = self
                .total_items
                .checked_add(1)
                .ok_or(FormatError::ArithmeticOverflow)?;
            if self.total_items > MAX_TOTAL_MENU_ITEMS {
                return Err(FormatError::InvalidNe(
                    "RT_MENU item count exceeds the 4096-item parser limit",
                ));
            }

            let item = if flags & MF_POPUP != 0 {
                let text = self.read_string("RT_MENU popup label")?;
                let child_depth = nesting_depth
                    .checked_add(1)
                    .ok_or(FormatError::ArithmeticOverflow)?;
                let menu = self.parse_menu(child_depth)?;
                Win16MenuItem::Popup { flags, text, menu }
            } else {
                let id = self.read_u16("RT_MENU command ID")?;
                let text = self.read_string("RT_MENU item label")?;
                if flags & MF_SEPARATOR != 0 {
                    Win16MenuItem::Separator { flags, id }
                } else {
                    Win16MenuItem::Item { flags, id, text }
                }
            };

            items.try_reserve(1).map_err(|_| FormatError::AllocationFailed)?;
            items.push(item);
            if ends_menu {
                return Ok(Win16Menu { items });
            }
        }
    }

    fn read_u16(&mut self, context: &'static str) -> Result<u16, FormatError> {
        let end = self
            .offset
            .checked_add(2)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(FormatError::Truncated {
            context,
            offset: self.offset,
            needed: 2,
        })?;
        let low = *bytes.first().ok_or(FormatError::Truncated {
            context,
            offset: self.offset,
            needed: 2,
        })?;
        let high = *bytes.get(1).ok_or(FormatError::Truncated {
            context,
            offset: self.offset,
            needed: 2,
        })?;
        self.offset = end;
        Ok(u16::from_le_bytes([low, high]))
    }

    fn read_string(&mut self, context: &'static str) -> Result<Vec<u8>, FormatError> {
        let remaining = self.bytes.get(self.offset..).ok_or(FormatError::Truncated {
            context,
            offset: self.offset,
            needed: 1,
        })?;
        let length = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(FormatError::Truncated {
                context,
                offset: self.offset,
                needed: 1,
            })?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let text = self.bytes.get(self.offset..end).ok_or(FormatError::Truncated {
            context,
            offset: self.offset,
            needed: length,
        })?;
        let after_terminator = end.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(text.len())
            .map_err(|_| FormatError::AllocationFailed)?;
        owned.extend_from_slice(text);
        self.offset = after_terminator;
        Ok(owned)
    }
}
