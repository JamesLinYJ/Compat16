//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserResourcesRequest {
    LoadBitmap { instance: u16, name: Win16ResourceName },
    CreateIcon {
        instance: u16, width: i16, height: i16, planes: u8, bits_per_pixel: u8,
        and_mask: u32, xor_mask: u32,
    },
    CreateCursor {
        instance: u16, x_hotspot: i16, y_hotspot: i16, width: i16, height: i16,
        and_mask: u32, xor_mask: u32,
    },
    /// Load a string resource into a checked guest buffer. A null output
    /// pointer requests the resource length without copying characters.
    LoadString {
        instance: u16,
        string_id: u16,
        output_buffer: Option<Win16OutputBuffer>,
    },

    /// Load a cursor resource by module instance and either a numeric resource
    /// ID or a copied guest ANSI resource name. Numeric IDs are decoded from
    /// the selector-zero far-pointer slot and are never treated as addresses.
    LoadCursor {
        instance: u16,
        name: Win16ResourceName,
    },

    /// Load an icon by guest module instance and either a numeric resource ID
    /// or a copied guest ANSI resource name. Numeric IDs are decoded from the
    /// selector-zero form of the Win16 far-pointer slot and are never treated
    /// as guest addresses.
    LoadIcon {
        instance: u16,
        name: Win16ResourceName,
    },
}
