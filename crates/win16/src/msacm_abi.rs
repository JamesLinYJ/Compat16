//! Explicit little-endian Win16 MSACM records.
//!
//! The Win16 export signatures come from this tree's `specs/msacm.spec`.
//! Microsoft's Windows 3.1 SDK subset here has no ACM-specific records, so
//! fixed ACM record declarations were cross-checked against a read-only
//! external Win16 compatibility header, not Microsoft documentation. Every
//! pointer and handle below remains a 16-bit guest representation; no host
//! record is overlaid on guest RAM.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const WAVEFORMAT16_BYTES: usize = 14;
pub const PCMWAVEFORMAT16_BYTES: usize = 16;
pub const WAVEFORMATEX16_FIXED_BYTES: usize = 18;
pub const WAVEFILTER16_BYTES: usize = 32;
pub const ACMDRIVERDETAILS16_BYTES: usize = 918;
pub const ACMFORMATTAGDETAILS16_BYTES: usize = 72;
pub const ACMFILTERTAGDETAILS16_BYTES: usize = 72;
pub const ACMFORMATDETAILS16_BYTES: usize = 152;
pub const ACMFILTERDETAILS16_BYTES: usize = 152;
pub const ACMFORMATCHOOSE16_BYTES: usize = 228;
pub const ACMFILTERCHOOSE16_BYTES: usize = 228;
pub const ACMSTREAMHEADER16_PREFIX_BYTES: usize = 44;
pub const ACMSTREAMHEADER16_BYTES: usize = 84;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct WaveFormat16Wire {
    pub format_tag: U16,
    pub channels: U16,
    pub samples_per_second: U32,
    pub average_bytes_per_second: U32,
    pub block_align: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct PcmWaveFormat16Wire {
    pub base: WaveFormat16Wire,
    pub bits_per_sample: U16,
}

/// The 18-byte WAVEFORMATEX prefix is followed by exactly `cbSize` owned
/// format-specific bytes; the runtime does not interpret private codec data.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct WaveFormatEx16Wire {
    pub base: PcmWaveFormat16Wire,
    pub extra_bytes: U16,
}

/// Generic Win16 WAVEFILTER header plus its five reserved DWORDs.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct WaveFilter16Wire {
    pub structure_bytes: U32,
    pub filter_tag: U32,
    pub flags: U32,
    pub reserved: [U32; 5],
}

/// `ACMDRIVERDETAILS16`; the icon is a WORD handle, not a native HICON.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct AcmDriverDetails16Wire {
    pub structure_bytes: U32,
    pub type_fourcc: U32,
    pub compression_fourcc: U32,
    pub manufacturer_id: U16,
    pub product_id: U16,
    pub acm_version: U32,
    pub driver_version: U32,
    pub support: U32,
    pub format_tag_count: U32,
    pub filter_tag_count: U32,
    pub icon_handle: U16,
    pub short_name: [u8; 32],
    pub long_name: [u8; 128],
    pub copyright: [u8; 80],
    pub licensing: [u8; 128],
    pub features: [u8; 512],
}

/// Shared fixed prefix shape of ACMFORMATTAGDETAILS16/ACMFILTERTAGDETAILS16.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct AcmTagDetails16Wire {
    pub structure_bytes: U32,
    pub tag_index: U32,
    pub tag: U32,
    pub format_or_filter_bytes: U32,
    pub support: U32,
    pub standard_count: U32,
    pub tag_name: [u8; 48],
}

/// Shared Win16 format/filter detail record. `data_far` is a serialized
/// selector:offset value, never a Rust or native pointer.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct AcmItemDetails16Wire {
    pub structure_bytes: U32,
    pub index: U32,
    pub tag: U32,
    pub support: U32,
    pub data_far: U32,
    pub data_bytes: U32,
    pub name: [u8; 128],
}

/// Win16 choose-dialog wire layout. FAR procedures/resources and HINSTANCE
/// remain four-byte/four-byte/WORD guest values; the host dialog adapter must
/// validate or explicitly reject those optional Win16-only customizations.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct AcmChoose16Wire {
    pub structure_bytes: U32,
    pub style: U32,
    pub owner_window: U16,
    pub data_far: U32,
    pub data_bytes: U32,
    pub title_far: U32,
    pub tag_name: [u8; 48],
    pub item_name: [u8; 128],
    pub saved_name_far: U32,
    pub saved_name_chars: U32,
    pub enum_flags: U32,
    pub enum_data_far: U32,
    pub instance: U16,
    pub template_name_far: U32,
    pub custom_data: U32,
    pub hook_far: U32,
}

/// Complete Win16 ACMSTREAMHEADER layout: an 11-DWORD public prefix and ten
/// DWORDs reserved for Win16 codec state. Modern host `ACMSTREAMHEADER` has
/// pointer-sized fields and an architecture-dependent reserve array and must
/// be built separately by the host adapter.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct AcmStreamHeader16Wire {
    pub structure_bytes: U32,
    pub status: U32,
    pub user: U32,
    pub source_far: U32,
    pub source_bytes: U32,
    pub source_bytes_used: U32,
    pub source_user: U32,
    pub destination_far: U32,
    pub destination_bytes: U32,
    pub destination_bytes_used: U32,
    pub destination_user: U32,
    pub reserved: [U32; 10],
}

const _: () = {
    assert!(core::mem::size_of::<WaveFormat16Wire>() == WAVEFORMAT16_BYTES);
    assert!(core::mem::align_of::<WaveFormat16Wire>() == 1);
    assert!(core::mem::size_of::<PcmWaveFormat16Wire>() == PCMWAVEFORMAT16_BYTES);
    assert!(core::mem::align_of::<PcmWaveFormat16Wire>() == 1);
    assert!(core::mem::size_of::<WaveFormatEx16Wire>() == WAVEFORMATEX16_FIXED_BYTES);
    assert!(core::mem::align_of::<WaveFormatEx16Wire>() == 1);
    assert!(core::mem::size_of::<WaveFilter16Wire>() == WAVEFILTER16_BYTES);
    assert!(core::mem::size_of::<AcmDriverDetails16Wire>() == ACMDRIVERDETAILS16_BYTES);
    assert!(core::mem::size_of::<AcmTagDetails16Wire>() == ACMFORMATTAGDETAILS16_BYTES);
    assert!(core::mem::size_of::<AcmItemDetails16Wire>() == ACMFORMATDETAILS16_BYTES);
    assert!(core::mem::size_of::<AcmChoose16Wire>() == ACMFORMATCHOOSE16_BYTES);
    assert!(core::mem::size_of::<AcmStreamHeader16Wire>() == ACMSTREAMHEADER16_BYTES);
    assert!(core::mem::align_of::<AcmStreamHeader16Wire>() == 1);
};
