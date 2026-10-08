//! Checked Win16 device-independent bitmap (DIB) layout decoding.
//!
//! This module describes guest bytes only. It does not use native Windows
//! structures or pointers. Windows 3.1 SDK Volume 2 documents BITMAPINFOHEADER
//! for GDI DIB calls; the Windows bitmap format also retains the 12-byte
//! BITMAPCOREHEADER form. See the SDK Programmer's Reference Volumes 2 and 4,
//! and Microsoft's BITMAPINFOHEADER, BITMAPCOREHEADER, BITMAPINFO, and packed
//! DIB documentation.

use std::fmt;
use zerocopy::FromBytes;

#[path = "gdi_dib_wire.rs"]
mod wire;

pub const BITMAPCOREHEADER16_SIZE: usize = 12;
pub const BITMAPINFOHEADER16_MIN_SIZE: usize = 40;

pub const DIB_RGB_COLORS16: u16 = 0;
pub const DIB_PAL_COLORS16: u16 = 1;

pub const BI_RGB16: u32 = 0;
pub const BI_RLE8_16: u32 = 1;
pub const BI_RLE4_16: u32 = 2;
pub const BI_BITFIELDS16: u32 = 3;
pub const BI_JPEG16: u32 = 4;
pub const BI_PNG16: u32 = 5;
pub const BI_ALPHABITFIELDS16: u32 = 6;

/// Header fields needed to compute the layout around a guest DIB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DibHeader16 {
    Core {
        size: u32,
        width: u16,
        height: u16,
        planes: u16,
        bits_per_pixel: u16,
    },
    Info {
        size: u32,
        width: i32,
        height: i32,
        planes: u16,
        bits_per_pixel: u16,
        compression: u32,
        image_size: u32,
        colors_used: u32,
    },
}

/// Byte offsets and minimum lengths for a guest DIB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DibLayout16 {
    pub header: DibHeader16,
    /// The complete header length from its `size` field, including extensions.
    pub header_bytes: usize,
    /// Masks appended after a 40-byte header when BI_BITFIELDS is used.
    pub external_mask_bytes: usize,
    pub color_table_offset: usize,
    pub color_table_bytes: usize,
    /// Offset of the first pixel/compressed-image byte in a packed DIB.
    pub bits_offset: usize,
    /// Minimum image-data length derived from the header.
    pub bits_bytes: usize,
    /// Minimum packed-DIB allocation size, including the header, masks, table,
    /// and image bytes. Trailing guest bytes are permitted.
    pub total_bytes: usize,
}

impl DibLayout16 {
    pub const fn info_bytes(self) -> usize {
        self.bits_offset
    }

    /// Returns the DWORD-aligned scan-line size for an uncompressed DIB.
    /// Compressed formats carry an image-size extent instead of a fixed row
    /// stride, so callers should use `bits_bytes` for those formats.
    pub fn row_bytes(self) -> Option<usize> {
        match self.header {
            DibHeader16::Core { width, planes, bits_per_pixel, .. } =>
                uncompressed_row_bytes(i64::from(width), planes, bits_per_pixel).ok(),
            DibHeader16::Info {
                width, planes, bits_per_pixel, compression, ..
            } if matches!(compression, BI_RGB16 | BI_BITFIELDS16 | BI_ALPHABITFIELDS16) =>
                uncompressed_row_bytes(i64::from(width), planes, bits_per_pixel).ok(),
            DibHeader16::Info { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DibLayoutError {
    TruncatedHeader,
    InvalidHeaderSize,
    TruncatedInfo,
    InvalidBitCount,
    InvalidPlanes,
    InvalidColorUsage,
    MissingCompressedImageSize,
    SizeOverflow,
    TruncatedPackedImage,
}

impl fmt::Display for DibLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TruncatedHeader => "Win16 DIB header is truncated",
            Self::InvalidHeaderSize => "Win16 DIB header size is unsupported",
            Self::TruncatedInfo => "Win16 DIB header or color table is truncated",
            Self::InvalidBitCount => "Win16 DIB bit count cannot describe image data",
            Self::InvalidPlanes => "Win16 DIB must describe one color plane",
            Self::InvalidColorUsage => "Win16 DIB color-table format is unsupported",
            Self::MissingCompressedImageSize => {
                "compressed Win16 DIB does not provide a bounded image size"
            }
            Self::SizeOverflow => "Win16 DIB extent overflows the host address space",
            Self::TruncatedPackedImage => "Win16 packed DIB image data is truncated",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DibLayoutError {}

#[derive(Clone, Copy)]
enum DibLayoutMode {
    Input,
    GetDIBitsOutput { query_only: bool },
}

impl DibLayoutMode {
    const fn is_output(self) -> bool {
        matches!(self, Self::GetDIBitsOutput { .. })
    }

    const fn is_query_only(self) -> bool {
        matches!(self, Self::GetDIBitsOutput { query_only: true })
    }
}

/// Parses header fields and computes the minimum information and pixel-data
/// extents. `header_prefix` need only contain the fixed 12- or 40-byte header;
/// callers then use `info_bytes()` to read the full variable-sized header and
/// color table from guest memory.
pub fn info_layout(
    header_prefix: &[u8],
    color_usage: u16,
) -> Result<DibLayout16, DibLayoutError> {
    layout_with_mode(header_prefix, color_usage, DibLayoutMode::Input)
}

fn layout_with_mode(
    header_prefix: &[u8],
    color_usage: u16,
    mode: DibLayoutMode,
) -> Result<DibLayout16, DibLayoutError> {
    // Native GDI accepts RGB entries or WORD palette indices. The extent
    // calculation must use the same representation that the host API sees:
    // https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getdibits
    if !matches!(color_usage, DIB_RGB_COLORS16 | DIB_PAL_COLORS16) {
        return Err(DibLayoutError::InvalidColorUsage);
    }
    // Header size is the shared discriminator and extension length. Read this
    // scalar first, then decode the selected fixed prefix as one wire value.
    let header_size = read_u32(header_prefix, wire::HEADER_SIZE_OFFSET)
        .ok_or(DibLayoutError::TruncatedHeader)?;
    if header_size == BITMAPCOREHEADER16_SIZE as u32 {
        if header_prefix.len() < BITMAPCOREHEADER16_SIZE {
            return Err(DibLayoutError::TruncatedHeader);
        }
        // The checked prefix reader decodes exactly the fixed header and
        // leaves following color-table or pixel bytes outside the wire value.
        let core = wire::BitmapCoreHeader12Wire::read_from_prefix(header_prefix)
            .map(|(header, _)| header)
            .map_err(|_| DibLayoutError::TruncatedHeader)?;
        let header_size = core.size.get();
        let width = core.width.get();
        let height = core.height.get();
        let planes = core.planes.get();
        let bits_per_pixel = core.bits_per_pixel.get();
        validate_planes(planes)?;
        let colors = if mode.is_output() && matches!(bits_per_pixel, 1..=8) {
            1_u64
                .checked_shl(u32::from(bits_per_pixel))
                .ok_or(DibLayoutError::SizeOverflow)?
        } else if !mode.is_output() && bits_per_pixel <= 8 {
            1_u64.checked_shl(u32::from(bits_per_pixel)).ok_or(DibLayoutError::SizeOverflow)?
        } else {
            0
        };
        let table_entry_bytes = if color_usage == DIB_PAL_COLORS16 { 2 } else { 3 };
        let color_table_bytes = checked_mul(colors, table_entry_bytes)?;
        let bits_offset = checked_add(BITMAPCOREHEADER16_SIZE, color_table_bytes)?;
        let bits_bytes = if mode.is_query_only() {
            0
        } else {
            uncompressed_image_bytes(
                i64::from(width),
                i64::from(height),
                planes,
                bits_per_pixel,
            )?
        };
        let total_bytes = checked_add(bits_offset, bits_bytes)?;
        return Ok(DibLayout16 {
            header: DibHeader16::Core {
                size: header_size,
                width,
                height,
                planes,
                bits_per_pixel,
            },
            header_bytes: BITMAPCOREHEADER16_SIZE,
            external_mask_bytes: 0,
            color_table_offset: BITMAPCOREHEADER16_SIZE,
            color_table_bytes,
            bits_offset,
            bits_bytes,
            total_bytes,
        });
    }

    if header_size < BITMAPINFOHEADER16_MIN_SIZE as u32 {
        return Err(DibLayoutError::InvalidHeaderSize);
    }
    if header_prefix.len() < BITMAPINFOHEADER16_MIN_SIZE {
        return Err(DibLayoutError::TruncatedHeader);
    }
    // Extended INFO headers keep their declared length separate from this
    // fixed 40-byte prefix; read_from_prefix deliberately ignores the tail.
    let info = wire::BitmapInfoHeader40Wire::read_from_prefix(header_prefix)
        .map(|(header, _)| header)
        .map_err(|_| DibLayoutError::TruncatedHeader)?;
    let header_size = info.size.get();
    let width = info.width.get();
    let height = info.height.get();
    let planes = info.planes.get();
    let bits_per_pixel = info.bits_per_pixel.get();
    let compression = info.compression.get();
    let image_size = info.image_size.get();
    let colors_used = info.colors_used.get();
    validate_planes(planes)?;

    if bits_per_pixel == 0
        && !matches!(compression, BI_JPEG16 | BI_PNG16)
    {
        return Err(DibLayoutError::InvalidBitCount);
    }
    let header_bytes = usize::try_from(header_size).map_err(|_| DibLayoutError::SizeOverflow)?;
    let mask_bytes: usize = match compression {
        BI_BITFIELDS16 => 12,
        BI_ALPHABITFIELDS16 => 16,
        _ => 0,
    };
    // V2/V3-style headers place RGB masks in their extension. A 52-byte
    // header therefore contains the three RGB masks, while alpha bitfields
    // still need the fourth mask immediately after it.
    let embedded_mask_bytes: usize = match compression {
        BI_BITFIELDS16 if header_bytes >= 52 => 12,
        BI_ALPHABITFIELDS16 if header_bytes >= 56 => 16,
        BI_ALPHABITFIELDS16 if header_bytes >= 52 => 12,
        _ => 0,
    };
    let external_mask_bytes = mask_bytes.saturating_sub(embedded_mask_bytes);
    let mask_start = checked_add(header_bytes, external_mask_bytes)?;
    let color_table_offset = mask_start;

    let color_count = if mode.is_output() && matches!(bits_per_pixel, 1..=8) {
        // GetDIBits fills a full palette; biClrUsed cannot limit output.
        1_u64
            .checked_shl(u32::from(bits_per_pixel))
            .ok_or(DibLayoutError::SizeOverflow)?
    } else if mode.is_output() {
        0
    } else if matches!(compression, BI_JPEG16 | BI_PNG16) {
        0
    } else if colors_used != 0 {
        u64::from(colors_used)
    } else if bits_per_pixel <= 8
        && matches!(compression, BI_RGB16 | BI_RLE8_16 | BI_RLE4_16)
    {
        1_u64.checked_shl(u32::from(bits_per_pixel)).ok_or(DibLayoutError::SizeOverflow)?
    } else {
        0
    };
    let color_entry_bytes = if color_usage == DIB_PAL_COLORS16 { 2 } else { 4 };
    let color_table_bytes = checked_mul(color_count, color_entry_bytes)?;
    let bits_offset = checked_add(color_table_offset, color_table_bytes)?;
    let bits_bytes = if mode.is_query_only() {
        0
    } else if matches!(compression, BI_RGB16 | BI_BITFIELDS16 | BI_ALPHABITFIELDS16) {
        let minimum = uncompressed_image_bytes(width.into(), height.into(), planes, bits_per_pixel)?;
        minimum.max(usize::try_from(image_size).map_err(|_| DibLayoutError::SizeOverflow)?)
    } else if image_size != 0 {
        usize::try_from(image_size).map_err(|_| DibLayoutError::SizeOverflow)?
    } else {
        return Err(DibLayoutError::MissingCompressedImageSize);
    };
    let total_bytes = checked_add(bits_offset, bits_bytes)?;

    Ok(DibLayout16 {
        header: DibHeader16::Info {
            size: header_size,
            width,
            height,
            planes,
            bits_per_pixel,
            compression,
            image_size,
            colors_used,
        },
        header_bytes,
        external_mask_bytes,
        color_table_offset,
        color_table_bytes,
        bits_offset,
        bits_bytes,
        total_bytes,
    })
}

/// Computes the minimum buffer layout for a `GetDIBits` output request.
///
/// For an INFO header with a nonzero bit count up to 8, output storage reserves
/// a complete palette of `2^biBitCount` entries regardless of `biClrUsed`.
/// Entries use WORD palette indices for `DIB_PAL_COLORS` and RGBQUAD-sized
/// values for `DIB_RGB_COLORS`. CORE layouts reserve their full palette too.
/// With `query_only`, the result includes only the header, external masks, and
/// palette (`bits_bytes` is zero), and does not require a compressed image size.
/// This describes output capacity only and does not rewrite the guest header.
///
/// Microsoft Knowledge Base article Q81498 states that `biClrUsed` cannot limit
/// `GetDIBits` output and GDI fills a full-size table; its 8-bpp case therefore
/// requires all 256 entries:
/// <https://jeffpar.github.io/kbarchive/kb/081/Q81498/>
/// The current API reference also documents synthesized color tables:
/// <https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getdibits>
pub fn get_dibits_output_layout(
    header_prefix: &[u8],
    color_usage: u16,
    query_only: bool,
) -> Result<DibLayout16, DibLayoutError> {
    layout_with_mode(
        header_prefix,
        color_usage,
        DibLayoutMode::GetDIBitsOutput { query_only },
    )
}

/// Converts a Win16 `CreateDIBitmap` CORE creation header to the 40-byte
/// `BITMAPINFOHEADER` form used at the native host boundary.
///
/// The Windows 3.0 SDK documents that `CreateDIBitmap` accepts a
/// `BITMAPCOREHEADER` in its independent creation-header argument when the
/// separate initialization-info argument uses `BITMAPCOREINFO`. The host
/// adapter needs an INFO-format header for its native declaration, so this
/// conversion retains the CORE dimensions and color depth while leaving that
/// separate initialization header and its table untouched. It reads only the
/// fixed 12-byte creation header; it does not consume color-table or pixel data.
/// <https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/>
pub fn core_to_info_header(
    header: &[u8],
) -> Result<[u8; BITMAPINFOHEADER16_MIN_SIZE], DibLayoutError> {
    let core = wire::BitmapCoreHeader12Wire::read_from_prefix(header)
        .map(|(header, _)| header)
        .map_err(|_| DibLayoutError::TruncatedHeader)?;
    if core.size.get() != BITMAPCOREHEADER16_SIZE as u32 {
        return Err(DibLayoutError::InvalidHeaderSize);
    }

    // This adapter preserves the Win16 CORE dimensions and format but emits a
    // fresh INFO value, with no native struct cast or attached variable tail.
    use zerocopy::byteorder::little_endian::{I32, U16, U32};

    let info = wire::BitmapInfoHeader40Wire {
        size: U32::new(BITMAPINFOHEADER16_MIN_SIZE as u32),
        width: I32::new(i32::from(core.width.get())),
        height: I32::new(i32::from(core.height.get())),
        planes: U16::new(core.planes.get()),
        bits_per_pixel: U16::new(core.bits_per_pixel.get()),
        compression: U32::new(BI_RGB16),
        image_size: U32::new(0),
        _x_pels_per_meter: I32::new(0),
        _y_pels_per_meter: I32::new(0),
        colors_used: U32::new(0),
        _colors_important: U32::new(0),
    };
    Ok(zerocopy::transmute!(info))
}

/// Computes and validates the required extent of a packed DIB. Extra trailing
/// bytes are allowed because global allocations can include caller-owned data.
pub fn packed_dib_layout(
    packed: &[u8],
    color_usage: u16,
) -> Result<DibLayout16, DibLayoutError> {
    let layout = info_layout(packed, color_usage)?;
    if packed.len() < layout.bits_offset {
        return Err(DibLayoutError::TruncatedInfo);
    }
    if packed.len() < layout.total_bytes {
        return Err(DibLayoutError::TruncatedPackedImage);
    }
    Ok(layout)
}

/// Checks a separately supplied BITMAPINFO header/table buffer while leaving
/// image bytes in their independent guest pointer argument.
pub fn validate_info_bytes(
    info: &[u8],
    layout: DibLayout16,
) -> Result<(), DibLayoutError> {
    if info.len() < layout.info_bytes() {
        return Err(DibLayoutError::TruncatedInfo);
    }
    Ok(())
}

fn uncompressed_image_bytes(
    width: i64,
    height: i64,
    planes: u16,
    bits_per_pixel: u16,
) -> Result<usize, DibLayoutError> {
    if bits_per_pixel == 0 {
        return Err(DibLayoutError::InvalidBitCount);
    }
    let width = width.unsigned_abs();
    let height = height.unsigned_abs();
    validate_planes(planes)?;
    let planes = u64::from(planes);
    let stride_bytes = uncompressed_row_bytes_u64(width, planes, bits_per_pixel)?;
    let total = stride_bytes.checked_mul(height).ok_or(DibLayoutError::SizeOverflow)?;
    usize::try_from(total).map_err(|_| DibLayoutError::SizeOverflow)
}

fn uncompressed_row_bytes(
    width: i64,
    planes: u16,
    bits_per_pixel: u16,
) -> Result<usize, DibLayoutError> {
    let width = width.unsigned_abs();
    validate_planes(planes)?;
    let planes = u64::from(planes);
    usize::try_from(uncompressed_row_bytes_u64(width, planes, bits_per_pixel)?)
        .map_err(|_| DibLayoutError::SizeOverflow)
}

fn uncompressed_row_bytes_u64(
    width: u64,
    planes: u64,
    bits_per_pixel: u16,
) -> Result<u64, DibLayoutError> {
    if bits_per_pixel == 0 {
        return Err(DibLayoutError::InvalidBitCount);
    }
    let row_bits = width
        .checked_mul(planes)
        .and_then(|value| value.checked_mul(u64::from(bits_per_pixel)))
        .ok_or(DibLayoutError::SizeOverflow)?;
    row_bits
        .checked_add(31)
        .ok_or(DibLayoutError::SizeOverflow)?
        .checked_div(32)
        .and_then(|value| value.checked_mul(4))
        .ok_or(DibLayoutError::SizeOverflow)
}

fn checked_mul(left: u64, right: usize) -> Result<usize, DibLayoutError> {
    let right = u64::try_from(right).map_err(|_| DibLayoutError::SizeOverflow)?;
    let value = left.checked_mul(right).ok_or(DibLayoutError::SizeOverflow)?;
    usize::try_from(value).map_err(|_| DibLayoutError::SizeOverflow)
}

fn validate_planes(planes: u16) -> Result<(), DibLayoutError> {
    // Both Windows DIB headers require one plane; silently replacing zero
    // changes the buffer calculation without changing the native header.
    // https://learn.microsoft.com/windows/win32/api/wingdi/ns-wingdi-bitmapcoreheader
    // https://learn.microsoft.com/windows/win32/api/wingdi/ns-wingdi-bitmapinfoheader
    if planes == 1 { Ok(()) } else { Err(DibLayoutError::InvalidPlanes) }
}

fn checked_add(left: usize, right: usize) -> Result<usize, DibLayoutError> {
    left.checked_add(right).ok_or(DibLayoutError::SizeOverflow)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}
