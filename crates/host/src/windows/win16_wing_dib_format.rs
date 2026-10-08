//! Host-side validation for the DIB formats used to create WinG DIB sections.

const BITMAPINFOHEADER_BYTES: usize = 40;
const BI_RGB: u32 = 0;
const BI_BITFIELDS: u32 = 3;

#[derive(Clone, Copy)]
pub(super) struct WinGDibFormat {
    pub width: i32,
    pub height: i32,
    pub bit_count: u16,
    pub compression: u32,
    pub row_bytes: u32,
    pub image_extent: u32,
}

/// Recheck the guest-provided BITMAPINFO independently at the native boundary.
/// The runtime's DIB parser determines a safe copy extent, while this parser
/// validates the Win32 CreateDIBSection formats and section size it will use.
pub(super) fn validate_win_g_dib(
    info: &[u8],
    image_extent: u32,
) -> Option<WinGDibFormat> {
    if info.len() < BITMAPINFOHEADER_BYTES { return None; }
    let header_bytes = usize::try_from(read_u32(info, 0)?).ok()?;
    if header_bytes < BITMAPINFOHEADER_BYTES || header_bytes > info.len() {
        return None;
    }
    let width = read_i32(info, 4)?;
    let height = read_i32(info, 8)?;
    let planes = read_u16(info, 12)?;
    let bit_count = read_u16(info, 14)?;
    let compression = read_u32(info, 16)?;
    let image_size = read_u32(info, 20)?;
    let colors_used = read_u32(info, 32)?;
    // Negative heights are accepted because the selected Win32 DIB-section
    // backend can represent top-down storage. The local WinG references do
    // not establish this as a historical WinG guarantee; it is a host-side
    // compatibility approximation, and the original signed height is kept.
    if width <= 0 || height == 0 || height == i32::MIN || planes != 1
        || !matches!(bit_count, 1 | 4 | 8 | 16 | 24 | 32)
        || !matches!(compression, BI_RGB | BI_BITFIELDS)
    {
        return None;
    }
    if compression == BI_BITFIELDS && !matches!(bit_count, 16 | 32) {
        return None;
    }

    let external_masks = if compression == BI_BITFIELDS && header_bytes < 52 { 12_usize } else { 0 };
    let colors = if colors_used != 0 {
        u64::from(colors_used)
    } else if compression == BI_RGB && bit_count <= 8 {
        1_u64.checked_shl(u32::from(bit_count))?
    } else {
        0
    };
    let info_end = header_bytes
        .checked_add(external_masks)?
        .checked_add(usize::try_from(colors.checked_mul(4)?).ok()?)?;
    if info_end > info.len() { return None; }

    let row_bits = u64::try_from(width).ok()?.checked_mul(u64::from(bit_count))?;
    let row_bytes = row_bits.checked_add(31)?.checked_div(32)?.checked_mul(4)?;
    let height_abs = u64::from(height.unsigned_abs());
    let minimum_image_extent = row_bytes.checked_mul(height_abs)?;
    if minimum_image_extent == 0 || minimum_image_extent > u64::from(u32::MAX) {
        return None;
    }
    if image_size != 0 && u64::from(image_size) < minimum_image_extent {
        return None;
    }
    if image_extent < minimum_image_extent as u32 || image_extent == 0 {
        return None;
    }

    Some(WinGDibFormat {
        width,
        height,
        bit_count,
        compression,
        row_bytes: u32::try_from(row_bytes).ok()?,
        image_extent,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}
