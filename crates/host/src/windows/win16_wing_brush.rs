//! Native WinG halftone brushes built from a real device palette and DIB tile.

use std::mem::size_of;

use super::win16_gdi_bitmap_transfer::AlignedBytes;
use super::win16_gdi_objects::Win16Objects;
use super::win16_wing_dib_header::{BITMAPINFOHEADER_SIZE, BitmapInfoHeaderWire};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16DitherPattern, Win16HostGdiObject};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, CLR_INVALID, CreateDIBPatternBrushPt, CreateHalftonePalette, DIB_RGB_COLORS,
    GetCurrentObject, GetDeviceCaps, GetNearestColor, GetNearestPaletteIndex, GetObjectW,
    GetPaletteEntries, HDC, HPALETTE, OBJ_PAL, PALETTEENTRY, PC_EXPLICIT, RASTERCAPS, RC_PALETTE,
};

const MAX_HALFTONE_PALETTE_ENTRIES: usize = 256;
const MAX_PATTERN_DIB_BYTES: usize =
    BITMAPINFOHEADER_SIZE + MAX_HALFTONE_PALETTE_ENTRIES * 4 + 8 * 8;
// GetObject reports logical-palette entry count as a WORD, bounding the
// temporary entry snapshot to at most 65,535 PALETTEENTRY records.
const MAX_LOGICAL_PALETTE_ENTRIES: usize = u16::MAX as usize;
// Windows 3.1 SDK MMSYSTEM.H: DIBINDEX(n) = MAKELONG(n, 0x10FF).
const DIB_INDEX_TAG: u32 = 0x10ff_0000;

/// Bayer's recursive rank construction uses the 2x2 seed [[0, 2], [3, 1]];
/// each expansion multiplies old ranks by four and adds the seed quadrant.
/// The same recurrence derives both sizes, so their orientation is consistent.
/// CreateDIBPatternBrushPt consumes a prepared tile rather than selecting a
/// WinG dither pattern; these ranks supply that part of the guest contract.
const DISPERSED_4X4: [u8; 16] = bayer_4x4();
const DISPERSED_8X8: [u8; 64] = bayer_8x8();

const fn bayer_4x4() -> [u8; 16] {
    const SEED: [u8; 4] = [0, 2, 3, 1];
    let mut ranks = [0_u8; 16];
    let mut row = 0;
    while row < 4 {
        let mut column = 0;
        while column < 4 {
            let source = (row % 2) * 2 + (column % 2);
            let quadrant = (row / 2) * 2 + (column / 2);
            ranks[row * 4 + column] = 4 * SEED[source] + SEED[quadrant];
            column += 1;
        }
        row += 1;
    }
    ranks
}

const fn bayer_8x8() -> [u8; 64] {
    const SEED: [u8; 4] = [0, 2, 3, 1];
    let previous = bayer_4x4();
    let mut ranks = [0_u8; 64];
    let mut row = 0;
    while row < 8 {
        let mut column = 0;
        while column < 8 {
            let source = (row % 4) * 4 + (column % 4);
            let quadrant = (row / 4) * 2 + (column / 4);
            ranks[row * 8 + column] = 4 * previous[source] + SEED[quadrant];
            column += 1;
        }
        row += 1;
    }
    ranks
}

/// Center-out 4x4 clustered-dot ranks: the central 2x2 square appears first,
/// 4-neighbor bands grow it next, and tile corners enter last. This standard
/// ordered-screen construction is deterministic but not WinG bit-exact.
const CLUSTERED_4X4: [u8; 16] = [12, 4, 5, 13, 6, 0, 1, 7, 8, 2, 3, 9, 14, 10, 11, 15];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rgb {
    red: u8,
    green: u8,
    blue: u8,
}

impl Rgb {
    fn from_colorref(color: u32) -> Self {
        Self {
            red: color as u8,
            green: (color >> 8) as u8,
            blue: (color >> 16) as u8,
        }
    }

    fn from_palette_entry(entry: PALETTEENTRY) -> Self {
        Self {
            red: entry.peRed,
            green: entry.peGreen,
            blue: entry.peBlue,
        }
    }

    fn channels(self) -> [i32; 3] {
        [
            i32::from(self.red),
            i32::from(self.green),
            i32::from(self.blue),
        ]
    }
}

struct OwnedPalette(HPALETTE);

impl Drop for OwnedPalette {
    fn drop(&mut self) {
        // SAFETY: This guard owns the palette returned by CreateHalftonePalette.
        crate::windows::win32_safe::delete_object(self.0.cast());
    }
}

/// Creates a pattern brush from the target DC's native Win32 halftone palette.
/// The generated tile is a packed, owned 8-bpp DIB; no guest or transient host
/// pointer is retained by the brush object.
pub(super) fn create(
    objects: &mut Win16Objects,
    dc: HDC,
    color: u32,
    pattern: Win16DitherPattern,
) -> Result<Option<Win16HostGdiObject>, RuntimeError> {
    let Some(color) = resolve_colorref(dc, color)? else {
        return Ok(None);
    };

    // SAFETY: `dc` is leased by the caller for this entire synchronous call.
    let palette = unsafe { CreateHalftonePalette(dc) };
    if palette.is_null() {
        return Ok(None);
    }
    let palette = OwnedPalette(palette);
    // DIB indices below address this exact generated palette snapshot. The
    // COLORREF palette markers were resolved against `dc`'s selected palette.
    let Some(colors) = palette_colors(palette.0)? else {
        return Ok(None);
    };
    if colors.is_empty() {
        return Ok(None);
    }

    let (low, high, high_weight) = closest_palette_mix(color, &colors);
    let (matrix, side) = threshold_matrix(pattern);
    let Some(packed_dib) = make_pattern_dib(&colors, low, high, high_weight, matrix, side)? else {
        return Ok(None);
    };

    // SAFETY: `packed_dib` is DWORD-aligned and contains a complete BI_RGB
    // BITMAPINFO plus color table and pixel tile. GDI consumes it synchronously.
    let brush = unsafe { CreateDIBPatternBrushPt(packed_dib.as_ptr(), DIB_RGB_COLORS) };
    if brush.is_null() {
        return Ok(None);
    }
    objects.adopt_owned(brush.cast())
}

fn resolve_colorref(dc: HDC, color: u32) -> Result<Option<Rgb>, RuntimeError> {
    if color & 0xffff_0000 == DIB_INDEX_TAG {
        // DIBINDEX is a documented COLORREF extension, also for 16-bpp DIBs
        // without a color table. Delegate resolution and device quantization
        // to GDI rather than interpreting the index as RGB or bit masks here.
        // SAFETY: The caller retains this HDC; the color is a scalar specifier.
        let resolved = unsafe { GetNearestColor(dc, color) };
        return Ok((resolved != CLR_INVALID).then(|| Rgb::from_colorref(resolved)));
    }
    match color >> 24 {
        0 => Ok(Some(Rgb::from_colorref(color))),
        1 => {
            // PALETTEINDEX encodes a WORD index in the low 16 bits; the
            // intervening byte is reserved by the COLORREF encoding.
            if color & 0x00ff_0000 != 0 {
                return Ok(None);
            }
            Ok(selected_palette_color(dc, color as u16 as u32))
        }
        2 => {
            let rgb = Rgb::from_colorref(color);
            // PALETTERGB maps through the selected logical palette on a
            // palette device; on other devices GDI treats it as ordinary RGB.
            // SAFETY: The caller holds the retained HDC lease.
            let raster_caps = unsafe { GetDeviceCaps(dc, RASTERCAPS as i32) };
            if raster_caps >= 0 && raster_caps as u32 & RC_PALETTE != 0 {
                nearest_selected_palette_color(dc, color & 0x00ff_ffff)
            } else {
                Ok(Some(rgb))
            }
        }
        // Includes CLR_INVALID and encodings not handled above. Do not silently
        // reinterpret them as RGB bytes.
        _ => Ok(None),
    }
}

fn selected_palette(dc: HDC) -> Option<HPALETTE> {
    // SAFETY: The caller holds the retained HDC lease.
    let object = unsafe { GetCurrentObject(dc, OBJ_PAL as u32) };
    if object.is_null() {
        return None;
    }
    // SAFETY: `object` is returned by GetCurrentObject for OBJ_PAL; the type
    // check rejects a stale or unexpected native object before palette calls.
    if (crate::windows::win32_safe::get_object_type(object)) != OBJ_PAL as u32 {
        return None;
    }
    Some(object.cast())
}

fn selected_palette_color(dc: HDC, index: u32) -> Option<Rgb> {
    let palette = selected_palette(dc)?;
    palette_color(palette, index)
}

fn nearest_selected_palette_color(dc: HDC, color: u32) -> Result<Option<Rgb>, RuntimeError> {
    let Some(palette) = selected_palette(dc) else {
        return Ok(None);
    };
    let Some(entries) = palette_entries(palette, MAX_LOGICAL_PALETTE_ENTRIES)? else {
        return Ok(None);
    };
    // GDI documents the nearest-index result as undefined if any entry is
    // PC_EXPLICIT. Fail cleanly instead of treating pixel values as RGB.
    if entries
        .iter()
        .any(|entry| u32::from(entry.peFlags) & PC_EXPLICIT != 0)
    {
        return Ok(None);
    }
    // SAFETY: The palette was returned from this leased DC and type-checked;
    // its full entry table has no PC_EXPLICIT entries.
    let index = unsafe { GetNearestPaletteIndex(palette, color) };
    if index == u32::MAX {
        return Ok(None);
    }
    let Some(entry) = usize::try_from(index)
        .ok()
        .and_then(|index| entries.get(index))
    else {
        return Ok(None);
    };
    Ok(Some(Rgb::from_palette_entry(*entry)))
}

fn palette_color(palette: HPALETTE, index: u32) -> Option<Rgb> {
    let mut entry = PALETTEENTRY::default();
    // SAFETY: `entry` is writable for one palette row and `palette` is either
    // the owned halftone palette or a type-checked currently selected palette.
    let copied = unsafe { GetPaletteEntries(palette, index, 1, &mut entry) };
    if copied != 1 || u32::from(entry.peFlags) & PC_EXPLICIT != 0 {
        return None;
    }
    Some(Rgb::from_palette_entry(entry))
}

fn palette_colors(palette: HPALETTE) -> Result<Option<Vec<Rgb>>, RuntimeError> {
    let Some(entries) = palette_entries(palette, MAX_HALFTONE_PALETTE_ENTRIES)? else {
        return Ok(None);
    };
    let mut colors = Vec::new();
    colors.try_reserve_exact(entries.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate WinG halftone RGB colors",
            error,
        )
    })?;
    colors.extend(entries.into_iter().filter_map(|entry| {
        (u32::from(entry.peFlags) & PC_EXPLICIT == 0).then(|| Rgb::from_palette_entry(entry))
    }));
    Ok(Some(colors))
}

fn palette_entries(
    palette: HPALETTE,
    max_entries: usize,
) -> Result<Option<Vec<PALETTEENTRY>>, RuntimeError> {
    // GetObject requires a DWORD-aligned output pointer even though its HPALETTE
    // result is only a WORD. Read into the low half of this aligned native slot.
    let mut count_storage = 0_u32;
    // SAFETY: The u32 output slot is DWORD-aligned and GetObject writes only
    // the documented two-byte palette entry count for an HPALETTE.
    let copied = unsafe {
        GetObjectW(
            palette.cast(),
            size_of::<u16>() as i32,
            (&mut count_storage as *mut u32).cast(),
        )
    };
    // Supported Windows host targets are little-endian AMD64/ARM64, so these
    // two bytes are the low WORD written by GDI.
    let count = usize::from(count_storage as u16);
    if copied != size_of::<u16>() as i32 || count == 0 || count > max_entries {
        return Ok(None);
    }

    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate WinG logical palette entries",
            error,
        )
    })?;
    entries.resize(count, PALETTEENTRY::default());
    // SAFETY: The owned vector contains `count` writable entries and the
    // palette handle remains owned until brush creation finishes.
    if unsafe { GetPaletteEntries(palette, 0, count as u32, entries.as_mut_ptr()) } != count as u32
    {
        return Ok(None);
    }
    Ok(Some(entries))
}

/// Finds the closest two-color palette blend using projected, clamped RGB
/// interpolation and squared 8-bit RGB error. The resulting weight is then
/// quantized to the chosen threshold matrix's finite set of coverage levels.
fn closest_palette_mix(target: Rgb, colors: &[Rgb]) -> (usize, usize, u8) {
    let target_channels = target.channels();
    let mut best = (0_usize, 0_usize, 0_u8, i64::MAX);

    for (low_index, low) in colors.iter().copied().enumerate() {
        let low_error = color_distance_squared(target, low);
        if low_error < best.3 {
            best = (low_index, low_index, 0, low_error);
        }

        for (high_index, high) in colors.iter().copied().enumerate().skip(low_index + 1) {
            let low_channels = low.channels();
            let high_channels = high.channels();
            let direction = [
                high_channels[0] - low_channels[0],
                high_channels[1] - low_channels[1],
                high_channels[2] - low_channels[2],
            ];
            let offset = [
                target_channels[0] - low_channels[0],
                target_channels[1] - low_channels[1],
                target_channels[2] - low_channels[2],
            ];
            let denominator = direction
                .iter()
                .map(|value| i64::from(*value * *value))
                .sum::<i64>();
            if denominator == 0 {
                continue;
            }
            let numerator = direction
                .iter()
                .zip(offset)
                .map(|(direction, offset)| i64::from(*direction * offset))
                .sum::<i64>();
            let weight = projected_weight(numerator, denominator);
            let error = color_distance_squared(target, interpolate(low, high, weight));
            if error < best.3 {
                best = (low_index, high_index, weight, error);
            }
        }
    }
    (best.0, best.1, best.2)
}

fn projected_weight(numerator: i64, denominator: i64) -> u8 {
    if numerator <= 0 {
        return 0;
    }
    if numerator >= denominator {
        return u8::MAX;
    }
    ((numerator * 255 + denominator / 2) / denominator) as u8
}

fn interpolate(low: Rgb, high: Rgb, weight: u8) -> Rgb {
    let blend = |left: u8, right: u8| {
        let weight = u32::from(weight);
        ((u32::from(left) * (255 - weight) + u32::from(right) * weight + 127) / 255) as u8
    };
    Rgb {
        red: blend(low.red, high.red),
        green: blend(low.green, high.green),
        blue: blend(low.blue, high.blue),
    }
}

fn color_distance_squared(left: Rgb, right: Rgb) -> i64 {
    let left = left.channels();
    let right = right.channels();
    left.iter()
        .zip(right)
        .map(|(left, right)| i64::from(*left - right).pow(2))
        .sum()
}

fn threshold_matrix(pattern: Win16DitherPattern) -> (&'static [u8], usize) {
    match pattern {
        Win16DitherPattern::Dispersed4x4 => (&DISPERSED_4X4, 4),
        Win16DitherPattern::Dispersed8x8 => (&DISPERSED_8X8, 8),
        Win16DitherPattern::Clustered4x4 => (&CLUSTERED_4X4, 4),
    }
}

fn make_pattern_dib(
    colors: &[Rgb],
    low_index: usize,
    high_index: usize,
    high_weight: u8,
    matrix: &[u8],
    side: usize,
) -> Result<Option<AlignedBytes>, RuntimeError> {
    let cell_count = side.checked_mul(side).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "WinG dither tile size overflowed")
    })?;
    let row_bytes = side;
    let stride = row_bytes
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "WinG dither stride overflowed")
        })?;
    let pixel_bytes = stride.checked_mul(side).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "WinG dither pixel size overflowed")
    })?;
    let color_table_bytes = colors.len().checked_mul(4).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "WinG DIB palette size overflowed")
    })?;
    let total_bytes = BITMAPINFOHEADER_SIZE
        .checked_add(color_table_bytes)
        .and_then(|size| size.checked_add(pixel_bytes))
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "WinG packed DIB size overflowed")
        })?;
    if colors.is_empty()
        || low_index >= colors.len()
        || high_index >= colors.len()
        || matrix.len() != cell_count
        || colors.len() > MAX_HALFTONE_PALETTE_ENTRIES
        || !matches!(side, 4 | 8)
        || total_bytes > MAX_PATTERN_DIB_BYTES
    {
        return Ok(None);
    }

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total_bytes).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "allocate WinG packed DIB", error)
    })?;
    let width = i32::try_from(side).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinG DIB width exceeds native header",
            error,
        )
    })?;
    let height = width.checked_neg().ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "WinG top-down DIB height overflowed",
        )
    })?;
    let image_size = u32::try_from(pixel_bytes).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinG DIB pixel size exceeds native header",
            error,
        )
    })?;
    let colors_used = u32::try_from(colors.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "WinG palette size exceeds native header",
            error,
        )
    })?;
    let header = BitmapInfoHeaderWire::new(
        BITMAPINFOHEADER_SIZE as u32,
        width,
        // A negative DIB height preserves threshold rows in top-down order.
        height,
        1,
        8,
        BI_RGB,
        image_size,
        0,
        0,
        colors_used,
        0,
    );
    let header_bytes = header.into_bytes();
    bytes.extend_from_slice(&header_bytes);

    for color in colors {
        bytes.extend_from_slice(&[color.blue, color.green, color.red, 0]);
    }

    let high_count = usize::from(high_weight)
        .checked_mul(cell_count)
        .and_then(|weight| weight.checked_add(127))
        .map(|weight| weight / 255)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "WinG dither coverage count overflowed",
            )
        })?;
    for row in 0..side {
        for column in 0..side {
            let rank = usize::from(matrix[row * side + column]);
            let index = if rank < high_count {
                high_index
            } else {
                low_index
            };
            bytes.push(index as u8);
        }
        let row_end = bytes.len().checked_add(stride - row_bytes).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "WinG DIB row end overflowed")
        })?;
        if row_end > total_bytes {
            return Ok(None);
        }
        bytes.resize(row_end, 0);
    }

    if bytes.len() != total_bytes {
        return Ok(None);
    }

    if bytes.len() % 4 != 0 {
        return Ok(None);
    }
    Ok(Some(AlignedBytes::copy_from(&bytes)?))
}
