//! Pure software scanout for the VGA-compatible graphics modes.
//!
//! Register indices follow the IBM VGA programming interface. CRTC Offset is
//! converted from its two-byte unit, then scaled by the active byte/word/
//! doubleword addressing mode. Standard VGA rendering uses its 256 KiB
//! interleaved plane store; VBE rendering reads packed pixels from the shared
//! four MiB allocation. Out-of-range backing bytes display as zero. CRTC
//! line-compare splits and raster-time display blanking are not modeled here.

use super::{
    VgaDevice, VgaState,
    modes::{ModeInfo, ModeKind, mode_info},
    svga::{self, SvgaState},
};

/// An immutable RGB snapshot of a graphics-mode VGA frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VgaFrame {
    pub width: u16,
    pub height: u16,
    /// Row-major pixels encoded as `0x00RRGGBB`.
    pub pixels: Vec<u32>,
    /// The adapter generation observed while this frame was decoded.
    pub generation: u64,
}

impl VgaDevice {
    /// Decode the current graphics framebuffer into row-major 24-bit RGB.
    ///
    /// Text modes and unknown BIOS modes do not have a graphics snapshot and
    /// return `None`. The shared state is immutably borrowed for the entire
    /// decode so registers, palette, and VRAM belong to one generation.
    pub fn graphics_frame(&self) -> Option<VgaFrame> {
        let state = self.borrow();
        if let Some(svga) = state.svga.as_ref() {
            return render_svga(&state, svga);
        }
        let mode = mode_info(state.bios_mode)?;
        render_with_mode(&state, mode)
    }
}

fn render_svga(state: &VgaState, svga_state: &SvgaState) -> Option<VgaFrame> {
    if !svga_state.is_valid() {
        return None;
    }
    let mode = svga::mode_info(svga_state.mode)?;
    let pixel_count = usize::from(mode.width).checked_mul(usize::from(mode.height))?;
    let bytes_per_scanline = usize::from(svga_state.stride)
        .checked_mul(usize::from(mode.bytes_per_pixel))?;
    let x_offset = usize::from(svga_state.display_x)
        .checked_mul(usize::from(mode.bytes_per_pixel))?;
    let y_offset = usize::from(svga_state.display_y).checked_mul(bytes_per_scanline)?;
    let display_start = y_offset.checked_add(x_offset)?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(pixel_count).ok()?;
    pixels.resize(pixel_count, 0);

    for y in 0..usize::from(mode.height) {
        let row_start = display_start.checked_add(y.checked_mul(bytes_per_scanline)?)?;
        for x in 0..usize::from(mode.width) {
            let pixel_offset = row_start
                .checked_add(x.checked_mul(usize::from(mode.bytes_per_pixel))?)?;
            let pixel = if mode.bytes_per_pixel == 1 {
                state
                    .vram
                    .get(pixel_offset)
                    .copied()
                    .map(|index| dac_rgb(state, index))
                    .unwrap_or(0)
            } else {
                let packed = state
                    .vram
                    .get(pixel_offset..pixel_offset.checked_add(2)?)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
                packed.map(rgb565_to_rgb).unwrap_or(0)
            };
            pixels[y * usize::from(mode.width) + x] = pixel;
        }
    }

    Some(VgaFrame {
        width: mode.width,
        height: mode.height,
        pixels,
        generation: state.generation,
    })
}

fn rgb565_to_rgb(value: u16) -> u32 {
    let red5 = ((value >> 11) & 0x1f) as u8;
    let green6 = ((value >> 5) & 0x3f) as u8;
    let blue5 = (value & 0x1f) as u8;
    let red = (red5 << 3) | (red5 >> 2);
    let green = (green6 << 2) | (green6 >> 4);
    let blue = (blue5 << 3) | (blue5 >> 2);
    (u32::from(red) << 16) | (u32::from(green) << 8) | u32::from(blue)
}

fn render_with_mode(state: &VgaState, mode: ModeInfo) -> Option<VgaFrame> {
    if mode.kind == ModeKind::Text || mode.width == 0 || mode.height == 0 {
        return None;
    }

    let pixel_count = usize::from(mode.width).checked_mul(usize::from(mode.height))?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(pixel_count).ok()?;
    pixels.resize(pixel_count, 0);

    let pixels_per_byte = match mode.kind {
        ModeKind::Planar => 8,
        ModeKind::Chain4 => 1,
        ModeKind::Cga1 => 8,
        ModeKind::Cga2 => 4,
        ModeKind::Text => return None,
    };

    let start_counter = (u16::from(state.crtc[0x0c]) << 8) | u16::from(state.crtc[0x0d]);
    let address_scale = crtc_address_scale(state);
    let row_step = u16::from(state.crtc[0x13]).wrapping_mul(2);
    let pel_pan = match mode.kind {
        // In VGA 256-color mode the least significant PEL-panning bit is
        // ignored; the documented values 0,2,4,6 select shifts 0..3 pixels.
        ModeKind::Chain4 => u16::from((state.attribute[0x13] & 0x0f) >> 1),
        _ => u16::from(state.attribute[0x13] & 0x07),
    };
    let crtc_byte_pan = u16::from((state.crtc[0x08] >> 5) & 0x03)
        .saturating_mul(pixels_per_byte);
    let horizontal_pan = pel_pan.saturating_add(crtc_byte_pan);

    for y in 0..mode.height {
        let row_counter = match mode.kind {
            // CGA scanout stores alternate raster lines in separate 8 KiB
            // banks; each pair advances one packed-memory row.
            ModeKind::Cga1 | ModeKind::Cga2 => {
                start_counter.wrapping_add(row_step.wrapping_mul(y / 2))
            }
            _ => start_counter.wrapping_add(row_step.wrapping_mul(y)),
        };
        let row_base = u32::from(row_counter) * u32::from(address_scale);

        for x in 0..mode.width {
            let source_x = u32::from(x) + u32::from(horizontal_pan);
            let pixel = match mode.kind {
                ModeKind::Planar => {
                    let address = row_base.wrapping_add(source_x / 8) as u16;
                    let bit = 7 - (source_x & 7) as u8;
                    let plane_enable = state.attribute[0x12] & 0x0f;
                    let mut color = 0u8;
                    for plane in 0..4u8 {
                        if plane_enable & (1 << plane) != 0 {
                            color |= ((plane_byte(state, address, plane) >> bit) & 1) << plane;
                        }
                    }
                    dac_rgb(state, attribute_dac_index(state, color))
                }
                ModeKind::Chain4 => {
                    let logical_byte = row_base.wrapping_add(source_x);
                    let input = chain4_byte(state, logical_byte);
                    let dac_index = if state.attribute[0x10] & 0x40 != 0 {
                        input
                    } else {
                        attribute_dac_index(state, input & 0x0f)
                    };
                    dac_rgb(state, dac_index)
                }
                ModeKind::Cga1 => {
                    let line_base = cga_line_base(row_base, y);
                    let byte_offset = source_x / 8;
                    let byte = cga1_byte(state, line_base.wrapping_add(byte_offset));
                    let bit = 7 - (source_x & 7) as u8;
                    dac_rgb(state, attribute_dac_index(state, (byte >> bit) & 1))
                }
                ModeKind::Cga2 => {
                    let line_base = cga_line_base(row_base, y);
                    let byte_offset = source_x / 4;
                    let byte = cga_byte(state, line_base.wrapping_add(byte_offset));
                    let shift = 6 - ((source_x & 3) * 2) as u8;
                    dac_rgb(state, attribute_dac_index(state, (byte >> shift) & 3))
                }
                ModeKind::Text => return None,
            };
            let index = usize::from(y) * usize::from(mode.width) + usize::from(x);
            pixels[index] = pixel;
        }
    }

    Some(VgaFrame {
        width: mode.width,
        height: mode.height,
        pixels,
        generation: state.generation,
    })
}

/// Number of emulated memory bytes selected by one CRTC address count.
fn crtc_address_scale(state: &VgaState) -> u8 {
    if state.crtc[0x14] & 0x40 != 0 {
        4 // Doubleword addressing overrides the byte/word selection.
    } else if state.crtc[0x17] & 0x40 == 0 {
        2 // Word addressing.
    } else {
        1 // Byte addressing.
    }
}

/// Route the four-bit attribute-controller pixel through its internal palette
/// and Color Select register to the eight-bit DAC index.
fn attribute_dac_index(state: &VgaState, pixel: u8) -> u8 {
    let pixel = pixel & (state.attribute[0x12] & 0x0f);
    let palette = state.attribute[usize::from(pixel)] & 0x3f;
    let color_select = state.attribute[0x14] & 0x0f;
    let high_two = (color_select & 0x0c) << 4;
    let palette_high = if state.attribute[0x10] & 0x80 != 0 {
        (color_select & 0x03) << 4
    } else {
        palette & 0x30
    };
    high_two | palette_high | (palette & 0x0f)
}

fn dac_rgb(state: &VgaState, index: u8) -> u32 {
    let [red, green, blue] = state.palette[usize::from(index & state.pel_mask)];
    (u32::from(expand_dac(red)) << 16)
        | (u32::from(expand_dac(green)) << 8)
        | u32::from(expand_dac(blue))
}

const fn expand_dac(component: u8) -> u8 {
    let six_bits = component & 0x3f;
    (six_bits << 2) | (six_bits >> 4)
}

fn plane_byte(state: &VgaState, address: u16, plane: u8) -> u8 {
    let index = usize::from(address) * 4 + usize::from(plane & 3);
    state.vram.get(index).copied().unwrap_or(0)
}

fn chain4_byte(state: &VgaState, logical_byte: u32) -> u8 {
    let logical_byte = logical_byte & 0x3ffff;
    let address = (logical_byte >> 2) as u16;
    let plane = (logical_byte & 3) as u8;
    plane_byte(state, address, plane)
}

/// Two-bit CGA modes use VGA odd/even byte addressing in planes zero and one.
/// The 16 KiB CGA display memory aliases within its 32 KiB aperture.
fn cga_byte(state: &VgaState, aperture_offset: u32) -> u8 {
    let aperture_offset = (aperture_offset & 0x3fff) as usize;
    let address = (aperture_offset >> 1) as u16;
    let plane = (aperture_offset & 1) as u8;
    plane_byte(state, address, plane)
}

/// The one-bit 06h mode disables VGA odd/even addressing, so each packed byte
/// occupies the full address lane in plane zero.
fn cga1_byte(state: &VgaState, aperture_offset: u32) -> u8 {
    plane_byte(state, (aperture_offset & 0xffff) as u16, 0)
}

fn cga_line_base(row_base: u32, y: u16) -> u32 {
    let bank = if y & 1 != 0 { 0x2000 } else { 0 };
    row_base.wrapping_add(bank)
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod frame_tests;
