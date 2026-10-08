//! Packed-pixel VBE modes backed by the VGA adapter's shared VRAM.

use super::{SVGA_BANK_BYTES, VIDEO_MEMORY_BYTES, VgaState};

/// VBE mode numbers advertised by this adapter.
pub(crate) const SUPPORTED_MODES: [u16; 6] = [0x101, 0x103, 0x105, 0x111, 0x114, 0x117];

/// Metadata for a supported VBE mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SvgaMode {
    pub(crate) mode: u16,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) bits_per_pixel: u8,
    pub(crate) bytes_per_pixel: u8,
    pub(crate) default_stride: u16,
    pub(crate) memory_bytes: u32,
}

/// VBE modes implemented by this software adapter.
pub(crate) fn mode_info(mode: u16) -> Option<SvgaMode> {
    let (width, height, bits_per_pixel, bytes_per_pixel) = match mode {
        0x101 => (640, 480, 8, 1),
        0x103 => (800, 600, 8, 1),
        0x105 => (1024, 768, 8, 1),
        0x111 => (640, 480, 16, 2),
        0x114 => (800, 600, 16, 2),
        0x117 => (1024, 768, 16, 2),
        _ => return None,
    };
    Some(SvgaMode {
        mode,
        width,
        height,
        bits_per_pixel,
        bytes_per_pixel,
        default_stride: width,
        memory_bytes: VIDEO_MEMORY_BYTES as u32,
    })
}

/// VBE display state shared by BIOS control, banked memory, and scanout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SvgaState {
    pub(crate) mode: u16,
    /// Scanline stride in pixels, as reported by VBE 4F06.
    pub(crate) stride: u16,
    pub(crate) bank: u16,
    pub(crate) display_x: u16,
    pub(crate) display_y: u16,
    pub(crate) preserve_memory: bool,
}

impl SvgaState {
    /// Validate a complete state before a restore operation commits it.
    pub(crate) fn is_valid(&self) -> bool {
        let Some(mode) = mode_info(self.mode) else {
            return false;
        };
        self.bank < (VIDEO_MEMORY_BYTES / SVGA_BANK_BYTES) as u16
            && display_bounds(mode, self.stride, self.display_x, self.display_y).is_some()
    }
}

impl VgaState {
    /// Enter a supported packed-pixel VBE mode.
    ///
    /// Unsupported modes or incomplete framebuffer storage leave the entire
    /// adapter unchanged. `clear` applies to all four MiB, while false keeps
    /// existing bytes and marks the new mode as preserving memory.
    pub fn set_svga_mode(&mut self, mode: u16, clear: bool) -> bool {
        let Some(info) = mode_info(mode) else {
            return false;
        };
        if self.vram.len() < VIDEO_MEMORY_BYTES {
            return false;
        }

        // Establish the VGA register and DAC state used by the VBE adapter.
        // All fallible validation has happened before this state transition.
        if !self.set_mode(0x13, false) {
            return false;
        }
        if clear {
            self.vram[..VIDEO_MEMORY_BYTES].fill(0);
        }
        self.svga = Some(SvgaState {
            mode,
            stride: info.default_stride,
            bank: 0,
            display_x: 0,
            display_y: 0,
            preserve_memory: !clear,
        });
        // BIOS mode is an 8-bit BDA field. Do not truncate a VBE mode into a
        // misleading legacy mode number; INT 10h 4F03 reads `svga.mode`.
        self.bios_mode = 0xff;
        true
    }

    /// Select one 64 KiB VBE bank for the A0000 aperture.
    pub fn set_svga_bank(&mut self, bank: u16) -> bool {
        if bank as usize >= VIDEO_MEMORY_BYTES / SVGA_BANK_BYTES {
            return false;
        }
        let Some(state) = self.svga.as_mut() else {
            return false;
        };
        let changed = state.bank != bank;
        state.bank = bank;
        if changed {
            self.mark_changed();
        }
        true
    }

    /// Change the packed-pixel scanline stride, specified in pixels.
    ///
    /// Returns `(bytes_per_scanline, pixels_per_scanline, maximum_lines)`.
    /// The operation is rejected atomically if the current display origin no
    /// longer fits the proposed stride.
    pub fn set_svga_stride(&mut self, pixels: u16) -> Option<(u16, u16, u16)> {
        let state = self.svga.as_ref()?;
        if !state.is_valid() {
            return None;
        }
        let mode = mode_info(state.mode)?;
        let bytes = scanline_bytes(mode, pixels)?;
        if display_bounds(mode, pixels, state.display_x, state.display_y).is_none() {
            return None;
        }
        let max_lines = maximum_lines(bytes)?;
        if state.stride != pixels {
            self.svga.as_mut()?.stride = pixels;
            self.mark_changed();
        }
        Some((bytes, pixels, max_lines))
    }

    /// Select a visible display origin within packed framebuffer memory.
    pub fn set_svga_display_start(&mut self, x: u16, y: u16) -> bool {
        let Some(state) = self.svga.as_ref() else {
            return false;
        };
        if !state.is_valid() {
            return false;
        }
        let Some(mode) = mode_info(state.mode) else {
            return false;
        };
        if display_bounds(mode, state.stride, x, y).is_none() {
            return false;
        }
        let Some(state) = self.svga.as_mut() else {
            return false;
        };
        let changed = (state.display_x, state.display_y) != (x, y);
        if changed {
            state.display_x = x;
            state.display_y = y;
        }
        if changed {
            self.mark_changed();
        }
        true
    }
}

pub(crate) fn scanline_bytes(mode: SvgaMode, pixels: u16) -> Option<u16> {
    if pixels < mode.width {
        return None;
    }
    pixels.checked_mul(u16::from(mode.bytes_per_pixel))
}

pub(crate) fn maximum_lines(bytes_per_scanline: u16) -> Option<u16> {
    if bytes_per_scanline == 0 {
        return None;
    }
    u16::try_from(VIDEO_MEMORY_BYTES / usize::from(bytes_per_scanline)).ok()
}

fn display_bounds(mode: SvgaMode, stride: u16, x: u16, y: u16) -> Option<(u16, u16)> {
    let bytes = scanline_bytes(mode, stride)?;
    let max_lines = maximum_lines(bytes)?;
    let right = u32::from(x).checked_add(u32::from(mode.width))?;
    let bottom = u32::from(y).checked_add(u32::from(mode.height))?;
    (right <= u32::from(stride) && bottom <= u32::from(max_lines))
        .then_some((bytes, max_lines))
}
