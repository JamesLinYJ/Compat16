//! VGA CPU aperture and BIOS pixel access.
//!
//! The register-level decode follows IBM's *VGA/XGA Technical Reference*,
//! Preliminary Draft (May 19, 1992), VGA Function section: memory maps,
//! Chain-4 and odd/even addressing, read modes, and the four write modes.
//! A local legacy graphics reference provides the supported BIOS graphics mode
//! list, but uses a linear framebuffer and does not implement
//! the VGA latch/plane memory controller, so its framebuffer shortcuts are
//! not used here.

use super::modes::{mode_info, ModeInfo, ModeKind};
use super::{SVGA_BANK_BYTES, VGA_VRAM_BYTES, VgaState};

const APERTURE_BYTES: u32 = 0x2_0000;
const MAP_64K_BYTES: u32 = 0x1_0000;
const MAP_32K_BYTES: u32 = 0x8000;
const PLANE_ADDRESS_MASK: u32 = 0xffff;

#[derive(Clone, Copy, Debug)]
struct CpuAddress {
    byte_address: usize,
    read_plane: usize,
    write_planes: u8,
}

impl VgaState {
    /// Read one byte from the 128 KiB A0000-BFFFF CPU aperture.
    ///
    /// `offset` is the guest physical address relative to A0000. Reads from
    /// an address excluded by the selected Graphics Controller memory map
    /// return 0xff and do not disturb the latches. In VBE mode only A0000-AFFFF
    /// is connected; B0000-BFFFF does not fall back to legacy VGA decoding.
    pub(super) fn aperture_read(&mut self, offset: u32) -> u8 {
        if let Some(svga) = self.svga.as_ref() {
            if offset >= SVGA_BANK_BYTES as u32 {
                return 0xff;
            }
            let index = usize::from(svga.bank)
                .checked_mul(SVGA_BANK_BYTES)
                .and_then(|base| base.checked_add(offset as usize));
            return index
                .and_then(|index| self.vram.get(index))
                .copied()
                .unwrap_or(0xff);
        }

        let Some(offset) = mapped_aperture_offset(self.graphics[6], offset) else {
            return 0xff;
        };
        let address = self.decode_cpu_address(offset);
        let Some(latches) = self.read_latches(address.byte_address) else {
            return 0xff;
        };

        if self.graphics[5] & 0x08 != 0 {
            read_mode_1(latches, self.graphics[2], self.graphics[7])
        } else {
            latches[address.read_plane]
        }
    }

    /// Write one byte through VGA's map, plane, latch, and write-mode logic.
    ///
    /// The write changes the adapter generation exactly once if at least one
    /// enabled plane receives a different byte. An ignored or idempotent
    /// write leaves the generation unchanged.
    pub(super) fn aperture_write_byte(&mut self, offset: u32, value: u8) {
        if let Some(svga) = self.svga.as_ref() {
            if offset >= SVGA_BANK_BYTES as u32 {
                return;
            }
            let index = usize::from(svga.bank)
                .checked_mul(SVGA_BANK_BYTES)
                .and_then(|base| base.checked_add(offset as usize));
            let mut changed = false;
            if let Some(destination) = index.and_then(|index| self.vram.get_mut(index)) {
                if *destination != value {
                    *destination = value;
                    changed = true;
                }
            }
            if changed {
                self.mark_changed();
            }
            return;
        }

        let Some(offset) = mapped_aperture_offset(self.graphics[6], offset) else {
            return;
        };
        let address = self.decode_cpu_address(offset);
        let Some(base) = address.byte_address.checked_mul(4) else {
            return;
        };
        if !base.checked_add(3).is_some_and(|last| last < self.vram.len()) {
            return;
        }
        // VGA write modes consume the latches loaded by the most recent CPU
        // read; they are intentionally independent of the write destination.
        let latches = self.latches;

        let mode = self.graphics[5] & 0x03;
        let rotate = u32::from(self.graphics[3] & 0x07);
        let rotated = value.rotate_right(rotate);
        let logic = (self.graphics[3] >> 3) & 0x03;
        let bit_mask = self.graphics[8];
        let set_reset = self.graphics[0];
        let enable_set_reset = self.graphics[1];
        let mut changed = false;

        for plane in 0..4 {
            if address.write_planes & (1 << plane) == 0 {
                continue;
            }

            let latch = latches[plane];
            let output = match mode {
                // Write mode 0: rotate CPU data, optionally substitute the
                // plane's set/reset value, then apply logic and bit masking.
                0 => {
                    let source = if enable_set_reset & (1 << plane) != 0 {
                        if set_reset & (1 << plane) != 0 { 0xff } else { 0x00 }
                    } else {
                        rotated
                    };
                    let operated = apply_logic(source, latch, logic);
                    (operated & bit_mask) | (latch & !bit_mask)
                }
                // Write mode 1 copies the four latches; the other data-path
                // controls do not participate.
                1 => latch,
                // Write mode 2 expands the corresponding CPU-data bit to a
                // whole byte, then uses the ordinary logic/mask path.
                2 => {
                    let source = if value & (1 << plane) != 0 { 0xff } else { 0x00 };
                    let operated = apply_logic(source, latch, logic);
                    (operated & bit_mask) | (latch & !bit_mask)
                }
                // Write mode 3 uses set/reset unconditionally. Rotated CPU
                // data only gates the bit mask.
                _ => {
                    let source = if set_reset & (1 << plane) != 0 { 0xff } else { 0x00 };
                    let operated = apply_logic(source, latch, logic);
                    let effective_mask = rotated & bit_mask;
                    (operated & effective_mask) | (latch & !effective_mask)
                }
            };

            let index = address.byte_address * 4 + plane;
            if let Some(destination) = self.vram.get_mut(index) {
                if *destination != output {
                    *destination = output;
                    changed = true;
                }
            }
        }

        if changed {
            self.mark_changed();
        }
    }

    /// Read a BIOS graphics pixel from a supported standard video mode.
    /// Text and unsupported modes, coordinates outside the active image, and
    /// pages beyond installed VGA memory return `None`.
    pub(crate) fn read_pixel(&self, x: u16, y: u16, page: u8) -> Option<u8> {
        let mode = mode_info(self.bios_mode)?;
        if !pixel_in_bounds(mode, x, y) {
            return None;
        }
        let x = usize::from(x);
        let y = usize::from(y);
        let page_base = pixel_page_base(mode, page, self.vram.len().min(VGA_VRAM_BYTES))?;

        match mode.kind {
            ModeKind::Text => None,
            ModeKind::Planar => {
                let row_bytes = usize::from(mode.width).checked_add(7)? / 8;
                let plane_address = page_base
                    .checked_add(y.checked_mul(row_bytes)?)?
                    .checked_add(x / 8)?;
                if plane_address > PLANE_ADDRESS_MASK as usize {
                    return None;
                }
                let bit = 0x80 >> (x & 7);
                let mut color = 0;
                for plane in 0..planar_plane_count(mode) {
                    let value = *self.vram.get(plane_address * 4 + plane)?;
                    if value & bit != 0 {
                        color |= 1 << plane;
                    }
                }
                Some(color)
            }
            ModeKind::Chain4 => {
                let linear = page_base
                    .checked_add(y.checked_mul(usize::from(mode.width))?)?
                    .checked_add(x)?;
                self.vram.get(linear).copied()
            }
            ModeKind::Cga1 | ModeKind::Cga2 => {
                let pixels_per_byte = if mode.kind == ModeKind::Cga1 { 8 } else { 4 };
                let row_bytes = usize::from(mode.width).checked_add(pixels_per_byte - 1)?
                    / pixels_per_byte;
                let bank_offset = cga_cpu_offset(page_base, y, row_bytes, x / pixels_per_byte)?;
                let index = cga_vram_index(mode.kind, bank_offset)?;
                let packed = *self.vram.get(index)?;
                if mode.kind == ModeKind::Cga1 {
                    Some((packed >> (7 - (x & 7))) & 1)
                } else {
                    Some((packed >> (6 - ((x & 3) * 2))) & 3)
                }
            }
        }
    }

    /// Write a BIOS graphics pixel. AL bit 7 requests XOR drawing in planar
    /// and CGA modes; 256-color Chain-4 pixels always replace the old byte.
    /// Returns false without changing state when the mode, page, or coordinate
    /// is not backed by this adapter's VRAM.
    pub(crate) fn write_pixel(&mut self, x: u16, y: u16, page: u8, color: u8) -> bool {
        let Some(mode) = mode_info(self.bios_mode) else { return false };
        if !pixel_in_bounds(mode, x, y) {
            return false;
        }
        let x = usize::from(x);
        let y = usize::from(y);
        let Some(page_base) = pixel_page_base(
            mode,
            page,
            self.vram.len().min(VGA_VRAM_BYTES),
        ) else {
            return false;
        };
        let mut changed = false;

        match mode.kind {
            ModeKind::Text => return false,
            ModeKind::Planar => {
                let row_bytes = usize::from(mode.width).div_ceil(8);
                let Some(plane_address) = y
                    .checked_mul(row_bytes)
                    .and_then(|offset| page_base.checked_add(offset))
                    .and_then(|offset| offset.checked_add(x / 8)) else { return false };
                if plane_address > PLANE_ADDRESS_MASK as usize {
                    return false;
                }
                let bit = 0x80 >> (x & 7);
                let xor = color & 0x80 != 0;
                let color = color & 0x0f;
                for plane in 0..planar_plane_count(mode) {
                    let Some(destination) = self.vram.get_mut(plane_address * 4 + plane) else {
                        return false;
                    };
                    let old = *destination;
                    let set = color & (1 << plane) != 0;
                    let new = if xor {
                        if set { old ^ bit } else { old }
                    } else if set {
                        old | bit
                    } else {
                        old & !bit
                    };
                    if new != old {
                        *destination = new;
                        changed = true;
                    }
                }
            }
            ModeKind::Chain4 => {
                let Some(linear) = y
                    .checked_mul(usize::from(mode.width))
                    .and_then(|offset| page_base.checked_add(offset))
                    .and_then(|offset| offset.checked_add(x)) else { return false };
                let Some(destination) = self.vram.get_mut(linear) else { return false };
                if *destination != color {
                    *destination = color;
                    changed = true;
                }
            }
            ModeKind::Cga1 | ModeKind::Cga2 => {
                let cga1 = mode.kind == ModeKind::Cga1;
                let pixels_per_byte = if cga1 { 8 } else { 4 };
                let row_bytes = usize::from(mode.width).div_ceil(pixels_per_byte);
                let Some(cpu_offset) = cga_cpu_offset(page_base, y, row_bytes, x / pixels_per_byte) else {
                    return false;
                };
                let Some(index) = cga_vram_index(mode.kind, cpu_offset) else { return false };
                let (shift, pixel_mask) = if cga1 {
                    (7 - (x & 7), 0x01)
                } else {
                    (6 - ((x & 3) * 2), 0x03)
                };
                let mask = pixel_mask << shift;
                let xor = color & 0x80 != 0;
                let color = (color & if cga1 { 0x01 } else { 0x03 }) << shift;
                let Some(destination) = self.vram.get_mut(index) else {
                    return false;
                };
                let old = *destination;
                let new = if xor {
                    old ^ (color & mask)
                } else {
                    (old & !mask) | (color & mask)
                };
                if new != old {
                    *destination = new;
                    changed = true;
                }
            }
        }

        if changed {
            self.mark_changed();
        }
        true
    }

    fn decode_cpu_address(&self, offset: u32) -> CpuAddress {
        let map_mask = self.sequencer[2] & 0x0f;
        if self.sequencer[4] & 0x08 != 0 {
            let plane = (offset & 3) as usize;
            return CpuAddress {
                byte_address: ((offset >> 2) & PLANE_ADDRESS_MASK) as usize,
                read_plane: plane,
                write_planes: map_mask & (1 << plane),
            };
        }

        let odd_even_enabled = self.sequencer[4] & 0x04 == 0;
        let parity = (offset & 1) as usize;
        let write_planes = if odd_even_enabled {
            map_mask & if parity == 0 { 0x05 } else { 0x0a }
        } else {
            map_mask
        };
        let address_replaced = self.graphics[6] & 0x02 != 0;
        let byte_address = (if odd_even_enabled && address_replaced {
            offset >> 1
        } else {
            offset
        }) & PLANE_ADDRESS_MASK;
        let read_plane = if odd_even_enabled && self.graphics[5] & 0x10 != 0 {
            (usize::from(self.graphics[4] & 0x02)) | parity
        } else {
            usize::from(self.graphics[4] & 0x03)
        };

        CpuAddress { byte_address: byte_address as usize, read_plane, write_planes }
    }

    fn read_latches(&mut self, byte_address: usize) -> Option<[u8; 4]> {
        let base = byte_address.checked_mul(4)?;
        if base.checked_add(3)? >= self.vram.len() {
            return None;
        }
        for (plane, latch) in self.latches.iter_mut().enumerate() {
            *latch = self.vram[base + plane];
        }
        Some(self.latches)
    }
}

fn mapped_aperture_offset(graphics_misc: u8, offset: u32) -> Option<u32> {
    if offset >= APERTURE_BYTES {
        return None;
    }
    match (graphics_misc >> 2) & 0x03 {
        0 => Some(offset),
        1 if offset < MAP_64K_BYTES => Some(offset),
        2 if (MAP_64K_BYTES..MAP_64K_BYTES + MAP_32K_BYTES).contains(&offset) => {
            Some(offset - MAP_64K_BYTES)
        }
        3 if (MAP_64K_BYTES + MAP_32K_BYTES..APERTURE_BYTES).contains(&offset) => {
            Some(offset - MAP_64K_BYTES - MAP_32K_BYTES)
        }
        _ => None,
    }
}

fn read_mode_1(latches: [u8; 4], color_compare: u8, color_dont_care: u8) -> u8 {
    let mut result = 0xff;
    for bit in 0..8 {
        let bit_mask = 1 << bit;
        for plane in 0..4 {
            // A zero Don't Care bit removes this plane from the comparison.
            if color_dont_care & (1 << plane) == 0 {
                continue;
            }
            let actual = latches[plane] & bit_mask != 0;
            let expected = color_compare & (1 << plane) != 0;
            if actual != expected {
                result &= !bit_mask;
                break;
            }
        }
    }
    result
}

fn apply_logic(source: u8, latch: u8, operation: u8) -> u8 {
    match operation & 0x03 {
        0 => source,
        1 => source & latch,
        2 => source | latch,
        _ => source ^ latch,
    }
}

fn pixel_in_bounds(mode: ModeInfo, x: u16, y: u16) -> bool {
    mode.width != 0 && mode.height != 0 && x < mode.width && y < mode.height
}

fn pixel_page_base(mode: ModeInfo, page: u8, vram_bytes: usize) -> Option<usize> {
    let stride = usize::try_from(mode.page_bytes).ok()?;
    if stride == 0 {
        return None;
    }
    let capacity = match mode.kind {
        ModeKind::Text => return None,
        ModeKind::Planar => vram_bytes / 4,
        ModeKind::Chain4 => vram_bytes,
        // The CGA-compatible CPU address alternates between planes 0 and 1.
        // Together those maps provide twice one plane's byte-address space.
        ModeKind::Cga1 => vram_bytes / 4,
        ModeKind::Cga2 => (vram_bytes / 4).checked_mul(2)?,
    };
    let base = stride.checked_mul(usize::from(page))?;
    (base.checked_add(stride)? <= capacity).then_some(base)
}

fn planar_plane_count(mode: ModeInfo) -> usize {
    match mode.mode {
        // VGA modes 0Fh and 11h expose a single monochrome bit plane.
        0x0f | 0x11 => 1,
        _ => 4,
    }
}

/// CPU byte offset for a legacy CGA scanline. The 6845 alternates each scan
/// line between the two 8 KiB banks. The mode-specific `cga_vram_index`
/// applies plane-0 sequential layout for mode 06h and odd/even planes for
/// modes 04h/05h.
fn cga_cpu_offset(page_base: usize, y: usize, row_bytes: usize, x_byte: usize) -> Option<usize> {
    let bank = if y & 1 == 0 { 0 } else { 0x2000 };
    page_base
        .checked_add(bank)?
        .checked_add((y / 2).checked_mul(row_bytes)?)?
        .checked_add(x_byte)
}

fn cga_vram_index(kind: ModeKind, cpu_offset: usize) -> Option<usize> {
    let plane_bytes = match kind {
        ModeKind::Cga1 => cpu_offset,
        ModeKind::Cga2 => cpu_offset >> 1,
        _ => return None,
    };
    let plane = if kind == ModeKind::Cga2 { cpu_offset & 1 } else { 0 };
    plane_bytes.checked_mul(4)?.checked_add(plane)
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod memory_tests;
