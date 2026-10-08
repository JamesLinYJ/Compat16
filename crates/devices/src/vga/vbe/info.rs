//! VBE 1.2 controller and mode information blocks.

use crate::vga::{svga::{self, SvgaMode}, SVGA_BANK_BYTES, VIDEO_MEMORY_BYTES};

pub(super) const CONTROLLER_BLOCK_BYTES: usize = 256;
pub(super) const MODE_INFO_BLOCK_BYTES: usize = 256;

const VBE_VERSION_1_2: u16 = 0x0102;
const OEM_STRING_OFFSET: usize = 64;
const OEM_DESCRIPTION: &[u8] = b"Emulated VGA\0";
const MODE_LIST_OFFSET: usize = 96;
const TOTAL_MEMORY_KIB_BLOCKS: u16 = (VIDEO_MEMORY_BYTES / SVGA_BANK_BYTES) as u16;
const BANK_WINDOW_KIB: u16 = (SVGA_BANK_BYTES / 1024) as u16;
const WINDOW_A_SEGMENT: u16 = 0xa000;

const MODE_ATTR_SUPPORTED: u16 = 1 << 0;
const MODE_ATTR_INFO_AVAILABLE: u16 = 1 << 1;
const MODE_ATTR_COLOR: u16 = 1 << 3;
const MODE_ATTR_GRAPHICS: u16 = 1 << 4;
const MODE_ATTRIBUTES: u16 = MODE_ATTR_SUPPORTED
    | MODE_ATTR_INFO_AVAILABLE
    | MODE_ATTR_COLOR
    | MODE_ATTR_GRAPHICS;

const WINDOW_A_RELOCATABLE: u8 = 1 << 0;
const WINDOW_A_READABLE: u8 = 1 << 1;
const WINDOW_A_WRITABLE: u8 = 1 << 2;
const WINDOW_A_ATTRIBUTES: u8 =
    WINDOW_A_RELOCATABLE | WINDOW_A_READABLE | WINDOW_A_WRITABLE;

const MODE_LIST_TERMINATOR: u16 = 0xffff;

/// Assemble the VBE 1.2 controller block and its referenced data in the
/// caller-provided 256-byte reserved area.
pub(super) fn controller_block(buffer_address: u32) -> Option<[u8; CONTROLLER_BLOCK_BYTES]> {
    let mut block = [0; CONTROLLER_BLOCK_BYTES];
    block[0..4].copy_from_slice(b"VESA");
    put_u16(&mut block, 4, VBE_VERSION_1_2);

    let oem_address = buffer_address.checked_add(OEM_STRING_OFFSET as u32)?;
    let mode_list_address = buffer_address.checked_add(MODE_LIST_OFFSET as u32)?;
    let (oem_segment, oem_offset) = normalized_far_pointer(oem_address)?;
    let (list_segment, list_offset) = normalized_far_pointer(mode_list_address)?;
    put_far_pointer(&mut block, 6, oem_segment, oem_offset);
    put_far_pointer(&mut block, 14, list_segment, list_offset);
    // No optional controller capabilities are claimed by this fixed-DAC,
    // banked-only VBE 1.2 adapter.
    put_u16(&mut block, 18, TOTAL_MEMORY_KIB_BLOCKS);

    block[OEM_STRING_OFFSET..OEM_STRING_OFFSET + OEM_DESCRIPTION.len()]
        .copy_from_slice(OEM_DESCRIPTION);
    for (index, mode) in svga::SUPPORTED_MODES
        .iter()
        .copied()
        .chain([MODE_LIST_TERMINATOR])
        .enumerate()
    {
        let offset = MODE_LIST_OFFSET + index * 2;
        put_u16(&mut block, offset, mode);
    }
    Some(block)
}

/// Build the complete 256-byte mode information block for a supported mode.
pub(super) fn mode_info_block(mode_number: u16) -> Option<[u8; MODE_INFO_BLOCK_BYTES]> {
    let mode = svga::mode_info(mode_number)?;
    Some(build_mode_info(mode))
}

fn build_mode_info(mode: SvgaMode) -> [u8; MODE_INFO_BLOCK_BYTES] {
    let mut block = [0; MODE_INFO_BLOCK_BYTES];
    put_u16(&mut block, 0, MODE_ATTRIBUTES);
    block[2] = WINDOW_A_ATTRIBUTES;
    // Window B and the bank-switch callback are absent.
    put_u16(&mut block, 4, BANK_WINDOW_KIB);
    put_u16(&mut block, 6, BANK_WINDOW_KIB);
    put_u16(&mut block, 8, WINDOW_A_SEGMENT);
    put_u16(&mut block, 16, mode.default_stride * u16::from(mode.bytes_per_pixel));
    put_u16(&mut block, 18, mode.width);
    put_u16(&mut block, 20, mode.height);
    block[22] = 8; // Largest supported BIOS character cell width.
    block[23] = 16; // Largest supported BIOS character cell height.
    block[24] = 1; // Packed/direct color has one plane.
    block[25] = mode.bits_per_pixel;
    block[26] = 1; // One logical framebuffer; CPU access is bank-switched.
    block[27] = if mode.bits_per_pixel == 8 { 4 } else { 6 };
    // BankSize describes the mode's memory organization, not the CPU window
    // size. The single packed/direct framebuffer is not divided into banks.
    block[28] = 0;
    block[29] = image_pages_minus_one(mode);
    block[30] = 1; // VBE-defined value, not part of the reserved tail padding.

    if mode.bits_per_pixel == 16 {
        // VBE direct-color channel masks: RGB565, little-endian packed pixels.
        block[31] = 5;
        block[32] = 11;
        block[33] = 6;
        block[34] = 5;
        block[35] = 5;
        block[36] = 0;
        block[39] = 0; // No reserved-bit channel or programmable color ramp.
    }
    // PhysicalBasePtr remains zero because no linear framebuffer is exposed.
    block
}

fn image_pages_minus_one(mode: SvgaMode) -> u8 {
    let Some(bytes_per_image) = usize::from(mode.default_stride)
        .checked_mul(usize::from(mode.bytes_per_pixel))
        .and_then(|stride| stride.checked_mul(usize::from(mode.height)))
    else {
        return 0;
    };
    if bytes_per_image == 0 {
        return 0;
    }
    (usize::try_from(mode.memory_bytes).unwrap_or(0) / bytes_per_image)
        .saturating_sub(1)
        .min(usize::from(u8::MAX)) as u8
}

fn normalized_far_pointer(address: u32) -> Option<(u16, u16)> {
    if address <= 0x000f_ffff {
        Some(((address >> 4) as u16, (address & 0x0f) as u16))
    } else if address <= 0x0010_ffef {
        Some((u16::MAX, u16::try_from(address - 0x000f_fff0).ok()?))
    } else {
        None
    }
}

fn put_far_pointer(block: &mut [u8], offset: usize, segment: u16, displacement: u16) {
    put_u16(block, offset, displacement);
    put_u16(block, offset + 2, segment);
}

fn put_u16(block: &mut [u8], offset: usize, value: u16) {
    block[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
