//! INT 10h services backed by the emulated VGA registers and video memory.
//!
//! The BIOS-visible tables here follow IBM's *PS/2 and PC BIOS Interface
//! Technical Reference* (April 1987), INT 10h, especially AH=10h and AH=1Bh
//! (pp. 2-20–2-22 and 2-39–2-43). Values are derived from the modeled adapter;
//! unimplemented optional services are left unsupported.

use super::{modes::{self, ModeInfo, ModeKind}, VgaDevice};
use crate::{bios::BDA_BASE, DeviceError};
use guest_core::{GuestMemory, PhysAddr, Registers, real_address};

pub const FUNCTIONALITY_SEGMENT: u16 = 0xf000;
pub const FUNCTIONALITY_OFFSET: u16 = 0x3000;
pub const FONT_8X16_SEGMENT: u16 = 0xf000;
pub const FONT_8X16_OFFSET: u16 = 0x6000;

const FUNCTIONALITY_BYTES: usize = 16;
const STATE_BYTES: usize = 64;
const COLOR_REGISTER_MASK: u8 = 0x3f;
const ACTIVE_DISPLAY_CODE_VGA_COLOR: u8 = 0x08;
const ATTRIBUTE_MODE_CONTROL: usize = 0x10;
const ATTRIBUTE_OVERSCAN: usize = 0x11;

/// Return the static 16-byte AH=1Bh capability bitmap for the current VGA
/// implementation. Mode bits are set only for modes present in `mode_info`.
pub fn functionality_table() -> [u8; FUNCTIONALITY_BYTES] {
    let mut table = [0; FUNCTIONALITY_BYTES];

    for mode in 0_u8..=0x13 {
        if modes::mode_info(mode).is_some() {
            table[usize::from(mode / 8)] |= 1 << (mode % 8);
        }
    }

    // Text-mode scan lines available: 200, 350, and 400 respectively.
    for mode in 0_u8..=0x13 {
        let Some(info) = modes::mode_info(mode) else { continue };
        if !matches!(info.kind, ModeKind::Text) {
            continue;
        }
        match u16::from(info.rows) * u16::from(info.char_height) {
            200 => table[0x07] |= 1 << 0,
            350 => table[0x07] |= 1 << 1,
            400 => table[0x07] |= 1 << 2,
            _ => {}
        }
    }

    // AH=10h palette and DAC operations plus intensity/blink selection are
    // modeled. The persistent summing feature is intentionally not advertised:
    // AH=12h/BL=33h and summing during palette/mode loads are not implemented.
    table[0x0a] = (1 << 6) | (1 << 5);
    table[0x0b] = (1 << 3) | (1 << 2);
    table
}

/// Handle the VGA-specific INT 10h services implemented by this adapter.
/// Returns `false` for other BIOS functions so the caller can route them.
pub fn dispatch(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<bool, DeviceError> {
    match regs.ah() {
        0x4f => super::vbe::dispatch(vga, regs, memory),
        0x10 => {
            dispatch_palette(vga, regs, memory)?;
            Ok(true)
        }
        0x12 if regs.bl() == 0x10 => {
            dispatch_vga_memory_info(vga, regs);
            Ok(true)
        }
        0x11 if regs.al() == 0x30 => {
            dispatch_font_info(vga, regs, memory)?;
            Ok(true)
        }
        0x1a => {
            dispatch_display_combination(vga, regs);
            Ok(true)
        }
        0x1b => {
            dispatch_functionality_state(vga, regs, memory)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// 8x16 glyphs for the INT 10h AH=11h AL=30h font pointer. The shapes are a
/// plain box for printable ASCII so a program can probe the table; they are
/// not a copy of a vendor font.
pub fn font_8x16() -> Vec<u8> {
    let mut font = vec![0u8; 256 * 16];
    for glyph in 0x20..0x7f {
        let base = glyph * 16;
        font[base] = 0xff;
        font[base + 15] = 0xff;
        for row in 1..15 {
            font[base + row] = 0x81;
        }
    }
    font
}

fn dispatch_font_info(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &impl GuestMemory,
) -> Result<(), DeviceError> {
    let rows = modes::mode_info(vga.borrow().bios_mode)
        .map(|info| u8::try_from(info.rows.saturating_sub(1)).unwrap_or(u8::MAX))
        .unwrap_or(24);
    match regs.bh() {
        0x00 => read_font_vector(memory, 0x1f, regs, 8)?,
        0x01 => read_font_vector(memory, 0x43, regs, 8)?,
        _ => {
            regs.es = FONT_8X16_SEGMENT;
            regs.set_bp(FONT_8X16_OFFSET);
            regs.set_cx(16);
        }
    }
    regs.set_dl(rows);
    Ok(())
}

fn read_font_vector(
    memory: &impl GuestMemory,
    vector: u8,
    regs: &mut Registers,
    bytes_per_character: u16,
) -> Result<(), DeviceError> {
    let mut entry = [0u8; 4];
    memory.read(PhysAddr(u32::from(vector) * 4), &mut entry)?;
    regs.set_bp(u16::from_le_bytes([entry[0], entry[1]]));
    regs.es = u16::from_le_bytes([entry[2], entry[3]]);
    regs.set_cx(bytes_per_character);
    Ok(())
}

fn dispatch_palette(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    match regs.al() {
        0x00 => {
            let index = usize::from(regs.bl());
            if index < 16 {
                let value = regs.bh() & COLOR_REGISTER_MASK;
                let mut state = vga.borrow_mut();
                if state.attribute[index] != value {
                    state.attribute[index] = value;
                    state.mark_changed();
                }
            }
        }
        0x01 => set_attribute_register(vga, ATTRIBUTE_OVERSCAN, regs.bh() & COLOR_REGISTER_MASK),
        0x02 => {
            let mut bytes = read_guest_buffer(memory, regs.es, regs.dx(), 17)?;
            for byte in &mut bytes {
                *byte &= COLOR_REGISTER_MASK;
            }
            let mut state = vga.borrow_mut();
            let changed = state.attribute[..16] != bytes[..16]
                || state.attribute[ATTRIBUTE_OVERSCAN] != bytes[16];
            if changed {
                state.attribute[..16].copy_from_slice(&bytes[..16]);
                state.attribute[ATTRIBUTE_OVERSCAN] = bytes[16];
                state.mark_changed();
            }
        }
        0x03 => match regs.bl() {
            0 => set_attribute_bit(vga, ATTRIBUTE_MODE_CONTROL, 0x08, false),
            1 => set_attribute_bit(vga, ATTRIBUTE_MODE_CONTROL, 0x08, true),
            _ => {}
        },
        0x07 => {
            let index = usize::from(regs.bl());
            if index < 16 {
                regs.set_bh(vga.borrow().attribute[index] & COLOR_REGISTER_MASK);
            }
        }
        0x08 => regs.set_bh(vga.borrow().attribute[ATTRIBUTE_OVERSCAN] & COLOR_REGISTER_MASK),
        0x09 => {
            let state = vga.borrow();
            let mut values = state.attribute[..16]
                .iter()
                .map(|value| value & COLOR_REGISTER_MASK)
                .collect::<Vec<_>>();
            values.push(state.attribute[ATTRIBUTE_OVERSCAN] & COLOR_REGISTER_MASK);
            drop(state);
            write_guest_buffer(memory, regs.es, regs.dx(), &values)?;
        }
        0x10 => {
            let index = regs.bx();
            if index <= u16::from(u8::MAX) {
                set_dac_register(
                    vga,
                    index as u8,
                    [regs.dh(), regs.ch(), regs.cl()],
                );
            }
        }
        0x12 => {
            let first = regs.bx();
            if first > u16::from(u8::MAX) {
                return Ok(());
            }
            let count = usize::from(regs.cx());
            let length = checked_buffer_length(count, 3, 0x12)?;
            let bytes = read_guest_buffer(memory, regs.es, regs.dx(), length)?;
            if count != 0 {
                let mut state = vga.borrow_mut();
                let mut changed = false;
                for (index, triple) in bytes.chunks_exact(3).enumerate() {
                    let slot = usize::from((first as u8).wrapping_add(index as u8));
                    let value = [triple[0] & COLOR_REGISTER_MASK,
                                 triple[1] & COLOR_REGISTER_MASK,
                                 triple[2] & COLOR_REGISTER_MASK];
                    if state.palette[slot] != value {
                        state.palette[slot] = value;
                        changed = true;
                    }
                }
                if changed { state.mark_changed(); }
            }
        }
        0x13 => {
            // The state model has no BIOS color-page selector. Returning no
            // fabricated page state is preferable to aliasing this to an
            // unrelated VGA attribute register.
        }
        0x15 => {
            let index = regs.bx();
            if index <= u16::from(u8::MAX) {
                let color = vga.borrow().palette[usize::from(index as u8)];
                regs.set_dh(color[0] & COLOR_REGISTER_MASK);
                regs.set_ch(color[1] & COLOR_REGISTER_MASK);
                regs.set_cl(color[2] & COLOR_REGISTER_MASK);
            }
        }
        0x17 => {
            let first = regs.bx();
            if first > u16::from(u8::MAX) {
                return Ok(());
            }
            let count = usize::from(regs.cx());
            let length = checked_buffer_length(count, 3, 0x17)?;
            let state = vga.borrow();
            let mut bytes = Vec::with_capacity(length);
            for index in 0..count {
                let color = state.palette[usize::from((first as u8).wrapping_add(index as u8))];
                bytes.extend(color.map(|component| component & COLOR_REGISTER_MASK));
            }
            drop(state);
            write_guest_buffer(memory, regs.es, regs.dx(), &bytes)?;
        }
        0x18 => {
            let mut state = vga.borrow_mut();
            if state.pel_mask != regs.bl() {
                state.pel_mask = regs.bl();
                state.mark_changed();
            }
        }
        0x19 => regs.set_bl(vga.borrow().pel_mask),
        0x1a => {
            // No palette-page selector is represented in the emulated BIOS
            // state, so preserve the caller's registers as the BIOS does for
            // unsupported optional functions.
        }
        0x1b => {
            if regs.bx() <= u16::from(u8::MAX) {
                grayscale_palette(vga, regs.bx() as u8, regs.cx());
            }
        }
        // IBM reserves several values and specifies no action for other
        // systems/subfunctions. Preserve their registers and device state.
        _ => {}
    }
    Ok(())
}

fn set_attribute_register(vga: &VgaDevice, index: usize, value: u8) {
    let mut state = vga.borrow_mut();
    if state.attribute[index] != value {
        state.attribute[index] = value;
        state.mark_changed();
    }
}

fn set_attribute_bit(vga: &VgaDevice, index: usize, mask: u8, enabled: bool) {
    let mut state = vga.borrow_mut();
    let old = state.attribute[index];
    let new = if enabled { old | mask } else { old & !mask };
    if old != new {
        state.attribute[index] = new;
        state.mark_changed();
    }
}

fn set_dac_register(vga: &VgaDevice, index: u8, color: [u8; 3]) {
    let value = color.map(|component| component & COLOR_REGISTER_MASK);
    let mut state = vga.borrow_mut();
    let slot = &mut state.palette[usize::from(index)];
    if *slot != value {
        *slot = value;
        state.mark_changed();
    }
}

fn grayscale_palette(vga: &VgaDevice, first: u8, count: u16) {
    if count == 0 { return; }
    let mut state = vga.borrow_mut();
    let mut changed = false;
    for displacement in 0..count {
        let index = usize::from(first.wrapping_add(displacement as u8));
        let [red, green, blue] = state.palette[index];
        // IBM specifies a weighted sum of 30% red, 59% green, and 11% blue.
        // Integer division keeps the six-bit DAC result within its range.
        let gray = ((30 * u16::from(red) + 59 * u16::from(green)
            + 11 * u16::from(blue)) / 100) as u8;
        let value = [gray; 3];
        if state.palette[index] != value {
            state.palette[index] = value;
            changed = true;
        }
    }
    if changed { state.mark_changed(); }
}

fn checked_buffer_length(count: usize, record_size: usize, function: u16) -> Result<usize, DeviceError> {
    count.checked_mul(record_size).ok_or(DeviceError::InvalidRequest {
        interrupt: 0x10,
        function,
        detail: "video palette buffer length overflow",
    })
}

fn read_guest_buffer(
    memory: &impl GuestMemory,
    segment: u16,
    offset: u16,
    length: usize,
) -> Result<Vec<u8>, DeviceError> {
    if length == 0 { return Ok(Vec::new()); }
    let chunks = far_buffer_chunks(segment, offset, length);
    for (address, _, chunk_length) in &chunks {
        memory.validate_read(*address, *chunk_length)?;
    }
    let mut bytes = vec![0; length];
    for (address, output_offset, chunk_length) in chunks {
        memory.read(address, &mut bytes[output_offset..output_offset + chunk_length])?;
    }
    Ok(bytes)
}

fn write_guest_buffer(
    memory: &mut impl GuestMemory,
    segment: u16,
    offset: u16,
    bytes: &[u8],
) -> Result<(), DeviceError> {
    if bytes.is_empty() { return Ok(()); }
    let chunks = far_buffer_chunks(segment, offset, bytes.len());
    for (address, _, chunk_length) in &chunks {
        memory.validate_write(*address, *chunk_length)?;
    }
    for (address, input_offset, chunk_length) in chunks {
        memory.write(address, &bytes[input_offset..input_offset + chunk_length])?;
    }
    Ok(())
}

fn far_buffer_chunks(segment: u16, offset: u16, length: usize) -> Vec<(PhysAddr, usize, usize)> {
    let mut chunks = Vec::new();
    let mut current_offset = offset;
    let mut data_offset = 0;
    let mut remaining = length;
    while remaining != 0 {
        let until_wrap = 0x1_0000 - usize::from(current_offset);
        let chunk_length = remaining.min(until_wrap);
        chunks.push((real_address(segment, current_offset), data_offset, chunk_length));
        remaining -= chunk_length;
        data_offset += chunk_length;
        current_offset = 0;
    }
    chunks
}

fn dispatch_vga_memory_info(vga: &VgaDevice, regs: &mut Registers) {
    let state = vga.borrow();
    // Miscellaneous Output bit 0 selects the color (3Dx) or monochrome
    // (3Bx) address range. The BIOS interface identifies this in BH.
    regs.set_bh(if state.misc_output & 1 != 0 { 0 } else { 1 });
    regs.set_bl(3); // 256 KiB of four-plane VGA memory.
    // This virtual VGA has no switch-input bits to report.
    regs.set_cx(0);
}

fn dispatch_display_combination(vga: &VgaDevice, regs: &mut Registers) {
    match regs.al() {
        0x00 => {
            if modes::mode_info(vga.borrow().bios_mode).is_some() {
                regs.set_al(0x1a);
                regs.set_bl(ACTIVE_DISPLAY_CODE_VGA_COLOR);
                regs.set_bh(0);
            } else {
                regs.set_al(0);
            }
        }
        0x01 => {
            // This profile has one analog-color configuration and no
            // alternate display. Accept only a request matching that state.
            let active_mode_is_supported = modes::mode_info(vga.borrow().bios_mode).is_some();
            if active_mode_is_supported
                && regs.bl() == ACTIVE_DISPLAY_CODE_VGA_COLOR
                && regs.bh() == 0
            {
                regs.set_al(0x1a);
            } else {
                regs.set_al(0);
            }
        }
        _ => {}
    }
}

fn dispatch_functionality_state(
    vga: &VgaDevice,
    regs: &mut Registers,
    memory: &mut impl GuestMemory,
) -> Result<(), DeviceError> {
    if regs.bx() != 0 {
        regs.set_al(0);
        return Ok(());
    }

    let state = vga.borrow();
    let Some(info) = modes::mode_info(state.bios_mode) else {
        regs.set_al(0);
        return Ok(());
    };
    let mode = state.bios_mode;
    let mode_register_3x8 = state.cga_mode_control;
    let mode_register_3x9 = state.cga_color_control;
    let blinking = state.attribute[ATTRIBUTE_MODE_CONTROL] & 0x08 != 0;
    drop(state);

    for (address, _, chunk_length) in far_buffer_chunks(regs.es, regs.di(), STATE_BYTES) {
        memory.validate_write(address, chunk_length)?;
    }
    let mut bda = [0; crate::bios::BDA_SIZE];
    memory.read(PhysAddr(BDA_BASE), &mut bda)?;
    let state_bytes = build_state_buffer(
        info,
        mode,
        mode_register_3x8,
        mode_register_3x9,
        blinking,
        &bda,
    );
    write_guest_buffer(memory, regs.es, regs.di(), &state_bytes)?;
    regs.set_al(0x1b);
    Ok(())
}

fn build_state_buffer(
    info: ModeInfo,
    mode: u8,
    mode_register_3x8: u8,
    mode_register_3x9: u8,
    blinking: bool,
    bda: &[u8; crate::bios::BDA_SIZE],
) -> [u8; STATE_BYTES] {
    let mut state = [0; STATE_BYTES];
    state[0..2].copy_from_slice(&FUNCTIONALITY_OFFSET.to_le_bytes());
    state[2..4].copy_from_slice(&FUNCTIONALITY_SEGMENT.to_le_bytes());

    state[4] = mode;
    state[5..7].copy_from_slice(&info.columns.to_le_bytes());
    state[7..9].copy_from_slice(&word_at(bda, 0x4c).to_le_bytes());
    state[9..11].copy_from_slice(&word_at(bda, 0x4e).to_le_bytes());
    state[11..27].copy_from_slice(&bda[0x50..0x60]);
    state[27..29].copy_from_slice(&word_at(bda, 0x60).to_le_bytes());
    state[29] = bda[0x62];
    state[30..32].copy_from_slice(&word_at(bda, 0x63).to_le_bytes());
    state[32] = mode_register_3x8;
    state[33] = mode_register_3x9;
    state[34] = info.rows.min(u16::from(u8::MAX)) as u8;
    state[35..37].copy_from_slice(&u16::from(info.char_height).to_le_bytes());
    state[37] = ACTIVE_DISPLAY_CODE_VGA_COLOR;
    state[38] = 0; // No alternate display is modeled.
    state[39..41].copy_from_slice(&mode_color_count(info).to_le_bytes());
    state[41] = mode_page_count(info);
    state[42] = scan_line_code(info.height);
    state[43] = 0; // Character-generator block zero is the reset selection.
    state[44] = 0;
    state[45] = u8::from(blinking) << 5;
    state[49] = 3; // 256 KiB video memory.
    state
}

fn mode_color_count(info: ModeInfo) -> u16 {
    match info.mode {
        0x00..=0x03 | 0x0d | 0x0e | 0x10 | 0x12 => 16,
        0x04 | 0x05 => 4,
        0x06 | 0x07 | 0x0f | 0x11 => 2,
        0x13 => 256,
        _ => match info.kind {
            ModeKind::Text | ModeKind::Planar => 16,
            ModeKind::Chain4 => 256,
            ModeKind::Cga1 => 2,
            ModeKind::Cga2 => 4,
        },
    }
}

fn mode_page_count(info: ModeInfo) -> u8 {
    if info.page_bytes == 0 { return 1; }
    let address_space = match info.kind {
        ModeKind::Text => 0x8000,
        ModeKind::Cga1 | ModeKind::Cga2 => 0x4000,
        ModeKind::Planar | ModeKind::Chain4 => 0x10000,
    };
    (address_space / info.page_bytes).clamp(1, 8) as u8
}

fn scan_line_code(height: u16) -> u8 {
    match height {
        200 => 0,
        350 => 1,
        400 => 2,
        480 => 3,
        _ => 4,
    }
}

fn word_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(test)]
#[path = "bios_tests.rs"]
mod tests;
