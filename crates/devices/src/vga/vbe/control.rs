//! VBE mode and display control functions.

use crate::vga::{svga, VgaDevice, SVGA_BANK_BYTES, VIDEO_MEMORY_BYTES};
use guest_core::Registers;

use super::{fail, succeed};

const BANK_WINDOW_COUNT: u16 = (VIDEO_MEMORY_BYTES / SVGA_BANK_BYTES) as u16;
const WINDOW_A: u8 = 0;
const SET_BANK: u8 = 0;
const GET_BANK: u8 = 1;
const SET_SCANLINE: u8 = 0;
const GET_SCANLINE: u8 = 1;
const SET_DISPLAY_START: u8 = 0;
const GET_DISPLAY_START: u8 = 1;
const SET_DISPLAY_START_DURING_RETRACE: u8 = 0x80;
const SET_DAC_WIDTH: u8 = 0;
const GET_DAC_WIDTH: u8 = 1;
const VBE_DAC_WIDTH: u8 = 6;
const LINEAR_FRAMEBUFFER_FLAG: u16 = 1 << 14;
const NO_CLEAR_MEMORY_FLAG: u16 = 1 << 15;
const RESERVED_MODE_FLAGS: u16 = 0x3e00;

pub(super) fn dispatch(vga: &VgaDevice, regs: &mut Registers) {
    match regs.al() {
        0x05 => set_or_get_bank(vga, regs),
        0x06 => set_or_get_scanline(vga, regs),
        0x07 => set_or_get_display_start(vga, regs),
        0x08 => set_or_get_dac_width(regs),
        _ => fail(regs),
    }
}

pub(super) fn set_mode(vga: &VgaDevice, regs: &mut Registers) {
    let mode_flags = regs.bx();
    if mode_flags & (LINEAR_FRAMEBUFFER_FLAG | RESERVED_MODE_FLAGS) != 0 {
        fail(regs);
        return;
    }
    let mode = mode_flags & 0x01ff;
    let clear = mode_flags & NO_CLEAR_MEMORY_FLAG == 0;
    if !vga.borrow_mut().set_svga_mode(mode, clear) {
        fail(regs);
        return;
    }
    succeed(regs);
}

pub(super) fn get_mode(vga: &VgaDevice, regs: &mut Registers) {
    let state = vga.borrow();
    let mode = if let Some(state) = state.svga.as_ref() {
        state.mode | if state.preserve_memory { NO_CLEAR_MEMORY_FLAG } else { 0 }
    } else {
        u16::from(state.bios_mode)
    };
    drop(state);
    regs.set_bx(mode);
    succeed(regs);
}

fn set_or_get_bank(vga: &VgaDevice, regs: &mut Registers) {
    let window = regs.bl();
    match (regs.bh(), window) {
        (SET_BANK, WINDOW_A) => {
            let bank = regs.dx();
            if bank >= BANK_WINDOW_COUNT || !vga.borrow_mut().set_svga_bank(bank) {
                fail(regs);
                return;
            }
            succeed(regs);
        }
        (GET_BANK, WINDOW_A) => {
            let state = vga.borrow();
            let Some(svga) = state.svga.as_ref() else {
                fail(regs);
                return;
            };
            if !svga.is_valid() {
                fail(regs);
                return;
            }
            let bank = svga.bank;
            drop(state);
            regs.set_dx(bank);
            succeed(regs);
        }
        // This adapter exposes only the standard A0000 window.
        _ => fail(regs),
    }
}

fn set_or_get_scanline(vga: &VgaDevice, regs: &mut Registers) {
    let results = match regs.bl() {
        SET_SCANLINE => vga.borrow_mut().set_svga_stride(regs.cx()),
        GET_SCANLINE => {
            let state = vga.borrow();
            let Some(svga_state) = state.svga.as_ref() else {
                fail(regs);
                return;
            };
            if !svga_state.is_valid() {
                fail(regs);
                return;
            }
            let Some(mode) = svga::mode_info(svga_state.mode) else {
                fail(regs);
                return;
            };
            let Some(bytes) = svga::scanline_bytes(mode, svga_state.stride) else {
                fail(regs);
                return;
            };
            let Some(lines) = svga::maximum_lines(bytes) else {
                fail(regs);
                return;
            };
            Some((bytes, svga_state.stride, lines))
        }
        _ => {
            fail(regs);
            return;
        }
    };

    if let Some((bytes, pixels, lines)) = results {
        regs.set_bx(bytes);
        regs.set_cx(pixels);
        regs.set_dx(lines);
        succeed(regs);
    } else {
        fail(regs);
    }
}

fn set_or_get_display_start(vga: &VgaDevice, regs: &mut Registers) {
    match (regs.bl(), regs.bh()) {
        (SET_DISPLAY_START, 0) | (SET_DISPLAY_START_DURING_RETRACE, 0) => {
            if !vga.borrow_mut().set_svga_display_start(regs.cx(), regs.dx()) {
                fail(regs);
                return;
            }
            succeed(regs);
        }
        (GET_DISPLAY_START, 0) => {
            let state = vga.borrow();
            let Some(svga_state) = state.svga.as_ref() else {
                fail(regs);
                return;
            };
            if !svga_state.is_valid() {
                fail(regs);
                return;
            }
            let x = svga_state.display_x;
            let y = svga_state.display_y;
            drop(state);
            regs.set_cx(x);
            regs.set_dx(y);
            succeed(regs);
        }
        _ => fail(regs),
    }
}

fn set_or_get_dac_width(regs: &mut Registers) {
    match regs.bl() {
        SET_DAC_WIDTH if regs.bh() == VBE_DAC_WIDTH => succeed(regs),
        GET_DAC_WIDTH => {
            regs.set_bh(VBE_DAC_WIDTH);
            succeed(regs);
        }
        _ => fail(regs),
    }
}
