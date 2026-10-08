use crate::{DeviceAction, DeviceError, DispatchOutcome};
use guest_core::{real_address, GuestMemory, Registers};

const MOUSE_STATE_BUFFER_SIZE: usize = 98;
const MOUSE_STATE_FORMAT_VERSION: u16 = 1;
const DEFAULT_TEXT_SCREEN_MASK: u16 = 0x77ff;
const DEFAULT_TEXT_CURSOR_MASK: u16 = 0x7700;

pub const EVENT_MOVEMENT: u16 = 0x0001;
pub const EVENT_LEFT_PRESS: u16 = 0x0002;
pub const EVENT_LEFT_RELEASE: u16 = 0x0004;
pub const EVENT_RIGHT_PRESS: u16 = 0x0008;
pub const EVENT_RIGHT_RELEASE: u16 = 0x0010;
pub const EVENT_MIDDLE_PRESS: u16 = 0x0020;
pub const EVENT_MIDDLE_RELEASE: u16 = 0x0040;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestFarPointer {
    pub segment: u16,
    pub offset: u16,
}

impl GuestFarPointer {
    pub fn is_null(self) -> bool { self.segment == 0 && self.offset == 0 }
}

/// Host event in the guest's 640x200 text coordinate space. Coordinates may
/// exceed the current guest range; they are clipped before guest delivery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MouseInput {
    pub x: i32,
    pub y: i32,
    /// Low three bits are left, right, and middle button state.
    pub buttons: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MouseState {
    pub x: u16,
    pub y: u16,
    pub buttons: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestCallbackRequest {
    pub entry: GuestFarPointer,
    pub event_mask: u16,
    pub buttons: u16,
    pub x: u16,
    pub y: u16,
    pub motion_x: i16,
    pub motion_y: i16,
}

impl GuestCallbackRequest {
    /// Register contract used by the Microsoft-compatible mouse callback:
    /// AX=event mask, BX=buttons, CX=x, DX=y, SI/DI=signed motion counters.
    /// CS:IP is the guest callback entry. The runtime supplies stack and
    /// interrupt semantics when it schedules the request.
    pub fn callback_registers(self) -> Registers {
        let mut regs = Registers::default();
        regs.set_ax(self.event_mask);
        regs.set_bx(self.buttons);
        regs.set_cx(self.x);
        regs.set_dx(self.y);
        regs.set_si(self.motion_x as u16);
        regs.set_di(self.motion_y as u16);
        regs.cs = self.entry.segment;
        regs.set_ip(self.entry.offset);
        regs
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ButtonRecord {
    presses: u16,
    releases: u16,
    press_x: u16,
    press_y: u16,
    release_x: u16,
    release_y: u16,
}

#[derive(Clone, Debug)]
struct SavedMouseState {
    x: u16,
    y: u16,
    raw_x: i32,
    raw_y: i32,
    buttons: u16,
    min_x: u16,
    max_x: u16,
    min_y: u16,
    max_y: u16,
    ratio_x: u16,
    ratio_y: u16,
    remainder_x: i32,
    remainder_y: i32,
    motion_x: i16,
    motion_y: i16,
    button_records: [ButtonRecord; 3],
    callback: GuestFarPointer,
    callback_mask: u16,
    cursor_hide_count: u16,
    text_screen_mask: u16,
    text_cursor_mask: u16,
    text_cursor_type: u8,
    hardware_cursor_start: u8,
    hardware_cursor_stop: u8,
}

#[derive(Clone, Debug)]
pub struct MouseDevice {
    present: bool,
    x: u16,
    y: u16,
    raw_x: i32,
    raw_y: i32,
    buttons: u16,
    min_x: u16,
    max_x: u16,
    min_y: u16,
    max_y: u16,
    ratio_x: u16,
    ratio_y: u16,
    remainder_x: i32,
    remainder_y: i32,
    motion_x: i16,
    motion_y: i16,
    button_records: [ButtonRecord; 3],
    callback: GuestFarPointer,
    callback_mask: u16,
    cursor_hide_count: u16,
    text_screen_mask: u16,
    text_cursor_mask: u16,
    text_cursor_type: u8,
    hardware_cursor_start: u8,
    hardware_cursor_stop: u8,
}

impl Default for MouseDevice {
    fn default() -> Self { Self::new() }
}

impl MouseDevice {
    pub fn new() -> Self {
        Self {
            present: false,
            x: 0,
            y: 0,
            raw_x: 0,
            raw_y: 0,
            buttons: 0,
            min_x: 0,
            max_x: 639,
            min_y: 0,
            max_y: 199,
            ratio_x: 8,
            ratio_y: 8,
            remainder_x: 0,
            remainder_y: 0,
            motion_x: 0,
            motion_y: 0,
            button_records: [ButtonRecord::default(); 3],
            callback: GuestFarPointer::default(),
            callback_mask: 0,
            cursor_hide_count: 1,
            text_screen_mask: DEFAULT_TEXT_SCREEN_MASK,
            text_cursor_mask: DEFAULT_TEXT_CURSOR_MASK,
            text_cursor_type: 0,
            hardware_cursor_start: 0,
            hardware_cursor_stop: 15,
        }
    }

    pub fn present(&self) -> bool { self.present }
    pub fn set_present(&mut self, present: bool) { self.present = present; }
    pub fn state(&self) -> MouseState { MouseState { x: self.x, y: self.y, buttons: self.buttons } }

    /// Returns the logical 640x200 mouse position and software text-cursor
    /// masks when the emulated driver is installed and the cursor is visible.
    pub fn text_cursor(&self) -> Option<(u16, u16, u16, u16)> {
        if !self.present || self.cursor_hide_count != 0 { return None; }
        let (screen_mask, cursor_mask) = if self.text_cursor_type == 0 {
            (self.text_screen_mask, self.text_cursor_mask)
        } else {
            // The snapshot renderer works at character-cell granularity. Map
            // the hardware scan-line cursor to the standard inverted cell.
            (DEFAULT_TEXT_SCREEN_MASK, DEFAULT_TEXT_CURSOR_MASK)
        };
        Some((self.x, self.y, screen_mask, cursor_mask))
    }

    pub fn reset(&mut self) {
        let present = self.present;
        *self = Self::new();
        self.present = present;
    }

    pub fn show_cursor(&mut self) {
        self.cursor_hide_count = self.cursor_hide_count.saturating_sub(1);
    }

    pub fn hide_cursor(&mut self) {
        self.cursor_hide_count = self.cursor_hide_count.saturating_add(1);
    }

    pub fn set_position(&mut self, x: u16, y: u16) -> (u16, u16) {
        self.x = x.clamp(self.min_x, self.max_x);
        self.y = y.clamp(self.min_y, self.max_y);
        self.raw_x = i32::from(self.x);
        self.raw_y = i32::from(self.y);
        (self.x, self.y)
    }

    pub fn set_x_range(&mut self, first: u16, second: u16) {
        self.min_x = first.min(second);
        self.max_x = first.max(second);
        self.x = self.x.clamp(self.min_x, self.max_x);
        self.raw_x = i32::from(self.x);
    }

    pub fn set_y_range(&mut self, first: u16, second: u16) {
        self.min_y = first.min(second);
        self.max_y = first.max(second);
        self.y = self.y.clamp(self.min_y, self.max_y);
        self.raw_y = i32::from(self.y);
    }

    pub fn take_button_data(&mut self, button: u16, released: bool) -> Option<(u16, u16, u16, u16)> {
        let record = self.button_records.get_mut(usize::from(button))?;
        if released {
            let result = (self.buttons, record.releases, record.release_x, record.release_y);
            record.releases = 0;
            Some(result)
        } else {
            let result = (self.buttons, record.presses, record.press_x, record.press_y);
            record.presses = 0;
            Some(result)
        }
    }

    pub fn take_motion(&mut self) -> (i16, i16) {
        let result = (self.motion_x, self.motion_y);
        self.motion_x = 0;
        self.motion_y = 0;
        result
    }

    pub fn install_callback(&mut self, segment: u16, offset: u16, mask: u16) {
        self.callback = GuestFarPointer { segment, offset };
        self.callback_mask = if self.callback.is_null() { 0 } else { mask };
    }

    pub fn exchange_callback(&mut self, segment: u16, offset: u16, mask: u16) -> (GuestFarPointer, u16) {
        let old = (self.callback, self.callback_mask);
        self.install_callback(segment, offset, mask);
        old
    }

    pub fn ranges(&self) -> (u16, u16, u16, u16) { (self.min_x, self.min_y, self.max_x, self.max_y) }

    pub fn set_mickey_ratio(&mut self, horizontal: u16, vertical: u16) {
        if horizontal != 0 { self.ratio_x = horizontal; }
        if vertical != 0 { self.ratio_y = vertical; }
        self.remainder_x = 0;
        self.remainder_y = 0;
    }

    pub fn text_cursor_masks(&self) -> (u16, u16) { (self.text_screen_mask, self.text_cursor_mask) }
    pub fn set_text_cursor_masks(&mut self, screen: u16, cursor: u16) {
        self.text_screen_mask = screen;
        self.text_cursor_mask = cursor;
        self.text_cursor_type = 0;
    }

    fn set_hardware_text_cursor(&mut self, start: u8, stop: u8) {
        self.text_cursor_type = 1;
        self.hardware_cursor_start = start;
        self.hardware_cursor_stop = stop;
        self.text_screen_mask = DEFAULT_TEXT_SCREEN_MASK;
        self.text_cursor_mask = DEFAULT_TEXT_CURSOR_MASK;
    }

    fn encode_saved_state(&self) -> [u8; MOUSE_STATE_BUFFER_SIZE] {
        let mut bytes = [0; MOUSE_STATE_BUFFER_SIZE];
        bytes[..4].copy_from_slice(b"NTMS");
        let mut offset = 4;
        write_state_u16(&mut bytes, &mut offset, MOUSE_STATE_FORMAT_VERSION);
        write_state_u16(&mut bytes, &mut offset, MOUSE_STATE_BUFFER_SIZE as u16);
        write_state_u16(&mut bytes, &mut offset, self.x);
        write_state_u16(&mut bytes, &mut offset, self.y);
        write_state_i32(&mut bytes, &mut offset, self.raw_x);
        write_state_i32(&mut bytes, &mut offset, self.raw_y);
        write_state_u16(&mut bytes, &mut offset, self.buttons);
        write_state_u16(&mut bytes, &mut offset, self.min_x);
        write_state_u16(&mut bytes, &mut offset, self.max_x);
        write_state_u16(&mut bytes, &mut offset, self.min_y);
        write_state_u16(&mut bytes, &mut offset, self.max_y);
        write_state_u16(&mut bytes, &mut offset, self.ratio_x);
        write_state_u16(&mut bytes, &mut offset, self.ratio_y);
        write_state_i32(&mut bytes, &mut offset, self.remainder_x);
        write_state_i32(&mut bytes, &mut offset, self.remainder_y);
        write_state_i16(&mut bytes, &mut offset, self.motion_x);
        write_state_i16(&mut bytes, &mut offset, self.motion_y);
        for record in self.button_records {
            write_state_u16(&mut bytes, &mut offset, record.presses);
            write_state_u16(&mut bytes, &mut offset, record.releases);
            write_state_u16(&mut bytes, &mut offset, record.press_x);
            write_state_u16(&mut bytes, &mut offset, record.press_y);
            write_state_u16(&mut bytes, &mut offset, record.release_x);
            write_state_u16(&mut bytes, &mut offset, record.release_y);
        }
        write_state_u16(&mut bytes, &mut offset, self.callback.segment);
        write_state_u16(&mut bytes, &mut offset, self.callback.offset);
        write_state_u16(&mut bytes, &mut offset, self.callback_mask);
        write_state_u16(&mut bytes, &mut offset, self.cursor_hide_count);
        write_state_u16(&mut bytes, &mut offset, self.text_screen_mask);
        write_state_u16(&mut bytes, &mut offset, self.text_cursor_mask);
        write_state_u8(&mut bytes, &mut offset, self.text_cursor_type);
        write_state_u8(&mut bytes, &mut offset, self.hardware_cursor_start);
        write_state_u8(&mut bytes, &mut offset, self.hardware_cursor_stop);
        write_state_u8(&mut bytes, &mut offset, 0);
        debug_assert_eq!(offset, MOUSE_STATE_BUFFER_SIZE);
        bytes
    }

    fn restore_saved_state(&mut self, bytes: &[u8; MOUSE_STATE_BUFFER_SIZE]) -> bool {
        let Some(saved) = SavedMouseState::decode(bytes) else { return false; };
        self.x = saved.x;
        self.y = saved.y;
        self.raw_x = saved.raw_x;
        self.raw_y = saved.raw_y;
        self.buttons = saved.buttons;
        self.min_x = saved.min_x;
        self.max_x = saved.max_x;
        self.min_y = saved.min_y;
        self.max_y = saved.max_y;
        self.ratio_x = saved.ratio_x;
        self.ratio_y = saved.ratio_y;
        self.remainder_x = saved.remainder_x;
        self.remainder_y = saved.remainder_y;
        self.motion_x = saved.motion_x;
        self.motion_y = saved.motion_y;
        self.button_records = saved.button_records;
        self.callback = saved.callback;
        self.callback_mask = saved.callback_mask;
        self.cursor_hide_count = saved.cursor_hide_count;
        self.text_screen_mask = saved.text_screen_mask;
        self.text_cursor_mask = saved.text_cursor_mask;
        self.text_cursor_type = saved.text_cursor_type;
        self.hardware_cursor_start = saved.hardware_cursor_start;
        self.hardware_cursor_stop = saved.hardware_cursor_stop;
        true
    }

    pub(super) fn dispatch_int33(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        outcome: &mut DispatchOutcome,
    ) -> Result<(), DeviceError> {
        let function = regs.ax();
        if !self.present {
            match function {
                0x0000 => { regs.set_ax(0); regs.set_bx(0); }
                0x0021 => regs.set_ax(0x0021),
                _ => {}
            }
            return Ok(());
        }
        match function {
            0x0000 => {
                self.reset();
                regs.set_ax(0xffff);
                regs.set_bx(3);
            }
            0x0021 => { regs.set_ax(0xffff); regs.set_bx(3); }
            0x0001 => self.show_cursor(),
            0x0002 => self.hide_cursor(),
            0x0003 => {
                let state = self.state();
                regs.set_bx(state.buttons);
                regs.set_cx(state.x);
                regs.set_dx(state.y);
            }
            0x0004 => {
                let (x, y) = self.set_position(regs.cx(), regs.dx());
                outcome.actions.push(DeviceAction::SetHostMousePosition { x, y });
            }
            0x0005 | 0x0006 => {
                let released = function == 0x0006;
                let Some((buttons, count, x, y)) = self.take_button_data(regs.bx(), released) else {
                    return Ok(());
                };
                regs.set_ax(buttons);
                regs.set_bx(count);
                regs.set_cx(x);
                regs.set_dx(y);
            }
            0x0007 => self.set_x_range(regs.cx(), regs.dx()),
            0x0008 => self.set_y_range(regs.cx(), regs.dx()),
            0x000a => match regs.bx() {
                0 => self.set_text_cursor_masks(regs.cx(), regs.dx()),
                1 if regs.cx() <= 31 && regs.dx() <= 31 && regs.cx() <= regs.dx() => {
                    self.set_hardware_text_cursor(regs.cl(), regs.dl());
                }
                _ => {}
            },
            0x000b => {
                let (dx, dy) = self.take_motion();
                regs.set_cx(dx as u16);
                regs.set_dx(dy as u16);
            }
            0x000c => self.install_callback(regs.es, regs.dx(), regs.cx()),
            0x000f => self.set_mickey_ratio(regs.cx(), regs.dx()),
            0x0014 => {
                let (old_entry, old_mask) = self.exchange_callback(regs.es, regs.dx(), regs.cx());
                regs.es = old_entry.segment;
                regs.set_dx(old_entry.offset);
                regs.set_cx(old_mask);
            }
            // Microsoft Mouse Programmer's Reference, 2nd ed. (1991),
            // functions 21-23: report, save, and restore the opaque driver
            // state buffer. This runtime uses a versioned, checked format.
            0x0015 => regs.set_bx(MOUSE_STATE_BUFFER_SIZE as u16),
            0x0016 => {
                let address = real_address(regs.es, regs.dx());
                let bytes = self.encode_saved_state();
                memory.validate_write(address, bytes.len())?;
                memory.write(address, &bytes)?;
            }
            0x0017 => {
                let address = real_address(regs.es, regs.dx());
                let mut bytes = [0; MOUSE_STATE_BUFFER_SIZE];
                memory.validate_read(address, bytes.len())?;
                memory.read(address, &mut bytes)?;
                self.restore_saved_state(&bytes);
            }
            // Microsoft Mouse Programmer's Reference, 2nd ed. (1991),
            // function 36 (AX=0024h) reports a legacy controller type and IRQ.
            // This host-window source has no value in that hardware enum, so
            // return the documented error instead of fabricating a type/IRQ.
            0x0024 => regs.set_ax(0xffff),
            _ => {}
        }
        Ok(())
    }

    pub fn inject(&mut self, input: MouseInput) -> Option<GuestCallbackRequest> {
        if !self.present { return None; }
        let old_buttons = self.buttons;
        let old_x = self.x;
        let old_y = self.y;
        let delta_x = input.x.saturating_sub(self.raw_x);
        let delta_y = input.y.saturating_sub(self.raw_y);
        let scaled_x = delta_x.saturating_mul(i32::from(self.ratio_x)).saturating_add(self.remainder_x);
        let scaled_y = delta_y.saturating_mul(i32::from(self.ratio_y)).saturating_add(self.remainder_y);
        let mickeys_x = scaled_x / 8;
        let mickeys_y = scaled_y / 8;
        self.remainder_x = scaled_x % 8;
        self.remainder_y = scaled_y % 8;
        self.motion_x = self.motion_x.wrapping_add(mickeys_x as i16);
        self.motion_y = self.motion_y.wrapping_add(mickeys_y as i16);
        self.raw_x = input.x;
        self.raw_y = input.y;
        self.x = input.x.clamp(i32::from(self.min_x), i32::from(self.max_x)) as u16;
        self.y = input.y.clamp(i32::from(self.min_y), i32::from(self.max_y)) as u16;
        self.buttons = input.buttons & 0x0007;

        let mut event_mask = 0;
        if self.x != old_x || self.y != old_y { event_mask |= EVENT_MOVEMENT; }
        let press_masks = [EVENT_LEFT_PRESS, EVENT_RIGHT_PRESS, EVENT_MIDDLE_PRESS];
        let release_masks = [EVENT_LEFT_RELEASE, EVENT_RIGHT_RELEASE, EVENT_MIDDLE_RELEASE];
        for button in 0..3 {
            let bit = 1u16 << button;
            let record = &mut self.button_records[button];
            if self.buttons & bit != 0 && old_buttons & bit == 0 {
                event_mask |= press_masks[button];
                record.presses = record.presses.saturating_add(1);
                record.press_x = self.x;
                record.press_y = self.y;
            } else if old_buttons & bit != 0 && self.buttons & bit == 0 {
                event_mask |= release_masks[button];
                record.releases = record.releases.saturating_add(1);
                record.release_x = self.x;
                record.release_y = self.y;
            }
        }

        if event_mask & self.callback_mask == 0 || self.callback.is_null() { return None; }
        Some(GuestCallbackRequest {
            entry: self.callback,
            event_mask: event_mask & self.callback_mask,
            buttons: self.buttons,
            x: self.x,
            y: self.y,
            motion_x: self.motion_x,
            motion_y: self.motion_y,
        })
    }
}

impl SavedMouseState {
    fn decode(bytes: &[u8; MOUSE_STATE_BUFFER_SIZE]) -> Option<Self> {
        if &bytes[..4] != b"NTMS" { return None; }
        let mut offset = 4;
        if read_state_u16(bytes, &mut offset)? != MOUSE_STATE_FORMAT_VERSION
            || read_state_u16(bytes, &mut offset)? as usize != MOUSE_STATE_BUFFER_SIZE
        {
            return None;
        }

        let x = read_state_u16(bytes, &mut offset)?;
        let y = read_state_u16(bytes, &mut offset)?;
        let raw_x = read_state_i32(bytes, &mut offset)?;
        let raw_y = read_state_i32(bytes, &mut offset)?;
        let buttons = read_state_u16(bytes, &mut offset)?;
        let min_x = read_state_u16(bytes, &mut offset)?;
        let max_x = read_state_u16(bytes, &mut offset)?;
        let min_y = read_state_u16(bytes, &mut offset)?;
        let max_y = read_state_u16(bytes, &mut offset)?;
        let ratio_x = read_state_u16(bytes, &mut offset)?;
        let ratio_y = read_state_u16(bytes, &mut offset)?;
        let remainder_x = read_state_i32(bytes, &mut offset)?;
        let remainder_y = read_state_i32(bytes, &mut offset)?;
        let motion_x = read_state_i16(bytes, &mut offset)?;
        let motion_y = read_state_i16(bytes, &mut offset)?;
        let mut button_records = [ButtonRecord::default(); 3];
        for record in &mut button_records {
            record.presses = read_state_u16(bytes, &mut offset)?;
            record.releases = read_state_u16(bytes, &mut offset)?;
            record.press_x = read_state_u16(bytes, &mut offset)?;
            record.press_y = read_state_u16(bytes, &mut offset)?;
            record.release_x = read_state_u16(bytes, &mut offset)?;
            record.release_y = read_state_u16(bytes, &mut offset)?;
        }
        let callback = GuestFarPointer {
            segment: read_state_u16(bytes, &mut offset)?,
            offset: read_state_u16(bytes, &mut offset)?,
        };
        let callback_mask = read_state_u16(bytes, &mut offset)?;
        let cursor_hide_count = read_state_u16(bytes, &mut offset)?;
        let text_screen_mask = read_state_u16(bytes, &mut offset)?;
        let text_cursor_mask = read_state_u16(bytes, &mut offset)?;
        let text_cursor_type = read_state_u8(bytes, &mut offset)?;
        let hardware_cursor_start = read_state_u8(bytes, &mut offset)?;
        let hardware_cursor_stop = read_state_u8(bytes, &mut offset)?;
        let reserved = read_state_u8(bytes, &mut offset)?;

        if offset != MOUSE_STATE_BUFFER_SIZE
            || reserved != 0
            || buttons & !0x0007 != 0
            || min_x > max_x
            || min_y > max_y
            || x < min_x
            || x > max_x
            || y < min_y
            || y > max_y
            || ratio_x == 0
            || ratio_y == 0
            || !(-7..=7).contains(&remainder_x)
            || !(-7..=7).contains(&remainder_y)
            || (callback.is_null() && callback_mask != 0)
            || text_cursor_type > 1
            || (text_cursor_type == 1
                && (hardware_cursor_start > 31
                    || hardware_cursor_stop > 31
                    || hardware_cursor_start > hardware_cursor_stop))
        {
            return None;
        }

        Some(Self {
            x,
            y,
            raw_x,
            raw_y,
            buttons,
            min_x,
            max_x,
            min_y,
            max_y,
            ratio_x,
            ratio_y,
            remainder_x,
            remainder_y,
            motion_x,
            motion_y,
            button_records,
            callback,
            callback_mask,
            cursor_hide_count,
            text_screen_mask,
            text_cursor_mask,
            text_cursor_type,
            hardware_cursor_start,
            hardware_cursor_stop,
        })
    }
}

fn write_state_u8(bytes: &mut [u8; MOUSE_STATE_BUFFER_SIZE], offset: &mut usize, value: u8) {
    bytes[*offset] = value;
    *offset += 1;
}

fn write_state_u16(bytes: &mut [u8; MOUSE_STATE_BUFFER_SIZE], offset: &mut usize, value: u16) {
    let end = *offset + 2;
    bytes[*offset..end].copy_from_slice(&value.to_le_bytes());
    *offset = end;
}

fn write_state_i16(bytes: &mut [u8; MOUSE_STATE_BUFFER_SIZE], offset: &mut usize, value: i16) {
    write_state_u16(bytes, offset, value as u16);
}

fn write_state_i32(bytes: &mut [u8; MOUSE_STATE_BUFFER_SIZE], offset: &mut usize, value: i32) {
    let end = *offset + 4;
    bytes[*offset..end].copy_from_slice(&value.to_le_bytes());
    *offset = end;
}

fn read_state_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    let value = *bytes.get(*offset)?;
    *offset += 1;
    Some(value)
}

fn read_state_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let end = (*offset).checked_add(2)?;
    let raw = bytes.get(*offset..end)?;
    *offset = end;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_state_i16(bytes: &[u8], offset: &mut usize) -> Option<i16> {
    read_state_u16(bytes, offset).map(|value| value as i16)
}

fn read_state_i32(bytes: &[u8], offset: &mut usize) -> Option<i32> {
    let end = (*offset).checked_add(4)?;
    let raw = bytes.get(*offset..end)?;
    *offset = end;
    Some(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}
