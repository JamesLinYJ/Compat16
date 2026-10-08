//! VGA indexed-register, attribute-flip-flop, DAC, and status-port behavior.

use guest_core::io::{PortError, PortWidth};

use super::VgaState;
use super::VgaDevice;

const VGA_PORT_START: u16 = 0x03b0;
const VGA_PORT_END: u16 = 0x03df;
const PIT_INPUT_HZ: u64 = 1_193_182;
const VIDEO_FRAME_HZ: u64 = 60;
const VIDEO_LINES_PER_FRAME: u64 = 525;

impl VgaDevice {
    /// Read one byte from a VGA I/O register. Unimplemented and reserved
    /// registers in the decoded range return the adapter's open-bus value.
    pub fn read_port(&self, port: u16) -> Result<u8, PortError> {
        if !(VGA_PORT_START..=VGA_PORT_END).contains(&port) {
            return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: false });
        }
        Ok(self.inner.borrow_mut().read_port(port))
    }

    /// Write one byte to a VGA I/O register. Reserved/write-only registers
    /// without modeled semantics ignore writes, matching absent hardware
    /// register behavior without failing the guest transaction.
    pub fn write_port(&self, port: u16, value: u8) -> Result<(), PortError> {
        if !(VGA_PORT_START..=VGA_PORT_END).contains(&port) {
            return Err(PortError::Unsupported { port, width: PortWidth::Byte, write: true });
        }
        self.inner.borrow_mut().write_port(port, value);
        Ok(())
    }
}

impl VgaState {
    fn monochrome_crtc_selected(&self) -> bool {
        self.misc_output & 0x01 == 0
    }

    fn read_indexed(registers: &[u8], index: u8) -> u8 {
        registers.get(usize::from(index)).copied().unwrap_or(0xff)
    }

    fn write_indexed(registers: &mut [u8], index: u8, value: u8) -> bool {
        let Some(register) = registers.get_mut(usize::from(index)) else {
            return false;
        };
        if *register == value {
            false
        } else {
            *register = value;
            true
        }
    }

    fn retrace_status(&mut self) -> u8 {
        // Model a stable 60Hz scan cycle from the emulated PIT clock. This is
        // intentionally deterministic and does not depend on host timing.
        let frame_ticks = PIT_INPUT_HZ / VIDEO_FRAME_HZ;
        let frame_phase = self.clock_ticks % frame_ticks;
        let vblank_start = frame_ticks * (VIDEO_LINES_PER_FRAME - 45) / VIDEO_LINES_PER_FRAME;
        let line_ticks = (frame_ticks / VIDEO_LINES_PER_FRAME).max(1);
        let line_phase = self.clock_ticks % line_ticks;
        let vertical_blank = frame_phase >= vblank_start;
        let horizontal_blank = line_phase >= (line_ticks * 9 / 10).max(1);

        // Reading input status 1 resets the attribute-controller index/data
        // flip-flop, which software uses before programming port 3C0h.
        self.attribute_data_phase = false;

        u8::from(vertical_blank) << 3 | u8::from(vertical_blank || horizontal_blank)
    }

    fn read_dac_component(&mut self) -> u8 {
        if !self.dac_read_mode {
            return 0xff;
        }
        let result = self.palette[usize::from(self.dac_read_index)]
            [usize::from(self.dac_component)]
            & 0x3f;
        self.advance_dac_read();
        result
    }

    fn advance_dac_read(&mut self) {
        self.dac_component += 1;
        if self.dac_component == 3 {
            self.dac_component = 0;
            self.dac_read_index = self.dac_read_index.wrapping_add(1);
        }
    }

    fn advance_dac_write(&mut self) {
        self.dac_component += 1;
        if self.dac_component == 3 {
            self.dac_component = 0;
            self.dac_write_index = self.dac_write_index.wrapping_add(1);
        }
    }

    fn read_port(&mut self, port: u16) -> u8 {
        match port {
            0x03b4 if self.monochrome_crtc_selected() => self.crtc_index,
            0x03b5 if self.monochrome_crtc_selected() => Self::read_indexed(&self.crtc, self.crtc_index),
            0x03d4 if !self.monochrome_crtc_selected() => self.crtc_index,
            0x03d5 if !self.monochrome_crtc_selected() => Self::read_indexed(&self.crtc, self.crtc_index),
            0x03ba if self.monochrome_crtc_selected() => self.retrace_status(),
            0x03da if !self.monochrome_crtc_selected() => self.retrace_status(),
            0x03b8 if self.monochrome_crtc_selected() => self.cga_mode_control,
            0x03d8 if !self.monochrome_crtc_selected() => self.cga_mode_control,
            0x03d9 if !self.monochrome_crtc_selected() => self.cga_color_control,
            0x03c0 => self.attribute_index | (u8::from(self.attribute_palette_enabled) << 5),
            0x03c1 => Self::read_indexed(&self.attribute, self.attribute_index),
            0x03c3 => self.video_subsystem_enable,
            0x03c4 => self.sequencer_index,
            0x03c5 => Self::read_indexed(&self.sequencer, self.sequencer_index),
            0x03c6 => self.pel_mask,
            0x03c7 => if self.dac_read_mode { 0x03 } else { 0x00 },
            0x03c8 => self.dac_write_index,
            0x03c9 => self.read_dac_component(),
            0x03ca => self.feature_control,
            0x03cc => self.misc_output,
            0x03ce => self.graphics_index,
            0x03cf => Self::read_indexed(&self.graphics, self.graphics_index),
            _ => 0xff,
        }
    }

    fn write_crtc_data(&mut self, value: u8) {
        let index = self.crtc_index;
        let Some(current) = self.crtc.get(usize::from(index)).copied() else {
            return;
        };
        let value = if self.crtc[0x11] & 0x80 != 0 && index <= 7 {
            if index == 7 {
                (current & !0x10) | (value & 0x10)
            } else {
                return;
            }
        } else {
            value
        };
        if current != value {
            self.crtc[usize::from(index)] = value;
            self.mark_changed();
        }
    }

    fn write_cga_mode(&mut self, value: u8) -> bool {
        let changed = self.cga_mode_control != value;
        self.cga_mode_control = value;
        // Retain legacy CGA control state for queries; it does not
        // reprogram a VGA mode unless a CGA adapter profile is selected.
        changed
    }

    fn write_port(&mut self, port: u16, value: u8) {
        let changed = match port {
            0x03c0 => {
                if self.attribute_data_phase {
                    let changed = Self::write_indexed(&mut self.attribute, self.attribute_index, value);
                    self.attribute_data_phase = false;
                    changed
                } else {
                    let index = value & 0x1f;
                    let enabled = value & 0x20 != 0;
                    let changed = self.attribute_index != index || self.attribute_palette_enabled != enabled;
                    self.attribute_index = index;
                    self.attribute_palette_enabled = enabled;
                    self.attribute_data_phase = true;
                    changed
                }
            }
            0x03c2 => {
                let changed = self.misc_output != value;
                self.misc_output = value;
                changed
            }
            0x03c3 => {
                let changed = self.video_subsystem_enable != value;
                self.video_subsystem_enable = value;
                changed
            }
            0x03c4 => {
                self.sequencer_index = value;
                false
            }
            0x03c5 => Self::write_indexed(&mut self.sequencer, self.sequencer_index, value),
            0x03c6 => {
                let changed = self.pel_mask != value;
                self.pel_mask = value;
                changed
            }
            0x03c7 => {
                self.dac_read_index = value;
                self.dac_component = 0;
                self.dac_read_mode = true;
                false
            }
            0x03c8 => {
                self.dac_write_index = value;
                self.dac_component = 0;
                self.dac_read_mode = false;
                false
            }
            0x03c9 if !self.dac_read_mode => {
                let color = &mut self.palette[usize::from(self.dac_write_index)]
                    [usize::from(self.dac_component)];
                let changed = *color != (value & 0x3f);
                *color = value & 0x3f;
                self.advance_dac_write();
                changed
            }
            0x03ca | 0x03cc | 0x03c1 => false,
            0x03ce => {
                self.graphics_index = value;
                false
            }
            0x03cf => Self::write_indexed(&mut self.graphics, self.graphics_index, value),
            0x03b4 if self.monochrome_crtc_selected() => {
                self.crtc_index = value & 0x1f;
                false
            }
            0x03b5 if self.monochrome_crtc_selected() => {
                self.write_crtc_data(value);
                false
            }
            0x03d4 if !self.monochrome_crtc_selected() => {
                self.crtc_index = value & 0x1f;
                false
            }
            0x03d5 if !self.monochrome_crtc_selected() => {
                self.write_crtc_data(value);
                false
            }
            0x03ba if self.monochrome_crtc_selected() => {
                let changed = self.feature_control != value;
                self.feature_control = value;
                changed
            }
            0x03da if !self.monochrome_crtc_selected() => {
                let changed = self.feature_control != value;
                self.feature_control = value;
                changed
            }
            0x03b8 if self.monochrome_crtc_selected() => {
                self.write_cga_mode(value)
            }
            0x03d8 if !self.monochrome_crtc_selected() => {
                self.write_cga_mode(value)
            }
            0x03d9 if !self.monochrome_crtc_selected() => {
                let changed = self.cga_color_control != value;
                self.cga_color_control = value;
                changed
            }
            _ => false,
        };
        if changed {
            self.mark_changed();
        }
    }
}
