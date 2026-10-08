//! Intel 8254-compatible timer channels and programming/readback protocol.
//!
//! Mode, gate, latch, and read-back behavior follows Intel datasheet
//! 231164-004 (https://www.cs.umb.edu/cs341/Intel8254/I8254PIT.pdf).

use guest_core::io::PortError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Lsb,
    Msb,
    LsbThenMsb,
}

#[derive(Clone, Debug)]
struct Channel {
    reload: u32,
    count: u32,
    access: Access,
    mode_bits: u8,
    bcd: bool,
    gate: bool,
    out: bool,
    null_count: bool,
    write_high: bool,
    write_low: u8,
    write_was_running: bool,
    read_high: bool,
    live_read_latch: Option<u16>,
    count_latch: Option<(u16, bool)>,
    status_latch: Option<u8>,
    load_pending: bool,
    trigger_pending: bool,
    phase: u32,
    strobe_low: bool,
    pending_reload: Option<u32>,
}

impl Channel {
    fn new(gate: bool) -> Self {
        Self {
            reload: 0,
            count: 0,
            access: Access::LsbThenMsb,
            mode_bits: 0,
            bcd: false,
            gate,
            out: false,
            null_count: true,
            write_high: false,
            write_low: 0,
            write_was_running: false,
            read_high: false,
            live_read_latch: None,
            count_latch: None,
            status_latch: None,
            load_pending: false,
            trigger_pending: false,
            phase: 0,
            strobe_low: false,
            pending_reload: None,
        }
    }

    fn mode(&self) -> u8 {
        match self.mode_bits {
            6 => 2,
            7 => 3,
            mode => mode,
        }
    }

    fn status(&self) -> u8 {
        (u8::from(self.out) << 7)
            | (u8::from(self.null_count) << 6)
            | (match self.access { Access::Lsb => 1, Access::Msb => 2, Access::LsbThenMsb => 3 } << 4)
            | (self.mode_bits << 1)
            | u8::from(self.bcd)
    }

    fn configure(&mut self, access: Access, mode_bits: u8, bcd: bool) {
        self.reload = 0;
        self.count = 0;
        self.access = access;
        self.mode_bits = mode_bits;
        self.bcd = bcd;
        self.out = self.mode() != 0;
        self.null_count = true;
        self.write_high = false;
        self.write_was_running = false;
        self.read_high = false;
        self.live_read_latch = None;
        self.count_latch = None;
        self.status_latch = None;
        self.load_pending = false;
        self.trigger_pending = false;
        self.phase = 0;
        self.strobe_low = false;
        self.pending_reload = None;
    }

    fn latch_count(&mut self) {
        if self.count_latch.is_none() {
            self.count_latch = Some((encode_count(self.count, self.bcd), false));
        }
    }

    fn latch_status(&mut self) {
        if self.status_latch.is_none() {
            self.status_latch = Some(self.status());
        }
    }

    fn read(&mut self) -> u8 {
        if let Some(status) = self.status_latch.take() {
            return status;
        }
        let latched = self.count_latch.is_some();
        let (value, high) = if let Some((value, high)) = self.count_latch {
            (value, high)
        } else if self.access == Access::LsbThenMsb {
            if !self.read_high {
                let value = self.live_read_latch.unwrap_or_else(|| encode_count(self.count, self.bcd));
                self.live_read_latch = Some(value);
                (value, false)
            } else {
                (self.live_read_latch.unwrap_or_else(|| encode_count(self.count, self.bcd)), true)
            }
        } else {
            (encode_count(self.count, self.bcd), false)
        };

        let byte = match self.access {
            Access::Lsb => value as u8,
            Access::Msb => (value >> 8) as u8,
            Access::LsbThenMsb => if high { (value >> 8) as u8 } else { value as u8 },
        };

        if latched {
            if let Some((value, _)) = self.count_latch {
                if self.access == Access::LsbThenMsb && !high {
                    self.count_latch = Some((value, true));
                } else {
                    self.count_latch = None;
                }
            }
        } else if self.access == Access::LsbThenMsb {
            if high {
                self.read_high = false;
                self.live_read_latch = None;
            } else {
                self.read_high = true;
            }
        }
        byte
    }

    fn write(&mut self, byte: u8, port: u16) -> Result<(), PortError> {
        let raw = match self.access {
            Access::Lsb => u16::from(byte),
            Access::Msb => u16::from(byte) << 8,
            Access::LsbThenMsb if !self.write_high => {
                self.write_low = byte;
                self.write_high = true;
                self.write_was_running = self.count != 0;
                self.null_count = true;
                if self.mode() == 0 {
                    self.out = false;
                }
                return Ok(());
            }
            Access::LsbThenMsb => (u16::from(byte) << 8) | u16::from(self.write_low),
        };
        let count = decode_count(raw, self.bcd).ok_or(PortError::InvalidState {
            port,
            detail: "8254 BCD counter digit is outside 0 through 9",
        })?;
        if self.mode() == 2 && count == 1 {
            return Err(PortError::InvalidState { port, detail: "8254 mode 2 does not permit an initial count of one" });
        }
        if self.mode() == 3 && count == 1 {
            return Err(PortError::InvalidState { port, detail: "8254 mode 3 requires an initial count of at least two" });
        }

        let was_running = if self.access == Access::LsbThenMsb && self.write_high {
            self.write_was_running
        } else {
            self.count != 0
        };
        self.write_high = false;
        self.write_was_running = false;
        self.null_count = true;
        self.count_latch = None;
        match self.mode() {
            0 => {
                self.reload = count;
                self.out = false;
                self.phase = 0;
                self.load_pending = true;
            }
            4 => {
                self.reload = count;
                self.out = true;
                self.phase = 0;
                self.strobe_low = false;
                self.load_pending = true;
            }
            1 | 5 => {
                self.reload = count;
                self.phase = 0;
                self.strobe_low = false;
                self.load_pending = false;
            }
            2 | 3 => {
                if !was_running {
                    self.reload = count;
                    self.phase = 0;
                    self.pending_reload = None;
                    self.load_pending = true;
                } else {
                    self.pending_reload = Some(count);
                }
            }
            _ => unreachable!("PIT mode bits are three-bit values"),
        }
        Ok(())
    }

    fn set_gate(&mut self, high: bool) -> bool {
        let old_out = self.out;
        let rising = !self.gate && high;
        let falling = self.gate && !high;
        self.gate = high;
        match self.mode() {
            1 | 5 if rising => self.trigger_pending = true,
            2 | 3 if rising => {
                if let Some(next) = self.pending_reload.take() {
                    self.reload = next;
                }
                self.load_pending = true;
                self.phase = 0;
            }
            2 | 3 if falling => self.out = true,
            _ => {}
        }
        !old_out && self.out
    }

    fn advance(&mut self, ticks: u64) -> bool {
        if ticks == 0 {
            return false;
        }
        match self.mode() {
            0 => self.advance_mode0(ticks),
            1 => self.advance_oneshot(ticks),
            2 => self.advance_periodic(ticks, false),
            3 => self.advance_periodic(ticks, true),
            4 => self.advance_strobe(ticks, false),
            5 => self.advance_strobe(ticks, true),
            _ => false,
        }
    }

    fn advance_mode0(&mut self, mut ticks: u64) -> bool {
        let old_out = self.out;
        if self.load_pending {
            self.count = self.reload;
            self.load_pending = false;
            self.null_count = false;
            ticks -= 1;
        }
        if self.gate && ticks != 0 && self.count != 0 {
            let used = ticks.min(u64::from(self.count));
            self.count -= used as u32;
            if self.count == 0 {
                self.out = true;
            }
        }
        !old_out && self.out
    }

    fn advance_oneshot(&mut self, mut ticks: u64) -> bool {
        let old_out = self.out;
        let triggered = self.trigger_pending;
        if self.trigger_pending {
            self.count = self.reload;
            self.trigger_pending = false;
            self.null_count = false;
            self.phase = 0;
            self.out = false;
            ticks -= 1;
        } else if self.load_pending {
            self.count = self.reload;
            self.load_pending = false;
            self.null_count = false;
            self.phase = 0;
            self.out = true;
            ticks -= 1;
        }
        if ticks != 0 && self.count != 0 {
            let used = ticks.min(u64::from(self.count));
            self.count -= used as u32;
            if self.count == 0 {
                self.out = true;
            }
        }
        (!old_out && self.out) || (triggered && self.out)
    }

    fn advance_periodic(&mut self, mut ticks: u64, square: bool) -> bool {
        let old_out = self.out;
        if self.load_pending {
            self.count = self.reload;
            self.load_pending = false;
            self.null_count = false;
            self.phase = 0;
            self.out = true;
            ticks -= 1;
        }
        if !self.gate || ticks == 0 || self.reload == 0 {
            return !old_out && self.out;
        }

        // A newly programmed count is transferred at the next period
        // boundary. Once transferred, all remaining clocks can be advanced in
        // one arithmetic step because these modes are periodic.
        let mut rose_at_reload = false;
        if let Some(next) = self.pending_reload {
            let until_wrap = u64::from(self.reload.saturating_sub(self.phase));
            if ticks >= until_wrap {
                ticks -= until_wrap;
                rose_at_reload = true;
                self.reload = next;
                self.pending_reload = None;
                self.phase = 0;
                self.null_count = false;
            } else {
                self.phase += ticks as u32;
                self.update_periodic_output(square);
                self.update_periodic_count(square);
                return !old_out && self.out;
            }
        }

        let period = self.reload;
        let first_wrap = u64::from(period - self.phase);
        let rose = ticks >= first_wrap;
        self.phase = ((u64::from(self.phase) + ticks % u64::from(period)) % u64::from(period)) as u32;
        self.update_periodic_output(square);
        self.update_periodic_count(square);
        (!old_out && self.out) || rose || rose_at_reload
    }

    fn update_periodic_output(&mut self, square: bool) {
        if square {
            let high_len = self.reload.div_ceil(2);
            self.out = self.phase < high_len;
        } else {
            self.out = self.phase != self.reload - 1;
        }
    }

    fn update_periodic_count(&mut self, square: bool) {
        self.count = if square {
            let high_len = self.reload.div_ceil(2);
            if self.phase < high_len {
                if self.reload & 1 != 0 && self.phase != 0 {
                    self.reload.saturating_sub(1).saturating_sub((self.phase - 1).saturating_mul(2))
                } else {
                    self.reload.saturating_sub(self.phase.saturating_mul(2))
                }
            } else {
                let low_phase = self.phase - high_len;
                let low_start = if self.reload & 1 != 0 { self.reload - 1 } else { self.reload };
                low_start.saturating_sub(low_phase.saturating_mul(2))
            }
        } else if self.phase == 0 {
            self.reload
        } else {
            self.reload.saturating_sub(self.phase)
        };
    }

    fn advance_strobe(&mut self, mut ticks: u64, hardware: bool) -> bool {
        let old_out = self.out;
        let mut rose = false;
        if hardware && self.trigger_pending {
            self.count = self.reload;
            self.trigger_pending = false;
            self.null_count = false;
            self.out = true;
            self.strobe_low = false;
            ticks -= 1;
        } else if !hardware && self.load_pending {
            self.count = self.reload;
            self.load_pending = false;
            self.null_count = false;
            self.out = true;
            ticks -= 1;
        }

        if self.strobe_low && ticks != 0 {
            self.out = true;
            self.strobe_low = false;
            ticks -= 1;
            rose = true;
        }
        if self.count != 0 && ticks != 0 && (hardware || self.gate) {
            let used = ticks.min(u64::from(self.count));
            self.count -= used as u32;
            ticks -= used;
            if self.count == 0 {
                self.out = false;
                self.strobe_low = true;
            }
        }
        if self.strobe_low && ticks != 0 {
            self.out = true;
            self.strobe_low = false;
            rose = true;
        }
        (!old_out && self.out) || rose
    }
}

/// Three independent deterministic 16-bit timer channels with the 8254
/// control, count-latch, read-back and byte-sequencing interfaces.
#[derive(Clone, Debug)]
pub struct Pit8254 {
    channels: [Channel; 3],
}

impl Default for Pit8254 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit8254 {
    pub fn new() -> Self {
        Self { channels: [Channel::new(true), Channel::new(true), Channel::new(false)] }
    }

    pub fn set_gate(&mut self, channel: u8, high: bool) -> Result<bool, PortError> {
        let Some(channel) = self.channels.get_mut(usize::from(channel)) else {
            return Err(PortError::InternalInvariant { port: 0x40 + u16::from(channel), detail: "8254 counter index is out of range" });
        };
        Ok(channel.set_gate(high))
    }

    pub fn output(&self, channel: u8) -> Option<bool> {
        self.channels.get(usize::from(channel)).map(|counter| counter.out)
    }

    /// Advances all channels; returns true if channel 0 produced a rising
    /// output edge during this interval.
    pub fn advance_ticks(&mut self, ticks: u64) -> bool {
        let irq0 = self.channels[0].advance(ticks);
        self.channels[1].advance(ticks);
        self.channels[2].advance(ticks);
        irq0
    }

    pub(super) fn read_counter(&mut self, channel: u8) -> Result<u8, PortError> {
        let Some(channel) = self.channels.get_mut(usize::from(channel)) else {
            return Err(PortError::InternalInvariant { port: 0x40 + u16::from(channel), detail: "8254 counter index is out of range" });
        };
        Ok(channel.read())
    }

    pub(super) fn write_counter(&mut self, channel: u8, value: u8) -> Result<(), PortError> {
        let port = 0x40 + u16::from(channel);
        let Some(channel) = self.channels.get_mut(usize::from(channel)) else {
            return Err(PortError::InternalInvariant { port, detail: "8254 counter index is out of range" });
        };
        channel.write(value, port)
    }

    pub(super) fn write_control(&mut self, value: u8) -> Result<(), PortError> {
        let select = value >> 6;
        if select == 3 {
            if value & 1 != 0 {
                return Err(PortError::InvalidState { port: 0x43, detail: "8254 read-back command reserved bit must be zero" });
            }
            self.read_back(value);
            return Ok(());
        }
        let index = usize::from(select);
        let rw = (value >> 4) & 3;
        if rw == 0 {
            self.channels[index].latch_count();
            return Ok(());
        }
        let access = match rw {
            1 => Access::Lsb,
            2 => Access::Msb,
            3 => Access::LsbThenMsb,
            _ => unreachable!(),
        };
        self.channels[index].configure(access, (value >> 1) & 7, value & 1 != 0);
        Ok(())
    }

    fn read_back(&mut self, command: u8) {
        let latch_count = command & 0x20 == 0;
        let latch_status = command & 0x10 == 0;
        for index in 0..3 {
            if command & (1 << (index + 1)) != 0 {
                if latch_count {
                    self.channels[index].latch_count();
                }
                if latch_status {
                    self.channels[index].latch_status();
                }
            }
        }
    }
}

fn decode_count(raw: u16, bcd: bool) -> Option<u32> {
    if !bcd {
        return Some(if raw == 0 { 65_536 } else { u32::from(raw) });
    }
    if raw == 0 {
        return Some(10_000);
    }
    let mut value = 0;
    let mut place = 1;
    for shift in [0, 4, 8, 12] {
        let digit = u32::from((raw >> shift) & 0xf);
        if digit > 9 {
            return None;
        }
        value += digit * place;
        place *= 10;
    }
    Some(value)
}

fn encode_count(count: u32, bcd: bool) -> u16 {
    if !bcd {
        return if count == 65_536 { 0 } else { count as u16 };
    }
    if count == 10_000 {
        return 0;
    }
    let mut value = count.min(9_999);
    let mut raw = 0u16;
    for shift in [0, 4, 8, 12] {
        raw |= ((value % 10) as u16) << shift;
        value /= 10;
    }
    raw
}
