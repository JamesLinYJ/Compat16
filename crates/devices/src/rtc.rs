use crate::bios::{set_high_byte, set_low_byte, BDA_BASE};
use crate::DeviceError;
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

pub const BIOS_TICKS_PER_DAY: u64 = 0x1800b0;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClockReading {
    pub ticks: u32,
    pub midnight_rollovers: u8,
}

#[derive(Clone, Debug, Default)]
pub struct RtcState {
    last_day: Option<i64>,
    unacknowledged_midnights: u8,
}

impl RtcState {
    pub fn new() -> Self { Self::default() }

    pub fn update_bda(&mut self, memory: &mut impl GuestMemory, unix_seconds: i64) -> Result<ClockReading, MemoryError> {
        let reading = self.observe(unix_seconds);
        memory.write_u32(PhysAddr(BDA_BASE + 0x6c), reading.ticks)?;
        memory.write_u8(PhysAddr(BDA_BASE + 0x70), reading.midnight_rollovers)?;
        Ok(reading)
    }

    pub(super) fn dispatch_int1a(
        &mut self,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        epoch_seconds: i64,
    ) -> Result<(), DeviceError> {
        let function = u16::from(regs.ah());
        if function == 0xb1 {
            // PCI BIOS §4 uses AH=81h/CF for FUNC_NOT_SUPPORTED. This machine
            // has no PCI BIOS; the B101h installation probe and other B1h
            // requests must report absence instead of aborting INT 1Ah.
            regs.set_ah(0x81);
            regs.set_carry(true);
            return Ok(());
        }
        if !matches!(function, 0x00 | 0x02 | 0x04) {
            // Return a recoverable failure for unavailable non-PCI
            // INT 1Ah calls; this is not asserted as a universal PC BIOS rule.
            regs.set_ah(0x86);
            regs.set_carry(true);
            return Ok(());
        }
        let time = self.update_bda(memory, epoch_seconds)?;
        match function {
            0x00 => {
                regs.set_cx((time.ticks >> 16) as u16);
                regs.set_dx(time.ticks as u16);
                regs.set_al(time.midnight_rollovers);
                memory.write_u8(PhysAddr(BDA_BASE + 0x70), 0)?;
                self.acknowledge_midnight();
            }
            0x02 => {
                let datetime = unix_seconds_to_datetime(epoch_seconds);
                set_high_byte(&mut regs.ecx, to_bcd(datetime.hour));
                set_low_byte(&mut regs.ecx, to_bcd(datetime.minute));
                set_high_byte(&mut regs.edx, to_bcd(datetime.second));
                set_low_byte(&mut regs.edx, 0);
                regs.set_carry(false);
            }
            0x04 => {
                let datetime = unix_seconds_to_datetime(epoch_seconds);
                set_high_byte(&mut regs.ecx, to_bcd((datetime.year / 100) as u8));
                set_low_byte(&mut regs.ecx, to_bcd((datetime.year % 100) as u8));
                set_high_byte(&mut regs.edx, to_bcd(datetime.month));
                set_low_byte(&mut regs.edx, to_bcd(datetime.day));
                regs.set_carry(false);
            }
            _ => return Err(DeviceError::UnsupportedInterrupt { interrupt: 0x1a, function }),
        }
        Ok(())
    }

    /// Observe a deterministic Unix timestamp and maintain BIOS midnight
    /// rollover state for INT 1Ah function 00h.
    pub fn observe(&mut self, unix_seconds: i64) -> ClockReading {
        let day = unix_seconds.div_euclid(86_400);
        if let Some(previous) = self.last_day {
            if day > previous {
                let crossed = day.saturating_sub(previous).min(i64::from(u8::MAX)) as u8;
                self.unacknowledged_midnights = self.unacknowledged_midnights.wrapping_add(crossed);
            }
        }
        self.last_day = Some(day);
        let second_of_day = unix_seconds.rem_euclid(86_400) as u64;
        let ticks = (second_of_day * BIOS_TICKS_PER_DAY / 86_400) as u32;
        ClockReading { ticks, midnight_rollovers: self.unacknowledged_midnights }
    }

    pub fn acknowledge_midnight(&mut self) { self.unacknowledged_midnights = 0; }
}

pub fn to_bcd(value: u8) -> u8 { ((value / 10) << 4) | (value % 10) }

/// Gregorian calendar conversion using integer arithmetic only. The same
/// timestamp always produces the same guest date/time on every host.
pub fn unix_seconds_to_datetime(unix_seconds: i64) -> DateTime {
    let days = unix_seconds.div_euclid(86_400);
    let second_of_day = unix_seconds.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += (month <= 2) as i64;
    DateTime {
        year: year.clamp(0, 9_999) as u16,
        month: month as u8,
        day: day as u8,
        hour: (second_of_day / 3_600) as u8,
        minute: ((second_of_day % 3_600) / 60) as u8,
        second: (second_of_day % 60) as u8,
    }
}

#[cfg(test)]
#[path = "rtc_tests.rs"]
mod tests;
