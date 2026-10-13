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
    cmos: crate::cmos::CmosRtc,
}

impl RtcState {
    pub fn new() -> Self { Self::default() }

    pub fn cmos(&self) -> crate::cmos::CmosRtc { self.cmos.clone() }

    pub fn update_bda(&mut self, memory: &mut impl GuestMemory, unix_seconds: i64) -> Result<ClockReading, MemoryError> {
        self.cmos.observe_host_time(unix_seconds);
        let reading = self.observe(self.cmos.unix_seconds());
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
        self.cmos.observe_host_time(epoch_seconds);
        match function {
            0x00 => {
                let time = self.update_bda(memory, epoch_seconds)?;
                regs.set_cx((time.ticks >> 16) as u16);
                regs.set_dx(time.ticks as u16);
                regs.set_al(time.midnight_rollovers);
                memory.write_u8(PhysAddr(BDA_BASE + 0x70), 0)?;
                self.acknowledge_midnight();
            }
            0x01 => {
                let ticks = (u32::from(regs.cx()) << 16) | u32::from(regs.dx());
                memory.write_u32(PhysAddr(BDA_BASE + 0x6c), ticks)?;
                memory.write_u8(PhysAddr(BDA_BASE + 0x70), 0)?;
                self.unacknowledged_midnights = 0;
                regs.set_ah(0);
                regs.set_carry(false);
            }
            0x02 => {
                let _ = self.update_bda(memory, epoch_seconds)?;
                match self.cmos.read_bios_time() {
                    Some((hour, minute, second, daylight)) => {
                        set_high_byte(&mut regs.ecx, hour);
                        set_low_byte(&mut regs.ecx, minute);
                        set_high_byte(&mut regs.edx, second);
                        set_low_byte(&mut regs.edx, daylight);
                        regs.set_carry(false);
                    }
                    None => {
                        regs.set_ah(0);
                        regs.set_carry(true);
                    }
                }
            }
            0x03 => {
                let hour = crate::bios::high_byte(regs.ecx);
                let minute = crate::bios::low_byte(regs.ecx);
                let second = crate::bios::high_byte(regs.edx);
                let daylight = crate::bios::low_byte(regs.edx) & 0x01 != 0;
                regs.set_carry(!self.cmos.write_bios_time(hour, minute, second, daylight));
            }
            0x04 => {
                let _ = self.update_bda(memory, epoch_seconds)?;
                match self.cmos.read_bios_date() {
                    Some((century, year, month, day)) => {
                        set_high_byte(&mut regs.ecx, century);
                        set_low_byte(&mut regs.ecx, year);
                        set_high_byte(&mut regs.edx, month);
                        set_low_byte(&mut regs.edx, day);
                        regs.set_carry(false);
                    }
                    None => {
                        regs.set_ah(0);
                        regs.set_carry(true);
                    }
                }
            }
            0x05 => {
                let century = crate::bios::high_byte(regs.ecx);
                let year = crate::bios::low_byte(regs.ecx);
                let month = crate::bios::high_byte(regs.edx);
                let day = crate::bios::low_byte(regs.edx);
                regs.set_carry(!self.cmos.write_bios_date(century, year, month, day));
            }
            0x06 => {
                let hour = crate::bios::high_byte(regs.ecx);
                let minute = crate::bios::low_byte(regs.ecx);
                let second = crate::bios::high_byte(regs.edx);
                regs.set_carry(!self.cmos.enable_alarm(hour, minute, second));
            }
            0x07 => {
                self.cmos.disable_alarm();
                regs.set_carry(false);
            }
            _ => {
                // Recoverable failure for an unavailable INT 1Ah call.
                regs.set_ah(0x86);
                regs.set_carry(true);
            }
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

    pub(crate) fn reset_tick_state(&mut self) {
        self.last_day = None;
        self.unacknowledged_midnights = 0;
    }
}

pub(crate) fn to_bcd(value: u8) -> u8 { ((value / 10) << 4) | (value % 10) }

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
