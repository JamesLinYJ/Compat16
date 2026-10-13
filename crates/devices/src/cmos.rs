//! MC146818-compatible real-time clock and CMOS RAM on ports 70h/71h.
//!
//! The index port keeps bit 7 as the NMI mask. That bit selects no register
//! and this machine has no separate NMI source, so the mask is only stored.
//! Time and date bytes follow register B: BCD or binary, and 12-hour or
//! 24-hour. Register C is cleared by reading it. A bad checksum over the
//! standard configuration bytes is replaced with the defaults.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::rtc::{to_bcd, unix_seconds_to_datetime, DateTime};

const CMOS_LEN: usize = 128;
const PIT_HZ: u64 = 1_193_182;
/// Update-in-progress window from the MC146818 datasheet, about 244 µs.
const UIP_TICKS: u64 = (PIT_HZ * 244) / 1_000_000;
const DIVIDER_RUNNING: u8 = 0x20;

const SECONDS: usize = 0x00;
const SECONDS_ALARM: usize = 0x01;
const MINUTES: usize = 0x02;
const MINUTES_ALARM: usize = 0x03;
const HOURS: usize = 0x04;
const HOURS_ALARM: usize = 0x05;
const WEEKDAY: usize = 0x06;
const DAY: usize = 0x07;
const MONTH: usize = 0x08;
const YEAR: usize = 0x09;
const REGISTER_A: usize = 0x0a;
const REGISTER_B: usize = 0x0b;
const REGISTER_C: usize = 0x0c;
const REGISTER_D: usize = 0x0d;
const DIAGNOSTIC: usize = 0x0e;
const FLOPPY_TYPE: usize = 0x10;
const FIXED_DISK_TYPE: usize = 0x12;
const EQUIPMENT: usize = 0x14;
const BASE_MEMORY_LO: usize = 0x15;
const BASE_MEMORY_HI: usize = 0x16;
const EXTENDED_MEMORY_LO: usize = 0x17;
const EXTENDED_MEMORY_HI: usize = 0x18;
const BOOT_ORDER: usize = 0x2d;
const CHECKSUM_HI: usize = 0x2e;
const CHECKSUM_LO: usize = 0x2f;
const CENTURY: usize = 0x32;

const STATUS_SET: u8 = 1 << 7;
const STATUS_PIE: u8 = 1 << 6;
const STATUS_AIE: u8 = 1 << 5;
const STATUS_UIE: u8 = 1 << 4;
const STATUS_BINARY: u8 = 1 << 2;
const STATUS_24_HOUR: u8 = 1 << 1;
const STATUS_DAYLIGHT: u8 = 1 << 0;

#[derive(Clone, Debug)]
struct UserWait {
    remaining_ticks: u64,
    segment: u16,
    offset: u16,
}

#[derive(Debug)]
struct State {
    ram: [u8; CMOS_LEN],
    index: u8,
    nmi_disabled: bool,
    /// Guest clock. Host time is copied here until the guest programs it.
    unix_seconds: i64,
    subsecond_ticks: u64,
    guest_time_override: bool,
    periodic_accum: u64,
    periodic: bool,
    alarm: bool,
    update_ended: bool,
    alarm_was_matching: bool,
    irq_line: bool,
    wait: Option<UserWait>,
    completed_waits: Vec<(u16, u16)>,
    loaded_from_file: bool,
    path: Option<PathBuf>,
}

/// Shared CMOS so the port bus and the BIOS services see one chip.
#[derive(Clone, Debug)]
pub struct CmosRtc {
    inner: Rc<RefCell<State>>,
}

impl CmosRtc {
    pub fn new() -> Self {
        let chip = Self {
            inner: Rc::new(RefCell::new(State::fresh())),
        };
        chip.install_defaults(0x10_0000);
        chip
    }

    /// Remember a host file. A readable image with a valid checksum replaces
    /// the RAM. A bad checksum is rebuilt from the defaults and written back.
    pub fn attach_file(&self, path: &Path) {
        let mut state = self.inner.borrow_mut();
        state.path = Some(path.to_path_buf());
        match fs::read(path) {
            Ok(bytes) if bytes.len() == CMOS_LEN => {
                let mut ram = [0u8; CMOS_LEN];
                ram.copy_from_slice(&bytes);
                state.ram = ram;
                if state.checksum_matches() {
                    state.loaded_from_file = true;
                    state.adopt_stored_time();
                } else {
                    state.recover_defaults(0x10_0000);
                    state.persist();
                }
            }
            Ok(_) => {
                state.recover_defaults(0x10_0000);
                state.persist();
            }
            Err(_) => {}
        }
    }

    pub fn loaded_from_file(&self) -> bool {
        self.inner.borrow().loaded_from_file
    }

    /// Publish the standard configuration block and its checksum.
    pub fn install_defaults(&self, memory_len: u32) {
        let mut state = self.inner.borrow_mut();
        state.install_defaults(memory_len);
        state.persist();
    }

    pub fn write_index(&self, value: u8) {
        let mut state = self.inner.borrow_mut();
        state.nmi_disabled = value & 0x80 != 0;
        state.index = value & 0x7f;
    }

    pub fn read_index(&self) -> u8 {
        let state = self.inner.borrow();
        state.index | (u8::from(state.nmi_disabled) << 7)
    }

    pub fn read_data(&self) -> u8 {
        let mut state = self.inner.borrow_mut();
        let index = usize::from(state.index);
        match index {
            REGISTER_A => state.register_a(),
            REGISTER_C => state.read_register_c(),
            REGISTER_D => 0x80,
            SECONDS | MINUTES | HOURS | WEEKDAY | DAY | MONTH | YEAR
                if state.ram[REGISTER_B] & STATUS_SET == 0 && state.clock_running() =>
            {
                state.live_time_byte(index)
            }
            _ => state.ram[index],
        }
    }

    pub fn write_data(&self, value: u8) {
        let mut state = self.inner.borrow_mut();
        let index = usize::from(state.index);
        match index {
            REGISTER_A => {
                state.ram[REGISTER_A] = value & 0x7f;
                state.periodic_accum = 0;
            }
            REGISTER_B => state.write_register_b(value),
            REGISTER_C | REGISTER_D => {}
            SECONDS | MINUTES | HOURS | WEEKDAY | DAY | MONTH | YEAR
                if state.ram[REGISTER_B] & STATUS_SET == 0 => {}
            _ => {
                state.ram[index] = value;
                if (0x10..=0x2d).contains(&index) {
                    state.write_checksum();
                    state.persist();
                }
            }
        }
    }

    /// Advance the divider by PIT input ticks. Returns whether IRQ8 rose.
    pub fn advance_pit_ticks(&self, ticks: u64) -> bool {
        self.inner.borrow_mut().advance_pit_ticks(ticks)
    }

    pub fn take_completed_waits(&self) -> Vec<(u16, u16)> {
        std::mem::take(&mut self.inner.borrow_mut().completed_waits)
    }

    pub fn observe_host_time(&self, unix_seconds: i64) {
        let mut state = self.inner.borrow_mut();
        if state.guest_time_override || state.ram[REGISTER_B] & STATUS_SET != 0 {
            return;
        }
        state.unix_seconds = unix_seconds;
        state.refresh_century();
    }

    pub fn unix_seconds(&self) -> i64 {
        self.inner.borrow().unix_seconds
    }

    pub fn update_in_progress(&self) -> bool {
        self.inner.borrow().update_in_progress()
    }

    pub fn equipment_word(&self) -> u16 {
        equipment_word(self.inner.borrow().ram[EQUIPMENT])
    }

    pub fn base_memory_kib(&self) -> u16 {
        let state = self.inner.borrow();
        u16::from_le_bytes([state.ram[BASE_MEMORY_LO], state.ram[BASE_MEMORY_HI]])
    }

    pub fn extended_memory_kib(&self) -> u16 {
        let state = self.inner.borrow();
        u16::from_le_bytes([
            state.ram[EXTENDED_MEMORY_LO],
            state.ram[EXTENDED_MEMORY_HI],
        ])
    }

    pub fn boot_order(&self) -> u8 {
        self.inner.borrow().ram[BOOT_ORDER]
    }

    pub fn floppy_type(&self) -> u8 {
        self.inner.borrow().ram[FLOPPY_TYPE]
    }

    pub fn fixed_disk_type(&self) -> u8 {
        self.inner.borrow().ram[FIXED_DISK_TYPE]
    }

    /// BIOS INT 1Ah time is always 24-hour BCD, whatever register B selects.
    pub fn read_bios_time(&self) -> Option<(u8, u8, u8, u8)> {
        let state = self.inner.borrow();
        if state.update_in_progress() {
            return None;
        }
        let date = state.current_datetime();
        Some((
            to_bcd(date.hour),
            to_bcd(date.minute),
            to_bcd(date.second),
            u8::from(state.ram[REGISTER_B] & STATUS_DAYLIGHT != 0),
        ))
    }

    pub fn write_bios_time(&self, hour: u8, minute: u8, second: u8, daylight: bool) -> bool {
        let Some(hour) = from_bcd(hour) else { return false };
        let Some(minute) = from_bcd(minute) else { return false };
        let Some(second) = from_bcd(second) else { return false };
        if hour > 23 || minute > 59 || second > 59 {
            return false;
        }
        let mut state = self.inner.borrow_mut();
        let mut date = state.current_datetime();
        date.hour = hour;
        date.minute = minute;
        date.second = second;
        if !state.apply_datetime(date) {
            return false;
        }
        if daylight {
            state.ram[REGISTER_B] |= STATUS_DAYLIGHT;
        } else {
            state.ram[REGISTER_B] &= !STATUS_DAYLIGHT;
        }
        state.guest_time_override = true;
        true
    }

    pub fn read_bios_date(&self) -> Option<(u8, u8, u8, u8)> {
        let state = self.inner.borrow();
        if state.update_in_progress() {
            return None;
        }
        let date = state.current_datetime();
        Some((
            to_bcd((date.year / 100) as u8),
            to_bcd((date.year % 100) as u8),
            to_bcd(date.month),
            to_bcd(date.day),
        ))
    }

    pub fn write_bios_date(&self, century: u8, year: u8, month: u8, day: u8) -> bool {
        let Some(century) = from_bcd(century) else { return false };
        let Some(year) = from_bcd(year) else { return false };
        let Some(month) = from_bcd(month) else { return false };
        let Some(day) = from_bcd(day) else { return false };
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(month, century, year) {
            return false;
        }
        let mut state = self.inner.borrow_mut();
        let mut date = state.current_datetime();
        date.year = u16::from(century) * 100 + u16::from(year);
        date.month = month;
        date.day = day;
        if !state.apply_datetime(date) {
            return false;
        }
        state.ram[CENTURY] = to_bcd(century);
        state.write_checksum();
        state.guest_time_override = true;
        state.persist();
        true
    }

    pub fn alarm_enabled(&self) -> bool {
        self.inner.borrow().ram[REGISTER_B] & STATUS_AIE != 0
    }

    pub fn enable_alarm(&self, hour: u8, minute: u8, second: u8) -> bool {
        if self.alarm_enabled() {
            return false;
        }
        let Some(hour) = from_bcd(hour) else { return false };
        let Some(minute) = from_bcd(minute) else { return false };
        let Some(second) = from_bcd(second) else { return false };
        if hour > 23 || minute > 59 || second > 59 {
            return false;
        }
        let mut state = self.inner.borrow_mut();
        state.ram[HOURS_ALARM] = state.encode_hour(hour);
        state.ram[MINUTES_ALARM] = state.encode_unit(minute);
        state.ram[SECONDS_ALARM] = state.encode_unit(second);
        state.ram[REGISTER_B] |= STATUS_AIE;
        state.alarm_was_matching = false;
        true
    }

    pub fn disable_alarm(&self) {
        let mut state = self.inner.borrow_mut();
        state.ram[REGISTER_B] &= !STATUS_AIE;
        state.alarm = false;
        state.irq_line = state.irq_asserted();
    }

    /// INT 15h AH=83h. A zero interval completes on the next tick sample.
    pub fn arm_user_wait(&self, microseconds: u32, segment: u16, offset: u16) -> bool {
        let mut state = self.inner.borrow_mut();
        if state.wait.is_some() {
            return false;
        }
        let remaining_ticks = u64::from(microseconds).saturating_mul(PIT_HZ) / 1_000_000;
        if remaining_ticks == 0 {
            state.completed_waits.push((segment, offset));
            return true;
        }
        state.wait = Some(UserWait { remaining_ticks, segment, offset });
        true
    }

    pub fn cancel_user_wait(&self) {
        self.inner.borrow_mut().wait = None;
    }

    pub fn user_wait_active(&self) -> bool {
        self.inner.borrow().wait.is_some()
    }

    pub fn ram(&self, index: u8) -> u8 {
        self.inner.borrow().ram[usize::from(index & 0x7f)]
    }

    /// Read register C, which clears the interrupt flags, without changing
    /// the index latched by guest software.
    pub fn acknowledge_interrupt(&self) -> u8 {
        self.inner.borrow_mut().read_register_c()
    }
}

impl Default for CmosRtc {
    fn default() -> Self { Self::new() }
}

impl State {
    fn fresh() -> Self {
        Self {
            ram: [0; CMOS_LEN],
            index: 0,
            nmi_disabled: false,
            unix_seconds: 0,
            subsecond_ticks: 0,
            guest_time_override: false,
            periodic_accum: 0,
            periodic: false,
            alarm: false,
            update_ended: false,
            alarm_was_matching: false,
            irq_line: false,
            wait: None,
            completed_waits: Vec::new(),
            loaded_from_file: false,
            path: None,
        }
    }

    fn install_defaults(&mut self, memory_len: u32) {
        let time = self.ram;
        self.ram = [0; CMOS_LEN];
        // Keep a guest-programmed clock across a configuration reset.
        self.ram[SECONDS] = time[SECONDS];
        self.ram[MINUTES] = time[MINUTES];
        self.ram[HOURS] = time[HOURS];
        self.ram[WEEKDAY] = time[WEEKDAY];
        self.ram[DAY] = time[DAY];
        self.ram[MONTH] = time[MONTH];
        self.ram[YEAR] = time[YEAR];
        self.ram[REGISTER_A] = DIVIDER_RUNNING;
        self.ram[REGISTER_B] = STATUS_24_HOUR;
        self.ram[CENTURY] = 0x20;
        self.ram[FLOPPY_TYPE] = 0;
        self.ram[FIXED_DISK_TYPE] = 0;
        self.ram[EQUIPMENT] = 0;
        let base = 640u16;
        let extended = extended_kib(memory_len);
        self.ram[BASE_MEMORY_LO] = base as u8;
        self.ram[BASE_MEMORY_HI] = (base >> 8) as u8;
        self.ram[EXTENDED_MEMORY_LO] = extended as u8;
        self.ram[EXTENDED_MEMORY_HI] = (extended >> 8) as u8;
        self.ram[BOOT_ORDER] = 0;
        self.write_checksum();
    }

    fn recover_defaults(&mut self, memory_len: u32) {
        self.install_defaults(memory_len);
        self.ram[DIAGNOSTIC] = 0x80;
        self.write_checksum();
        self.loaded_from_file = true;
    }

    fn adopt_stored_time(&mut self) {
        if let Some(date) = self.decode_stored_datetime() {
            if let Some(unix) = datetime_to_unix(date) {
                self.unix_seconds = unix;
                self.guest_time_override = true;
                self.subsecond_ticks = 0;
            }
        }
    }

    fn checksum_matches(&self) -> bool {
        self.stored_checksum() == self.computed_checksum()
    }

    fn stored_checksum(&self) -> u16 {
        u16::from(self.ram[CHECKSUM_HI]) << 8 | u16::from(self.ram[CHECKSUM_LO])
    }

    fn computed_checksum(&self) -> u16 {
        self.ram[0x10..=0x2d].iter().fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)))
    }

    fn write_checksum(&mut self) {
        let sum = self.computed_checksum();
        self.ram[CHECKSUM_HI] = (sum >> 8) as u8;
        self.ram[CHECKSUM_LO] = sum as u8;
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let _ = fs::write(path, self.image());
    }

    /// Clock bytes are synthesized while the chip is running, so a saved image
    /// stores the time that port reads would return.
    fn image(&self) -> [u8; CMOS_LEN] {
        let mut ram = self.ram;
        if self.ram[REGISTER_B] & STATUS_SET == 0 && self.clock_running() {
            let date = unix_seconds_to_datetime(self.unix_seconds);
            ram[SECONDS] = self.encode_unit(date.second);
            ram[MINUTES] = self.encode_unit(date.minute);
            ram[HOURS] = self.encode_hour(date.hour);
            ram[WEEKDAY] = self.encode_unit(weekday_sunday1(self.unix_seconds));
            ram[DAY] = self.encode_unit(date.day);
            ram[MONTH] = self.encode_unit(date.month);
            ram[YEAR] = self.encode_unit((date.year % 100) as u8);
        }
        ram
    }

    fn clock_running(&self) -> bool {
        self.ram[REGISTER_A] & 0x70 == DIVIDER_RUNNING
    }

    fn update_in_progress(&self) -> bool {
        self.clock_running()
            && self.ram[REGISTER_B] & STATUS_SET == 0
            && self.subsecond_ticks >= PIT_HZ.saturating_sub(UIP_TICKS)
    }

    fn register_a(&self) -> u8 {
        let uip = u8::from(self.update_in_progress()) << 7;
        (self.ram[REGISTER_A] & 0x7f) | uip
    }

    fn write_register_b(&mut self, value: u8) {
        let previous = self.ram[REGISTER_B];
        let rising_set = previous & STATUS_SET == 0 && value & STATUS_SET != 0;
        let falling_set = previous & STATUS_SET != 0 && value & STATUS_SET == 0;
        if rising_set {
            self.latch_time();
        }
        self.ram[REGISTER_B] = value;
        if falling_set {
            self.adopt_stored_time();
            self.guest_time_override = true;
        }
        self.irq_line = self.irq_asserted();
    }

    fn read_register_c(&mut self) -> u8 {
        let value = self.status_c();
        self.periodic = false;
        self.alarm = false;
        self.update_ended = false;
        self.irq_line = false;
        value
    }

    fn status_c(&self) -> u8 {
        let mut value = 0;
        if self.periodic { value |= 0x40; }
        if self.alarm { value |= 0x20; }
        if self.update_ended { value |= 0x10; }
        if self.irq_asserted() { value |= 0x80; }
        value
    }

    fn irq_asserted(&self) -> bool {
        let status = self.ram[REGISTER_B];
        (self.periodic && status & STATUS_PIE != 0)
            || (self.alarm && status & STATUS_AIE != 0)
            || (self.update_ended && status & STATUS_UIE != 0)
    }

    fn advance_pit_ticks(&mut self, ticks: u64) -> bool {
        if let Some(wait) = &mut self.wait {
            if ticks >= wait.remaining_ticks {
                let completed = (wait.segment, wait.offset);
                self.completed_waits.push(completed);
                self.wait = None;
            } else {
                wait.remaining_ticks -= ticks;
            }
        }
        // SET stops the calendar update. The periodic divider keeps running.
        if self.clock_running() && self.ram[REGISTER_B] & STATUS_SET == 0 {
            self.subsecond_ticks = self.subsecond_ticks.saturating_add(ticks);
            while self.subsecond_ticks >= PIT_HZ {
                self.subsecond_ticks -= PIT_HZ;
                self.unix_seconds = self.unix_seconds.saturating_add(1);
                self.update_ended = true;
                self.note_alarm();
                self.refresh_century();
            }
        }
        if self.clock_running() {
            if let Some(period) = periodic_period_ticks(self.ram[REGISTER_A]) {
                self.periodic_accum = self.periodic_accum.saturating_add(ticks);
                while self.periodic_accum >= period {
                    self.periodic_accum -= period;
                    self.periodic = true;
                }
            }
        }
        self.raise_irq()
    }

    fn raise_irq(&mut self) -> bool {
        let asserted = self.irq_asserted();
        let edge = asserted && !self.irq_line;
        self.irq_line = asserted;
        edge
    }

    fn note_alarm(&mut self) {
        let matching = self.alarm_matches();
        if matching && !self.alarm_was_matching {
            self.alarm = true;
        }
        self.alarm_was_matching = matching;
    }

    fn alarm_matches(&self) -> bool {
        let date = self.current_datetime();
        field_matches(self.ram[SECONDS_ALARM], date.second, self.binary())
            && field_matches(self.ram[MINUTES_ALARM], date.minute, self.binary())
            && hour_matches(self.ram[HOURS_ALARM], date.hour, self.binary(), self.hour_24())
    }

    fn binary(&self) -> bool { self.ram[REGISTER_B] & STATUS_BINARY != 0 }
    fn hour_24(&self) -> bool { self.ram[REGISTER_B] & STATUS_24_HOUR != 0 }

    fn current_datetime(&self) -> DateTime {
        if self.ram[REGISTER_B] & STATUS_SET != 0 {
            self.decode_stored_datetime().unwrap_or_else(|| unix_seconds_to_datetime(self.unix_seconds))
        } else {
            unix_seconds_to_datetime(self.unix_seconds)
        }
    }

    fn live_time_byte(&self, index: usize) -> u8 {
        let date = unix_seconds_to_datetime(self.unix_seconds);
        match index {
            SECONDS => self.encode_unit(date.second),
            MINUTES => self.encode_unit(date.minute),
            HOURS => self.encode_hour(date.hour),
            WEEKDAY => self.encode_unit(weekday_sunday1(self.unix_seconds)),
            DAY => self.encode_unit(date.day),
            MONTH => self.encode_unit(date.month),
            YEAR => self.encode_unit((date.year % 100) as u8),
            _ => 0,
        }
    }

    fn encode_unit(&self, value: u8) -> u8 {
        if self.binary() { value } else { to_bcd(value) }
    }

    fn encode_hour(&self, hour24: u8) -> u8 {
        encode_hour(hour24, self.hour_24(), self.binary())
    }

    fn latch_time(&mut self) {
        let date = unix_seconds_to_datetime(self.unix_seconds);
        self.ram[SECONDS] = self.encode_unit(date.second);
        self.ram[MINUTES] = self.encode_unit(date.minute);
        self.ram[HOURS] = self.encode_hour(date.hour);
        self.ram[WEEKDAY] = self.encode_unit(weekday_sunday1(self.unix_seconds));
        self.ram[DAY] = self.encode_unit(date.day);
        self.ram[MONTH] = self.encode_unit(date.month);
        self.ram[YEAR] = self.encode_unit((date.year % 100) as u8);
    }

    fn decode_stored_datetime(&self) -> Option<DateTime> {
        let binary = self.binary();
        let second = decode_unit(self.ram[SECONDS], binary)?;
        let minute = decode_unit(self.ram[MINUTES], binary)?;
        let hour = decode_hour(self.ram[HOURS], self.hour_24(), binary)?;
        let day = decode_unit(self.ram[DAY], binary)?;
        let month = decode_unit(self.ram[MONTH], binary)?;
        let year = decode_unit(self.ram[YEAR], binary)?;
        let century = from_bcd(self.ram[CENTURY]).unwrap_or(20);
        if second > 59 || minute > 59 || !(1..=12).contains(&month) || day == 0 {
            return None;
        }
        Some(DateTime {
            year: u16::from(century) * 100 + u16::from(year),
            month,
            day,
            hour,
            minute,
            second,
        })
    }

    fn apply_datetime(&mut self, date: DateTime) -> bool {
        let Some(unix) = datetime_to_unix(date) else { return false };
        self.unix_seconds = unix;
        self.subsecond_ticks = 0;
        self.latch_time();
        self.refresh_century();
        true
    }

    fn refresh_century(&mut self) {
        let century = to_bcd((unix_seconds_to_datetime(self.unix_seconds).year / 100) as u8);
        if self.ram[CENTURY] != century {
            self.ram[CENTURY] = century;
            self.write_checksum();
            self.persist();
        }
    }
}

fn extended_kib(memory_len: u32) -> u16 {
    let kib = memory_len.saturating_sub(0x10_0000) / 1024;
    u16::try_from(kib).unwrap_or(u16::MAX)
}

pub(crate) fn equipment_word(cmos_equipment: u8) -> u16 {
    let video = match (cmos_equipment >> 4) & 0x03 {
        1 => 0x01,
        3 => 0x03,
        _ => 0x02,
    };
    let mut word = video << 4;
    if cmos_equipment & 0x01 != 0 {
        word |= 1;
        word |= u16::from((cmos_equipment >> 6) & 0x03) << 6;
    }
    if cmos_equipment & 0x02 != 0 {
        word |= 1 << 1;
    }
    word
}

fn periodic_period_ticks(register_a: u8) -> Option<u64> {
    let hz = match register_a & 0x0f {
        0 => return None,
        1 => 256,
        2 => 128,
        rate => 32768u32 >> (rate - 1),
    };
    Some((PIT_HZ + u64::from(hz) / 2) / u64::from(hz))
}

fn encode_hour(hour24: u8, mode_24: bool, binary: bool) -> u8 {
    if mode_24 {
        return if binary { hour24 } else { to_bcd(hour24) };
    }
    let pm = hour24 >= 12;
    let mut hour = hour24 % 12;
    if hour == 0 { hour = 12; }
    let mut encoded = if binary { hour } else { to_bcd(hour) };
    if pm { encoded |= 0x80; }
    encoded
}

fn decode_hour(encoded: u8, mode_24: bool, binary: bool) -> Option<u8> {
    if mode_24 {
        let hour = decode_unit(encoded, binary)?;
        return (hour <= 23).then_some(hour);
    }
    let pm = encoded & 0x80 != 0;
    let hour = decode_unit(encoded & 0x7f, binary)?;
    if !(1..=12).contains(&hour) { return None; }
    let mut hour24 = hour % 12;
    if pm { hour24 += 12; }
    Some(hour24)
}

fn decode_unit(encoded: u8, binary: bool) -> Option<u8> {
    if binary { Some(encoded) } else { from_bcd(encoded) }
}

fn from_bcd(value: u8) -> Option<u8> {
    let tens = value >> 4;
    let ones = value & 0x0f;
    (tens <= 9 && ones <= 9).then_some(tens * 10 + ones)
}

fn field_matches(alarm: u8, value: u8, binary: bool) -> bool {
    if alarm & 0xc0 == 0xc0 { return true; }
    decode_unit(alarm, binary) == Some(value)
}

fn hour_matches(alarm: u8, hour24: u8, binary: bool, mode_24: bool) -> bool {
    if alarm & 0xc0 == 0xc0 { return true; }
    decode_hour(alarm, mode_24, binary) == Some(hour24)
}

fn weekday_sunday1(unix_seconds: i64) -> u8 {
    let days = unix_seconds.div_euclid(86_400);
    ((days.rem_euclid(7) + 4) % 7) as u8 + 1
}

fn days_in_month(month: u8, century: u8, year: u8) -> u8 {
    let year = u16::from(century) * 100 + u16::from(year);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn datetime_to_unix(date: DateTime) -> Option<i64> {
    if date.year < 1970 || date.month == 0 || date.day == 0 {
        return None;
    }
    let mut days: i64 = 0;
    for year in 1970..date.year {
        days += if leap(year) { 366 } else { 365 };
    }
    for month in 1..date.month {
        days += i64::from(days_in_month(month, (date.year / 100) as u8, (date.year % 100) as u8));
    }
    days += i64::from(date.day - 1);
    let seconds = i64::from(date.hour) * 3600 + i64::from(date.minute) * 60 + i64::from(date.second);
    days.checked_mul(86_400)?.checked_add(seconds)
}

fn leap(year: u16) -> bool {
    year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
}

#[cfg(test)]
#[path = "cmos_tests.rs"]
mod tests;
