//! Monotonic scheduling for the emulated PIT input clock.
//!
//! Host time schedules state transitions in `MachinePorts`; no host hardware
//! ports or physical memory are accessed. This is a time-driven machine, not
//! a cycle-accurate model of the guest CPU. PIC requests remain latched until
//! the CPU permits delivery at an instruction boundary, including SS/STI shadows.

use std::time::{Duration, Instant};
use devices::ports::MachinePorts;

const PIT_HZ: u128 = 1_193_182;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub(crate) struct DeviceClock {
    sampled_at: Instant,
    fractional_tick: u128,
}

impl DeviceClock {
    pub(crate) fn new() -> Self {
        Self { sampled_at: Instant::now(), fractional_tick: 0 }
    }

    pub(crate) fn advance(&mut self, ports: &mut MachinePorts) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.sampled_at);
        self.sampled_at = now;
        ports.advance_ticks(self.ticks_for(elapsed));
    }

    fn ticks_for(&mut self, elapsed: Duration) -> u64 {
        let numerator = elapsed.as_nanos() * PIT_HZ + self.fractional_tick;
        self.fractional_tick = numerator % NANOS_PER_SECOND;
        // Duration can represent centuries beyond an emulated machine's
        // lifetime. Saturation makes even that input bounded and panic-free.
        u64::try_from(numerator / NANOS_PER_SECOND).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
#[path = "clock/tests.rs"]
mod tests;
