//! Legacy TIMER driver procedure behavior.

use win16_abi::Win16TimerDriverProcRequest;

use super::Win16State;

impl Win16State {
    /// The TIMER.DRV procedure is a known Win16 driver stub; its defined
    /// fallback result is zero for every message.
    pub(super) fn timer_driver_proc(&self, _request: Win16TimerDriverProcRequest) -> u32 {
        0
    }
}
