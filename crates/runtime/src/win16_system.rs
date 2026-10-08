//! SYSTEM.DRV host services with a direct, type-compatible runtime boundary.

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};

impl Win16State {
    /// SYSTEM.DRV's milliseconds counter shares the host tick source used by
    /// USER.GetTickCount; the guest receives only the documented 32-bit tick
    /// value, never a host handle or pointer.
    pub(super) fn system_msec_count(
        &mut self, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        host.win16_get_tick_count()
    }
}
