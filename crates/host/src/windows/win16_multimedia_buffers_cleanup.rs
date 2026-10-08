//! Retryable cleanup for process-retained WinMM WAVE and SOUND owners.

use super::*;

impl Win16WaveHost {
    /// Native WAVE handles and SOUND sessions have separate cleanup
    /// contracts; attempt both so one failure never hides the other cause.
    pub(in crate::windows) fn cleanup_retained_owners(&mut self) -> Result<(), RuntimeError> {
        let mut failures = Vec::new();
        failures.try_reserve_exact(2).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE and SOUND cleanup causes",
                error,
            )
        })?;
        if let Err(error) = sound::cleanup(self) {
            failures.push(error.with_context("close SOUND-owned WAVE and PlaySound resources"));
        }
        for device in self.devices.drain(..) {
            let owner_thread = device.owner_thread.clone();
            retired::retain(device, owner_thread, None);
        }
        if let Err(error) = retired::retry_current_thread() {
            failures.push(error.with_context("retry process-retained WAVE devices"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(retired::aggregate_failures(
                "retained multimedia owners remain after cleanup",
                failures,
            ))
        }
    }
}

impl Drop for Win16WaveHost {
    fn drop(&mut self) {
        sound::retain_on_drop(&mut self.sound);
        for device in self.devices.drain(..) {
            let _ = retired::dispose_or_retain(device);
        }
    }
}
