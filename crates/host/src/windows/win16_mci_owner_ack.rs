//! Exact FIFO acknowledgement for one delivered native MCI source.

use super::MciNotificationLedger;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16GuestNotificationSource};

impl MciNotificationLedger {
    pub(super) fn acknowledge(
        &mut self,
        source: Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        if source.id == 0
            || source.id == u64::MAX
            || source.generation == 0
            || source.sequence == 0
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI notification source ACK has a zero or reserved identity component",
            ));
        }
        match self.events.front() {
            Some(event)
                if event.source == source
                    && event.id.0 == source.sequence
                    && event.device.generation == source.generation =>
            {
                self.events.pop_front();
                self.failed_callbacks
                    .retain(|failure| {
                        failure.id.map(|id| id.0) != Some(source.sequence)
                    });
                Ok(())
            }
            Some(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI notification ACK does not match the queue head",
            )),
            None => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI notification ACK has no queued event",
            )),
        }
    }
}
