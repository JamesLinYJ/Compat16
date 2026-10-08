//! Route retained SOUND-owned notifications before exposing WAVE events.

use super::*;

pub(super) fn poll(
    host: &mut Win16WaveHost,
) -> Result<Option<Win16HostWaveEvent>, RuntimeError> {
    loop {
        if let Some(event) = host.pending_wave_events.pop_front() {
            match sound::consume_wave_event(host, &event) {
                Ok(true) => continue,
                Ok(false) => return Ok(Some(event)),
                Err(error) => {
                    // Keep the exact owner event when private SOUND handling
                    // reports a retryable failure.
                    host.pending_wave_events.push_front(event);
                    return Err(error);
                }
            }
        }
        let Some(event) = host.poll_native_event()? else {
            if host.pending_wave_events.is_empty() {
                return Ok(None);
            }
            continue;
        };
        match sound::consume_wave_event(host, &event) {
            Ok(true) => continue,
            Ok(false) => return Ok(Some(event)),
            Err(error) => {
                // poll_native_event reserved this slot before consuming the
                // native signal, including space used by Close reaping.
                insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
                return Err(error);
            }
        }
    }
}
