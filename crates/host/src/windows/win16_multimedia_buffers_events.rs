//! Ordered WAVE event retention helpers.

use std::collections::VecDeque;

use super::Win16HostWaveEvent;

pub(in crate::windows) fn insert_reserved_pending_wave_event(
    events: &mut VecDeque<Win16HostWaveEvent>,
    event: Win16HostWaveEvent,
) {
    let index = events
        .iter()
        .position(|queued| queued.sequence > event.sequence)
        .unwrap_or(events.len());
    events.insert(index, event);
}
