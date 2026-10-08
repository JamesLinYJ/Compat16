//! MIDI-specific operations at the runtime/host boundary.

use crate::RuntimeError;

/// Host operations for owned Win16 MIDI devices and their notifications.
///
/// The methods remain object-safe so callers can use the family through a
/// `dyn RuntimeHost`; the umbrella trait supplies this family as a supertrait.
pub trait RuntimeMidiHost {
    /// Execute one checked Win16 MIDI operation using opaque host-owned handles.
    fn win16_midi(
        &mut self,
        _call: crate::Win16HostMidiCall,
    ) -> Result<crate::Win16HostMidiResult, RuntimeError> {
        Err(crate::win16_host_midi::unavailable())
    }

    /// Peek without retiring the source; exact ACK follows guest publication or callback return.
    fn win16_midi_peek_notification(
        &mut self,
    ) -> Result<Option<crate::Win16HostMidiNotification>, RuntimeError> {
        Ok(None)
    }

    fn win16_midi_ack_notification(
        &mut self,
        _device: crate::Win16HostMidiDevice,
        _sequence: u64,
        _disposition: crate::Win16HostMidiNotificationDisposition,
    ) -> Result<(), RuntimeError> {
        Err(crate::win16_host_midi::unavailable())
    }

    /// A wake is only a hint to poll the owned native queue, never an ACK.
    fn win16_midi_wait_notification(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    fn win16_midi_finalize_closed_device(
        &mut self,
        _device: crate::Win16HostMidiDevice,
    ) -> Result<bool, RuntimeError> {
        Ok(false)
    }

    fn win16_midi_get_mixer_id(
        &mut self,
        _device: crate::Win16HostMidiDevice,
        _expected: crate::Win16HostMidiDirection,
    ) -> Result<crate::Win16HostMidiMixerId, RuntimeError> {
        Err(crate::win16_host_midi::unavailable())
    }

    fn win16_midi_close_all(
        &mut self,
    ) -> Result<crate::Win16HostMidiCloseAll, RuntimeError> {
        Ok(crate::Win16HostMidiCloseAll {
            devices: Vec::new(),
            failures: Vec::new(),
        })
    }

    /// Stop new MIDI producer activity while retaining each native device,
    /// callback registration, prepared header, and sample allocation. Hosts
    /// must return an exact snapshot of every native owner; unsupported hosts
    /// must fail instead of claiming an empty registry.
    fn win16_midi_quiesce_all(
        &mut self,
    ) -> Result<crate::Win16HostMidiProducerQuiescence, RuntimeError> {
        Err(crate::win16_host_midi::unavailable())
    }
}
