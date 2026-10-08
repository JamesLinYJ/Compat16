//! WindowsHost implementation of the MIDI-specific runtime host seam.

use super::*;

impl runtime::RuntimeMidiHost for WindowsHost {
    fn win16_midi(
        &mut self,
        call: runtime::Win16HostMidiCall,
    ) -> Result<runtime::Win16HostMidiResult, RuntimeError> {
        runtime_host_multimedia::midi_call(self, call)
    }

    fn win16_midi_peek_notification(
        &mut self,
    ) -> Result<Option<runtime::Win16HostMidiNotification>, RuntimeError> {
        runtime_host_multimedia::midi_peek(self)
    }

    fn win16_midi_ack_notification(
        &mut self,
        device: runtime::Win16HostMidiDevice,
        sequence: u64,
        disposition: runtime::Win16HostMidiNotificationDisposition,
    ) -> Result<(), RuntimeError> {
        runtime_host_multimedia::midi_ack(self, device, sequence, disposition)
    }

    fn win16_midi_wait_notification(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<bool, RuntimeError> {
        runtime_host_multimedia::midi_wait(self, timeout)
    }

    fn win16_midi_get_mixer_id(
        &mut self,
        device: runtime::Win16HostMidiDevice,
        expected: runtime::Win16HostMidiDirection,
    ) -> Result<runtime::Win16HostMidiMixerId, RuntimeError> {
        runtime_host_multimedia::midi_get_mixer_id(self, device, expected)
    }

    fn win16_midi_close_all(
        &mut self,
    ) -> Result<runtime::Win16HostMidiCloseAll, RuntimeError> {
        runtime_host_multimedia::midi_close_all(self)
    }

    fn win16_midi_quiesce_all(
        &mut self,
    ) -> Result<runtime::Win16HostMidiProducerQuiescence, RuntimeError> {
        self.win16_midi.quiesce_all()
    }

    fn win16_midi_finalize_closed_device(
        &mut self,
        device: runtime::Win16HostMidiDevice,
    ) -> Result<bool, RuntimeError> {
        runtime_host_multimedia::midi_finalize_closed_device(self, device)
    }
}
