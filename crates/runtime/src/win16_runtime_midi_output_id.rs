//! MIDI operations whose Win16 ABI names a device ID rather than a handle.

use guest_core::memory::Memory;
use win16_abi::Win16MidiDirection as GuestDirection;

use super::calls::{is_guest_pointer_error, midi_invariant};
use super::{MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR,
    MMSYSERR_NOTSUPPORTED, Win16State};
use crate::{RuntimeError, RuntimeHost, Win16HostMidiCall as HostCall,
    Win16HostMidiResult as HostResult};

impl Win16State {
    pub(super) fn midi_get_volume(
        &mut self,
        device_id: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match self.capture_midi_range(memory, output_far, 4, false, true) {
            Ok(output) => output,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let response = host.win16_midi(HostCall::OutputGetVolumeById { device_id })?;
        let HostResult::Volume { result, value } = response else {
            return Err(midi_invariant("MIDI output-volume query returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if value.is_some() {
                return Err(midi_invariant("failed MIDI volume query returned a value"));
            }
            return Ok(result);
        }
        let Some(value) = value else {
            return Err(midi_invariant("successful MIDI volume query returned no value"));
        };
        output.commit(self, memory, &value.to_le_bytes())?;
        Ok(result)
    }

    pub(super) fn midi_get_id(
        &mut self,
        direction: GuestDirection,
        guest_device: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(host_device) = self.midi_host(direction.into(), guest_device) else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        let output = match self.capture_midi_range(memory, output_far, 2, false, true) {
            Ok(output) => output,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let response = host.win16_midi(HostCall::GetId { device: host_device })?;
        let HostResult::DeviceId { result, device_id } = response else {
            return Err(midi_invariant("MIDI device-ID query returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if device_id.is_some() {
                return Err(midi_invariant("failed MIDI ID query returned an ID"));
            }
            return Ok(result);
        }
        let Some(device_id) = device_id else {
            return Err(midi_invariant("successful MIDI ID query returned no ID"));
        };
        let Ok(device_id) = u16::try_from(device_id) else {
            self.warn_midi_gap(host, match direction {
                GuestDirection::Input => 312,
                GuestDirection::Output => 215,
            }, "native MIDI device ID does not fit the Win16 output word");
            return Ok(MMSYSERR_NOTSUPPORTED);
        };
        output.commit(self, memory, &device_id.to_le_bytes())?;
        Ok(result)
    }
}
