//! Device-ID volume calls, distinct from opened-handle pitch and rate calls.

use super::calls::commit_one_wave_output;
use super::*;

impl Win16State {
    pub(super) fn wave_get_device_volume(
        &self,
        device_id: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match self.capture_wave_output(memory, output_far, 4) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_wave(Win16HostWaveOperation::GetVolumeById { device_id })?;
        let Win16HostWaveResult::Parameter { result, value } = reply else {
            return Err(wave_invariant(
                "WAVE device-volume getter returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if value.is_some() {
                return Err(wave_invariant(
                    "failed WAVE device-volume getter returned a value",
                ));
            }
            return Ok(result);
        }
        let value = value.ok_or_else(|| {
            wave_invariant("successful WAVE device-volume getter omitted its value")
        })?;
        commit_one_wave_output(self, memory, output, wave_bytes(value.to_le_bytes())?)?;
        Ok(result)
    }

    pub(super) fn wave_set_device_volume(
        &self,
        device_id: u16,
        value: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match host.win16_wave(Win16HostWaveOperation::SetVolumeById { device_id, value })? {
            Win16HostWaveResult::Scalar(result) => Ok(result),
            _ => Err(wave_invariant(
                "WAVE device-volume setter returned the wrong result shape",
            )),
        }
    }
}
