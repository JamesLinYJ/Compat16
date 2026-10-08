//! Guest WAVE Close ordering with exact per-header native Unprepare results.

use super::*;

impl Win16State {
    pub(super) fn wave_control(
        &mut self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        command: Win16WaveControl,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.wave_audio.device(guest_handle, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if command == Win16WaveControl::Close {
            if let Some(result) =
                self.unprepare_for_guest_close(direction, guest_handle, device, memory, host)?
            {
                return Ok(result);
            }
        }
        let command = host_control(command);
        let reply = host.win16_wave(Win16HostWaveOperation::Control {
            device: device.host,
            command,
        })?;
        let Win16HostWaveResult::Scalar(result) = reply else {
            return Err(wave_invariant("WAVE control returned the wrong result"));
        };
        if command == Win16HostWaveControl::Close && result == MMSYSERR_NOERROR {
            let Some(record) = self.wave_audio.devices.iter_mut()
                .find(|record| record.host == device.host
                    && record.generation == device.generation)
            else {
                return Err(wave_invariant(
                    "closed WAVE device disappeared from runtime table",
                ));
            };
            record.closing = true;
            record.close_result = Some(result);
        }
        Ok(result)
    }

    fn unprepare_for_guest_close(
        &mut self,
        direction: Win16WaveDirection,
        guest_handle: u16,
        device: WaveDeviceRecord,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u32>, RuntimeError> {
        let mut headers = Vec::new();
        headers.try_reserve_exact(self.wave_audio.headers.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact WAVE headers before guest Close",
                error,
            )
        })?;
        for record in &self.wave_audio.headers {
            if record.host_device != device.host {
                continue;
            }
            if record.guest_handle != guest_handle || record.direction != direction {
                return Err(wave_invariant(
                    "WAVE Close found a header bound to another guest device identity",
                ));
            }
            if record.native_prepared != record.guest_prepared {
                return Err(wave_invariant(
                    "WAVE Close found different guest and native prepared states",
                ));
            }
            if record.native_prepared {
                headers.push(record.header_far);
            }
        }

        // WinMM keeps each prepared WAVEHDR until a real Unprepare succeeds.
        // A queued header's MMRESULT is returned unchanged; the handle stays live.
        for header_far in headers {
            let result = self.wave_unprepare(
                direction,
                guest_handle,
                header_far,
                WAVEHDR16_SIZE as u16,
                memory,
                host,
            )?;
            if result != MMSYSERR_NOERROR {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}
