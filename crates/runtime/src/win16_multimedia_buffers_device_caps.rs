//! Win16 WAVE device-capability projection into target-width records.

// `wSize` bounds the caller-visible record prefix. Zero succeeds without a
// device query or output FAR access, matching the WinMM caps contract.

use super::calls::commit_one_wave_output;
use super::*;

impl Win16State {
    pub(super) fn wave_device_capabilities(
        &self,
        direction: Win16WaveDirection,
        device: u16,
        output_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let expected = match direction {
            Win16WaveDirection::Input => WAVEINCAPS16_SIZE,
            Win16WaveDirection::Output => WAVEOUTCAPS16_SIZE,
        };
        let output_length = usize::from(size).min(expected);
        if output_length == 0 {
            return Ok(MMSYSERR_NOERROR);
        }
        let output = match self.capture_wave_output(memory, output_far, output_length) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_wave(Win16HostWaveOperation::DeviceCapabilities {
            direction: host_direction(direction),
            device_id: device,
        })?;
        let Win16HostWaveResult::DeviceCapabilities {
            result,
            capabilities,
        } = reply
        else {
            return Err(wave_invariant(
                "WAVE device-capabilities call returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if capabilities.is_some() {
                return Err(wave_invariant(
                    "failed WAVE device-capabilities call returned output",
                ));
            }
            return Ok(result);
        }
        let capabilities = capabilities.ok_or_else(|| {
            wave_invariant("successful WAVE device-capabilities call omitted output")
        })?;
        // Windows 3.1 WAVEINCAPS and WAVEOUTCAPS store VERSION as a 16-bit
        // UINT. A wider native value is not truncated into the guest record.
        let raw_version = match capabilities {
            Win16HostWaveCapabilities::Input { driver_version, .. }
            | Win16HostWaveCapabilities::Output { driver_version, .. } => driver_version,
        };
        let driver_version = u16::try_from(raw_version).map_err(|_| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                "native WAVE driver version does not fit Win16 VERSION",
            )
        })?;
        let mut bytes = match (direction, capabilities) {
            (
                Win16WaveDirection::Input,
                Win16HostWaveCapabilities::Input {
                    manufacturer_id,
                    product_id,
                    driver_version: _,
                    product_name,
                    formats,
                    channels,
                },
            ) => wave_bytes(
                Win16WaveInputCapabilities16 {
                    manufacturer_id,
                    product_id,
                    driver_version,
                    product_name,
                    formats,
                    channels,
                }
                .encode(),
            )?,
            (
                Win16WaveDirection::Output,
                Win16HostWaveCapabilities::Output {
                    manufacturer_id,
                    product_id,
                    driver_version: _,
                    product_name,
                    formats,
                    channels,
                    support,
                },
            ) => wave_bytes(
                Win16WaveOutputCapabilities16 {
                    manufacturer_id,
                    product_id,
                    driver_version,
                    product_name,
                    formats,
                    channels,
                    support,
                }
                .encode(),
            )?,
            _ => {
                return Err(wave_invariant(
                    "WAVE device-capabilities direction changed at host boundary",
                ));
            }
        };
        bytes.truncate(output_length);
        commit_one_wave_output(self, memory, output, bytes)?;
        Ok(result)
    }
}
