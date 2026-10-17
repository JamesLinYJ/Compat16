//! MMSYSTEM auxiliary audio. Guest device ids and FAR outputs stay checked
//! guest values; the host receives owned bytes and never a physical device.

use guest_core::memory::Memory;
use win16_abi::{AUXCAPS16_SIZE, Access, Win16AuxCapabilities16, Win16AuxRequest};

use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
};
use crate::{
    DiagnosticKind as Kind, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR, RuntimeError, RuntimeHost,
    Win16HostAuxCapabilities, Win16HostAuxOperation as Operation,
    Win16HostAuxResult as ResultValue,
};

impl Win16State {
    pub(in crate::win16_runtime) fn aux_api(
        &mut self,
        request: Win16AuxRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16AuxRequest::GetNumDevs => match host.win16_aux(Operation::GetNumDevs)? {
                ResultValue::Count(count) => Ok(u32::from(count)),
                _ => Err(invariant("auxGetNumDevs returned the wrong result shape")),
            },
            Win16AuxRequest::GetDevCaps {
                device,
                output,
                size,
            } => self.aux_get_dev_caps(device, output, size, memory, host),
            Win16AuxRequest::GetVolume { device, output } => {
                self.aux_get_volume(device, output, memory, host)
            }
            Win16AuxRequest::SetVolume { device, value } => {
                match host.win16_aux(Operation::SetVolume { device, value })? {
                    ResultValue::Status(result) => Ok(result),
                    _ => Err(invariant("auxSetVolume returned the wrong result shape")),
                }
            }
            Win16AuxRequest::OutMessage {
                device,
                message,
                parameter1,
                parameter2,
            } => {
                match host.win16_aux(Operation::OutMessage {
                    device,
                    message,
                    parameter1,
                    parameter2,
                })? {
                    ResultValue::Status(result) => Ok(result),
                    _ => Err(invariant("auxOutMessage returned the wrong result shape")),
                }
            }
        }
    }

    fn aux_get_dev_caps(
        &self,
        device: u16,
        output_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        // A zero length copies nothing and does not query a device, matching
        // the WinMM caps contract already used for WAVE.
        let output_length = usize::from(size).min(AUXCAPS16_SIZE);
        if output_length == 0 {
            return Ok(MMSYSERR_NOERROR);
        }
        let output = match capture_output(self, memory, output_far, output_length) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_aux(Operation::GetDevCaps { device })?;
        let ResultValue::Capabilities {
            result,
            capabilities,
        } = reply
        else {
            return Err(invariant("auxGetDevCaps returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if capabilities.is_some() {
                return Err(invariant("failed auxGetDevCaps returned capability bytes"));
            }
            return Ok(result);
        }
        let capabilities = capabilities
            .ok_or_else(|| invariant("successful auxGetDevCaps omitted capability bytes"))?;
        let mut bytes = encode_capabilities(capabilities).to_vec();
        bytes.truncate(output_length);
        commit_guest_writes(self, memory, vec![(output, bytes)])?;
        Ok(result)
    }

    fn aux_get_volume(
        &self,
        device: u16,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match capture_output(self, memory, output_far, 4) {
            Ok(output) => output,
            Err(error) if is_guest_api_failure(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let reply = host.win16_aux(Operation::GetVolume { device })?;
        let ResultValue::Volume { result, value } = reply else {
            return Err(invariant("auxGetVolume returned the wrong result shape"));
        };
        if result != MMSYSERR_NOERROR {
            if value.is_some() {
                return Err(invariant("failed auxGetVolume returned a volume"));
            }
            return Ok(result);
        }
        let value = value.ok_or_else(|| invariant("successful auxGetVolume omitted its volume"))?;
        commit_guest_writes(self, memory, vec![(output, value.to_le_bytes().to_vec())])?;
        Ok(result)
    }
}

fn capture_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state
        .selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    state
        .selectors
        .translate(pointer, Access::Write, size, memory)
        .map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, size)
}

fn encode_capabilities(capabilities: Win16HostAuxCapabilities) -> [u8; AUXCAPS16_SIZE] {
    Win16AuxCapabilities16 {
        manufacturer_id: capabilities.manufacturer_id,
        product_id: capabilities.product_id,
        driver_version: capabilities.driver_version,
        product_name: capabilities.product_name,
        technology: capabilities.technology,
        support: capabilities.support,
    }
    .encode()
}

fn is_guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
