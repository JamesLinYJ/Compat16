//! Win16 MIDI patch-cache array marshalling.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMidiCall as HostCall, Win16HostMidiDirection as HostDirection,
    Win16HostMidiResult as HostResult};

use super::{MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOMEM,
    MMSYSERR_NOERROR, Win16State};

const MIDI_CACHE_ALL: u16 = 1;
const MIDI_CACHE_BESTFIT: u16 = 2;
const MIDI_CACHE_QUERY: u16 = 3;
const MIDI_UNCACHE: u16 = 4;

impl Win16State {
    pub(super) fn midi_cache_patches(
        &mut self,
        guest_device: u16,
        bank: u16,
        patches_far: u32,
        flags: u16,
        drums: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(device) = self.midi.device(guest_device, HostDirection::Output).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        // Every documented output mode must have a writable guest lease before
        // WinMM is allowed to change its native PATCHARRAY.
        let range = match self.capture_midi_range(memory, patches_far, 256, true, true) {
            Ok(range) => range,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        };
        let mut bytes = match range.read(self, memory) {
            Ok(bytes) => bytes,
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) if error.kind() == Kind::ResourceExhausted => return Ok(MMSYSERR_NOMEM),
            Err(error) => return Err(error),
        };
        let values = words(&bytes)?;
        let call = if drums {
            HostCall::OutputCacheDrumPatches { device: device.host, patch: bank,
                keys: values, flags }
        } else {
            HostCall::OutputCachePatches { device: device.host, bank,
                patches: values, flags }
        };
        let response = host.win16_midi(call)?;
        let HostResult::PatchArray { result, values } = response else {
            return Err(midi_invariant("MIDI patch-cache returned the wrong result shape"));
        };
        if patch_array_is_output(flags, result) {
            if values.len() != 128 { return Err(midi_invariant(
                "native MIDI patch-cache output did not return 128 entries")); }
            for (destination, word) in bytes.chunks_exact_mut(2).zip(values) {
                destination.copy_from_slice(&word.to_le_bytes());
            }
            range.commit(self, memory, &bytes)?;
        } else if !values.is_empty() {
            return Err(midi_invariant(
                "MIDI patch-cache returned an array without a documented output result"));
        }
        Ok(result)
    }

    pub(super) fn midi_cache_drum_patches(
        &mut self,
        guest_device: u16,
        patch: u16,
        keys_far: u32,
        flags: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.midi_cache_patches(guest_device, patch, keys_far, flags, true, memory, host)
    }
}

fn words(bytes: &[u8]) -> Result<Vec<u16>, RuntimeError> {
    if bytes.len() != 256 { return Err(midi_invariant("Win16 MIDI patch array is not 128 words")); }
    let mut values = Vec::new();
    values.try_reserve_exact(128).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 MIDI patch array", error))?;
    for word in bytes.chunks_exact(2) { values.push(u16::from_le_bytes([word[0], word[1]])); }
    Ok(values)
}

fn patch_array_is_output(flags: u16, result: u32) -> bool {
    (flags == MIDI_CACHE_ALL && result == MMSYSERR_NOMEM)
        || (flags == MIDI_CACHE_BESTFIT && result == MMSYSERR_NOMEM)
        || (flags == MIDI_CACHE_QUERY && result == MMSYSERR_NOERROR)
        || (flags == MIDI_UNCACHE && result == MMSYSERR_NOERROR)
}

fn is_guest_pointer_error(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn midi_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
