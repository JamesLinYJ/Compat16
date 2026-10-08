//! Ordinary MIDI UnprepareHeader projection and exact native-row retirement.

use guest_core::memory::Memory;
use std::{error::Error, fmt, sync::Arc};
use win16_abi::{Win16MidiDirection as GuestDirection, MIDIHDR16_SIZE};

use super::{Win16State, MHDR_DONE, MHDR_INQUEUE, MHDR_PREPARED, MIDIERR_UNPREPARED,
    MMSYSERR_INVALHANDLE, MMSYSERR_INVALPARAM, MMSYSERR_NOERROR};
use super::calls::{is_guest_pointer_error, midi_invariant};
use crate::{RuntimeError, RuntimeHost,
    Win16HostMidiCall as HostCall, Win16HostMidiDirection as HostDirection,
    Win16HostMidiResult as HostResult};

impl Win16State {
    pub(super) fn midi_unprepare(
        &mut self,
        direction: GuestDirection,
        guest_device: u16,
        header_far: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let direction = HostDirection::from(direction);
        let Some(device) = self.midi.device(guest_device, direction).copied() else {
            return Ok(MMSYSERR_INVALHANDLE);
        };
        if usize::from(size) != MIDIHDR16_SIZE {
            return Ok(MMSYSERR_INVALPARAM);
        }
        let Some(record) = self.midi.header(guest_device, header_far).cloned() else {
            return Ok(MIDIERR_UNPREPARED);
        };
        if record.host_device != device.host || record.direction != direction {
            return Ok(MIDIERR_UNPREPARED);
        }

        // A successful native Unprepare can precede a guest-memory fault. Its
        // exact native state remains in the runtime row, so retry only the
        // projection and never call WinMM twice for the same header.
        if let Some(state) = record.pending_unprepare_projection.as_ref() {
            let native_result = record.pending_unprepare_native_result.ok_or_else(|| {
                midi_invariant("retained MIDI unprepare projection lost its native MMRESULT")
            })?;
            if native_result != MMSYSERR_NOERROR {
                return Err(midi_invariant(
                    "retained successful MIDI unprepare has a nonzero native MMRESULT",
                ));
            }
            self.commit_pending_unprepare(&record, state, memory)?;
            let _ = self.recycle_retired_midi_header(
                guest_device, header_far, memory, host,
            )?;
            return Ok(native_result);
        }
        if !record.prepared || record.retired {
            return Ok(MIDIERR_UNPREPARED);
        }
        match self.validate_prepared_header(&record, memory) {
            Ok(_) => {}
            Err(error) if is_guest_pointer_error(&error) => return Ok(MMSYSERR_INVALPARAM),
            Err(error) => return Err(error),
        }

        let response = host.win16_midi(HostCall::UnprepareHeader {
            device: device.host,
            header: record.host_header,
        })?;
        let HostResult::Header { result, state } = response else {
            return Err(midi_invariant(
                "MIDI unprepare-header returned the wrong result shape",
            ));
        };
        if result != MMSYSERR_NOERROR {
            if state.as_ref().is_some_and(|state| state.header != record.host_header) {
                return Err(midi_invariant(
                    "failed MIDI unprepare returned a different header",
                ));
            }
            return Ok(result);
        }
        let state = state.ok_or_else(|| {
            midi_invariant("successful MIDI unprepare returned no header state")
        })?;

        let Some(live) = self.midi.headers.iter_mut()
            .find(|entry| entry.host_header == record.host_header)
        else {
            return Err(midi_invariant("unprepare lost the exact guest MIDI header"));
        };
        live.prepared = false;
        live.retired = true;
        live.pending_unprepare_projection = Some(state.clone());
        live.pending_unprepare_native_result = Some(result);

        self.commit_pending_unprepare(&record, &state, memory)?;
        let _ = self.recycle_retired_midi_header(
            guest_device, header_far, memory, host,
        )?;
        Ok(result)
    }

    pub(super) fn commit_pending_unprepare(
        &mut self,
        record: &super::MidiHeaderRecord,
        state: &crate::Win16HostMidiHeaderState,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if let Err(error) = validate_unprepare_state(record, state) {
            return Err(self.retain_unprepare_projection_failure(
                record.host_header,
                error.with_context(
                    "validate exact MIDI state after successful native UnprepareHeader",
                ),
            ));
        }
        if let Err(error) = self.commit_midi_header_state(record, state, None, memory) {
            return Err(self.retain_unprepare_projection_failure(
                record.host_header,
                error.with_context(
                    "project MIDIHDR after successful native UnprepareHeader MMRESULT 0",
                ),
            ));
        }
        let Some(live) = self.midi.headers.iter_mut()
            .find(|entry| entry.host_header == record.host_header)
        else {
            return Err(midi_invariant(
                "committed MIDI unprepare lost the exact runtime header row",
            ));
        };
        live.guest_flags = (live.guest_flags & !(MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE))
            | (state.flags & (MHDR_DONE | MHDR_PREPARED | MHDR_INQUEUE));
        live.pending_unprepare_projection = None;
        live.pending_unprepare_native_result = None;
        Ok(())
    }

    fn retain_unprepare_projection_failure(
        &mut self,
        header: crate::Win16HostMidiHeader,
        error: RuntimeError,
    ) -> RuntimeError {
        let Some(live) = self.midi.headers.iter_mut()
            .find(|entry| entry.host_header == header)
        else {
            return error.with_context(
                "MIDI unprepare projection failure lost its exact runtime owner",
            );
        };
        let first = match live.pending_unprepare_failure.as_ref() {
            Some(first) => Arc::clone(first),
            None => {
                let first = Arc::new(error);
                live.pending_unprepare_failure = Some(Arc::clone(&first));
                return RuntimeError::with_source(
                    first.kind(),
                    "MIDI Unprepare retains its first guest-projection failure",
                    RetainedUnprepareFailure(first),
                );
            }
        };
        RuntimeError::with_source(
            first.kind(),
            "MIDI Unprepare retains its first guest-projection failure",
            RetainedUnprepareFailure(first),
        )
        .with_cleanup("MIDI unprepare projection retry also failed", error)
    }
}

#[derive(Debug)]
struct RetainedUnprepareFailure(Arc<RuntimeError>);

impl fmt::Display for RetainedUnprepareFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl Error for RetainedUnprepareFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) fn validate_unprepare_state(
    record: &super::MidiHeaderRecord,
    state: &crate::Win16HostMidiHeaderState,
) -> Result<(), RuntimeError> {
    if state.header != record.host_header
        || state.capacity != record.capacity
        || state.user != record.user
        || state.bytes_recorded > record.capacity
        || state.submission.is_some()
        || state.completed_submission.is_some()
        || state.input_data.is_some()
        || state.flags & (MHDR_PREPARED | MHDR_INQUEUE) != 0
    {
        return Err(midi_invariant(
            "successful MIDI unprepare returned invalid exact header state",
        ));
    }
    Ok(())
}
