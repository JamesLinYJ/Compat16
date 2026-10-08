//! Native WAVE producer stop and exact host Close/Quiescent consumption.

use std::time::Duration;

use super::*;
use super::cleanup::{unprepare_for_cleanup, wave_cleanup_error};

pub(super) fn close_quiesced_wave_devices(
    state: &mut Win16State,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let mut devices = Vec::new();
    devices.try_reserve_exact(state.wave_audio.devices.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve WAVE final-close device snapshot",
            error,
        )
    })?;
    devices.extend(state.wave_audio.devices.iter().copied());

    for device in devices {
        let Some(current) = state.wave_audio.devices.iter().find(|current| {
            current.host == device.host && current.generation == device.generation
        }).copied() else {
            continue;
        };
        if current.closing {
            if current.close_result != Some(MMSYSERR_NOERROR) {
                return Err(wave_invariant(
                    "closed WAVE owner has no exact successful Close receipt",
                ));
            }
            wait_for_device_quiescence(state, current, memory, host)?;
            continue;
        }
        if current.reset_result != Some(MMSYSERR_NOERROR) {
            return Err(wave_invariant(
                "WAVE final Close began without a successful producer Reset receipt",
            ));
        }

        loop {
            let Some(record) = state.wave_audio.headers.iter().find(|record| {
                record.host_device == device.host
                    && (record.native_prepared || record.submission.is_some())
            }).cloned() else {
                break;
            };
            if !record.native_prepared {
                // A live guest callback/source may pin this row after native
                // completion. Drain only the exact submission before Close;
                // row release waits for callback/source retirement.
                wait_for_submission_retirement(state, record.host_buffer, memory, host)?;
                continue;
            }
            let result = unprepare_for_cleanup(state, &record, memory, host)?;
            if result == MMSYSERR_NOERROR {
                continue;
            }
            if result == WAVERR_STILLPLAYING {
                wait_for_submission_retirement(state, record.host_buffer, memory, host)?;
                let current = state.wave_audio.headers.iter().find(|current| {
                    current.host_buffer == record.host_buffer
                }).cloned().ok_or_else(|| {
                    wave_invariant("WAVE header disappeared before unprepare retry")
                })?;
                let retry = unprepare_for_cleanup(state, &current, memory, host)?;
                if retry == MMSYSERR_NOERROR {
                    continue;
                }
                return Err(wave_cleanup_error("unprepare after reset", retry));
            }
            return Err(wave_cleanup_error("unprepare", result));
        }

        let close = host.win16_wave(Win16HostWaveOperation::Control {
            device: device.host,
            command: Win16HostWaveControl::Close,
        })?;
        let Win16HostWaveResult::Scalar(close) = close else {
            return Err(wave_invariant("WAVE close returned the wrong result"));
        };
        let record = state.wave_audio.devices.iter_mut().find(|record| {
            record.host == device.host && record.generation == device.generation
        }).ok_or_else(|| wave_invariant(
            "WAVE device generation disappeared after native Close",
        ))?;
        record.close_result = Some(close);
        if close != MMSYSERR_NOERROR {
            return Err(wave_cleanup_error("close", close));
        }
        record.closing = true;
        wait_for_device_quiescence(state, device, memory, host)?;
    }
    Ok(())
}

fn wait_for_submission_retirement(
    state: &mut Win16State,
    buffer: Win16HostWaveBuffer,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    while state.wave_audio.headers.iter().any(|record| {
        record.host_buffer == buffer && record.submission.is_some()
    }) {
        wait_and_consume_wave_event(state, memory, host)?;
    }
    Ok(())
}

fn wait_for_device_quiescence(
    state: &mut Win16State,
    expected: WaveDeviceRecord,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    loop {
        let Some(record) = state.wave_audio.devices.iter()
            .find(|record| record.host == expected.host)
        else {
            if state.wave_audio.pending_callbacks.iter().any(|source| {
                source.source.id == expected.host.0
                    && source.source.generation == expected.generation
            }) {
                return Err(wave_invariant(
                    "WAVE producer generation retired while its exact source row remained",
                ));
            }
            return Ok(());
        };
        if record.generation != expected.generation {
            return Err(wave_invariant(
                "WAVE host token was rebound to another device generation during cleanup",
            ));
        }
        if !record.closing || record.close_result != Some(MMSYSERR_NOERROR) {
            return Err(wave_invariant(
                "WAVE quiescence wait lacks an exact successful native Close",
            ));
        }
        if let Some(quiescence_sequence) = record.producer_quiescence_sequence {
            let close_sequence = record.close_event_sequence.ok_or_else(|| {
                wave_invariant("WAVE Quiescent receipt has no matching Close event")
            })?;
            if quiescence_sequence <= close_sequence
                || record.last_received_sequence != quiescence_sequence
                || state.wave_audio.pending_host_events.iter()
                    .any(|event| event.device == expected.host)
            {
                return Err(wave_invariant(
                    "WAVE terminal receipt changed its exact native device generation",
                ));
            }
            return Ok(());
        }
        wait_and_consume_wave_event(state, memory, host)?;
    }
}

pub(super) fn validate_quiescent_wave_sources(
    state: &Win16State,
) -> Result<(), RuntimeError> {
    for source in &state.wave_audio.pending_callbacks {
        let Some(device) = state.wave_audio.devices.iter().find(|device| {
            device.host.0 == source.source.id && device.generation == source.source.generation
        }) else {
            return Err(wave_invariant(
                "WAVE source row lost its exact producer generation before central retirement",
            ));
        };
        let (Some(close_sequence), Some(quiescence_sequence)) =
            (device.close_event_sequence, device.producer_quiescence_sequence)
        else {
            return Err(wave_invariant(
                "WAVE source row has no consumed native Close and Quiescent pair",
            ));
        };
        if !device.closing
            || device.close_result != Some(MMSYSERR_NOERROR)
            || quiescence_sequence <= close_sequence
            || device.last_received_sequence != quiescence_sequence
            || source.source.sequence > close_sequence
            || state.wave_audio.pending_host_events.iter()
                .any(|event| event.device == device.host)
        {
            return Err(wave_invariant(
                "WAVE source row is not covered by its exact terminal producer generation",
            ));
        }
    }
    Ok(())
}

fn wait_and_consume_wave_event(
    state: &mut Win16State,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    state.wave_audio.pending_host_events.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve WAVE host event queue during cleanup",
            error,
        )
    })?;
    if let Some(event) = host.win16_wave_poll_wait(Duration::from_millis(25))? {
        state.wave_audio.pending_host_events.push_back(event);
    }
    // A bounded wait only services queued host work; timeout is not completion.
    host.pump_events()?;
    state.poll_wave_events(memory, host, true)?;
    Ok(())
}
