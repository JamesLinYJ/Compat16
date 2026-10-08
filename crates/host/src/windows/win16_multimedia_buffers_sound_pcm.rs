//! PCM SOUND playback records and their native WAVE completion projection.

use super::*;

#[path = "win16_multimedia_buffers_sound_pcm_completion.rs"]
mod completion;
#[path = "win16_multimedia_buffers_sound_pcm_lifecycle.rs"]
mod lifecycle;
use completion::{
    complete_closed_session_playbacks, retire_completed_chunk, update_playback_completion,
};
pub(super) use completion::retry_completed_headers;
pub(super) use lifecycle::{retire_playback, stop_playback, wait_playback};

pub(super) fn consume_wave_event(
    host: &mut Win16WaveHost,
    event: &Win16HostWaveEvent,
) -> Result<bool, RuntimeError> {
    if let Win16HostWaveEventKind::Completed(completion) = &event.kind {
        let playback_chunk = host
            .sound
            .playbacks
            .iter()
            .enumerate()
            .find_map(|(playback_index, playback)| {
                (playback.device == event.device)
                    .then(|| {
                        playback
                            .chunks
                            .iter()
                            .position(|chunk| {
                                chunk.buffer == completion.buffer
                                    && chunk.submission == completion.submission
                            })
                            .map(|chunk_index| (playback_index, chunk_index))
                    })
                    .flatten()
            });
        if let Some((playback_index, chunk_index)) = playback_chunk {
            if !host.sound.playbacks[playback_index].chunks[chunk_index].retired {
                let session = host.sound.playbacks[playback_index].session;
                if !host.sound.sessions.iter().any(|session_record| {
                    session_record.token == session && session_record.device == event.device
                }) {
                    return Err(wave_invariant(
                        "active SOUND completion lost its exact native session",
                    ));
                }
                host.sound.playbacks[playback_index].chunks[chunk_index].completion_seen = true;
                retire_completed_chunk(host, playback_index, chunk_index)?;
            }
            update_playback_completion(host, playback_index)?;
            return Ok(true);
        }
    }
    let Some(session_index) = host
        .sound
        .sessions
        .iter()
        .position(|session| session.device == event.device)
    else {
        return Ok(false);
    };
    match &event.kind {
        Win16HostWaveEventKind::Open => Ok(true),
        Win16HostWaveEventKind::Close => {
            if host.sound.sessions[session_index]
                .close_sequence
                .is_some_and(|sequence| sequence != event.sequence)
            {
                return Err(wave_invariant("SOUND session received a different Close sequence"));
            }
            host.sound.sessions[session_index].closing = true;
            host.sound.sessions[session_index].close_sequence = Some(event.sequence);
            complete_closed_session_playbacks(host, session_index)?;
            Ok(true)
        }
        Win16HostWaveEventKind::Quiescent { close_sequence } => {
            let session = &host.sound.sessions[session_index];
            if !session.closing
                || session.close_sequence != Some(*close_sequence)
                || event.sequence <= *close_sequence
            {
                return Err(wave_invariant(
                    "SOUND Quiescent receipt does not match its retained Close owner",
                ));
            }
            complete_closed_session_playbacks(host, session_index)?;
            let token = host.sound.sessions[session_index].token;
            if host.sound.playbacks.iter().any(|playback| {
                playback.session == token
                    && (!playback.complete || playback.chunks.iter().any(|chunk| !chunk.retired))
            }) {
                return Err(wave_invariant(
                    "SOUND Quiescent receipt arrived before playback headers retired",
                ));
            }
            // Keep completed playback records until their exact runtime ACK;
            // only the native SOUND session owner ends at Quiescent.
            host.sound.sessions.swap_remove(session_index);
            Ok(true)
        }
        Win16HostWaveEventKind::Completed(_) => Err(wave_invariant(
            "SOUND completion does not match an owned playback generation",
        )),
    }
}

pub(super) fn play_pcm(
    host: &mut Win16WaveHost,
    session: Win16SoundSession,
    sound_format: Win16SoundPcmFormat,
    samples: Vec<u8>,
    boundaries: Vec<u64>,
) -> Result<ResultValue, RuntimeError> {
    let Some(session_index) = host
        .sound
        .sessions
        .iter()
        .position(|record| record.token == session)
    else {
        return Ok(ResultValue::PcmStarted {
            result: MM_INVALHANDLE,
            playback: None,
        });
    };
    if host.sound.sessions[session_index].closing
        || format_spec(sound_format)
            .is_none_or(|(_, format)| format != host.sound.sessions[session_index].format)
    {
        return Ok(ResultValue::PcmStarted {
            result: MM_INVALPARAM,
            playback: None,
        });
    }
    if host
        .sound
        .playbacks
        .iter()
        .any(|playback| playback.session == session && !playback.complete)
    {
        return Ok(ResultValue::PcmStarted {
            result: WAVERR_STILLPLAYING,
            playback: None,
        });
    }
    let format = host.sound.sessions[session_index].format;
    let Some(frames) = validate_samples(&samples, format.block_align, &boundaries) else {
        return Ok(ResultValue::PcmStarted {
            result: MM_INVALPARAM,
            playback: None,
        });
    };
    host.sound.playbacks.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "reserve SOUND playback", error)
    })?;
    let mut chunks = Vec::new();
    chunks.try_reserve_exact(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve SOUND playback headers",
            error,
        )
    })?;
    let device = host.sound.sessions[session_index].device;
    let token = Win16SoundPlayback(host.allocate_identity()?);
    let start_position = match session_position(host, session_index) {
        Ok(Ok(value)) => value,
        Ok(Err(result)) => {
            return Ok(ResultValue::PcmStarted {
                result,
                playback: None,
            });
        }
        Err(error) => return Err(error),
    };
    let length = u32::try_from(samples.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "convert SOUND buffer size", error)
    })?;
    let initial = duplicate_bytes(&samples)?;
    let prepared = host.prepare(
        device,
        Win16HostWaveInitialBuffer::Playback { bytes: initial },
        length,
        0,
    )?;
    let Win16HostWaveResult::Header { result, buffer, .. } = prepared else {
        return Err(wave_invariant("SOUND prepare returned the wrong result"));
    };
    if result != MM_NOERROR {
        return Ok(ResultValue::PcmStarted {
            result,
            playback: None,
        });
    }
    let Some(buffer) = buffer else {
        return Err(wave_invariant(
            "successful SOUND prepare returned no header token",
        ));
    };
    let submitted = host.submit(
        device,
        buffer,
        Win16HostWaveSubmit::Playback {
            bytes: samples,
            length,
            flags: 0,
            loops: 0,
        },
    )?;
    let Win16HostWaveResult::Header {
        result, submission, ..
    } = submitted
    else {
        return Err(wave_invariant("SOUND submit returned the wrong result"));
    };
    if result != MM_NOERROR {
        let unprepare = host.unprepare(device, buffer)?;
        if let Win16HostWaveResult::Header {
            result: cleanup, ..
        } = unprepare
        {
            if cleanup != MM_NOERROR {
                return Err(operation_and_cleanup_error(
                    mm_error("submit SOUND PCM", result),
                    mm_error("unprepare rejected SOUND PCM", cleanup),
                ));
            }
        } else {
            return Err(wave_invariant(
                "SOUND rollback unprepare returned the wrong result",
            ));
        }
        return Ok(ResultValue::PcmStarted {
            result,
            playback: None,
        });
    }
    let Some(submission) = submission else {
        return Err(wave_invariant(
            "accepted SOUND PCM omitted submission identity",
        ));
    };
    chunks.push(SoundChunk {
        buffer,
        submission,
        completion_seen: false,
        retired: false,
    });
    host.sound.playbacks.push(SoundPlaybackRecord {
        token,
        session,
        device,
        start_position,
        frames_queued: frames,
        frames_played: 0,
        complete: false,
        stop_requested: false,
        chunks,
    });
    Ok(ResultValue::PcmStarted {
        result,
        playback: Some(token),
    })
}

pub(super) fn append_pcm(
    host: &mut Win16WaveHost,
    token: Win16SoundPlayback,
    samples: Vec<u8>,
    boundaries: Vec<u64>,
) -> Result<ResultValue, RuntimeError> {
    let Some(playback_index) = host
        .sound
        .playbacks
        .iter()
        .position(|record| record.token == token)
    else {
        return Ok(ResultValue::PcmAppended {
            result: MM_INVALHANDLE,
        });
    };
    if host.sound.playbacks[playback_index].complete
        || host.sound.playbacks[playback_index].stop_requested
    {
        return Ok(ResultValue::PcmAppended {
            result: WAVERR_STILLPLAYING,
        });
    }
    let session_index = host.sound.sessions.iter().position(|session| {
        session.token == host.sound.playbacks[playback_index].session && !session.closing
    });
    let Some(session_index) = session_index else {
        return Ok(ResultValue::PcmAppended {
            result: MM_INVALHANDLE,
        });
    };
    let format = host.sound.sessions[session_index].format;
    let Some(frames) = validate_samples(&samples, format.block_align, &boundaries) else {
        return Ok(ResultValue::PcmAppended {
            result: MM_INVALPARAM,
        });
    };
    let Some(total_frames) = host.sound.playbacks[playback_index]
        .frames_queued
        .checked_add(frames)
    else {
        return Ok(ResultValue::PcmAppended {
            result: MM_INVALPARAM,
        });
    };
    host.sound.playbacks[playback_index]
        .chunks
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve appended SOUND header",
                error,
            )
        })?;
    let device = host.sound.sessions[session_index].device;
    let length = u32::try_from(samples.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "convert appended SOUND size",
            error,
        )
    })?;
    let prepared = host.prepare(
        device,
        Win16HostWaveInitialBuffer::Playback {
            bytes: duplicate_bytes(&samples)?,
        },
        length,
        0,
    )?;
    let Win16HostWaveResult::Header { result, buffer, .. } = prepared else {
        return Err(wave_invariant(
            "appended SOUND prepare returned the wrong result",
        ));
    };
    if result != MM_NOERROR {
        return Ok(ResultValue::PcmAppended { result });
    }
    let Some(buffer) = buffer else {
        return Err(wave_invariant(
            "successful appended SOUND prepare returned no header token",
        ));
    };
    let submitted = host.submit(
        device,
        buffer,
        Win16HostWaveSubmit::Playback {
            bytes: samples,
            length,
            flags: 0,
            loops: 0,
        },
    )?;
    let Win16HostWaveResult::Header {
        result, submission, ..
    } = submitted
    else {
        return Err(wave_invariant(
            "appended SOUND submit returned the wrong result",
        ));
    };
    if result != MM_NOERROR {
        let unprepare = host.unprepare(device, buffer)?;
        if let Win16HostWaveResult::Header {
            result: cleanup, ..
        } = unprepare
        {
            if cleanup != MM_NOERROR {
                return Err(operation_and_cleanup_error(
                    mm_error("append SOUND PCM", result),
                    mm_error("unprepare rejected appended SOUND PCM", cleanup),
                ));
            }
        } else {
            return Err(wave_invariant(
                "appended SOUND rollback returned the wrong result",
            ));
        }
        return Ok(ResultValue::PcmAppended { result });
    }
    let Some(submission) = submission else {
        return Err(wave_invariant(
            "accepted appended SOUND PCM omitted submission",
        ));
    };
    host.sound.playbacks[playback_index]
        .chunks
        .push(SoundChunk {
            buffer,
            submission,
            completion_seen: false,
            retired: false,
        });
    host.sound.playbacks[playback_index].frames_queued = total_frames;
    Ok(ResultValue::PcmAppended { result })
}

pub(super) fn playback_position(
    host: &mut Win16WaveHost,
    token: Win16SoundPlayback,
) -> Result<ResultValue, RuntimeError> {
    let Some(index) = host
        .sound
        .playbacks
        .iter()
        .position(|record| record.token == token)
    else {
        return Ok(ResultValue::PlaybackPosition {
            result: MM_INVALHANDLE,
            frames_played: 0,
            complete: false,
        });
    };
    if host.sound.playbacks[index].complete {
        let playback = &host.sound.playbacks[index];
        return Ok(ResultValue::PlaybackPosition {
            result: MM_NOERROR,
            frames_played: playback.frames_played,
            complete: true,
        });
    }
    match refresh_playback_position(host, index) {
        Ok(Ok(())) => {
            let playback = &host.sound.playbacks[index];
            Ok(ResultValue::PlaybackPosition {
                result: MM_NOERROR,
                frames_played: playback.frames_played,
                complete: playback.complete,
            })
        }
        Ok(Err(result)) => Ok(ResultValue::PlaybackPosition {
            result,
            frames_played: host.sound.playbacks[index].frames_played,
            complete: host.sound.playbacks[index].complete,
        }),
        Err(error) => Err(error),
    }
}

fn validate_samples(samples: &[u8], block_align: u16, boundaries: &[u64]) -> Option<u64> {
    if block_align == 0 || samples.is_empty() || samples.len() % usize::from(block_align) != 0 {
        return None;
    }
    let frames = u64::try_from(samples.len() / usize::from(block_align)).ok()?;
    let mut previous = 0;
    for boundary in boundaries {
        if *boundary < previous || *boundary > frames {
            return None;
        }
        previous = *boundary;
    }
    Some(frames)
}

pub(super) fn poll_preserving_sound_event(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    retry_completed_headers(host)?;
    drain_retained_sound_events(host)?;

    // Each native device contributes at most Open, one completion per owned
    // header, and Close to a single drain. Quiescent receipts are already
    // retained by poll_native_event and are drained when it returns None.
    let event_budget = host.devices.iter().fold(1usize, |budget, device| {
        budget.saturating_add(device.buffers.len().saturating_add(2))
    });
    for _ in 0..event_budget {
        // A WAVE event may be removed from the native mailbox before SOUND
        // processing can fail, so reserve its replay slot first.
        host.pending_wave_events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve ordinary WAVE event before SOUND wait",
                error,
            )
        })?;
        let Some(event) = host.poll_native_event()? else {
            drain_retained_sound_events(host)?;
            retry_completed_headers(host)?;
            break;
        };
        match consume_wave_event(host, &event) {
            Ok(true) => {}
            Ok(false) => {
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
            }
            Err(error) => {
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
                return Err(error);
            }
        }
        retry_completed_headers(host)?;
    }
    refresh_all_positions(host)
}

fn drain_retained_sound_events(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    let Some(last_sequence) = host.pending_wave_events.back().map(|event| event.sequence) else {
        return Ok(());
    };
    let mut previous_sequence = None;
    loop {
        let next = host.pending_wave_events.iter().position(|event| {
            event.sequence <= last_sequence
                && previous_sequence.is_none_or(|previous| event.sequence > previous)
        });
        let Some(index) = next else {
            break;
        };
        let event = host
            .pending_wave_events
            .remove(index)
            .ok_or_else(|| wave_invariant("retained WAVE event disappeared during SOUND drain"))?;
        previous_sequence = Some(event.sequence);
        match consume_wave_event(host, &event) {
            Ok(true) => {}
            Ok(false) => {
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
            }
            Err(error) => {
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
                return Err(error);
            }
        }
    }
    Ok(())
}

fn duplicate_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut duplicate = Vec::new();
    duplicate.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy owned SOUND PCM", error)
    })?;
    duplicate.extend_from_slice(bytes);
    Ok(duplicate)
}

fn session_position(
    host: &mut Win16WaveHost,
    index: usize,
) -> Result<Result<u64, u32>, RuntimeError> {
    let session = host
        .sound
        .sessions
        .get(index)
        .ok_or_else(|| wave_invariant("SOUND session disappeared"))?;
    let device = session.device;
    let format = session.format;
    let result = host.get_position(device, TIME_SAMPLES)?;
    let Win16HostWaveResult::Position { result, position } = result else {
        return Err(wave_invariant(
            "SOUND position query returned the wrong result shape",
        ));
    };
    if result != MM_NOERROR {
        return Ok(Err(result));
    }
    let Some(position) = position else {
        return Err(wave_invariant(
            "successful SOUND position query omitted its value",
        ));
    };
    let raw = match position.time_type {
        TIME_SAMPLES => match position.value[..4].try_into() {
            Ok(bytes) => u32::from_le_bytes(bytes),
            Err(_) => return Ok(Err(MM_NOTSUPPORTED)),
        },
        TIME_BYTES => {
            let bytes = match position.value[..4].try_into() {
                Ok(bytes) => u32::from_le_bytes(bytes),
                Err(_) => return Ok(Err(MM_NOTSUPPORTED)),
            };
            bytes / u32::from(format.block_align)
        }
        TIME_MS => {
            let milliseconds = match position.value[..4].try_into() {
                Ok(bytes) => u32::from_le_bytes(bytes),
                Err(_) => return Ok(Err(MM_NOTSUPPORTED)),
            };
            match u64::from(milliseconds)
                .checked_mul(u64::from(format.samples_per_second))
                .and_then(|frames| frames.checked_div(1000))
                .and_then(|frames| u32::try_from(frames).ok())
            {
                Some(frames) => frames,
                None => return Ok(Err(MM_INVALPARAM)),
            }
        }
        _ => return Ok(Err(MM_NOTSUPPORTED)),
    };
    let session = host
        .sound
        .sessions
        .get_mut(index)
        .ok_or_else(|| wave_invariant("SOUND session disappeared"))?;
    if let Some(previous) = session.position_last_raw {
        if session.position_reset_pending && raw < previous {
            session.position_offset = session.position_total.saturating_sub(u64::from(raw));
            session.position_high = 0;
        } else if !session.position_reset_pending
            && raw < previous
            && previous.wrapping_sub(raw) > (1_u32 << 31)
        {
            let Some(next) = session.position_high.checked_add(1_u64 << 32) else {
                return Ok(Err(MM_INVALPARAM));
            };
            session.position_high = next;
        }
    }
    session.position_reset_pending = false;
    session.position_last_raw = Some(raw);
    let Some(total) = session
        .position_offset
        .checked_add(session.position_high)
        .and_then(|position| position.checked_add(u64::from(raw)))
    else {
        return Ok(Err(MM_INVALPARAM));
    };
    // Native position can be coarse and occasionally repeat a prior sample.
    // Keep the session ledger monotonic; a later observation can advance it.
    session.position_total = session.position_total.max(total);
    Ok(Ok(session.position_total))
}

fn refresh_playback_position(
    host: &mut Win16WaveHost,
    index: usize,
) -> Result<Result<(), u32>, RuntimeError> {
    let playback = host
        .sound
        .playbacks
        .get(index)
        .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
    let session_token = playback.session;
    let start_position = playback.start_position;
    let frames_queued = playback.frames_queued;
    let session_index = host
        .sound
        .sessions
        .iter()
        .position(|session| session.token == session_token)
        .ok_or_else(|| wave_invariant("SOUND session disappeared"))?;
    let position = match session_position(host, session_index)? {
        Ok(position) => position,
        Err(result) => return Ok(Err(result)),
    };
    let playback = host
        .sound
        .playbacks
        .get_mut(index)
        .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
    playback.frames_played = playback
        .frames_played
        .max(position.saturating_sub(start_position))
        .min(frames_queued);
    Ok(Ok(()))
}

pub(super) fn refresh_all_positions(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    refresh_positions(host, false, None).map(|_| ())
}

pub(super) fn refresh_session_positions_before_reset(
    host: &mut Win16WaveHost,
    session: Win16SoundSession,
) -> Result<Result<(), u32>, RuntimeError> {
    refresh_positions(host, true, Some(session))
}

fn refresh_positions(
    host: &mut Win16WaveHost,
    preserve_native_failure: bool,
    session_filter: Option<Win16SoundSession>,
) -> Result<Result<(), u32>, RuntimeError> {
    host.sound
        .events
        .try_reserve(host.sound.playbacks.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve SOUND position events",
                error,
            )
        })?;
    for index in 0..host.sound.playbacks.len() {
        if host.sound.playbacks[index].complete {
            continue;
        }
        if session_filter
            .as_ref()
            .is_some_and(|session| host.sound.playbacks[index].session != *session)
        {
            continue;
        }
        let prior = host.sound.playbacks[index].frames_played;
        match refresh_playback_position(host, index) {
            Ok(Ok(())) => {
                if host.sound.playbacks[index].frames_played != prior {
                    queue_playback_event(host, index, MM_NOERROR)?;
                }
            }
            // Reset destroys the position counter; let Stop/Close return the
            // real MMRESULT before either operation can reset or retire it.
            Ok(Err(result)) if preserve_native_failure => return Ok(Err(result)),
            Ok(Err(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Ok(()))
}

pub(super) fn queue_playback_event(
    host: &mut Win16WaveHost,
    playback_index: usize,
    result: u32,
) -> Result<(), RuntimeError> {
    host.sound.events.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve SOUND playback event",
            error,
        )
    })?;
    let playback = host
        .sound
        .playbacks
        .get(playback_index)
        .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
    host.sound.events.push_back(Win16SoundPlaybackEvent {
        playback: playback.token,
        frames_played: playback.frames_played,
        complete: playback.complete,
        result,
    });
    Ok(())
}
