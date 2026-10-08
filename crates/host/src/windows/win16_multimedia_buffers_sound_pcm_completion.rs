//! WAVE completion and retirement for SOUND-owned PCM headers.

use super::*;

pub(super) fn update_playback_completion(
    host: &mut Win16WaveHost,
    index: usize,
) -> Result<(), RuntimeError> {
    let complete = host
        .sound
        .playbacks
        .get(index)
        .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
    if !complete.complete && complete.chunks.iter().all(|chunk| chunk.retired) {
        host.sound.events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve SOUND completion event",
                error,
            )
        })?;
        let playback = host
            .sound
            .playbacks
            .get_mut(index)
            .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
        playback.complete = true;
        if !playback.stop_requested {
            playback.frames_played = playback.frames_queued;
        }
        queue_playback_event(host, index, MM_NOERROR)?;
    }
    Ok(())
}

pub(super) fn complete_closed_session_playbacks(
    host: &mut Win16WaveHost,
    session_index: usize,
) -> Result<(), RuntimeError> {
    let session = host
        .sound
        .sessions
        .get(session_index)
        .ok_or_else(|| wave_invariant("SOUND close lost session"))?
        .token;
    for index in 0..host.sound.playbacks.len() {
        if host.sound.playbacks[index].session == session {
            update_playback_completion(host, index)?;
        }
    }
    Ok(())
}

pub(super) fn retire_completed_chunk(
    host: &mut Win16WaveHost,
    playback_index: usize,
    chunk_index: usize,
) -> Result<(), RuntimeError> {
    if host.sound.playbacks[playback_index].chunks[chunk_index].retired {
        return Ok(());
    }
    let session = host.sound.playbacks[playback_index].session;
    let session_index = host
        .sound
        .sessions
        .iter()
        .position(|item| item.token == session)
        .ok_or_else(|| wave_invariant("SOUND completion lost session"))?;
    let device = host.sound.sessions[session_index].device;
    let buffer = host.sound.playbacks[playback_index].chunks[chunk_index].buffer;
    let result = host.unprepare(device, buffer)?;
    let Win16HostWaveResult::Header {
        result,
        buffer: Some(returned),
        ..
    } = result
    else {
        return Err(wave_invariant(
            "SOUND completion unprepare returned the wrong result",
        ));
    };
    if returned != buffer {
        return Err(wave_invariant(
            "SOUND completion unprepare changed buffer identity",
        ));
    }
    if result != MM_NOERROR {
        return Err(mm_error("unprepare completed SOUND header", result));
    }
    host.sound.playbacks[playback_index].chunks[chunk_index].retired = true;
    Ok(())
}

pub(in crate::windows::win16_multimedia_buffers::sound) fn retry_completed_headers(
    host: &mut Win16WaveHost,
) -> Result<(), RuntimeError> {
    for playback_index in 0..host.sound.playbacks.len() {
        for chunk_index in 0..host.sound.playbacks[playback_index].chunks.len() {
            let retry = {
                let chunk = &host.sound.playbacks[playback_index].chunks[chunk_index];
                chunk.completion_seen && !chunk.retired
            };
            if retry {
                retire_completed_chunk(host, playback_index, chunk_index)?;
                update_playback_completion(host, playback_index)?;
            }
        }
        let completion_pending = {
            let playback = &host.sound.playbacks[playback_index];
            !playback.complete && playback.chunks.iter().all(|chunk| chunk.retired)
        };
        if completion_pending {
            update_playback_completion(host, playback_index)?;
        }
    }
    Ok(())
}
