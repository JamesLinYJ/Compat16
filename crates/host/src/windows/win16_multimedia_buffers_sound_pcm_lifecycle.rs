//! Playback queries, stop, and exact caller retirement for SOUND PCM.

use std::time::Duration;

use super::{
    poll_preserving_sound_event, refresh_playback_position,
    refresh_session_positions_before_reset, update_playback_completion,
};
use super::super::{
    wave_invariant, ResultValue, RuntimeError, Win16HostWaveControl, Win16HostWaveResult,
    Win16SoundPlayback, Win16SoundStopStatus, Win16SoundWaitTarget, Win16WaveHost,
    MM_INVALHANDLE, MM_NOERROR, WAVERR_STILLPLAYING,
};

pub(in crate::windows::win16_multimedia_buffers::sound) fn retire_playback(
    host: &mut Win16WaveHost,
    token: Win16SoundPlayback,
) -> Result<ResultValue, RuntimeError> {
    if !host.sound.playbacks.iter().any(|record| record.token == token) {
        return Ok(ResultValue::PlaybackRetired { result: MM_NOERROR });
    }
    poll_preserving_sound_event(host)?;
    let Some(index) = host.sound.playbacks.iter().position(|record| record.token == token) else {
        return Ok(ResultValue::PlaybackRetired { result: MM_NOERROR });
    };
    let playback = &host.sound.playbacks[index];
    if !playback.complete {
        return Ok(ResultValue::PlaybackRetired { result: WAVERR_STILLPLAYING });
    }
    if playback.chunks.iter().any(|chunk| !chunk.retired) {
        return Err(wave_invariant(
            "completed SOUND playback retained a prepared native header",
        ));
    }
    let has_retained_completion = host.pending_wave_events.iter().any(|event| {
        event.device == playback.device
            && match &event.kind {
                super::super::super::Win16HostWaveEventKind::Completed(completion) => playback
                    .chunks
                    .iter()
                    .any(|chunk| {
                        chunk.buffer == completion.buffer
                            && chunk.submission == completion.submission
                    }),
                _ => false,
            }
    });
    if has_retained_completion {
        return Ok(ResultValue::PlaybackRetired {
            result: WAVERR_STILLPLAYING,
        });
    }
    host.sound.playbacks.swap_remove(index);
    host.sound.events.retain(|event| event.playback != token);
    Ok(ResultValue::PlaybackRetired { result: MM_NOERROR })
}

pub(in crate::windows::win16_multimedia_buffers::sound) fn wait_playback(
    host: &mut Win16WaveHost,
    token: Win16SoundPlayback,
    target: Win16SoundWaitTarget,
) -> Result<ResultValue, RuntimeError> {
    let Some(index) = host.sound.playbacks.iter().position(|record| record.token == token) else {
        return Ok(ResultValue::PlaybackWait {
            result: MM_INVALHANDLE,
            frames_played: 0,
            complete: false,
        });
    };
    loop {
        poll_preserving_sound_event(host)?;
        let (complete, frames_played) = host
            .sound
            .playbacks
            .get(index)
            .map(|playback| (playback.complete, playback.frames_played))
            .ok_or_else(|| wave_invariant("SOUND playback disappeared"))?;
        if complete {
            return Ok(ResultValue::PlaybackWait {
                result: MM_NOERROR,
                frames_played,
                complete: true,
            });
        }
        if let Err(result) = refresh_playback_position(host, index)? {
            let playback = &host.sound.playbacks[index];
            return Ok(ResultValue::PlaybackWait {
                result,
                frames_played: playback.frames_played,
                complete: playback.complete,
            });
        }
        let playback = &host.sound.playbacks[index];
        let target_reached = match target {
            Win16SoundWaitTarget::PlaybackComplete => playback.complete,
            Win16SoundWaitTarget::SampleFrame(frame) => {
                playback.frames_played >= frame || playback.complete
            }
        };
        if target_reached {
            return Ok(ResultValue::PlaybackWait {
                result: MM_NOERROR,
                frames_played: playback.frames_played,
                complete: playback.complete,
            });
        }
        let observed = host.callback_wake.generation();
        host.callback_wake.wait_for_change(observed, Duration::from_millis(25));
    }
}

pub(in crate::windows::win16_multimedia_buffers::sound) fn stop_playback(
    host: &mut Win16WaveHost,
    token: Win16SoundPlayback,
) -> Result<ResultValue, RuntimeError> {
    let Some(index) = host.sound.playbacks.iter().position(|record| record.token == token) else {
        return Ok(ResultValue::PlaybackStopped {
            result: MM_INVALHANDLE,
            status: Win16SoundStopStatus::NotOwned,
        });
    };
    if host.sound.playbacks[index].complete {
        return Ok(ResultValue::PlaybackStopped {
            result: MM_NOERROR,
            status: Win16SoundStopStatus::Stopped,
        });
    }
    let session_token = host.sound.playbacks[index].session;
    let Some(session_index) = host.sound.sessions.iter()
        .position(|session| session.token == session_token)
    else {
        return Ok(ResultValue::PlaybackStopped {
            result: MM_INVALHANDLE,
            status: Win16SoundStopStatus::NotOwned,
        });
    };
    // Capture the exact position before Reset changes the device counter.
    if let Err(result) = refresh_session_positions_before_reset(host, session_token)? {
        return Ok(ResultValue::PlaybackStopped {
            result,
            status: Win16SoundStopStatus::Pending,
        });
    }
    let reset = host.control(
        host.sound.sessions[session_index].device,
        Win16HostWaveControl::Reset,
    )?;
    let Win16HostWaveResult::Scalar(result) = reset else {
        return Err(wave_invariant("SOUND playback reset returned the wrong result"));
    };
    if result != MM_NOERROR {
        return Ok(ResultValue::PlaybackStopped {
            result,
            status: Win16SoundStopStatus::Pending,
        });
    }
    host.sound.sessions[session_index].position_reset_pending = true;
    host.sound.playbacks[index].stop_requested = true;
    poll_preserving_sound_event(host)?;
    update_playback_completion(host, index)?;
    Ok(ResultValue::PlaybackStopped {
        result: MM_NOERROR,
        status: if host.sound.playbacks[index].complete {
            Win16SoundStopStatus::Stopped
        } else {
            Win16SoundStopStatus::Pending
        },
    })
}
