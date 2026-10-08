//! SOUND.DRV PCM and PlaySound operations on the shared native WAVE owner.
//!
//! Playback tokens name host-owned WAVE sessions and headers. Sound bytes are
//! copied into the same stable native buffers used by ordinary Win16 WAVE;
//! no guest pointer reaches WinMM.

use super::*;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};
use windows_sys::Win32::Media::Audio::PlaySoundW;

#[path = "win16_multimedia_buffers_sound_pcm.rs"]
mod pcm;
#[path = "win16_multimedia_buffers_sound_play.rs"]
mod play_sound;

use runtime::{
    Win16SoundHostOperation as Operation, Win16SoundHostResult as ResultValue, Win16SoundLease,
    Win16SoundPcmFormat, Win16SoundPlayback, Win16SoundPlaybackEvent, Win16SoundSession,
    Win16SoundSource, Win16SoundStopStatus, Win16SoundWaitTarget,
};

const MM_NOERROR: u32 = 0;
const MM_INVALHANDLE: u32 = 5;
const MM_INVALPARAM: u32 = 11;
const MM_NOTSUPPORTED: u32 = 8;
const MM_ALLOCATED: u32 = 4;
const WAVERR_STILLPLAYING: u32 = 33;
const SND_ASYNC: u32 = 0x0001;
const SND_MEMORY: u32 = 0x0004;
const TIME_MS: u32 = 0x0001;
const TIME_SAMPLES: u32 = 0x0002;
const TIME_BYTES: u32 = 0x0004;

#[derive(Default)]
pub(super) struct SoundState {
    sessions: Vec<SoundSessionRecord>,
    playbacks: Vec<SoundPlaybackRecord>,
    events: VecDeque<Win16SoundPlaybackEvent>,
    active_play_sound: Option<PlaySoundLeaseRecord>,
}

struct SoundSessionRecord {
    token: Win16SoundSession,
    device: Win16HostWaveDevice,
    format: Win16HostWaveFormat,
    position_last_raw: Option<u32>,
    position_high: u64,
    position_offset: u64,
    position_reset_pending: bool,
    position_total: u64,
    closing: bool,
    close_sequence: Option<u64>,
}

struct SoundPlaybackRecord {
    token: Win16SoundPlayback,
    session: Win16SoundSession,
    device: Win16HostWaveDevice,
    start_position: u64,
    frames_queued: u64,
    frames_played: u64,
    complete: bool,
    stop_requested: bool,
    chunks: Vec<SoundChunk>,
}

struct SoundChunk {
    buffer: Win16HostWaveBuffer,
    submission: Win16HostWaveSubmission,
    completion_seen: bool,
    retired: bool,
}

struct PlaySoundLeaseRecord {
    token: Win16SoundLease,
    host_identity: Arc<AtomicU64>,
    generation: u64,
}

struct ProcessPlaySoundOwner {
    host_identity: Arc<AtomicU64>,
    token: Win16SoundLease,
    generation: u64,
    // WinMM may keep reading asynchronous PlaySoundW input until a stop or
    // successful replacement. Own its original bytes/path for that full lease.
    _retained_source: PlaySoundSourceOwner,
    owner_thread: ThreadId,
    orphaned: bool,
}

enum PlaySoundSourceOwner {
    Bytes(Vec<u8>),
    // Native playback borrows this allocation until its owner lease retires.
    WidePath { _units: Vec<u16> },
}

struct PlaySoundProcessState {
    next_generation: u64,
    active_owner: Option<ProcessPlaySoundOwner>,
}

impl Default for PlaySoundProcessState {
    fn default() -> Self {
        Self {
            next_generation: 1,
            active_owner: None,
        }
    }
}

static PLAY_SOUND_PROCESS: OnceLock<Mutex<PlaySoundProcessState>> = OnceLock::new();

fn lock_play_sound_process() -> MutexGuard<'static, PlaySoundProcessState> {
    PLAY_SOUND_PROCESS
        .get_or_init(|| Mutex::new(PlaySoundProcessState::default()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn execute(
    host: &mut Win16WaveHost,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::OpenSound { format } => open_sound(host, format),
        Operation::CloseSound { session } => close_sound(host, session),
        Operation::QueryPcmFormat { format } => query_format(host, format),
        Operation::PlayOwnedPcm {
            session,
            format,
            samples,
            note_frame_boundaries,
        } => pcm::play_pcm(host, session, format, samples, note_frame_boundaries),
        Operation::AppendOwnedPcm {
            playback,
            samples,
            note_frame_boundaries,
        } => pcm::append_pcm(host, playback, samples, note_frame_boundaries),
        Operation::PlaybackPosition { playback } => pcm::playback_position(host, playback),
        Operation::RetirePlayback { playback } => pcm::retire_playback(host, playback),
        Operation::WaitPlayback { playback, target } => pcm::wait_playback(host, playback, target),
        Operation::StopPlayback { playback } => pcm::stop_playback(host, playback),
        Operation::PlayWave { source, flags } => play_sound::play_wave(host, source, flags),
        Operation::StopPlayWave { lease } => play_sound::stop_play_wave(host, lease),
    }
}

pub(super) fn poll(
    host: &mut Win16WaveHost,
) -> Result<Option<Win16SoundPlaybackEvent>, RuntimeError> {
    pcm::retry_completed_headers(host)?;
    if let Some(event) = host.sound.events.pop_front() {
        return Ok(Some(event));
    }
    loop {
        if let Some(event) = host.pending_wave_events.pop_front() {
            match consume_wave_event(host, &event) {
                Ok(true) => {
                    if let Some(sound_event) = host.sound.events.pop_front() {
                        return Ok(Some(sound_event));
                    }
                    continue;
                }
                Ok(false) => {
                    host.pending_wave_events.push_front(event);
                    return Ok(host.sound.events.pop_front());
                }
                Err(error) => {
                    host.pending_wave_events.push_front(event);
                    return Err(error);
                }
            }
        }
        // Retain capacity before consuming a native event; if the event belongs
        // to an ordinary Win16 WAVE client it must survive this SOUND poll.
        host.pending_wave_events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve ordinary WAVE event before SOUND poll",
                error,
            )
        })?;
        let Some(event) = host.poll_native_event()? else {
            if !host.pending_wave_events.is_empty() {
                continue;
            }
            pcm::refresh_all_positions(host)?;
            return Ok(host.sound.events.pop_front());
        };
        match consume_wave_event(host, &event) {
            Ok(true) => {
                if let Some(sound_event) = host.sound.events.pop_front() {
                    return Ok(Some(sound_event));
                }
            }
            Ok(false) => {
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
                pcm::refresh_all_positions(host)?;
                return Ok(host.sound.events.pop_front());
            }
            Err(error) => {
                // Capacity was retained before polling, so the native event
                // remains owned and retryable after a fallible SOUND step.
                super::insert_reserved_pending_wave_event(&mut host.pending_wave_events, event);
                return Err(error);
            }
        }
    }
}

pub(super) fn consume_wave_event(
    host: &mut Win16WaveHost,
    event: &Win16HostWaveEvent,
) -> Result<bool, RuntimeError> {
    pcm::consume_wave_event(host, event)
}

pub(super) fn cleanup(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    failures
        .try_reserve_exact(host.sound.sessions.len().saturating_add(2))
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve SOUND cleanup failures",
                error,
            )
        })?;
    if let Err(error) = play_sound::cleanup(host) {
        failures.push(error);
    }
    let mut session_index = 0;
    while session_index < host.sound.sessions.len() {
        let session = host.sound.sessions[session_index].token;
        match close_sound(host, session) {
            Ok(ResultValue::SoundClosed { result })
                if u32::from(result) == MM_NOERROR || u32::from(result) == WAVERR_STILLPLAYING => {}
            Ok(ResultValue::SoundClosed { result }) => {
                failures.push(mm_error("close SOUND WAVE session", u32::from(result)))
            }
            Ok(_) => failures.push(wave_invariant("SOUND cleanup returned the wrong result")),
            Err(error) => failures.push(error.with_context("close SOUND WAVE session")),
        }
        session_index += 1;
    }
    if let Err(error) = play_sound::retry_retired_play_sounds() {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(aggregate_errors(
            "one or more SOUND-owned native resources remain active",
            failures,
        ))
    }
}

/// Retire only orphaned same-thread PlaySound owners here. A live owner still
/// attached to a runtime lease must be stopped through its exact guest token
/// before the shared WAVE/SOUND producer barrier can pass.
pub(super) fn producer_barrier(host: &mut Win16WaveHost) -> Result<(), RuntimeError> {
    play_sound::producer_barrier(host)
}

pub(super) fn retain_on_drop(state: &mut SoundState) {
    play_sound::retain_on_drop(state);
}

fn open_sound(
    host: &mut Win16WaveHost,
    sound_format: Win16SoundPcmFormat,
) -> Result<ResultValue, RuntimeError> {
    if host.sound.sessions.iter().any(|session| session.closing) {
        pcm::poll_preserving_sound_event(host)?;
    }
    if !host.sound.sessions.is_empty() {
        return Ok(ResultValue::SoundOpened {
            result: MM_ALLOCATED as u16,
            session: None,
        });
    }
    let Some((spec, format)) = format_spec(sound_format) else {
        return Ok(ResultValue::SoundOpened {
            result: MM_INVALPARAM as u16,
            session: None,
        });
    };
    host.sound.sessions.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "reserve SOUND session", error)
    })?;
    let token = Win16SoundSession(host.allocate_identity()?);
    let result = host.open(
        Win16HostWaveDirection::Output,
        u16::MAX,
        true,
        Some(spec),
        CALLBACK_FUNCTION_WIN16,
    )?;
    let Win16HostWaveResult::Opened { result, device } = result else {
        return Err(wave_invariant("SOUND WAVE open returned the wrong result"));
    };
    if result != MM_NOERROR {
        if device.is_some() {
            return Err(wave_invariant("failed SOUND open returned a live device"));
        }
        return Ok(ResultValue::SoundOpened {
            result: result as u16,
            session: None,
        });
    }
    let Some(device) = device else {
        return Err(wave_invariant(
            "successful SOUND open omitted its device token",
        ));
    };
    host.sound.sessions.push(SoundSessionRecord {
        token,
        device,
        format,
        position_last_raw: None,
        position_high: 0,
        position_offset: 0,
        position_reset_pending: false,
        position_total: 0,
        closing: false,
        close_sequence: None,
    });
    Ok(ResultValue::SoundOpened {
        result: MM_NOERROR as u16,
        session: Some(token),
    })
}

fn query_format(
    host: &mut Win16WaveHost,
    sound_format: Win16SoundPcmFormat,
) -> Result<ResultValue, RuntimeError> {
    let Some((spec, _)) = format_spec(sound_format) else {
        return Ok(ResultValue::PcmFormat {
            result: MM_INVALPARAM,
            supported: false,
        });
    };
    let result = host.open(
        Win16HostWaveDirection::Output,
        u16::MAX,
        false,
        Some(spec),
        WAVE_FORMAT_QUERY,
    )?;
    let Win16HostWaveResult::Opened { result, device } = result else {
        return Err(wave_invariant(
            "SOUND format query returned the wrong result",
        ));
    };
    if device.is_some() {
        return Err(wave_invariant("SOUND format query allocated a device"));
    }
    Ok(ResultValue::PcmFormat {
        result,
        supported: result == MM_NOERROR,
    })
}

fn format_spec(
    sound_format: Win16SoundPcmFormat,
) -> Option<(Win16HostWaveFormatSpec, Win16HostWaveFormat)> {
    let bytes_per_sample = sound_format.bits_per_sample.checked_div(8)?;
    if sound_format.channels == 0
        || sound_format.samples_per_second == 0
        || bytes_per_sample == 0
        || sound_format.bits_per_sample % 8 != 0
    {
        return None;
    }
    let block_align = sound_format.channels.checked_mul(bytes_per_sample)?;
    let average = sound_format
        .samples_per_second
        .checked_mul(u32::from(block_align))?;
    let format = Win16HostWaveFormat {
        channels: sound_format.channels,
        samples_per_second: sound_format.samples_per_second,
        average_bytes_per_second: average,
        block_align,
        bits_per_sample: sound_format.bits_per_sample,
    };
    Some((
        Win16HostWaveFormatSpec {
            format_tag: 1,
            channels: format.channels,
            samples_per_second: format.samples_per_second,
            average_bytes_per_second: format.average_bytes_per_second,
            block_align: format.block_align,
            bits_per_sample: format.bits_per_sample,
            extension: Vec::new(),
            shape: runtime::Win16HostWaveFormatShape::PcmWaveFormat,
        },
        format,
    ))
}

fn close_sound(
    host: &mut Win16WaveHost,
    token: Win16SoundSession,
) -> Result<ResultValue, RuntimeError> {
    let Some(index) = host
        .sound
        .sessions
        .iter()
        .position(|session| session.token == token)
    else {
        return Ok(ResultValue::SoundClosed {
            result: MM_INVALHANDLE as u16,
        });
    };
    if host.sound.sessions[index].closing {
        pcm::poll_preserving_sound_event(host)?;
        return Ok(ResultValue::SoundClosed {
            result: if host
                .sound
                .sessions
                .iter()
                .any(|session| session.token == token)
            {
                WAVERR_STILLPLAYING as u16
            } else {
                MM_NOERROR as u16
            },
        });
    }
    // Snapshot actual WinMM progress before Reset changes the device's
    // position counter. The per-playback records keep this cumulative value
    // after the native session closes.
    if let Err(result) = pcm::refresh_session_positions_before_reset(host, token)? {
        return Ok(ResultValue::SoundClosed {
            result: result as u16,
        });
    }
    let device = host.sound.sessions[index].device;
    let reset = host.control(device, Win16HostWaveControl::Reset)?;
    let Win16HostWaveResult::Scalar(reset) = reset else {
        return Err(wave_invariant("SOUND reset returned the wrong result"));
    };
    if reset != MM_NOERROR {
        return Ok(ResultValue::SoundClosed {
            result: reset as u16,
        });
    }
    host.sound.sessions[index].position_reset_pending = true;
    for playback in &mut host.sound.playbacks {
        if playback.session == token && !playback.complete {
            playback.stop_requested = true;
        }
    }
    pcm::poll_preserving_sound_event(host)?;
    let mut pending = false;
    for buffer in host
        .devices
        .iter()
        .find(|record| record.token == device)
        .ok_or_else(|| wave_invariant("SOUND session lost its native device"))?
        .buffers
        .iter()
    {
        if buffer.in_flight || buffer.active_submission.is_some() || buffer.signal.peek().is_some()
        {
            pending = true;
        }
    }
    if pending {
        return Ok(ResultValue::SoundClosed {
            result: WAVERR_STILLPLAYING as u16,
        });
    }
    loop {
        let device_record = host
            .devices
            .iter()
            .find(|record| record.token == device)
            .ok_or_else(|| wave_invariant("SOUND session lost its native device"))?;
        let buffer = device_record
            .buffers
            .iter()
            .find(|buffer| buffer.prepared)
            .map(|buffer| buffer.token);
        let Some(buffer) = buffer else {
            break;
        };
        let result = host.unprepare(device, buffer)?;
        let Win16HostWaveResult::Header { result, .. } = result else {
            return Err(wave_invariant("SOUND unprepare returned the wrong result"));
        };
        if result != MM_NOERROR {
            return Ok(ResultValue::SoundClosed {
                result: result as u16,
            });
        }
    }
    let closed = host.control(device, Win16HostWaveControl::Close)?;
    let Win16HostWaveResult::Scalar(closed) = closed else {
        return Err(wave_invariant("SOUND close returned the wrong result"));
    };
    if closed == MM_NOERROR {
        host.sound.sessions[index].closing = true;
    }
    Ok(ResultValue::SoundClosed {
        result: closed as u16,
    })
}

fn mm_error(operation: &'static str, result: u32) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, operation, NativeMmResult(result))
}

#[derive(Debug)]
struct NativeMmResult(u32);

impl fmt::Display for NativeMmResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WinMM returned MMRESULT {}", self.0)
    }
}

impl Error for NativeMmResult {}

fn aggregate_errors(context: &'static str, errors: Vec<RuntimeError>) -> RuntimeError {
    let kind = super::cleanup_failures_kind(&errors);
    RuntimeError::with_source(kind, context, SoundCleanupErrors(errors))
}

#[derive(Debug)]
struct SoundCleanupErrors(Vec<RuntimeError>);

impl fmt::Display for SoundCleanupErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl Error for SoundCleanupErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.first().map(|cause| cause as &(dyn Error + 'static))
    }
}

fn operation_and_cleanup_error(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    let kind = super::cleanup_failure_kind(primary.kind(), cleanup.kind());
    RuntimeError::with_source(
        kind,
        "SOUND native operation and rollback both failed",
        SoundCleanupErrors(vec![primary, cleanup]),
    )
}
