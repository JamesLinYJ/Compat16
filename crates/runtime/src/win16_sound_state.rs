//! Per-task SOUND queue, native playback token, and persistent threshold word.

use win16_abi::{GlobalHandle, SelectorRef};
use std::sync::Arc;

use super::sound_queue::{QueueSnapshotError, RenderedQueue, VoiceQueue};
use super::{global_memory::GlobalTeardownResult, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16SoundHostOperation as Op,
    Win16SoundHostResult as ResultValue, Win16SoundPlayback, Win16SoundSession,
    Win16SoundStopStatus};
use guest_core::memory::Memory;
pub(super) const MAX_SOUND_VOICES: usize = 16;
const PCM_CHANNELS: u16 = 1;
const PCM_BITS: u16 = 8;

#[derive(Clone)]
pub(super) struct ThresholdEventWord {
    pub(super) handle: u16,
    pub(super) allocation: GlobalHandle,
    pub(super) selector: Option<SelectorRef>,
    pub(super) address: u32,
    retirement_cause: Option<Arc<RuntimeError>>,
}

pub(super) struct ActiveSoundPlayback {
    pub(super) token: Win16SoundPlayback,
    pub(super) submitted_frames: u64,
    pub(super) observed_frames: u64,
    /// Set after StopPlayback is requested. Completion can then mean the
    /// owner quiesced a partial buffer instead of naturally playing it all.
    pub(super) stopping: bool,
    /// A positive Stopped/NotOwned/complete receipt means native playback is
    /// retired. Keep this exact token and snapshots until its final measured
    /// position is committed; retry position only, never StopPlayback again.
    pub(super) stop_confirmed: bool,
    pub(super) snapshots: Vec<RenderedQueue>,
}

pub(super) struct Win16SoundState {
    pub(super) work: parallel_work::SharedExecutor,
    pub(super) session: Option<Win16SoundSession>,
    pub(super) voices: Vec<VoiceQueue>,
    pub(super) active: Option<ActiveSoundPlayback>,
    /// Keep every token until the shared owner confirms retirement. A successful
    /// native call can replace another task's current token, and a missing
    /// `retired_lease` does not prove that this task's prior memory lease ended.
    pub(super) play_wave_leases: Vec<crate::Win16SoundLease>,
    pub(super) threshold_word: Option<ThresholdEventWord>,
}

impl Default for Win16SoundState {
    fn default() -> Self {
        Self { work: Arc::new(parallel_work::BoundedExecutor::new()), session: None, voices: Vec::new(), active: None,
            play_wave_leases: Vec::new(), threshold_word: None }
    }
}

impl Win16SoundState {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        self.session.is_some()
            || self.active.is_some()
            || !self.play_wave_leases.is_empty()
            || self.threshold_word.as_ref().is_some_and(|word| word.retirement_cause.is_some())
    }

    pub(super) fn is_playing(&self) -> bool { self.active.is_some() }

    pub(super) fn native_sources_quiescent(&self) -> bool {
        self.active.is_none() && self.session.is_none() && self.play_wave_leases.is_empty()
    }

    fn remember_threshold_retirement_failure(&mut self, error: RuntimeError) -> RuntimeError {
        let Some(word) = self.threshold_word.as_mut() else { return error; };
        if let Some(cause) = &word.retirement_cause {
            return RuntimeError::with_source(
                cause.kind().with_cleanup(error.kind()),
                "SOUND threshold owner retry retained its first typed cleanup cause",
                Arc::clone(cause),
            ).with_cleanup("retrying SOUND threshold owner retirement", error);
        }
        let cause = Arc::new(error);
        let report = RuntimeError::with_source(
            cause.kind(),
            "SOUND threshold owner retained its initial typed cleanup cause",
            Arc::clone(&cause),
        );
        word.retirement_cause = Some(cause);
        report
    }

    pub(super) fn voice_index(&self, voice: i16) -> Option<usize> {
        let index = usize::try_from(voice.checked_sub(1)?).ok()?;
        (index < self.voices.len()).then_some(index)
    }

    pub(super) fn threshold_status(&self) -> u16 {
        self.voices.iter().take(MAX_SOUND_VOICES).enumerate().fold(0, |bits, (index, voice)| {
            if voice.below_threshold() { bits | (1_u16 << index) } else { bits }
        })
    }

    pub(super) fn threshold_event(&self) -> bool {
        self.voices.iter().any(VoiceQueue::threshold_event)
    }

    pub(super) fn clear_threshold_events(&mut self) {
        for voice in &mut self.voices { voice.clear_threshold_event(); }
    }
}

impl Win16State {
    pub(super) fn ensure_sound_threshold_word(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if self.sound.threshold_word.is_none() {
            // A fixed, zero-initialized Win16 global block gives the SDK's
            // GetThresholdEvent pointer real guest storage with selector and
            // heap generations, rather than a synthetic FAR address.
            let handle = self.global_alloc(0x0040, 2, memory, host)?;
            if handle == 0 { return Ok(0); }
            let address = self.global_lock(handle, memory)?;
            let Some(allocation) = self.global_handles.get(&handle).copied() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND threshold allocation lost its global identity"));
            };
            let Some(selector) = self.global_selectors.get(&handle).copied() else {
                self.sound.threshold_word = Some(ThresholdEventWord {
                    handle, allocation, selector: None, address: 0,
                    retirement_cause: None,
                });
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND threshold allocation lost its selector identity"));
            };
            if address != (u32::from(selector.raw().0) << 16) {
                self.sound.threshold_word = Some(ThresholdEventWord {
                    handle, allocation, selector: Some(selector), address,
                    retirement_cause: None,
                });
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND threshold FAR pointer disagrees with its selector identity"));
            }
            self.sound.threshold_word = Some(ThresholdEventWord {
                handle, allocation, selector: Some(selector), address,
                retirement_cause: None,
            });
        }
        self.write_sound_threshold_word(memory)?;
        Ok(self.sound.threshold_word.as_ref().map_or(0, |word| word.address))
    }

    pub(super) fn write_sound_threshold_word(
        &self,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let Some(word) = self.sound.threshold_word.clone() else { return Ok(()); };
        if self.global_handles.get(&word.handle).copied() != Some(word.allocation)
            || word.selector.is_none()
            || self.global_selectors.get(&word.handle).copied() != word.selector
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND threshold FAR pointer refers to a stale global generation"));
        }
        let selector = word.selector.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "SOUND threshold owner has no selector generation"))?;
        let pointer = self.selectors.pointer_from_raw(selector.raw(), 0)
            .map_err(crate::runtime_error)?;
        let value = if self.sound.threshold_event() { 1_i16 } else { 0_i16 };
        self.write_text_bytes(memory, pointer, &value.to_le_bytes())
    }

    /// Poll only the shared WAVE owner's measured position/completion. The
    /// retained SOUND program advances a cursor at rendered note boundaries,
    /// never from a clock or destructive queue drain.
    pub(super) fn poll_sound(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(token) = self.sound.active.as_ref().map(|active| active.token) else {
            // Completion receipts survive event dequeue. Draining a stale
            // event here cannot lose another task's position; that task polls
            // its own token receipt on its next scheduler turn.
            let _ = host.poll_win16_sound()?;
            return self.write_sound_threshold_word(memory);
        };
        let stop_confirmed = self.sound.active.as_ref()
            .is_some_and(|active| active.stop_confirmed);
        if let Some(event) = host.poll_win16_sound()? {
            if event.playback == token {
                self.consume_sound_position(memory, host, event.frames_played,
                    event.complete || stop_confirmed, event.result)?;
                return Ok(());
            }
        }
        match host.win16_sound(Op::PlaybackPosition { playback: token })? {
            ResultValue::PlaybackPosition { result, frames_played, complete } => {
                self.consume_sound_position(memory, host, frames_played,
                    complete || stop_confirmed, result)
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND position query returned the wrong host result")),
        }
    }

    pub(super) fn consume_sound_position(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frames_played: u64,
        complete: bool,
        result: u32,
    ) -> Result<(), RuntimeError> {
        if result != 0 {
            return Err(native_sound_failure("native SOUND playback position", result));
        }
        let Some(current) = self.sound.active.as_ref() else { return Ok(()); };
        let submitted_frames = current.submitted_frames;
        let observed_frames = current.observed_frames;
        let stopping = current.stopping;
        let playback_token = current.token;
        let complete = complete || current.stop_confirmed;
        if frames_played > submitted_frames {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WAVE owner reported more SOUND frames than it accepted"));
        }
        if complete && frames_played != submitted_frames && !stopping {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WAVE owner completed SOUND playback before its accepted PCM frame count"));
        }
        if frames_played < observed_frames {
            if complete {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WAVE owner completion moved SOUND position backwards"));
            }
            return self.write_sound_threshold_word(memory);
        }
        {
            let sound = &mut self.sound;
            let Some(active) = sound.active.as_mut() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND playback disappeared during position commit"));
            };
            active.observed_frames = frames_played;
            for (voice, rendered) in sound.voices.iter_mut().zip(active.snapshots.iter_mut()) {
                voice.consume_rendered_prefix(rendered, frames_played).map_err(|error| {
                    snapshot_runtime_error(error)
                })?;
            }
        }
        if complete {
            match host.win16_sound(Op::RetirePlayback { playback: playback_token })? {
                ResultValue::PlaybackRetired { result: 0 } => {}
                ResultValue::PlaybackRetired { result } => {
                    return Err(native_sound_failure("retire completed SOUND playback", result));
                }
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND playback retirement returned the wrong host result")),
            }
            self.sound.active = None;
            if stopping {
                for voice in &mut self.sound.voices { voice.clear(); }
            }
        }
        self.write_sound_threshold_word(memory)
    }

    /// Record the positive stop receipt and commit its final measured prefix.
    /// On query or queue-commit failure the exact playback owner stays here in
    /// a confirmed-stop phase; later cleanup retries position/commit without
    /// issuing StopPlayback a second time.
    pub(super) fn finalize_stopped_sound(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        token: Win16SoundPlayback,
    ) -> Result<(), RuntimeError> {
        if let Some(active) = self.sound.active.as_mut() {
            if active.token != token {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND stop receipt does not match the retained playback owner"));
            }
            active.stopping = true;
            active.stop_confirmed = true;
        } else {
            return Ok(());
        }
        match host.win16_sound(Op::PlaybackPosition { playback: token })? {
            ResultValue::PlaybackPosition { result: 0, frames_played, .. } => {
                // Stop confirmation is the terminal receipt; this second call
                // supplies only its final measured prefix. Preserve the owner
                // if measurement or guest queue commit fails.
                self.consume_sound_position(memory, host, frames_played, true, 0)
            }
            ResultValue::PlaybackPosition { result, .. } =>
                Err(native_sound_failure("final SOUND position query", result)),
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND stop position query returned the wrong host result")),
        }
    }

    pub(super) fn retire_sound(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failures = None;
        if self.sound.active.is_some() {
            match self.stop_sound_inner(memory, host, true) {
                Ok(0) => {}
                Ok(status) => remember_sound_failure(&mut failures,
                    native_sound_failure("SOUND task stop status", u32::from(status))),
                Err(error) => remember_sound_failure(&mut failures, error),
            }
        }

        if self.sound.active.is_none() {
            if let Some(session) = self.sound.session {
                match host.win16_sound(Op::CloseSound { session }) {
                    Ok(ResultValue::SoundClosed { result: 0 }) => {
                        self.sound.session = None;
                        self.sound.voices.clear();
                    }
                    Ok(ResultValue::SoundClosed { result }) => remember_sound_failure(
                        &mut failures, native_sound_failure("native SOUND session close",
                            u32::from(result))),
                    Ok(_) => remember_sound_failure(&mut failures, RuntimeError::new(
                        Kind::InternalInvariant, "SOUND close returned the wrong host result")),
                    Err(error) => remember_sound_failure(&mut failures, error),
                }
            }
        }

        let mut lease_index = 0;
        while lease_index < self.sound.play_wave_leases.len() {
            let lease = self.sound.play_wave_leases[lease_index];
            match host.win16_sound(Op::StopPlayWave { lease }) {
                Ok(ResultValue::PlayWaveStopped { result: true, status: Win16SoundStopStatus::Stopped }) => {
                    self.sound.play_wave_leases.remove(lease_index);
                }
                // Another task may have replaced the owner-global native
                // playback. NotOwned confirms this token is already retired;
                // it must not be used to stop the new task's sound.
                Ok(ResultValue::PlayWaveStopped { result: true, status: Win16SoundStopStatus::NotOwned }) => {
                    self.sound.play_wave_leases.remove(lease_index);
                }
                Ok(ResultValue::PlayWaveStopped { result: false, status: Win16SoundStopStatus::NotOwned }) => {
                    // The owner replaced this exact lease elsewhere. The
                    // negative result means it did not stop the current
                    // playback; NotOwned still proves this old token retired.
                    self.sound.play_wave_leases.remove(lease_index);
                }
                Ok(ResultValue::PlayWaveStopped { result: true, status: Win16SoundStopStatus::Pending }) => {
                    remember_sound_failure(&mut failures, RuntimeError::new(Kind::HostFailure,
                        "SOUND PlaySound lease stop remains pending"));
                    lease_index += 1;
                }
                Ok(ResultValue::PlayWaveStopped { result: false, .. }) => {
                    remember_sound_failure(&mut failures, RuntimeError::new(Kind::HostFailure,
                        "native PlaySound lease could not be stopped"));
                    lease_index += 1;
                }
                Ok(_) => {
                    remember_sound_failure(&mut failures, RuntimeError::new(
                        Kind::InternalInvariant, "PlaySound stop returned the wrong host result"));
                    lease_index += 1;
                }
                Err(error) => {
                    remember_sound_failure(&mut failures, error);
                    lease_index += 1;
                }
            }
        }

        if self.sound.active.is_none() && self.sound.session.is_none() {
            self.sound.voices.clear();
        }
        if self.sound.active.is_none() && self.sound.session.is_none() {
            if let Some(word) = self.sound.threshold_word.clone() {
                let result = if word.selector.is_some() {
                    self.free_global_on_teardown(word.handle, word.allocation)
                } else {
                    self.free_global_on_teardown_without_primary(word.handle, word.allocation)
                };
                match result {
                    Ok(GlobalTeardownResult::Freed) => self.sound.threshold_word = None,
                    Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                        let error = retained.retained_error("SOUND threshold")
                            .unwrap_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                "SOUND teardown lost its retained result diagnostic"));
                        let error = self.sound.remember_threshold_retirement_failure(error);
                        remember_sound_failure(&mut failures, error);
                    }
                    Err(error) => {
                        let error = self.sound.remember_threshold_retirement_failure(error);
                        remember_sound_failure(&mut failures, error);
                    }
                }
            }
        }
        match failures { Some(error) => Err(error), None => Ok(()) }
    }
}

pub(super) fn pcm_format() -> crate::Win16SoundPcmFormat {
    crate::Win16SoundPcmFormat { channels: PCM_CHANNELS,
        samples_per_second: super::sound_queue::pcm_rate(), bits_per_sample: PCM_BITS }
}

pub(super) fn snapshot_runtime_error(error: QueueSnapshotError) -> RuntimeError {
    let message = match error {
        QueueSnapshotError::InvalidSnapshot => "SOUND renderer returned an invalid queue snapshot",
        QueueSnapshotError::QueueIncarnationChanged => "SOUND queue changed while audio was outstanding",
        QueueSnapshotError::QueuePrefixChanged => "SOUND queue prefix differs from submitted audio",
    };
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn native_sound_failure(operation: &'static str, result: u32) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure,
        format!("native {operation} failed (0x{result:08X})"),
        NativeSoundStatus { operation, result })
}

pub(super) fn combine_sound_failures(
    context: &'static str,
    primary: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    // A recoverable protocol gap must not mask a later real owner/cleanup
    // failure when task teardown aggregates independent SOUND resources.
    let kind = match (primary.kind(), cleanup.kind()) {
        (Kind::InternalInvariant, _) | (_, Kind::InternalInvariant) => Kind::InternalInvariant,
        (Kind::ExecutionLimit, additional) => additional,
        (primary, _) => primary,
    };
    RuntimeError::with_source(kind, context, SoundFailurePair { primary, cleanup })
}

pub(super) fn remember_sound_failure(
    failures: &mut Option<RuntimeError>,
    error: RuntimeError,
) {
    *failures = Some(match failures.take() {
        None => error,
        Some(primary) => combine_sound_failures(
            "multiple SOUND cleanup operations failed",
            primary,
            error,
        ),
    });
}

#[derive(Debug)]
struct NativeSoundStatus {
    operation: &'static str,
    result: u32,
}

impl std::fmt::Display for NativeSoundStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} returned 0x{:08X}", self.operation, self.result)
    }
}

impl std::error::Error for NativeSoundStatus {}

#[derive(Debug)]
struct SoundFailurePair {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for SoundFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; SOUND cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for SoundFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
