//! SOUND.DRV request controller and measured WAVE queue submission.

use guest_core::memory::Memory;
use win16_abi::Win16SoundRequest;

use super::sound_queue::{QueueBoundary, VoiceQueue};
use super::sound_render::{align_appended_syncs, align_voice_syncs, collect_boundaries,
    mix_snapshots, mix_tracks, validate_snapshot_budget};
use super::sound_state::{pcm_format, snapshot_runtime_error, ActiveSoundPlayback,
    combine_sound_failures, native_sound_failure, MAX_SOUND_VOICES};
use super::Win16State;
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16SoundHostOperation as Op, Win16SoundHostResult as HostResult,
    Win16SoundStopStatus, Win16SoundWaitTarget};

const S_SERDVNA: u16 = u16::MAX;
const S_QUEUEEMPTY: i16 = 0;
const S_THRESHOLD: i16 = 1;
const S_ALLTHRESHOLD: i16 = 2;

struct VoiceAppend {
    entries: Vec<super::sound_queue::QueueEntry>,
    identities: Vec<u64>,
    boundaries: Vec<QueueBoundary>,
}

impl Win16State {
    pub(super) fn sound_api(
        &mut self,
        request: Win16SoundRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        self.poll_sound(memory, host)?;
        use Win16SoundRequest as Request;
        match request {
            Request::Open => self.open_sound(host).map(u32::from),
            Request::Close => self.close_sound(memory, host).map(u32::from),
            Request::SetVoiceQueueSize { voice, bytes } => {
                let Some(index) = self.sound.voice_index(voice) else { return Ok(0); };
                let playing = self.sound.is_playing();
                let result = self.sound.voices[index].set_capacity(bytes, playing);
                self.write_sound_threshold_word(memory)?;
                Ok(u32::from(result))
            }
            Request::SetVoiceNote { voice, value, length, dots } => {
                let Some(index) = self.sound.voice_index(voice) else { return Ok(0); };
                let previous = self.sound.voices[index].clone();
                let result = self.sound.voices[index].set_note(voice, value, length, dots);
                if result == 0 { return self.finish_voice_change(index, previous, memory, host).map(u32::from); }
                Ok(u32::from(result))
            }
            Request::SetVoiceAccent { voice, tempo, volume, mode, pitch } => {
                let Some(index) = self.sound.voice_index(voice) else { return Ok(0); };
                let previous = self.sound.voices[index].clone();
                let protected = self.sound.active.as_ref().map_or(0, |active| {
                    active.snapshots.get(index).map_or(0, |rendered| rendered.entries.len())
                });
                let result = self.sound.voices[index]
                    .set_accent(voice, tempo, volume, mode, pitch, protected);
                if result == 0 { return self.finish_voice_change(index, previous, memory, host).map(u32::from); }
                Ok(u32::from(result))
            }
            Request::SetVoiceEnvelope { voice, shape: _, repeat: _ } => {
                if self.sound.voice_index(voice).is_none() { return Ok(0); }
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 SOUND voice envelopes require OEM-specific shapes; the PCM renderer does not synthesize one"));
                Ok(u32::from(super::sound_queue::S_SERDSH))
            }
            Request::SetSoundNoise { source, duration } => {
                if duration <= 0 { return Ok(u32::from(super::sound_queue::S_SERDDR)); }
                if !(0..=7).contains(&source) {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 SOUND noise source {source} is outside the documented 0..=7 range")));
                    return Ok(u32::from(super::sound_queue::S_SERDSR));
                }
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 SOUND noise sources are hardware-specific and unavailable in the PCM note renderer"));
                Ok(u32::from(super::sound_queue::S_SERDSR))
            }
            Request::SetVoiceSound { voice, frequency_16_16, duration } => {
                let Some(index) = self.sound.voice_index(voice) else { return Ok(0); };
                let previous = self.sound.voices[index].clone();
                let result = self.sound.voices[index].set_tone(voice, frequency_16_16, duration);
                if result == 0 { return self.finish_voice_change(index, previous, memory, host).map(u32::from); }
                Ok(u32::from(result))
            }
            Request::Start => self.start_sound(memory, host).map(u32::from),
            Request::Stop => self.stop_sound(memory, host).map(u32::from),
            Request::WaitState { state } => self.wait_sound_state(state, memory, host).map(u32::from),
            Request::SyncAllVoices => {
                if self.sound.session.is_none() { return Ok(u32::from(S_SERDVNA)); }
                // One fresh marker belongs to each invocation. Reserve every
                // voice first, so capacity/allocation failure is all-or-none;
                // the reserved VecDeque slots make the subsequent commits
                // infallible and give each marker a new queue identity.
                for voice in &mut self.sound.voices {
                    let result = voice.reserve_sync_marker();
                    if result != 0 { return Ok(u32::from(result)); }
                }
                for voice in &mut self.sound.voices { voice.append_sync_marker(); }

                let result = match self.append_sound_tail(host) {
                    Ok(result) => result,
                    Err(error) => {
                        if let Err(cleanup) = self.rollback_sync_markers() {
                            return Err(combine_sound_failures(
                                "SOUND append failure also failed to roll back SyncAllVoices markers",
                                error,
                                cleanup,
                            ));
                        }
                        return Err(error);
                    }
                };
                if result != 0 {
                    self.rollback_sync_markers().map_err(|error| error.with_context(
                        format!("rolling back SyncAllVoices after append status 0x{result:04X}")))?;
                }
                self.write_sound_threshold_word(memory)?;
                Ok(u32::from(result))
            }
            Request::CountVoiceNotes { voice } => {
                let count = self.sound.voice_index(voice)
                    .map_or(0, |index| self.sound.voices[index].note_count());
                Ok(u32::from(count))
            }
            Request::GetThresholdEvent => self.ensure_sound_threshold_word(memory, host),
            Request::GetThresholdStatus => {
                let status = self.sound.threshold_status();
                self.sound.clear_threshold_events();
                self.write_sound_threshold_word(memory)?;
                Ok(u32::from(status))
            }
            Request::SetVoiceThreshold { voice, notes } => {
                let Some(index) = self.sound.voice_index(voice) else { return Ok(0); };
                let result = self.sound.voices[index].set_threshold(voice, notes);
                self.write_sound_threshold_word(memory)?;
                Ok(u32::from(result))
            }
            Request::Play { api, sound_name, module, flags } => {
                super::sound_play::play_wave_api(self, api, sound_name, module, flags, memory, host)
            }
        }
    }

    fn open_sound(&mut self, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        // Keep a prior token/snapshot's queue incarnation alive until its
        // native playback has actually retired, even if host/session state is
        // inconsistent.
        if self.sound.session.is_some() || self.sound.active.is_some() {
            return Ok(super::sound_queue::S_SERMACT);
        }
        let mut voices = Vec::new();
        voices.try_reserve_exact(MAX_SOUND_VOICES)
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "allocate Win16 SOUND voice queues", error))?;
        voices.resize_with(MAX_SOUND_VOICES, VoiceQueue::default);
        let format = pcm_format();
        let query = host.win16_sound(Op::QueryPcmFormat { format });
        self.note_sound_wave_owner_attempt(&query);
        match query {
            Ok(HostResult::PcmFormat { result: 0, supported: true }) => {}
            Ok(HostResult::PcmFormat { .. }) => return Ok(S_SERDVNA),
            Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND PCM query returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "shared WAVE owner does not provide SOUND PCM yet"));
                return Ok(S_SERDVNA);
            }
            Err(error) => return Err(error),
        }
        let opened = host.win16_sound(Op::OpenSound { format });
        self.note_sound_wave_owner_attempt(&opened);
        match opened {
            Ok(HostResult::SoundOpened { result: 0, session: Some(session) }) =>
            {
                self.sound.voices = voices;
                self.sound.session = Some(session);
                Ok(MAX_SOUND_VOICES as u16)
            }
            Ok(HostResult::SoundOpened { result: 0, session: None }) => Err(
                RuntimeError::new(Kind::InternalInvariant,
                    "successful SOUND open returned no session identity")),
            Ok(HostResult::SoundOpened { result, session: Some(session) }) => {
                let primary = native_sound_failure("SOUND open", u32::from(result));
                match host.win16_sound(Op::CloseSound { session }) {
                    Ok(HostResult::SoundClosed { result: 0 }) => Ok(S_SERDVNA),
                    Ok(HostResult::SoundClosed { result: close_result }) => {
                        self.sound.session = Some(session);
                        Err(combine_sound_failures("SOUND open rollback could not close its session",
                            primary, native_sound_failure("SOUND open rollback close",
                                u32::from(close_result))))
                    }
                    Ok(_) => {
                        self.sound.session = Some(session);
                        Err(combine_sound_failures("SOUND open rollback returned an invalid close result",
                            primary, RuntimeError::new(Kind::InternalInvariant,
                                "SOUND open rollback close returned the wrong host result")))
                    }
                    Err(cleanup) => {
                        self.sound.session = Some(session);
                        Err(combine_sound_failures("SOUND open rollback failed",
                            primary, cleanup))
                    }
                }
            }
            Ok(HostResult::SoundOpened { result: _, session: None }) => Ok(S_SERDVNA),
            Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND open returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "shared WAVE owner does not provide SOUND device reservation yet"));
                Ok(S_SERDVNA)
            }
            Err(error) => Err(error),
        }
    }

    /// SOUND opens and queries share the native WAVE owner, so their partial
    /// handles must enter the same retired-owner barrier as waveOpen.
    fn note_sound_wave_owner_attempt(
        &mut self,
        result: &Result<HostResult, RuntimeError>,
    ) {
        // The active Windows provider returns CompatibilityGap only when the
        // provider is unavailable; native failures are results with owners
        // already registered for retirement.
        if !matches!(result, Err(error) if error.kind() == Kind::CompatibilityGap) {
            self.require_wave_owner_barrier();
        }
    }

    fn close_sound(&mut self, memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        if self.sound.session.is_none() && self.sound.active.is_none() { return Ok(0); }
        let stopped = self.stop_sound_inner(memory, host, true)?;
        if stopped != 0 {
            return Err(native_sound_failure(
                "SOUND stop required by void CloseSound",
                u32::from(stopped),
            ));
        }
        let Some(session) = self.sound.session else {
            self.write_sound_threshold_word(memory)?;
            return Ok(0);
        };
        match host.win16_sound(Op::CloseSound { session }) {
            Ok(HostResult::SoundClosed { result: 0 }) => {
                self.sound.session = None;
                self.sound.voices.clear();
            }
            Ok(HostResult::SoundClosed { result }) => return Err(
                native_sound_failure("native SOUND session close", u32::from(result))),
            Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND close returned the wrong host result")),
            Err(error) => return Err(error.with_context("SOUND session close retained its owner")),
        }
        self.write_sound_threshold_word(memory)?;
        Ok(0)
    }

    fn finish_voice_change(
        &mut self,
        index: usize,
        previous: VoiceQueue,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if self.sound.active.is_some() {
            let result = match self.append_sound_tail(host) {
                Ok(result) => result,
                Err(error) => { self.sound.voices[index] = previous; return Err(error); }
            };
            if result != 0 {
                self.sound.voices[index] = previous;
                return Ok(result);
            }
        }
        self.write_sound_threshold_word(memory)?;
        Ok(0)
    }

    fn start_sound(&mut self, memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        let Some(session) = self.sound.session else { return Ok(S_SERDVNA); };
        if self.sound.active.is_some() { return Ok(super::sound_queue::S_SERMACT); }
        let mut snapshots = Vec::new();
        snapshots.try_reserve_exact(self.sound.voices.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND rendered voice snapshots", error))?;
        for voice in &self.sound.voices {
            let rendered = match voice.render() {
                Ok(rendered) => rendered,
                Err(status) => return Ok(status),
            };
            snapshots.push(rendered);
            if let Err(status) = validate_snapshot_budget(&snapshots) { return Ok(status); }
        }
        if let Err(status) = align_voice_syncs(&mut snapshots) { return Ok(status); }
        if let Err(status) = validate_snapshot_budget(&snapshots) { return Ok(status); }
        let samples = mix_snapshots(&snapshots)?;
        if samples.is_empty() {
            for voice in &mut self.sound.voices { voice.begin_rendered_replay(); }
            for (voice, rendered) in self.sound.voices.iter_mut().zip(snapshots.iter_mut()) {
                voice.consume_rendered_prefix(rendered, 0).map_err(snapshot_runtime_error)?;
            }
            self.write_sound_threshold_word(memory)?;
            return Ok(0);
        }
        let boundaries = collect_boundaries(&snapshots)?;
        let submitted_frames = samples.len() as u64;
        match host.win16_sound(Op::PlayOwnedPcm { session, format: pcm_format(),
            samples, note_frame_boundaries: boundaries }) {
            Ok(HostResult::PcmStarted { result: 0, playback: Some(token) }) => {
                for voice in &mut self.sound.voices { voice.begin_rendered_replay(); }
                self.sound.active = Some(ActiveSoundPlayback {
                    token, submitted_frames, observed_frames: 0, stopping: false,
                    stop_confirmed: false, snapshots,
                });
                Ok(0)
            }
            Ok(HostResult::PcmStarted { result: 0, playback: None }) => Err(
                RuntimeError::new(Kind::InternalInvariant,
                    "successful SOUND PCM start returned no playback identity")),
            // The WAVE owner returns the actual MMRESULT on native prepare or
            // write failure; a playback token is required only on success.
            Ok(HostResult::PcmStarted { result, playback: None }) if result != 0 =>
                Ok(S_SERDVNA),
            Ok(HostResult::PcmStarted { result, playback: Some(token) }) => {
                for voice in &mut self.sound.voices { voice.begin_rendered_replay(); }
                self.sound.active = Some(ActiveSoundPlayback {
                    token, submitted_frames, observed_frames: 0, stopping: false,
                    stop_confirmed: false, snapshots,
                });
                let primary = native_sound_failure("SOUND PCM start", result);
                match host.win16_sound(Op::StopPlayback { playback: token }) {
                    Ok(HostResult::PlaybackStopped { result: 0,
                        status: Win16SoundStopStatus::Stopped | Win16SoundStopStatus::NotOwned }) => {
                        self.finalize_stopped_sound(memory, host, token).map_err(|cleanup|
                            combine_sound_failures("failed SOUND start also failed playback cleanup",
                                primary, cleanup))?;
                        Ok(S_SERDVNA)
                    }
                    Ok(HostResult::PlaybackStopped { result: 0,
                        status: Win16SoundStopStatus::Pending }) => {
                        if let Some(active) = self.sound.active.as_mut() { active.stopping = true; }
                        Err(combine_sound_failures("failed SOUND start left playback pending",
                            primary, RuntimeError::new(Kind::HostFailure,
                                "SOUND playback stop requires a later completion receipt")))
                    }
                    Ok(HostResult::PlaybackStopped { result: stop_result, .. }) => Err(
                        combine_sound_failures("failed SOUND start could not stop its playback",
                            primary, native_sound_failure("SOUND start rollback stop", stop_result))),
                    Ok(_) => Err(combine_sound_failures("failed SOUND start received an invalid stop result",
                        primary, RuntimeError::new(Kind::InternalInvariant,
                            "SOUND start rollback returned the wrong host result"))),
                    Err(cleanup) => Err(combine_sound_failures(
                        "failed SOUND start could not retire its playback token", primary, cleanup)),
                }
            }
            Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND PCM start returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "shared WAVE owner cannot start owned SOUND PCM"));
                Ok(S_SERDVNA)
            }
            Err(error) => Err(error),
        }
    }

    fn append_sound_tail(&mut self, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        let Some(active) = self.sound.active.as_ref() else { return Ok(0); };
        if active.snapshots.len() != self.sound.voices.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND active snapshot count differs from its voices"));
        }
        let token = active.token;
        let submitted_frames = active.submitted_frames;
        let mut current = Vec::new();
        current.try_reserve_exact(self.sound.voices.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND append render plan", error))?;
        for voice in &self.sound.voices {
            let rendered = match voice.render() {
                Ok(rendered) => rendered,
                Err(status) => return Ok(status),
            };
            current.push(rendered);
            if let Err(status) = validate_snapshot_budget(&current) { return Ok(status); }
        }
        let mut prefix_lengths = Vec::new();
        prefix_lengths.try_reserve_exact(current.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND append prefix lengths", error))?;
        for (index, rendered) in current.iter().enumerate() {
            let snapshot = self.sound.active.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "SOUND playback disappeared during append planning"))?
                .snapshots.get(index).ok_or_else(|| snapshot_runtime_error(
                    super::sound_queue::QueueSnapshotError::InvalidSnapshot))?;
            if snapshot.entries.len() != snapshot.entry_identities.len()
                || snapshot.entries.len() != snapshot.boundaries.len()
                || snapshot.consumed_entries > snapshot.entries.len()
            {
                return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::InvalidSnapshot));
            }
            if rendered.queue_incarnation != snapshot.queue_incarnation {
                return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::QueueIncarnationChanged));
            }
            if rendered.entries.len() != rendered.entry_identities.len()
                || rendered.entries.len() != rendered.boundaries.len()
            {
                return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::InvalidSnapshot));
            }
            let prefix_len = snapshot.entries.len();
            if rendered.entries.len() < prefix_len {
                return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::QueuePrefixChanged));
            }
            for offset in 0..prefix_len {
                if rendered.entries[offset] != snapshot.entries[offset]
                    || rendered.entry_identities[offset] != snapshot.entry_identities[offset]
                {
                    return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::QueuePrefixChanged));
                }
            }
            prefix_lengths.push(prefix_len);
        }
        if let Err(status) = align_appended_syncs(&mut current, &prefix_lengths) {
            return Ok(status);
        }
        if let Err(status) = validate_snapshot_budget(&current) { return Ok(status); }

        let mut appends = Vec::new();
        appends.try_reserve_exact(current.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND append voices", error))?;
        let boundary_capacity = current.iter().try_fold(0_usize, |total, rendered| {
            total.checked_add(rendered.boundaries.len())
        }).ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "SOUND append boundary count overflow"))?;
        let mut boundaries = Vec::new();
        boundaries.try_reserve_exact(boundary_capacity).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND append frame boundaries", error))?;
        for (index, rendered) in current.iter().enumerate() {
            let active_snapshot = &self.sound.active.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "SOUND playback disappeared during append planning"))?
                .snapshots[index];
            if active_snapshot.entries.len() != active_snapshot.entry_identities.len()
                || active_snapshot.entries.len() != active_snapshot.boundaries.len()
                || active_snapshot.consumed_entries > active_snapshot.entries.len()
            {
                return Err(snapshot_runtime_error(super::sound_queue::QueueSnapshotError::InvalidSnapshot));
            }
            let prefix_len = prefix_lengths[index];
            let skip_frames = if prefix_len == 0 { 0 } else {
                rendered.boundaries.get(prefix_len - 1).ok_or_else(|| snapshot_runtime_error(
                    super::sound_queue::QueueSnapshotError::InvalidSnapshot))?.end_frame
            };
            let mut suffix_entries = Vec::new();
            suffix_entries.try_reserve_exact(rendered.entries.len() - prefix_len)
                .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended queue entries", error))?;
            suffix_entries.extend_from_slice(&rendered.entries[prefix_len..]);
            let mut suffix_identities = Vec::new();
            suffix_identities.try_reserve_exact(rendered.entry_identities.len() - prefix_len)
                .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended queue identities", error))?;
            suffix_identities.extend_from_slice(&rendered.entry_identities[prefix_len..]);
            let mut suffix_boundaries = Vec::new();
            suffix_boundaries.try_reserve_exact(rendered.boundaries.len().saturating_sub(prefix_len))
                .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended entry boundaries", error))?;
            for boundary in rendered.boundaries.iter().skip(prefix_len) {
                let relative = boundary.end_frame.checked_sub(skip_frames).ok_or_else(||
                    snapshot_runtime_error(super::sound_queue::QueueSnapshotError::InvalidSnapshot))?;
                let global_end = submitted_frames.checked_add(relative).ok_or_else(|| RuntimeError::new(
                    Kind::ResourceExhausted, "SOUND appended frame position overflow"))?;
                suffix_boundaries.push(QueueBoundary {
                    end_frame: global_end,
                    entries_consumed: active_snapshot.entries.len()
                        .checked_add(boundary.entries_consumed.saturating_sub(prefix_len))
                        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                            "SOUND appended entry count overflow"))?,
                });
                if relative != 0 { boundaries.push(relative); }
            }
            appends.push(VoiceAppend {
                entries: suffix_entries,
                identities: suffix_identities,
                boundaries: suffix_boundaries,
            });
        }
        if appends.iter().all(|append| append.entries.is_empty()) { return Ok(0); }
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut suffix_tracks = Vec::new();
        suffix_tracks.try_reserve_exact(current.len())
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve SOUND suffix mixer tracks", error))?;
        for (index, rendered) in current.iter().enumerate() {
            let prefix_len = prefix_lengths[index];
            let skip = if prefix_len == 0 { 0 } else {
                usize::try_from(rendered.boundaries[prefix_len - 1].end_frame)
                    .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                        "SOUND append prefix exceeds host memory", error))?
            };
            let tail = rendered.samples.get(skip..).ok_or_else(|| snapshot_runtime_error(
                super::sound_queue::QueueSnapshotError::InvalidSnapshot))?;
            suffix_tracks.push(tail);
        }
        let samples = mix_tracks(&suffix_tracks)?;
        let appended_frames = samples.len() as u64;
        let next_submitted_frames = submitted_frames.checked_add(appended_frames)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                "SOUND playback frame count overflow"))?;

        // Reserve all commit storage before a native write can take ownership.
        let active = self.sound.active.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "SOUND playback disappeared before append"))?;
        for (snapshot, append) in active.snapshots.iter_mut().zip(&appends) {
            snapshot.entries.try_reserve(append.entries.len()).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended queue entries", error))?;
            snapshot.entry_identities.try_reserve(append.identities.len()).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended entry identities", error))?;
            snapshot.boundaries.try_reserve(append.boundaries.len()).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve SOUND appended queue boundaries", error))?;
        }
        if samples.is_empty() {
            for (snapshot, append) in active.snapshots.iter_mut().zip(appends) {
                snapshot.entries.extend(append.entries);
                snapshot.entry_identities.extend(append.identities);
                snapshot.boundaries.extend(append.boundaries);
            }
            return Ok(0);
        }
        match host.win16_sound(Op::AppendOwnedPcm { playback: token, samples,
            note_frame_boundaries: boundaries }) {
            Ok(HostResult::PcmAppended { result: 0 }) => {
                active.submitted_frames = next_submitted_frames;
                for (snapshot, append) in active.snapshots.iter_mut().zip(appends) {
                    snapshot.entries.extend(append.entries);
                    snapshot.entry_identities.extend(append.identities);
                    snapshot.boundaries.extend(append.boundaries);
                }
                Ok(0)
            }
            Ok(HostResult::PcmAppended { result }) => {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    format!("native SOUND PCM append returned 0x{result:08X}")));
                Ok(S_SERDVNA)
            }
            Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND PCM append returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "shared WAVE owner does not provide SOUND PCM append yet"));
                Ok(S_SERDVNA)
            }
            Err(error) => Err(error),
        }
    }

    fn rollback_sync_markers(&mut self) -> Result<(), RuntimeError> {
        if self.sound.voices.iter().any(|voice| !voice.can_rollback_sync_marker()) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND SyncAllVoices lost a staged tail marker before rollback"));
        }
        for voice in &mut self.sound.voices { voice.rollback_sync_marker(); }
        Ok(())
    }

    fn stop_sound(&mut self, memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        self.poll_sound(memory, host)?;
        let result = self.stop_sound_inner(memory, host, false)?;
        self.write_sound_threshold_word(memory)?;
        Ok(result)
    }

    pub(super) fn stop_sound_inner(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        required_for_cleanup: bool,
    ) -> Result<u16, RuntimeError> {
        let Some(active) = self.sound.active.as_ref() else {
            for voice in &mut self.sound.voices { voice.clear(); }
            return Ok(0);
        };
        let token = active.token;
        if active.stop_confirmed {
            self.finalize_stopped_sound(memory, host, token)?;
            return Ok(0);
        }
        if active.stopping {
            return self.wait_stopped_sound(memory, host, token, required_for_cleanup);
        }
        match host.win16_sound(Op::StopPlayback { playback: token }) {
            Ok(HostResult::PlaybackStopped { result: 0, status: Win16SoundStopStatus::Stopped }) => {
                self.finalize_stopped_sound(memory, host, token)?;
                Ok(0)
            }
            Ok(HostResult::PlaybackStopped { result: 0, status: Win16SoundStopStatus::NotOwned }) => {
                self.finalize_stopped_sound(memory, host, token)?;
                Ok(0)
            }
            Ok(HostResult::PlaybackStopped { result: 0, status: Win16SoundStopStatus::Pending }) => {
                if let Some(active) = self.sound.active.as_mut() {
                    active.stopping = true;
                }
                self.wait_stopped_sound(memory, host, token, required_for_cleanup)
            }
            Ok(HostResult::PlaybackStopped { result, .. }) => {
                if required_for_cleanup {
                    return Err(native_sound_failure("native SOUND stop", result));
                }
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    format!("native SOUND stop returned 0x{result:08X}")));
                Ok(S_SERDVNA)
            }
            Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND stop returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                if required_for_cleanup { return Err(error); }
                host.report_diagnostic(&Diagnostic::warning(error.kind(),
                    "shared WAVE owner cannot stop SOUND playback yet"));
                Ok(S_SERDVNA)
            }
            Err(error) => Err(error.with_context("SOUND stop operation failed")),
        }
    }

    fn wait_stopped_sound(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        token: crate::Win16SoundPlayback,
        required_for_cleanup: bool,
    ) -> Result<u16, RuntimeError> {
        match host.win16_sound(Op::WaitPlayback { playback: token,
            target: Win16SoundWaitTarget::PlaybackComplete }) {
            Ok(HostResult::PlaybackWait { result: 0, frames_played, complete: true }) => {
                let Some(active) = self.sound.active.as_mut() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "SOUND stop completion lost its playback owner"));
                };
                if active.token != token {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "SOUND stop completion belongs to another playback token"));
                }
                active.stop_confirmed = true;
                active.stopping = true;
                self.consume_sound_position(memory, host, frames_played, true, 0)?;
                Ok(0)
            }
            Ok(HostResult::PlaybackWait { result: 0, complete: false, .. }) =>
                Ok(super::sound_queue::S_SERMACT),
            Ok(HostResult::PlaybackWait { result, .. }) => {
                if required_for_cleanup {
                    return Err(native_sound_failure("wait for SOUND stop", result));
                }
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    format!("native SOUND stop wait returned 0x{result:08X}")));
                Ok(S_SERDVNA)
            }
            Ok(_) => Err(RuntimeError::new(Kind::InternalInvariant,
                "SOUND stop wait returned the wrong host result")),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                if required_for_cleanup { return Err(error); }
                host.report_diagnostic(&Diagnostic::warning(error.kind(),
                    "shared WAVE owner cannot wait for SOUND stop completion yet"));
                Ok(S_SERDVNA)
            }
            Err(error) => Err(error.with_context("SOUND stop wait failed")),
        }
    }

    fn wait_sound_state(
        &mut self,
        state: i16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if !matches!(state, S_QUEUEEMPTY | S_THRESHOLD | S_ALLTHRESHOLD) {
            return Ok(super::sound_queue::S_SERDST);
        }
        loop {
            self.poll_sound(memory, host)?;
            if let Some(result) = self.wait_state_result(state) { return Ok(result); }
            let Some((token, target)) = self.wait_target(state) else { return Ok(S_SERDVNA); };
            let old_frames = self.sound.active.as_ref().map_or(0, |active| active.observed_frames);
            match host.win16_sound(Op::WaitPlayback { playback: token,
                target })? {
                HostResult::PlaybackWait { result, frames_played, complete } => {
                    if result != 0 { return Ok(S_SERDVNA); }
                    self.consume_sound_position(memory, host, frames_played, complete, result)?;
                    let new_frames = self.sound.active.as_ref().map_or(old_frames, |active| active.observed_frames);
                    if !complete && new_frames <= old_frames {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "native SOUND wait returned without advancing the measured playback position"));
                    }
                }
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "SOUND wait returned the wrong host result")),
            }
        }
    }

    fn wait_state_result(&self, state: i16) -> Option<u16> {
        match state {
            S_QUEUEEMPTY if self.sound.active.is_none()
                && self.sound.voices.iter().all(VoiceQueue::is_empty) => Some(0),
            // SDK 3.0's S_THRESHOLD row says "returns voice", although its
            // general return paragraph says zero on success. SDK 3.1 marks
            // WaitSoundState obsolete and points to a separate multimedia
            // reference not present in this source set. Follow the specific
            // row and choose the first 1-based queue in runtime order; the
            // available SDK text does not define simultaneous tie order.
            S_THRESHOLD => self.sound.voices.iter().enumerate()
                .find(|(_, voice)| voice.below_threshold())
                .and_then(|(index, _)| u16::try_from(index + 1).ok()),
            S_ALLTHRESHOLD if self.sound.voices.iter()
                .any(|voice| voice.threshold_notes() != 0)
                && self.sound.voices.iter()
                    .filter(|voice| voice.threshold_notes() != 0)
                    .all(VoiceQueue::below_threshold) => Some(0),
            _ => None,
        }
    }

    fn wait_target(&self, state: i16) -> Option<(crate::Win16SoundPlayback, Win16SoundWaitTarget)> {
        let active = self.sound.active.as_ref()?;
        if state == S_QUEUEEMPTY {
            return Some((active.token, Win16SoundWaitTarget::PlaybackComplete));
        }
        let mut first_target = None;
        let mut last_target = None;
        let mut waiting_voices = 0_usize;
        let mut reached_voices = 0_usize;
        for (index, voice) in self.sound.voices.iter().enumerate() {
            let threshold = voice.threshold_notes();
            if threshold == 0 || voice.below_threshold() { continue; }
            waiting_voices += 1;
            let snapshot = active.snapshots.get(index)?;
            for boundary in &snapshot.boundaries {
                if boundary.entries_consumed <= snapshot.consumed_entries { continue; }
                let start = snapshot.consumed_entries;
                let end = boundary.entries_consumed.min(snapshot.entries.len());
                let notes_retired = snapshot.entries.get(start..end)?
                    .iter().filter(|entry| entry.counts_as_note()).count();
                if voice.note_count().saturating_sub(notes_retired.min(usize::from(u16::MAX)) as u16) < threshold {
                    first_target = Some(first_target.map_or(boundary.end_frame, |target: u64|
                        target.min(boundary.end_frame)));
                    last_target = Some(last_target.map_or(boundary.end_frame, |target: u64|
                        target.max(boundary.end_frame)));
                    reached_voices += 1;
                    break;
                }
            }
        }
        if state == S_THRESHOLD {
            first_target.map(|frame| (active.token, Win16SoundWaitTarget::SampleFrame(frame)))
        } else if waiting_voices != 0 && reached_voices == waiting_voices {
            last_target.map(|frame| (active.token, Win16SoundWaitTarget::SampleFrame(frame)))
        } else {
            None
        }
    }
}
