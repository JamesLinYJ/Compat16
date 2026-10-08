//! Bounded single-voice SOUND queue and portable 8-bit PCM note renderer.
//!
//! The Microsoft Windows 3.0 SDK defines pitch numbers, reciprocal note
//! lengths, dotted notes, tempo, volume and articulation, but leaves the
//! SOUND.DRV device implementation OEM-specific. This renderer uses the
//! documented note/tempo model and a generated square wave; it does not model
//! an OEM speaker port, noise generator or envelope table. The renderer is a
//! functional host-PCM approximation, not a reproduction of an OEM waveform.
//! No mature portable crate implements the Win16 queue, note-count and
//! threshold contract; this small portable renderer produces owned PCM for
//! the shared WAVE owner instead of adding a second native audio backend.

use std::collections::VecDeque;

const DEFAULT_QUEUE_BYTES: usize = 192;
// SDK 3.0 describes the 192-byte default as room for about 32 notes. Six
// bytes per queued note is the smallest guest-record capacity consistent with
// that contract; Rust metadata and renderer snapshots stay outside this size.
const QUEUE_RECORD_BYTES: usize = 6;
// The renderer emits unsigned 8-bit mono frames directly, so 48 kHz avoids
// resampling or changing its amplitude representation. It is a conventional
// PCM rate and is explicitly queried from the shared WAVE owner before open.
const PCM_RATE: u32 = 48_000;
pub(super) const MAX_PCM_FRAMES: usize = 24_000_000;
const MAX_DOTS: i16 = 3;

pub(super) const S_SEROFM: u16 = (-2_i16) as u16;
pub(super) const S_SERMACT: u16 = (-3_i16) as u16;
pub(super) const S_SERQFUL: u16 = (-4_i16) as u16;
pub(super) const S_SERBDNT: u16 = (-5_i16) as u16;
pub(super) const S_SERDLN: u16 = (-6_i16) as u16;
pub(super) const S_SERDCC: u16 = (-7_i16) as u16;
pub(super) const S_SERDTP: u16 = (-8_i16) as u16;
pub(super) const S_SERDVL: u16 = (-9_i16) as u16;
pub(super) const S_SERDMD: u16 = (-10_i16) as u16;
pub(super) const S_SERDSH: u16 = (-11_i16) as u16;
pub(super) const S_SERDPT: u16 = (-12_i16) as u16;
pub(super) const S_SERDFQ: u16 = (-13_i16) as u16;
pub(super) const S_SERDDR: u16 = (-14_i16) as u16;
pub(super) const S_SERDSR: u16 = (-15_i16) as u16;
pub(super) const S_SERDST: u16 = (-16_i16) as u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Articulation {
    Normal,
    Legato,
    Staccato,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Accent {
    tempo: u16,
    volume: u8,
    mode: Articulation,
    pitch: u8,
}

impl Default for Accent {
    fn default() -> Self {
        Self { tempo: 120, volume: 255, mode: Articulation::Normal, pitch: 0 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum QueueEntry {
    Note { value: u8, length: u16, dots: u8 },
    Tone { frequency_16_16: u32, duration_ticks: u16 },
    Accent(Accent),
    Sync,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueueRecord {
    identity: u64,
    entry: QueueEntry,
}

impl QueueEntry {
    pub(super) const fn counts_as_note(&self) -> bool {
        matches!(self, Self::Note { .. })
    }
}

#[derive(Clone, Debug)]
pub(super) struct QueueBoundary {
    pub(super) end_frame: u64,
    pub(super) entries_consumed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QueueSnapshotError {
    InvalidSnapshot,
    QueueIncarnationChanged,
    QueuePrefixChanged,
}

#[derive(Clone, Debug)]
pub(super) struct RenderedQueue {
    pub(super) samples: Vec<u8>,
    pub(super) entries: Vec<QueueEntry>,
    pub(super) entry_identities: Vec<u64>,
    pub(super) boundaries: Vec<QueueBoundary>,
    pub(super) queue_incarnation: Option<u64>,
    pub(super) consumed_entries: usize,
}

#[derive(Clone, Debug)]
pub(super) struct VoiceQueue {
    capacity_bytes: usize,
    entries: VecDeque<QueueRecord>,
    queue_incarnation: Option<u64>,
    next_entry_identity: u64,
    identity_exhausted: bool,
    threshold_notes: u16,
    threshold_event: bool,
    /// Current accent after the last measured playback prefix. StopSound
    /// preserves that device setting when it flushes the queue.
    accent: Accent,
    /// StartSound is repeatable: playback progress never changes the stored
    /// program. Replays always begin with this queue's original accent state.
    queue_initial_accent: Accent,
    /// Measured prefix in the retained queue used for current queue-empty and
    /// threshold status. A new successful StartSound resets it to zero.
    played_entries: usize,
}

impl Default for VoiceQueue {
    fn default() -> Self {
        Self {
            capacity_bytes: DEFAULT_QUEUE_BYTES,
            entries: VecDeque::new(),
            queue_incarnation: Some(0),
            next_entry_identity: 0,
            identity_exhausted: false,
            threshold_notes: 0,
            threshold_event: false,
            accent: Accent::default(),
            queue_initial_accent: Accent::default(),
            played_entries: 0,
        }
    }
}

impl VoiceQueue {
    pub(super) fn is_empty(&self) -> bool { self.played_entries >= self.entries.len() }

    pub(super) fn note_count(&self) -> u16 {
        self.entries.iter().skip(self.played_entries)
            .filter(|record| record.entry.counts_as_note()).count()
            .min(usize::from(u16::MAX)) as u16
    }

    pub(super) fn set_capacity(&mut self, bytes: i16, playing: bool) -> u16 {
        if playing { return S_SERMACT; }
        if bytes < 0 { return S_SEROFM; }
        let next = usize::try_from(bytes).unwrap_or(0);
        let mut entries = VecDeque::<QueueRecord>::new();
        let slot_count = next / QUEUE_RECORD_BYTES;
        if entries.try_reserve(slot_count).is_err() { return S_SEROFM; }
        self.entries = entries;
        self.capacity_bytes = next;
        self.invalidate_rendered_snapshots();
        self.next_entry_identity = 0;
        self.identity_exhausted = false;
        self.threshold_event = false;
        self.queue_initial_accent = self.accent;
        self.played_entries = 0;
        0
    }

    pub(super) fn set_note(&mut self, voice: i16, value: i16, length: i16, dots: i16) -> u16 {
        let _ = voice;
        if value < 0 || value > 84 { return S_SERBDNT; }
        if length <= 0 { return S_SERDLN; }
        // The SDK names S_SERDCC but does not publish the numeric dot range.
        // Three dots is the bounded conventional notation range used here.
        if !(0..=MAX_DOTS).contains(&dots) { return S_SERDCC; }
        // SDK 3.0 requires SetVoiceNote to leave a slot for SyncAllVoices.
        self.push_with_reserved_slots(QueueEntry::Note {
            value: value as u8,
            length: length as u16,
            dots: dots as u8,
        }, 1)
    }

    pub(super) fn set_tone(
        &mut self,
        voice: i16,
        frequency_16_16: u32,
        duration: i16,
    ) -> u16 {
        let _ = voice;
        if duration <= 0 { return S_SERDDR; }
        // The SDK defines S_SERDFQ but no numeric range. Keep the historical
        // lower bound and cap this 48 kHz renderer at Nyquist rather than
        // aliasing a tone it cannot represent.
        let minimum = 37_u32 << 16;
        let maximum = 24_000_u32 << 16;
        if frequency_16_16 != 0 && !(minimum..=maximum).contains(&frequency_16_16) {
            return S_SERDFQ;
        }
        self.push(QueueEntry::Tone {
            frequency_16_16,
            duration_ticks: duration as u16,
        })
    }

    pub(super) fn set_accent(
        &mut self,
        voice: i16,
        tempo: i16,
        volume: i16,
        mode: i16,
        pitch: i16,
        protected_prefix: usize,
    ) -> u16 {
        let _ = voice;
        if !(32..=255).contains(&tempo) { return S_SERDTP; }
        if !(0..=255).contains(&volume) { return S_SERDVL; }
        if !(0..=2).contains(&mode) { return S_SERDMD; }
        if !(0..=83).contains(&pitch) { return S_SERDPT; }
        let mode = match mode {
            1 => Articulation::Legato,
            2 => Articulation::Staccato,
            _ => Articulation::Normal,
        };
        let accent = Accent { tempo: tempo as u16, volume: volume as u8, mode, pitch: pitch as u8 };
        if self.entries.len() > protected_prefix
            && self.entries.back().is_some_and(|record| matches!(&record.entry, QueueEntry::Accent(_)))
        {
            if let Some(QueueRecord { entry: QueueEntry::Accent(previous), .. }) = self.entries.back_mut() {
                *previous = accent;
                return 0;
            }
        }
        // SDK 3.0 gives SetVoiceAccent the same one-slot sync reservation.
        self.push_with_reserved_slots(QueueEntry::Accent(accent), 1)
    }

    /// Reserve storage and verify that this voice can accept one new marker.
    /// SyncAllVoices preflights every voice before committing any marker, so
    /// queue-full or allocation failure cannot leave only part of a barrier.
    pub(super) fn reserve_sync_marker(&mut self) -> u16 {
        if self.queue_incarnation.is_none() || self.identity_exhausted { return S_SEROFM; }
        if self.entries.len() >= self.capacity_bytes / QUEUE_RECORD_BYTES { return S_SERQFUL; }
        if self.entries.try_reserve(1).is_err() { return S_SEROFM; }
        0
    }

    /// Commit after every voice passed reserve_sync_marker. Each call allocates
    /// a new identity, including when an older Sync is still at the queue tail.
    pub(super) fn append_sync_marker(&mut self) {
        self.append_reserved(QueueEntry::Sync);
    }

    pub(super) fn can_rollback_sync_marker(&self) -> bool {
        self.entries.back().is_some_and(|record| matches!(&record.entry, QueueEntry::Sync))
    }

    /// Undo only the marker just committed by this SyncAllVoices transaction.
    /// The caller preflights every voice with can_rollback_sync_marker first.
    pub(super) fn rollback_sync_marker(&mut self) {
        if let Some(record) = self.entries.pop_back() {
            self.next_entry_identity = record.identity;
            self.identity_exhausted = false;
        }
    }

    pub(super) fn set_threshold(&mut self, voice: i16, notes: i16) -> u16 {
        let _ = voice;
        let max_notes = self.capacity_bytes / QUEUE_RECORD_BYTES;
        if notes < 0 || usize::try_from(notes).is_ok_and(|n| n > max_notes) { return 1; }
        self.threshold_notes = notes as u16;
        self.threshold_event = false;
        0
    }

    pub(super) fn below_threshold(&self) -> bool {
        self.threshold_notes != 0 && self.note_count() < self.threshold_notes
    }

    pub(super) fn threshold_notes(&self) -> u16 { self.threshold_notes }

    pub(super) fn clear_threshold_event(&mut self) {
        self.threshold_event = false;
    }

    pub(super) fn threshold_event(&self) -> bool {
        self.threshold_event
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.invalidate_rendered_snapshots();
        self.next_entry_identity = 0;
        self.identity_exhausted = false;
        self.queue_initial_accent = self.accent;
        self.played_entries = 0;
        // Stop/discard removes queued work but does not acknowledge a
        // threshold event already raised by measured playback. GetThresholdStatus
        // remains the explicit event-clear operation.
    }

    pub(super) fn render(&self) -> Result<RenderedQueue, u16> {
        if self.queue_incarnation.is_none() { return Err(S_SEROFM); }
        let entry_count = self.entries.len();
        let mut entries = Vec::new();
        entries.try_reserve_exact(entry_count).map_err(|_| S_SEROFM)?;
        let mut entry_identities = Vec::new();
        entry_identities.try_reserve_exact(entry_count).map_err(|_| S_SEROFM)?;
        for record in &self.entries {
            entries.push(record.entry.clone());
            entry_identities.push(record.identity);
        }
        let mut render = RenderedQueue {
            samples: Vec::new(),
            entries,
            entry_identities,
            boundaries: Vec::new(),
            queue_incarnation: self.queue_incarnation,
            consumed_entries: 0,
        };
        render.boundaries.try_reserve_exact(entry_count).map_err(|_| S_SEROFM)?;
        let mut accent = self.queue_initial_accent;
        for (index, entry) in render.entries.iter().enumerate() {
            match entry {
                QueueEntry::Accent(next) => accent = *next,
                QueueEntry::Sync => {}
                QueueEntry::Note { value, length, dots } => {
                    let total = note_frames(*length, *dots, accent.tempo)?;
                    // SDK 3.0 S_NORMAL sustains for the full note value.
                    // Exact S_STACCATO and S_LEGATO envelopes remain device
                    // behavior; the shortened staccato duration is an explicit
                    // host-renderer approximation, not an OEM contract.
                    let played = match accent.mode {
                        Articulation::Legato => total,
                        Articulation::Normal => total,
                        Articulation::Staccato => (total * 3 + 2) / 4,
                    };
                    if *value == 0 {
                        append_silence(&mut render.samples, total)?;
                    } else {
                        let note = ((usize::from(*value - 1) + usize::from(accent.pitch)) % 84) as u8 + 1;
                        append_tone(&mut render.samples, note_frequency_16_16(note), played, accent.volume)?;
                        append_silence(&mut render.samples, u64::from(total) - played)?;
                    }
                }
                QueueEntry::Tone { frequency_16_16, duration_ticks } => {
                    let total = tone_frames(*duration_ticks)?;
                    if *frequency_16_16 == 0 {
                        append_silence(&mut render.samples, total)?;
                    } else {
                        append_tone(&mut render.samples, *frequency_16_16, total, accent.volume)?;
                    }
                }
            }
            render.boundaries.push(QueueBoundary {
                end_frame: render.samples.len() as u64,
                entries_consumed: index + 1,
            });
        }
        Ok(render)
    }

    /// StartSound does not remove or consume the stored SOUND program. Reset
    /// only the measured playback cursor after the host accepted a submission.
    pub(super) fn begin_rendered_replay(&mut self) {
        self.played_entries = 0;
    }

    /// Advance the retained program's measured playback cursor. Entries stay
    /// in the queue for later StartSound replays; no timer discards them.
    pub(super) fn consume_rendered_prefix(
        &mut self,
        rendered: &mut RenderedQueue,
        frames: u64,
    ) -> Result<bool, QueueSnapshotError> {
        if self.queue_incarnation.is_none() || rendered.queue_incarnation != self.queue_incarnation {
            return Err(QueueSnapshotError::QueueIncarnationChanged);
        }
        if rendered.entries.len() != rendered.entry_identities.len()
            || rendered.consumed_entries > rendered.entries.len()
        {
            return Err(QueueSnapshotError::InvalidSnapshot);
        }
        let consumed = rendered.boundaries.iter()
            .take_while(|boundary| boundary.end_frame <= frames)
            .map(|boundary| boundary.entries_consumed)
            .last().unwrap_or(0);
        if consumed > rendered.entries.len() {
            return Err(QueueSnapshotError::InvalidSnapshot);
        }
        // Duplicate or out-of-order position notifications carry no new
        // played prefix and must not retire anything twice.
        if consumed <= rendered.consumed_entries { return Ok(false); }
        // Compare both value and identity before changing anything. Identity
        // prevents a stale rendered snapshot from advancing progress through
        // newly appended entries that happen to have the same note values.
        for offset in rendered.consumed_entries..consumed {
            let current = self.entries.get(offset).ok_or(QueueSnapshotError::QueuePrefixChanged)?;
            if current.identity != rendered.entry_identities[offset]
                || current.entry != rendered.entries[offset]
            {
                return Err(QueueSnapshotError::QueuePrefixChanged);
            }
        }
        let old_notes = self.note_count();
        for record in self.entries.iter().take(consumed).skip(rendered.consumed_entries) {
            if let QueueEntry::Accent(accent) = &record.entry { self.accent = *accent; }
        }
        rendered.consumed_entries = consumed;
        self.played_entries = consumed;
        let new_notes = self.note_count();
        let crossed_threshold = self.threshold_notes != 0
            && old_notes >= self.threshold_notes
            && new_notes < self.threshold_notes;
        self.update_threshold(old_notes, new_notes);
        Ok(crossed_threshold)
    }

    fn push(&mut self, entry: QueueEntry) -> u16 {
        self.push_with_reserved_slots(entry, 0)
    }

    fn push_with_reserved_slots(&mut self, entry: QueueEntry, reserved_slots: usize) -> u16 {
        if self.queue_incarnation.is_none() || self.identity_exhausted { return S_SEROFM; }
        let slots = self.capacity_bytes / QUEUE_RECORD_BYTES;
        let usable_slots = slots.saturating_sub(reserved_slots);
        if self.entries.len() >= usable_slots { return S_SERQFUL; }
        if self.entries.try_reserve(1).is_err() { return S_SEROFM; }
        self.append_reserved(entry);
        0
    }

    fn append_reserved(&mut self, entry: QueueEntry) {
        let identity = self.next_entry_identity;
        if let Some(next) = self.next_entry_identity.checked_add(1) {
            self.next_entry_identity = next;
        } else {
            // The maximum identity remains usable once. Refuse further writes
            // until clear/capacity replacement advances the queue generation.
            self.identity_exhausted = true;
        }
        self.entries.push_back(QueueRecord { identity, entry });
    }

    fn invalidate_rendered_snapshots(&mut self) {
        // Exhaustion disables snapshot retirement rather than reusing a token.
        self.queue_incarnation = self.queue_incarnation.and_then(|generation| generation.checked_add(1));
    }

    fn update_threshold(&mut self, before: u16, after: u16) {
        if self.threshold_notes != 0 && before >= self.threshold_notes && after < self.threshold_notes {
            self.threshold_event = true;
        }
    }
}

fn note_frames(length: u16, dots: u8, tempo: u16) -> Result<u64, u16> {
    let dot_denominator = 1_u128 << dots;
    let dot_numerator = dot_denominator * 2 - 1;
    let numerator = 240_000_u128 * u128::from(PCM_RATE / 1_000) * dot_numerator;
    let denominator = u128::from(length) * u128::from(tempo) * dot_denominator;
    let frames = numerator.checked_add(denominator / 2)
        .ok_or(S_SERDLN)? / denominator;
    if frames == 0 || frames > u128::from(u64::MAX) { return Err(S_SERDLN); }
    Ok(frames as u64)
}

fn tone_frames(ticks: u16) -> Result<u64, u16> {
    // The Microsoft SDK specifies clock ticks but not their duration. The
    // A local historical renderer comparison treats two ticks as 5 ms and rounds an
    // odd tick count up to that granularity; retain it only as a renderer
    // approximation, not as a Microsoft timing guarantee.
    let quanta = (u64::from(ticks) + 1) / 2;
    quanta
        .checked_mul(5)
        .and_then(|milliseconds| milliseconds.checked_mul(u64::from(PCM_RATE / 1_000)))
        .ok_or(S_SERDDR)
}

fn append_tone(output: &mut Vec<u8>, frequency_16_16: u32, frames: u64, volume: u8) -> Result<(), u16> {
    reserve_frames(output, frames)?;
    let sample_threshold = u64::from(PCM_RATE) << 16;
    let mut phase = 0_u64;
    let mut high = true;
    let increment = u64::from(frequency_16_16).saturating_mul(2);
    let amplitude = (u16::from(volume) * 127 + 127) / 255;
    for _ in 0..frames {
        phase += increment;
        if phase >= sample_threshold {
            phase %= sample_threshold;
            high = !high;
        }
        // volume is at most 255, so rounded 7-bit amplitude is at most 127.
        let amplitude = amplitude as i16;
        let signed = if high { amplitude } else { -amplitude };
        output.push((128_i16 + signed) as u8);
    }
    Ok(())
}

fn append_silence(output: &mut Vec<u8>, frames: u64) -> Result<(), u16> {
    reserve_frames(output, frames)?;
    let count = usize::try_from(frames).map_err(|_| S_SEROFM)?;
    output.resize(output.len() + count, 128);
    Ok(())
}

fn reserve_frames(output: &mut Vec<u8>, frames: u64) -> Result<(), u16> {
    let next = output.len().checked_add(usize::try_from(frames).map_err(|_| S_SEROFM)?)
        .filter(|size| *size <= MAX_PCM_FRAMES)
        .ok_or(S_SEROFM)?;
    output.try_reserve(next - output.len()).map_err(|_| S_SEROFM)
}

const fn note_frequency_16_16(note: u8) -> u32 {
    // Pitches 73-84 are C8-B8 in the old SOUND model. Lower octaves halve
    // those semitones; this is a table implementation, not copied device code.
    const C8_TO_B8: [u32; 12] = [
        4_186, 4_435, 4_699, 4_978, 5_274, 5_588,
        5_920, 6_272, 6_645, 7_040, 7_459, 7_902,
    ];
    let index = (note - 1) as usize;
    let octave_down = 6 - index / 12;
    (C8_TO_B8[index % 12] >> octave_down) << 16
}

pub(super) const fn pcm_rate() -> u32 { PCM_RATE }
