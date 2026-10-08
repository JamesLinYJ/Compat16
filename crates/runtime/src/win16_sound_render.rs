//! PCM mixing and measured-frame boundary planning for SOUND queue playback.

use super::sound_queue::{QueueEntry, RenderedQueue, S_SEROFM, MAX_PCM_FRAMES};
use crate::{DiagnosticKind as Kind, RuntimeError};

const MAX_TOTAL_VOICE_FRAMES: usize = 24_000_000;

/// Mono 8-bit samples use one byte per frame. Bound the sum of all retained
/// voice renderings as well as each individual track so sixteen valid guest
/// queues cannot multiply the single-track budget into hundreds of MiB.
pub(super) fn validate_snapshot_budget(snapshots: &[RenderedQueue]) -> Result<(), u16> {
    let total = snapshots.iter().try_fold(0_usize, |total, snapshot| {
        total.checked_add(snapshot.samples.len())
    }).ok_or(S_SEROFM)?;
    (total <= MAX_TOTAL_VOICE_FRAMES).then_some(()).ok_or(S_SEROFM)
}

pub(super) fn mix_snapshots(snapshots: &[RenderedQueue]) -> Result<Vec<u8>, RuntimeError> {
    let mut tracks = Vec::new();
    tracks.try_reserve_exact(snapshots.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve SOUND renderer tracks", error))?;
    tracks.extend(snapshots.iter().map(|snapshot| snapshot.samples.as_slice()));
    mix_tracks(&tracks)
}

pub(super) fn mix_tracks(tracks: &[&[u8]]) -> Result<Vec<u8>, RuntimeError> {
    let frames = tracks.iter().map(|track| track.len()).max().unwrap_or(0);
    let total_frames = tracks.iter().try_fold(0_usize, |total, track| {
        total.checked_add(track.len())
    }).unwrap_or(usize::MAX);
    if frames > MAX_PCM_FRAMES || total_frames > MAX_TOTAL_VOICE_FRAMES {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "SOUND voices exceed their bounded PCM frame budget"));
    }
    let mut samples = Vec::new();
    samples.try_reserve_exact(frames).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve mixed SOUND PCM buffer", error))?;
    samples.resize(frames, 128_u8);
    for (frame, mixed) in samples.iter_mut().enumerate() {
        let sum = tracks.iter().filter_map(|track| track.get(frame))
            .map(|sample| i32::from(*sample) - 128).sum::<i32>();
        *mixed = (128 + sum.clamp(-128, 127)) as u8;
    }
    Ok(samples)
}

/// Align the initial queue prefix across voices at every SyncAllVoices marker.
pub(super) fn align_voice_syncs(snapshots: &mut [RenderedQueue]) -> Result<(), u16> {
    let Some(first) = snapshots.first() else { return Ok(()); };
    let sync_count = first.entries.iter().filter(|entry| matches!(entry, QueueEntry::Sync)).count();
    for snapshot in snapshots.iter() {
        if snapshot.entries.len() != snapshot.entry_identities.len()
            || snapshot.entries.len() != snapshot.boundaries.len()
            || snapshot.entries.iter().filter(|entry| matches!(entry, QueueEntry::Sync)).count() != sync_count
        {
            return Err(S_SEROFM);
        }
    }
    for ordinal in 0..sync_count {
        let mut target = 0_u64;
        for snapshot in snapshots.iter() {
            let index = sync_entry_index(snapshot, ordinal).ok_or(S_SEROFM)?;
            target = target.max(snapshot.boundaries[index].end_frame);
        }
        if target > MAX_PCM_FRAMES as u64 { return Err(S_SEROFM); }
        for snapshot in snapshots.iter_mut() {
            let index = sync_entry_index(snapshot, ordinal).ok_or(S_SEROFM)?;
            let position = snapshot.boundaries[index].end_frame;
            let delay = target.checked_sub(position).ok_or(S_SEROFM)?;
            let position = usize::try_from(position).map_err(|_| S_SEROFM)?;
            let old_len = snapshot.samples.len();
            if position > old_len { return Err(S_SEROFM); }
            if delay == 0 { continue; }
            let delay = usize::try_from(delay).map_err(|_| S_SEROFM)?;
            let new_len = old_len.checked_add(delay)
                .filter(|length| *length <= MAX_PCM_FRAMES).ok_or(S_SEROFM)?;
            if snapshot.boundaries.iter().skip(index)
                .any(|boundary| boundary.end_frame.checked_add(delay as u64).is_none())
            {
                return Err(S_SEROFM);
            }
            snapshot.samples.try_reserve_exact(delay).map_err(|_| S_SEROFM)?;
            snapshot.samples.resize(new_len, 128);
            snapshot.samples.copy_within(position..old_len, position + delay);
            snapshot.samples[position..position + delay].fill(128);
            for boundary in snapshot.boundaries.iter_mut().skip(index) {
                boundary.end_frame += delay as u64;
            }
        }
    }
    Ok(())
}

/// Align only newly appended sync markers; the native submitted prefix is immutable.
pub(super) fn align_appended_syncs(
    snapshots: &mut [RenderedQueue],
    prefix_lengths: &[usize],
) -> Result<(), u16> {
    if snapshots.len() != prefix_lengths.len() { return Err(S_SEROFM); }
    let mut marker_count = None;
    for (snapshot, prefix_len) in snapshots.iter().zip(prefix_lengths) {
        if snapshot.entries.len() != snapshot.entry_identities.len()
            || snapshot.entries.len() != snapshot.boundaries.len()
            || *prefix_len > snapshot.entries.len()
        {
            return Err(S_SEROFM);
        }
        let count = snapshot.entries.iter().skip(*prefix_len)
            .filter(|entry| matches!(entry, QueueEntry::Sync)).count();
        if marker_count.is_some_and(|expected| expected != count) { return Err(S_SEROFM); }
        marker_count = Some(count);
    }

    for ordinal in 0..marker_count.unwrap_or(0) {
        let mut target = 0_u64;
        for (snapshot, prefix_len) in snapshots.iter().zip(prefix_lengths) {
            let base_frame = if *prefix_len == 0 { 0 } else {
                snapshot.boundaries.get(*prefix_len - 1).ok_or(S_SEROFM)?.end_frame
            };
            let index = sync_entry_index_after(snapshot, *prefix_len, ordinal).ok_or(S_SEROFM)?;
            let relative = snapshot.boundaries[index].end_frame.checked_sub(base_frame).ok_or(S_SEROFM)?;
            target = target.max(relative);
        }
        for (snapshot, prefix_len) in snapshots.iter_mut().zip(prefix_lengths) {
            let base_frame = if *prefix_len == 0 { 0 } else {
                snapshot.boundaries.get(*prefix_len - 1).ok_or(S_SEROFM)?.end_frame
            };
            let index = sync_entry_index_after(snapshot, *prefix_len, ordinal).ok_or(S_SEROFM)?;
            let position = snapshot.boundaries[index].end_frame;
            let relative = position.checked_sub(base_frame).ok_or(S_SEROFM)?;
            let delay = target.checked_sub(relative).ok_or(S_SEROFM)?;
            let old_len = snapshot.samples.len();
            let position = usize::try_from(position).map_err(|_| S_SEROFM)?;
            if position > old_len { return Err(S_SEROFM); }
            let delay = usize::try_from(delay).map_err(|_| S_SEROFM)?;
            if delay == 0 { continue; }
            let new_len = old_len.checked_add(delay)
                .filter(|length| *length <= MAX_PCM_FRAMES).ok_or(S_SEROFM)?;
            if snapshot.boundaries.iter().skip(index)
                .any(|boundary| boundary.end_frame.checked_add(delay as u64).is_none())
            {
                return Err(S_SEROFM);
            }
            snapshot.samples.try_reserve_exact(delay).map_err(|_| S_SEROFM)?;
            snapshot.samples.resize(new_len, 128);
            snapshot.samples.copy_within(position..old_len, position + delay);
            snapshot.samples[position..position + delay].fill(128);
            for boundary in snapshot.boundaries.iter_mut().skip(index) {
                boundary.end_frame += delay as u64;
            }
        }
    }
    Ok(())
}

pub(super) fn collect_boundaries(snapshots: &[RenderedQueue]) -> Result<Vec<u64>, RuntimeError> {
    let capacity = snapshots.iter().try_fold(0_usize, |total, snapshot| {
        total.checked_add(snapshot.boundaries.len())
    }).ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
        "SOUND playback boundary count overflow"))?;
    let mut boundaries = Vec::new();
    boundaries.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve SOUND playback boundaries", error))?;
    for snapshot in snapshots {
        boundaries.extend(snapshot.boundaries.iter().map(|boundary| boundary.end_frame));
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    Ok(boundaries)
}

fn sync_entry_index_after(snapshot: &RenderedQueue, start: usize, ordinal: usize) -> Option<usize> {
    snapshot.entries.iter().enumerate().skip(start)
        .filter(|(_, entry)| matches!(entry, QueueEntry::Sync))
        .nth(ordinal).map(|(index, _)| index)
}

fn sync_entry_index(snapshot: &RenderedQueue, ordinal: usize) -> Option<usize> {
    snapshot.entries.iter().enumerate()
        .filter(|(_, entry)| matches!(entry, QueueEntry::Sync))
        .nth(ordinal).map(|(index, _)| index)
}
