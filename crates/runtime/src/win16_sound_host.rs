//! Owned SOUND-family host seam; one WAVE owner implements these operations.
//!
//! No guest selector, resource handle, or native pointer crosses this
//! boundary. The Windows adapter maps PCM calls to the shared Win16WaveHost
//! owner and maps PlaySound to WinMM while that same owner retains async RIFF
//! memory until native stop or successful replacement.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SoundSession(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SoundPlayback(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SoundLease(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SoundPcmFormat {
    pub channels: u16,
    pub samples_per_second: u32,
    pub bits_per_sample: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16SoundSource {
    /// A null `pszSound`, which asks PlaySound to stop current playback.
    Stop,
    /// Owned ANSI path or alias bytes without the guest NUL terminator. The
    /// Windows adapter adds one terminator for LPCSTR; Windows receives the
    /// original flags and owns file/alias interpretation.
    FileOrAlias(Vec<u8>),
    /// A copied RIFF/WAVE byte stream. The Win16 resource reader must copy the
    /// checked guest bytes before crossing this boundary.
    MemoryWave(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SoundStopStatus {
    Stopped,
    Pending,
    NotOwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SoundWaitTarget {
    PlaybackComplete,
    /// A cumulative frame position measured from the start of this playback.
    SampleFrame(u64),
}

/// Typed operations used by `RuntimeHost::win16_sound` for the single WAVE
/// owner. They must not create a second audio device or lease registry.
///
/// `MemoryWave` storage belongs to the host owner after a successful ASYNC
/// PlaySound call. Keep the current token and bytes until an explicit native
/// stop succeeds, a replacement call succeeds, or host shutdown ends the
/// native call. A failed call or SND_NOSTOP refusal must retain the old lease.
/// A successful non-Stop call with `SND_ASYNC` returns its unique live lease;
/// a synchronous call returns no new lease because native PlaySound has
/// completed before the call returns. Lease tokens are not reused while live.
/// Native PlaySound has no completion callback; elapsed time is not proof that
/// its memory is no longer in use.
#[derive(Debug)]
pub enum Win16SoundHostOperation {
    /// Reserve the play device exclusively for the SOUND.DRV queue. The owner
    /// must return a real reservation, not a local runtime boolean.
    OpenSound { format: Win16SoundPcmFormat },
    CloseSound { session: Win16SoundSession },
    QueryPcmFormat { format: Win16SoundPcmFormat },
    PlayOwnedPcm {
        session: Win16SoundSession,
        format: Win16SoundPcmFormat,
        samples: Vec<u8>,
        /// End-frame offsets within this owned buffer, in queue-entry order.
        note_frame_boundaries: Vec<u64>,
    },
    AppendOwnedPcm {
        playback: Win16SoundPlayback,
        samples: Vec<u8>,
        /// End-frame offsets within the appended buffer, in queue-entry order.
        note_frame_boundaries: Vec<u64>,
    },
    /// Return a measured cumulative sample-frame position for this token.
    PlaybackPosition { playback: Win16SoundPlayback },
    /// Release a completed playback after the runtime commits its final
    /// measured position and queue prefix.
    RetirePlayback { playback: Win16SoundPlayback },
    WaitPlayback {
        playback: Win16SoundPlayback,
        /// `SampleFrame` is absolute within this playback, not its last append.
        target: Win16SoundWaitTarget,
    },
    StopPlayback { playback: Win16SoundPlayback },
    PlayWave {
        source: Win16SoundSource,
        flags: u32,
    },
    /// Stop only the matching SOUND-owned asynchronous PlaySound lease.
    StopPlayWave { lease: Win16SoundLease },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16SoundHostResult {
    SoundOpened {
        result: u16,
        session: Option<Win16SoundSession>,
    },
    SoundClosed { result: u16 },
    PcmFormat { result: u32, supported: bool },
    PcmStarted { result: u32, playback: Option<Win16SoundPlayback> },
    PcmAppended { result: u32 },
    /// `complete` means every owned header is quiescent. Natural completion
    /// reports the full accepted frame count; confirmed Stop/Reset completion
    /// may report a shorter measured prefix.
    PlaybackPosition { result: u32, frames_played: u64, complete: bool },
    /// Idempotent receipt for the exact playback token's host record release.
    PlaybackRetired { result: u32 },
    /// Same completion and cumulative-frame contract as PlaybackPosition.
    PlaybackWait { result: u32, frames_played: u64, complete: bool },
    PlaybackStopped { result: u32, status: Win16SoundStopStatus },
    PlayWave {
        result: bool,
        lease: Option<Win16SoundLease>,
        /// Exact prior token released only after native stop/replacement is
        /// confirmed. `None` means the caller must retain its previous token.
        retired_lease: Option<Win16SoundLease>,
    },
    /// `NotOwned` is an exact retirement receipt for this lease even when
    /// `result` is false: the owner did not stop the replacement playback,
    /// but this caller's old token is no longer live.
    PlayWaveStopped { result: bool, status: Win16SoundStopStatus },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16SoundPlaybackEvent {
    pub playback: Win16SoundPlayback,
    /// Measured cumulative native sample position, not an estimate from time.
    pub frames_played: u64,
    /// True after natural completion or a confirmed partial Stop/Reset.
    pub complete: bool,
    pub result: u32,
}
