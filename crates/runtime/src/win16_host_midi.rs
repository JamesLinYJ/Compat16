//! Owned MIDI operations and callback records crossing the runtime/host ABI.
//!
//! MIDIHDR16, guest FAR values, and native HMIDI values never cross this
//! boundary. The host retains native headers and sample storage until the
//! matching unprepare/close operation succeeds.

use std::sync::Arc;
use crate::RuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Win16HostMidiDirection {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMidiDevice {
    pub token: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMidiHeader {
    pub token: u64,
    pub generation: u64,
}

/// One accepted asynchronous submission of a prepared MIDIHDR. A prepared
/// header may be submitted more than once, so completion identity is distinct
/// from header identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMidiSubmission {
    pub token: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMidiMixerId {
    pub result: u32,
    pub mixer_id: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMidiCaps {
    Input {
        manufacturer: u16,
        product: u16,
        driver_version: u16,
        product_name: [u8; 32],
    },
    Output {
        manufacturer: u16,
        product: u16,
        driver_version: u16,
        product_name: [u8; 32],
        technology: u16,
        voices: u16,
        notes: u16,
        channel_mask: u16,
        support: u32,
    },
}

#[derive(Clone, Debug)]
pub enum Win16HostMidiCall {
    DeviceCount { direction: Win16HostMidiDirection },
    GetCaps { direction: Win16HostMidiDirection, device_id: u16, size: u16 },
    GetErrorText { direction: Win16HostMidiDirection, error: u16, capacity: u16 },
    Open { direction: Win16HostMidiDirection, device_id: u16, instance: u32, flags: u32 },
    Close { device: Win16HostMidiDevice },
    /// Roll back an open whose guest handle could not be published. The host
    /// keeps the exact owner until its callback stream is drained.
    CloseUnpublished { device: Win16HostMidiDevice },
    /// Release an actually unprepared native header after runtime callback
    /// sources and acknowledgments for its exact identity have quiesced.
    ReleaseRetiredHeader { device: Win16HostMidiDevice, header: Win16HostMidiHeader },
    PrepareHeader {
        device: Win16HostMidiDevice,
        capacity: u32,
        user: u32,
        initial_data: Vec<u8>,
    },
    UnprepareHeader { device: Win16HostMidiDevice, header: Win16HostMidiHeader },
    OutputShort { device: Win16HostMidiDevice, message: u32 },
    OutputLong { device: Win16HostMidiDevice, header: Win16HostMidiHeader, data: Vec<u8> },
    OutputReset { device: Win16HostMidiDevice },
    /// Win16 MMSYSTEM declares volume operations by UINT device ID, not HMIDIOUT.
    OutputGetVolumeById { device_id: u16 },
    OutputSetVolumeById { device_id: u16, volume: u32 },
    OutputCachePatches { device: Win16HostMidiDevice, bank: u16, patches: Vec<u16>, flags: u16 },
    OutputCacheDrumPatches { device: Win16HostMidiDevice, patch: u16, keys: Vec<u16>, flags: u16 },
    GetId { device: Win16HostMidiDevice },
    InputAddBuffer { device: Win16HostMidiDevice, header: Win16HostMidiHeader },
    InputStart { device: Win16HostMidiDevice },
    InputStop { device: Win16HostMidiDevice },
    InputReset { device: Win16HostMidiDevice },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMidiHeaderState {
    pub header: Win16HostMidiHeader,
    /// A submitted buffer that WinMM has not completed yet.
    pub submission: Option<Win16HostMidiSubmission>,
    /// Submission represented by the completion callback carrying this state.
    /// It is distinct from `submission`, because guest callback code may submit
    /// this header again before the previous callback is acknowledged.
    pub completed_submission: Option<Win16HostMidiSubmission>,
    pub capacity: u32,
    pub bytes_recorded: u32,
    pub user: u32,
    pub flags: u32,
    /// True when an unprepare succeeded while a native callback for this exact
    /// header was already queued. The runtime must keep its guest FAR identity
    /// until that callback is acknowledged.
    pub callback_pending: bool,
    /// Set only for a completed input header; contains copied bytes, never
    /// MIDIHDR::lpData or the native MIDIHDR address.
    pub input_data: Option<Arc<[u8]>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMidiResult {
    Scalar(u32),
    DeviceId { result: u32, device_id: Option<u32> },
    Volume { result: u32, value: Option<u32> },
    Caps { result: u32, caps: Option<Win16HostMidiCaps> },
    ErrorText { result: u32, bytes: Vec<u8> },
    Opened { result: u32, device: Option<Win16HostMidiDevice> },
    /// Close stages are separate so an unprepare failure cannot masquerade as
    /// a close result. `retired_headers` contains the native state captured
    /// after each successful unprepare, including callback ownership needed
    /// before the runtime may recycle a guest MIDIHDR identity. The failing
    /// header, when present, is an opaque host token, never a host pointer.
    Closed {
        result: u32,
        retired_headers: Vec<Win16HostMidiHeaderState>,
        reset_result: Option<u32>,
        unprepare_header: Option<Win16HostMidiHeader>,
        unprepare_result: Option<u32>,
        close_result: Option<u32>,
    },
    Header { result: u32, state: Option<Win16HostMidiHeaderState> },
    RetiredHeaderReleased { header: Win16HostMidiHeader, released: bool },
    PatchArray { result: u32, values: Vec<u16> },
}

/// Exact identity for a non-destructively peeked native callback. A sequence
/// may be ACKed only for the same owner generation that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostMidiNotificationId {
    pub device: Win16HostMidiDevice,
    pub sequence: u64,
}

/// Why an exact native callback queue item is retired. Cancellation is not
/// reported as guest delivery; its reason records a typed unavailable-target,
/// rejected USER post, or teardown outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMidiNotificationDisposition {
    Delivered,
    Cancelled(Win16HostMidiCancellationReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMidiCancellationReason {
    /// CALLBACK_NULL uses the native trampoline only for local bookkeeping.
    NoCallbackRequested,
    CallbackRegistrationRetired,
    WindowTargetRetired,
    TaskTargetRetired,
    /// USER returned false for the exact cached notification post.
    UserPostRejected,
    /// A native handle opened during a failed guest open never acquired a
    /// guest alias, so its exact callback is drained without guest delivery.
    UnpublishedOwner,
    /// The owning Win16 task/process is retiring, so no guest callback can run.
    OwnerTerminated,
    GuestCallbackFailed,
}

/// One callback recorded by the native-only trampoline. The runtime verifies
/// the exact device generation and header before touching guest memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMidiNotification {
    pub sequence: u64,
    pub device: Win16HostMidiDevice,
    pub callback_instance: u32,
    pub message: u32,
    pub parameter1: u32,
    pub parameter2: u32,
    pub header: Option<Win16HostMidiHeaderState>,
}

/// Native device close result used by task cleanup and explicit close.
#[derive(Debug)]
pub struct Win16HostMidiCloseAll {
    pub devices: Vec<Win16HostMidiClosedDevice>,
    /// Native close failures and unpublished-owner quiescence failures retain
    /// exact generation identity alongside independent successful receipts.
    pub failures: Vec<Win16HostMidiCloseFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostMidiClosedDevice {
    pub device: Win16HostMidiDevice,
    /// `None` means Reset was not part of the close sequence.
    pub reset_result: Option<u32>,
    /// Exact headers actually unprepared before the native device close.
    pub unprepared_headers: Vec<Win16HostMidiHeader>,
    /// `None` means Close was not attempted in this operation.
    pub close_result: Option<u32>,
}

#[derive(Debug)]
pub struct Win16HostMidiCloseFailure {
    pub device: Win16HostMidiDevice,
    pub reset_result: Option<u32>,
    /// Header tokens actually unprepared earlier in the same attempt.
    pub unprepared_headers: Vec<Win16HostMidiHeader>,
    /// Exact failed native unprepare stage, when it was attempted.
    pub unprepare_header: Option<Win16HostMidiHeader>,
    pub unprepare_result: Option<u32>,
    pub close_result: Option<u32>,
    /// True only for a partial-open native owner that never acquired a guest
    /// device alias. Runtime may accept its otherwise unknown exact token.
    pub unpublished_owner: bool,
    /// Only present for a host-private partial-open orphan. This typed cause
    /// reports its still-owned callback/quiescence failure to task cleanup.
    pub unpublished_owner_error: Option<RuntimeError>,
}

/// Exact host registry owner class for a MIDI producer barrier receipt.
/// The device token includes creation generation; direction and instance bind
/// the owner to the native callback registration that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostMidiProducerOwner {
    GuestPublished {
        direction: Win16HostMidiDirection,
        callback_instance: u32,
    },
    Unpublished {
        direction: Win16HostMidiDirection,
        callback_instance: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMidiProducerReceipt {
    pub device: Win16HostMidiDevice,
    pub owner: Win16HostMidiProducerOwner,
    /// `None` is valid only when the same native owner has a successful Close.
    pub reset_result: Option<u32>,
    pub close_result: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostMidiProducerFailure {
    pub device: Win16HostMidiDevice,
    pub owner: Win16HostMidiProducerOwner,
    /// The exact nonzero MMRESULT retained on this host owner.
    pub reset_result: u32,
}

/// Snapshot of every actual native MIDI owner at one quiescence request.
/// Empty is meaningful only from a provider that implements this operation.
#[derive(Debug)]
pub struct Win16HostMidiProducerQuiescence {
    pub observed_owner_count: usize,
    pub devices: Vec<Win16HostMidiProducerReceipt>,
    pub failures: Vec<Win16HostMidiProducerFailure>,
}

pub(crate) fn unavailable() -> crate::RuntimeError {
    crate::RuntimeError::new(crate::DiagnosticKind::CompatibilityGap,
        "host Win16 MIDI services are unavailable")
}
