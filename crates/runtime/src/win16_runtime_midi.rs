//! Win16 MIDI handle, header, and notification ownership.
//!
//! Native MIDIHDR storage remains in the host adapter. This state file keeps
//! only guest FAR identities and generation-qualified host tokens.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use guest_core::OwnerId;
use super::Win16State;
use super::window_post::WindowPostAttempt;
use crate::{Win16GuestCallbackToken, Win16HostMidiDevice, Win16HostMidiDirection,
    Win16HostMidiHeader, Win16HostMidiHeaderState, Win16HostMidiNotificationId};

#[path = "win16_runtime_midi_calls.rs"]
mod calls;
#[path = "win16_runtime_midi_close.rs"]
mod close;
#[path = "win16_runtime_midi_notifications.rs"]
mod notifications;
#[path = "win16_runtime_midi_posts.rs"]
mod posts;
#[path = "win16_runtime_midi_output_id.rs"]
mod output_id;
#[path = "win16_runtime_midi_patches.rs"]
mod patches;
#[path = "win16_runtime_midi_ranges.rs"]
mod ranges;
#[path = "win16_runtime_midi_shutdown.rs"]
mod shutdown;
#[path = "win16_runtime_midi_terminal.rs"]
mod terminal;
#[path = "win16_runtime_midi_task.rs"]
mod task;
#[path = "win16_runtime_midi_unprepare.rs"]
mod unprepare;

pub(crate) use notifications::Win16MidiNotificationTarget;
use ranges::MidiGuestRange;

pub(crate) const MMSYSERR_NOERROR: u32 = 0;
pub(crate) const MMSYSERR_INVALHANDLE: u32 = 5;
pub(crate) const MMSYSERR_NOMEM: u32 = 7;
pub(crate) const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub(crate) const MMSYSERR_INVALFLAG: u32 = 10;
pub(crate) const MMSYSERR_INVALPARAM: u32 = 11;
pub(crate) const MIDIERR_UNPREPARED: u32 = 64;
pub(crate) const MIDIERR_STILLPLAYING: u32 = 65;

pub(crate) const CALLBACK_TYPEMASK: u32 = 0x0007_0000;
pub(crate) const CALLBACK_NULL: u32 = 0x0000_0000;
pub(crate) const CALLBACK_WINDOW: u32 = 0x0001_0000;
pub(crate) const CALLBACK_TASK: u32 = 0x0002_0000;
pub(crate) const CALLBACK_FUNCTION: u32 = 0x0003_0000;
pub(crate) const MHDR_DONE: u32 = 1;
pub(crate) const MHDR_PREPARED: u32 = 2;
pub(crate) const MHDR_INQUEUE: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MidiDispatch { Idle, Progress, CallbackEntered }

#[derive(Debug)]
pub(super) struct Win16MidiState {
    notification_progress: u64,
    next_guest_device: u32,
    devices: Vec<MidiDeviceRecord>,
    headers: Vec<MidiHeaderRecord>,
    dispatching: Option<Win16MidiDispatch>,
    /// Callback-stack rollback owns this exact unACKed source until its
    /// temporary guest buffers can be released and the notification retried.
    pending_callback_cleanup: Option<super::CallbackFrameId>,
    warned_gaps: BTreeSet<u16>,
    pending_cleanup: VecDeque<Win16HostMidiDevice>,
    producers_quiesced: bool,
    cleanup_complete: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Win16MidiDispatch {
    pub(super) identity: Win16HostMidiNotificationId,
    pub(super) message: u32,
    pub(super) guest_device: u16,
    pub(super) host_header: Option<Win16HostMidiHeader>,
    pub(super) completion: Option<crate::Win16HostMidiSubmission>,
    pub(super) callback_route: MidiCallbackRoute,
    /// FUNCTION callback dispatch has started from this exact native
    /// notification/header/submission generation. This phase survives the
    /// guest-visible completion marker being cleared before entry.
    pub(super) function_started: bool,
    /// Normal USER proof/result/cause remains attached to this native MIDI
    /// notification until its proof is consumed and its family ACK succeeds.
    pub(super) post_attempt: Option<WindowPostAttempt>,
    /// A successful USER post is an exact delivery point. If the source ACK
    /// then fails, retry only the ACK; posting again would duplicate delivery.
    pub(super) post_accepted: bool,
    /// The exact host-created USER POST failure stays with this native source
    /// until USER terminal ACK and MIDI notification retirement both succeed.
    pub(super) post_failure: Option<Arc<crate::Win16WindowOperationStartedFailure>>,
    pub(super) terminal_ack: Option<crate::Win16WindowTerminalAck>,
    pub(super) terminal_acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MidiCallbackRoute {
    None,
    Function(Win16GuestCallbackToken),
    Window { host: crate::Win16HostWindow, guest: u16 },
    Task(Win16GuestTaskIdentity),
}

/// A Win16 task target stays distinct from the one native USER worker queue.
/// OwnerId is never recycled; the TDB selector generation detects raw HTASK
/// reuse before a queued callback can be delivered to another task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16GuestTaskIdentity {
    pub(super) owner: OwnerId,
    pub(super) handle: u16,
    pub(super) selector_generation: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct MidiDeviceRecord {
    pub(super) guest: u16,
    pub(super) direction: Win16HostMidiDirection,
    pub(super) host: Win16HostMidiDevice,
    pub(super) callback: MidiCallbackRoute,
    pub(super) instance: u32,
    pub(super) closing: bool,
    pub(super) reset_result: Option<u32>,
    /// Preserve the first native reset MMRESULT without treating it as a
    /// receipt; host cleanup retries Reset until it obtains an actual success.
    pub(super) reset_failure_result: Option<u32>,
    pub(super) close_result: Option<u32>,
    /// A terminal host callback was explicitly ACKed for this exact device
    /// generation. A successful native close alone is not the close receipt.
    pub(super) close_seen: bool,
}

#[derive(Clone, Debug)]
pub(super) struct MidiHeaderRecord {
    pub(super) guest_device: u16,
    pub(super) direction: Win16HostMidiDirection,
    pub(super) host_device: Win16HostMidiDevice,
    pub(super) host_header: Win16HostMidiHeader,
    pub(super) header_far: u32,
    pub(super) data_far: u32,
    pub(super) capacity: u32,
    pub(super) user: u32,
    pub(super) guest_flags: u32,
    pub(super) submission: Option<crate::Win16HostMidiSubmission>,
    /// Completion is committed to guest memory but its WINDOW/TASK post or
    /// FUNCTION callback return has not yet retired the host queue item.
    pub(super) completed_pending: Option<crate::Win16HostMidiSubmission>,
    header_range: MidiGuestRange,
    data_range: MidiGuestRange,
    pub(super) prepared: bool,
    pub(super) retired: bool,
    /// Exact successful Close-stage unprepare state retained until its guest
    /// flag projection and host/runtime callback quiescence both complete.
    pub(super) pending_close_projection: Option<Win16HostMidiHeaderState>,
    /// Original nonzero WinMM result retained if guest publication must retry.
    pub(super) pending_close_native_result: Option<u32>,
    pub(super) close_projection_committed: bool,
    /// Successful ordinary UnprepareHeader state and MMRESULT survive until
    /// its guest-memory projection commits and exact native release is asked.
    pub(super) pending_unprepare_projection: Option<Win16HostMidiHeaderState>,
    pub(super) pending_unprepare_native_result: Option<u32>,
    pub(super) pending_unprepare_failure: Option<Arc<crate::RuntimeError>>,
}

impl Default for Win16MidiState {
    fn default() -> Self {
        Self {
            notification_progress: 0,
            next_guest_device: 1,
            devices: Vec::new(),
            headers: Vec::new(),
            dispatching: None,
            pending_callback_cleanup: None,
            warned_gaps: BTreeSet::new(),
            pending_cleanup: VecDeque::new(),
            producers_quiesced: false,
            cleanup_complete: false,
        }
    }
}

impl Win16MidiState {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.devices.is_empty()
            || !self.headers.is_empty()
            || self.dispatching.is_some()
            || self.pending_callback_cleanup.is_some()
            || !self.pending_cleanup.is_empty()
    }

    pub(super) fn device(&self, guest: u16, direction: Win16HostMidiDirection)
        -> Option<&MidiDeviceRecord>
    {
        self.devices.iter().find(|record| record.guest == guest
            && record.direction == direction && !record.closing)
    }

    pub(super) fn device_for_host(&self, host: Win16HostMidiDevice)
        -> Option<&MidiDeviceRecord>
    {
        self.devices.iter().find(|record| record.host == host)
    }

    pub(super) fn header(&self, guest_device: u16, header_far: u32)
        -> Option<&MidiHeaderRecord>
    {
        self.headers.iter().find(|record| record.guest_device == guest_device
            && record.header_far == header_far)
    }

    pub(super) fn header_mut(&mut self, guest_device: u16, header_far: u32)
        -> Option<&mut MidiHeaderRecord>
    {
        self.headers.iter_mut().find(|record| record.guest_device == guest_device
            && record.header_far == header_far)
    }

    pub(super) fn reserve_guest_device(&mut self) -> Option<u16> {
        let candidate = self.next_guest_device;
        if candidate == 0 || candidate > u32::from(u16::MAX) {
            return None;
        }
        self.next_guest_device = candidate.checked_add(1)?;
        Some(candidate as u16)
    }

    pub(super) fn warned_gap(&mut self, ordinal: u16) -> bool {
        self.warned_gaps.insert(ordinal)
    }

    pub(super) fn notification_is_dispatching(
        &self,
        identity: Win16HostMidiNotificationId,
    ) -> bool {
        self.dispatching.as_ref().is_some_and(|pending| pending.identity == identity)
    }
}
