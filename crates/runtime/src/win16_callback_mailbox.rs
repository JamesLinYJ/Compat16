//! Owned asynchronous callback events crossing into the Win16 CPU thread.
//!
//! Native callback threads may publish values, but never execute guest code
//! and never receive a guest FAR procedure address. The runtime resolves the
//! opaque registration token and schedules the callback at a guest instruction
//! boundary. Family modules remain responsible for allocating any byte payload
//! in guest memory and retiring it after the callback returns.

use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};

use win16_abi::Access;
use crate::{DiagnosticKind, RuntimeError};

/// Bound callback work before an event can sit in the cross-thread mailbox.
/// Payloads are copied into guest memory only after the runtime accepts the
/// event, so bounding both count and bytes also bounds queued host allocations.
const MAX_CALLBACK_EVENT_ARGUMENTS: usize = 256;
const MAX_CALLBACK_EVENT_BYTES: usize = 1_048_576;

/// Runtime-owned identity for a registered guest callback. This is not a FAR
/// address and has no meaning to native Windows APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Win16GuestCallbackToken(pub u64);

/// Values copied from a native callback event. Pointer arguments cross as
/// owned bytes and are turned into checked guest buffers by the family codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16CallbackArgumentData {
    Word(u16),
    Dword(u32),
    OwnedBytes { bytes: Vec<u8>, access: Access },
}

/// One asynchronous callback request. The registration token is resolved by
/// the runtime; no native callback thread can select or invoke arbitrary guest
/// code by supplying a FAR value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16GuestCallbackEvent {
    pub callback: Win16GuestCallbackToken,
    pub arguments: Vec<Win16CallbackArgumentData>,
}

impl Win16GuestCallbackEvent {
    fn fits_mailbox_budget(&self) -> bool {
        if self.arguments.len() > MAX_CALLBACK_EVENT_ARGUMENTS {
            return false;
        }
        self.arguments.iter().try_fold(0_usize, |total, argument| {
            let length = match argument {
                Win16CallbackArgumentData::OwnedBytes { bytes, .. } => bytes.len(),
                Win16CallbackArgumentData::Word(_) | Win16CallbackArgumentData::Dword(_) => 0,
            };
            total.checked_add(length)
                .filter(|size| *size <= MAX_CALLBACK_EVENT_BYTES)
        }).is_some()
    }
}

/// A bounded nonblocking event sender for native callback producers.
#[derive(Clone, Debug)]
pub struct Win16GuestCallbackSender(SyncSender<Win16GuestCallbackEvent>);

/// Runtime-thread receiver. It is polled only between guest instructions or
/// after a completed synchronous host operation.
pub struct Win16GuestCallbackReceiver(Receiver<Win16GuestCallbackEvent>);

#[derive(Debug)]
pub enum Win16GuestCallbackSendError {
    TooLarge(Win16GuestCallbackEvent),
    Full(Win16GuestCallbackEvent),
    Closed(Win16GuestCallbackEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16GuestCallbackPoll {
    Empty,
    Closed,
}

/// Create a bounded callback channel. Producers must use `try_send`; native
/// callback threads are never blocked waiting for guest execution.
pub fn win16_guest_callback_channel(
    capacity: usize,
) -> Result<(Win16GuestCallbackSender, Win16GuestCallbackReceiver), RuntimeError> {
    if capacity == 0 {
        return Err(RuntimeError::new(DiagnosticKind::InvalidInput,
            "Win16 callback event capacity must be nonzero"));
    }
    let (sender, receiver) = mpsc::sync_channel(capacity);
    Ok((Win16GuestCallbackSender(sender), Win16GuestCallbackReceiver(receiver)))
}

impl Win16GuestCallbackSender {
    pub fn try_send(
        &self,
        event: Win16GuestCallbackEvent,
    ) -> Result<(), Win16GuestCallbackSendError> {
        if !event.fits_mailbox_budget() {
            return Err(Win16GuestCallbackSendError::TooLarge(event));
        }
        self.0.try_send(event).map_err(|error| match error {
            TrySendError::Full(event) => Win16GuestCallbackSendError::Full(event),
            TrySendError::Disconnected(event) => Win16GuestCallbackSendError::Closed(event),
        })
    }
}

impl Win16GuestCallbackReceiver {
    pub fn try_recv(
        &self,
    ) -> Result<Win16GuestCallbackEvent, Win16GuestCallbackPoll> {
        self.0.try_recv().map_err(|error| match error {
            TryRecvError::Empty => Win16GuestCallbackPoll::Empty,
            TryRecvError::Disconnected => Win16GuestCallbackPoll::Closed,
        })
    }
}
