//! Owned asynchronous callback events crossing into the Win16 CPU thread.
//!
//! Native callback threads may publish values, but never execute guest code
//! and never receive a guest FAR procedure address. The runtime resolves the
//! opaque registration token and schedules the callback at a guest instruction
//! boundary. Family modules remain responsible for allocating any byte payload
//! in guest memory and retiring it after the callback returns.

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
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
pub struct Win16GuestCallbackSender {
    channel: SyncSender<Win16GuestCallbackEvent>,
    pending: Arc<AtomicUsize>,
}

/// Runtime-thread receiver. It is polled only between guest instructions or
/// after a completed synchronous host operation.
pub struct Win16GuestCallbackReceiver {
    channel: Receiver<Win16GuestCallbackEvent>,
    pending: Arc<AtomicUsize>,
}

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
    let pending = Arc::new(AtomicUsize::new(0));
    Ok((Win16GuestCallbackSender { channel: sender, pending: Arc::clone(&pending) },
        Win16GuestCallbackReceiver { channel: receiver, pending }))
}

impl Win16GuestCallbackSender {
    pub fn try_send(
        &self,
        event: Win16GuestCallbackEvent,
    ) -> Result<(), Win16GuestCallbackSendError> {
        if !event.fits_mailbox_budget() {
            return Err(Win16GuestCallbackSendError::TooLarge(event));
        }
        // Reserve before publication so a concurrent receive cannot subtract
        // from zero. An in-flight reservation is only an advisory wake hint.
        if self.pending.try_update(Ordering::AcqRel, Ordering::Acquire,
            |count| count.checked_add(1)).is_err()
        {
            return Err(Win16GuestCallbackSendError::Full(event));
        }
        match self.channel.try_send(event) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                Err(match error {
                    TrySendError::Full(event) => Win16GuestCallbackSendError::Full(event),
                    TrySendError::Disconnected(event) => Win16GuestCallbackSendError::Closed(event),
                })
            }
        }
    }
}

impl Win16GuestCallbackReceiver {
    /// Reading demand does not consume or acknowledge a callback event.
    pub fn has_pending(&self) -> bool { self.pending.load(Ordering::Acquire) != 0 }

    pub fn try_recv(
        &self,
    ) -> Result<Win16GuestCallbackEvent, Win16GuestCallbackPoll> {
        match self.channel.try_recv() {
            Ok(event) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                Ok(event)
            }
            Err(TryRecvError::Empty) => Err(Win16GuestCallbackPoll::Empty),
            Err(TryRecvError::Disconnected) => Err(Win16GuestCallbackPoll::Closed),
        }
    }
}
