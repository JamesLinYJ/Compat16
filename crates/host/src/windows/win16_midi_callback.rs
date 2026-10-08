//! Native CALLBACK_FUNCTION trampoline. It records, signals and returns.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use super::super::multimedia_wake::MultimediaWakeSender;
use windows_sys::Win32::Media::Multimedia::HDRVR;

const CALLBACK_QUEUE_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub(super) struct NativeMidiCallback {
    pub(super) sequence: u64,
    pub(super) native_device: usize,
    pub(super) message: u32,
    pub(super) parameter1: usize,
    pub(super) parameter2: usize,
}

pub(super) struct CallbackContext {
    sequences: Arc<AtomicU64>,
    wake: MultimediaWakeSender,
    queue_wake: Arc<QueueWake>,
    queue: Mutex<VecDeque<NativeMidiCallback>>,
    failure: Mutex<Option<RuntimeError>>,
    in_flight: AtomicUsize,
}

struct CallbackInvocation(Arc<CallbackContext>);

impl Deref for CallbackInvocation {
    type Target = CallbackContext;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Drop for CallbackInvocation {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
        self.0.queue_wake.signal();
        if let Err(error) = self.0.wake.signal() {
            self.0.latch(error);
        }
    }
}

/// One host-owner wait point for callbacks from every open MIDI device. A
/// sticky bit prevents losing a callback signal between queue inspection and
/// the condition-variable wait; notifications remain in their per-device
/// owned queues until the runtime commits an exact ACK.
pub(super) struct QueueWake {
    pending: Mutex<bool>,
    changed: Condvar,
}

impl QueueWake {
    pub(super) fn new() -> Self {
        Self { pending: Mutex::new(false), changed: Condvar::new() }
    }

    fn signal(&self) {
        *self.pending.lock().unwrap_or_else(|poison| poison.into_inner()) = true;
        self.changed.notify_all();
    }

    pub(super) fn wait(&self, timeout: Duration) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|poison| poison.into_inner());
        if *pending {
            *pending = false;
            return true;
        }
        let (mut pending, result) = self.changed.wait_timeout(pending, timeout)
            .unwrap_or_else(|poison| poison.into_inner());
        let signalled = *pending;
        *pending = false;
        signalled || !result.timed_out()
    }
}

impl CallbackContext {
    pub(super) fn new(
        sequences: Arc<AtomicU64>,
        wake: MultimediaWakeSender,
        queue_wake: Arc<QueueWake>,
    ) -> Self {
        Self {
            sequences,
            wake,
            queue_wake,
            queue: Mutex::new(VecDeque::new()),
            failure: Mutex::new(None),
            in_flight: AtomicUsize::new(0),
        }
    }

    pub(super) fn peek(&self) -> Option<NativeMidiCallback> {
        self.queue.lock().unwrap_or_else(|poison| poison.into_inner()).front().copied()
    }

    pub(super) fn contains_header(&self, native_header: usize) -> bool {
        self.queue.lock().unwrap_or_else(|poison| poison.into_inner()).iter()
            .any(|event| event.parameter1 == native_header)
    }

    pub(super) fn acknowledge(
        &self,
        sequence: u64,
        _disposition: runtime::Win16HostMidiNotificationDisposition,
    ) -> Result<(), RuntimeError> {
        let mut queue = self.queue.lock().unwrap_or_else(|poison| poison.into_inner());
        if queue.front().is_none_or(|event| event.sequence != sequence) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native MIDI callback ACK did not match the owned queue front"));
        }
        queue.pop_front();
        Ok(())
    }

    pub(super) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    pub(super) fn take_failure(&self) -> Option<RuntimeError> {
        self.failure.lock().unwrap_or_else(|poison| poison.into_inner()).take()
    }

    pub(super) fn latch(&self, error: RuntimeError) {
        let mut failure = self.failure.lock().unwrap_or_else(|poison| poison.into_inner());
        *failure = Some(match failure.take() {
            Some(primary) => primary.with_cleanup(
                "native MIDI callback publication and wake failed",
                error,
            ),
            None => error,
        });
        self.queue_wake.signal();
    }

    fn publish(&self, event: NativeMidiCallback) -> Result<(), RuntimeError> {
        {
            let mut queue = self.queue.lock().unwrap_or_else(|poison| poison.into_inner());
            if queue.len() >= CALLBACK_QUEUE_LIMIT {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "native MIDI callback queue exceeded its owned bound"));
            }
            queue.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve native MIDI callback event", error))?;
            queue.push_back(event);
        }
        self.queue_wake.signal();
        // The owned event is visible before the common USER worker is signaled.
        self.wake.signal()
    }
}

static CALLBACKS: OnceLock<Mutex<Vec<(usize, Arc<CallbackContext>)>>> = OnceLock::new();
static UNKNOWN_CONTEXT: AtomicBool = AtomicBool::new(false);

fn registry() -> &'static Mutex<Vec<(usize, Arc<CallbackContext>)>> {
    CALLBACKS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(super) fn register(id: usize, context: Arc<CallbackContext>) -> Result<(), RuntimeError> {
    let mut entries = registry().lock().unwrap_or_else(|poison| poison.into_inner());
    if entries.iter().any(|(existing, _)| *existing == id) {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native MIDI callback context identity was reused"));
    }
    entries.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve native MIDI callback context table", error))?;
    entries.push((id, context));
    Ok(())
}

pub(super) fn unregister_if_idle(id: usize, context: &Arc<CallbackContext>) -> bool {
    let mut entries = registry().lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(index) = entries.iter().position(|(registered, existing)|
        *registered == id && Arc::ptr_eq(existing, context)) else { return false; };
    if context.in_flight() != 0 || context.peek().is_some() { return false; }
    entries.remove(index);
    true
}

pub(super) fn unknown_context_failure() -> Option<RuntimeError> {
    UNKNOWN_CONTEXT.swap(false, Ordering::AcqRel).then(|| RuntimeError::new(
        Kind::InternalInvariant, "native MIDI callback named an unregistered owner context"))
}

pub(super) fn has_unknown_context_failure() -> bool {
    UNKNOWN_CONTEXT.load(Ordering::Acquire)
}

fn context_for(id: usize) -> Option<CallbackInvocation> {
    let entries = registry().lock().unwrap_or_else(|poison| poison.into_inner());
    let context = entries.iter().find(|(registered, _)| *registered == id)
        .map(|(_, context)| Arc::clone(context))?;
    if context.in_flight.try_update(Ordering::AcqRel, Ordering::Acquire,
        |current| current.checked_add(1)).is_err()
    {
        context.latch(RuntimeError::new(Kind::ResourceExhausted,
            "native MIDI callback in-flight counter exhausted"));
        None
    } else {
        Some(CallbackInvocation(context))
    }
}

fn next_sequence(source: &AtomicU64) -> Result<u64, RuntimeError> {
    source.try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
        next.checked_add(1).filter(|value| *value != 0)
    }).map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
        "native MIDI callback sequence source exhausted"))
}

/// Native callbacks may run on a driver-owned thread. Their only outputs are
/// queue records and a typed failure latch; guest addresses are never read.
unsafe extern "system" fn midi_callback(
    driver: HDRVR,
    message: u32,
    context_id: usize,
    parameter1: usize,
    parameter2: usize,
) {
    let context = context_for(context_id);
    let Some(context) = context else {
        UNKNOWN_CONTEXT.store(true, Ordering::Release);
        return;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let sequence = next_sequence(&context.sequences)?;
        context.publish(NativeMidiCallback {
            sequence,
            native_device: driver as usize,
            message,
            parameter1,
            parameter2,
        })
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => context.latch(error),
        Err(_) => context.latch(RuntimeError::new(Kind::HostFailure,
            "panic was contained in native MIDI callback trampoline")),
    }
}

pub(super) fn procedure() -> usize { midi_callback as *const () as usize }
