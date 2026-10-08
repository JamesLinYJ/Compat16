//! Native WinMM CALLBACK_FUNCTION trampoline.
//!
//! The callback only records host-owned completion signals. It never touches
//! guest memory, and it never queues a guest FAR address for the native OS.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::super::multimedia_wake::MultimediaWakeSender;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWaveDirection, Win16HostWaveHeaderState,
    Win16HostWaveSubmission,
};
use windows_sys::Win32::Media::Audio::{HWAVEIN, HWAVEOUT, WAVEHDR};

#[derive(Debug, Default)]
pub(super) struct CallbackSignal {
    sequence: AtomicU64,
    submission_generation: AtomicU64,
    flags: AtomicU32,
    bytes_recorded: AtomicU32,
}

pub(super) struct CallbackWake {
    generation: Mutex<u64>,
    changed: Condvar,
    multimedia: Option<MultimediaWakeSender>,
    signal_failure: Mutex<Option<RuntimeError>>,
}

impl CallbackWake {
    pub(super) fn new(multimedia: Option<MultimediaWakeSender>) -> Self {
        Self {
            generation: Mutex::new(0),
            changed: Condvar::new(),
            multimedia,
            signal_failure: Mutex::new(None),
        }
    }

    pub(super) fn take_signal_failure(&self) -> Option<RuntimeError> {
        self.signal_failure
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
    }

    pub(super) fn generation(&self) -> u64 {
        *self
            .generation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(super) fn notify(&self) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *generation = generation.wrapping_add(1);
        self.changed.notify_all();
        drop(generation);
        if let Some(multimedia) = &self.multimedia {
            if let Err(error) = multimedia.signal() {
                let mut failure = self
                    .signal_failure
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if failure.is_none() {
                    *failure = Some(error);
                }
            }
        }
    }

    pub(super) fn wait_for_change(&self, observed: u64, timeout: Duration) {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if *generation == observed {
            let _ = self
                .changed
                .wait_timeout_while(generation, timeout, |current| *current == observed)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }
}

impl CallbackSignal {
    fn publish(
        &self,
        sequence_source: &AtomicU64,
        submission: Option<Win16HostWaveSubmission>,
        state: Option<Win16HostWaveHeaderState>,
    ) -> bool {
        let Some(sequence) = next_sequence(sequence_source) else {
            return false;
        };
        if self
            .sequence
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if let Some(state) = state {
            self.flags.store(state.flags, Ordering::Relaxed);
            self.bytes_recorded
                .store(state.bytes_recorded, Ordering::Relaxed);
        }
        self.submission_generation
            .store(submission.map_or(0, |value| value.0), Ordering::Relaxed);
        self.sequence.store(sequence, Ordering::Release);
        true
    }

    pub(super) fn arm_submission(&self, submission: Win16HostWaveSubmission) {
        self.submission_generation
            .store(submission.0, Ordering::Release);
    }

    pub(super) fn disarm_submission(&self) {
        self.submission_generation.store(0, Ordering::Release);
    }

    pub(super) fn peek(
        &self,
    ) -> Option<(
        u64,
        Option<Win16HostWaveSubmission>,
        Win16HostWaveHeaderState,
    )> {
        let sequence = self.sequence.load(Ordering::Acquire);
        if sequence == 0 || sequence == u64::MAX {
            return None;
        }
        Some((
            sequence,
            match self.submission_generation.load(Ordering::Relaxed) {
                0 => None,
                value => Some(Win16HostWaveSubmission(value)),
            },
            Win16HostWaveHeaderState {
                flags: self.flags.load(Ordering::Relaxed),
                bytes_recorded: self.bytes_recorded.load(Ordering::Relaxed),
            },
        ))
    }

    pub(super) fn consume(&self, sequence: u64) -> bool {
        self.sequence
            .compare_exchange(sequence, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn active_submission(&self) -> Option<Win16HostWaveSubmission> {
        match self.submission_generation.load(Ordering::Acquire) {
            0 => None,
            value => Some(Win16HostWaveSubmission(value)),
        }
    }
}

#[derive(Clone, Debug)]
struct HeaderSignal {
    native_header: usize,
    signal: Arc<CallbackSignal>,
}

pub(super) struct CallbackContext {
    pub(super) direction: Win16HostWaveDirection,
    sequences: Arc<AtomicU64>,
    open_signal: CallbackSignal,
    close_signal: CallbackSignal,
    close_seen: AtomicBool,
    active_callbacks: AtomicUsize,
    callback_failure: AtomicBool,
    wake: Arc<CallbackWake>,
    headers: Mutex<Vec<HeaderSignal>>,
}

impl CallbackContext {
    pub(super) fn new(
        direction: Win16HostWaveDirection,
        sequences: Arc<AtomicU64>,
        wake: Arc<CallbackWake>,
    ) -> Self {
        Self {
            direction,
            sequences,
            open_signal: CallbackSignal::default(),
            close_signal: CallbackSignal::default(),
            close_seen: AtomicBool::new(false),
            active_callbacks: AtomicUsize::new(0),
            callback_failure: AtomicBool::new(false),
            wake,
            headers: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn open_signal(&self) -> &CallbackSignal {
        &self.open_signal
    }
    pub(super) fn close_signal(&self) -> &CallbackSignal {
        &self.close_signal
    }
    pub(super) fn close_seen(&self) -> bool {
        self.close_seen.load(Ordering::Acquire)
    }
    pub(super) fn active_callbacks(&self) -> usize {
        self.active_callbacks.load(Ordering::Acquire)
    }
    pub(super) fn wait_for_change(&self, timeout: Duration) {
        let observed = self.wake.generation();
        self.wake.wait_for_change(observed, timeout);
    }
    pub(super) fn take_failure(&self) -> bool {
        self.callback_failure.swap(false, Ordering::AcqRel)
    }

    pub(super) fn register_header(
        &self,
        native_header: usize,
        signal: Arc<CallbackSignal>,
    ) -> Result<(), RuntimeError> {
        let mut headers = self
            .headers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        headers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WinMM callback header map",
                error,
            )
        })?;
        headers.push(HeaderSignal {
            native_header,
            signal,
        });
        Ok(())
    }

    pub(super) fn unregister_header(&self, native_header: usize) {
        let mut headers = self
            .headers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        headers.retain(|entry| entry.native_header != native_header);
    }

    fn header_signal(&self, native_header: usize) -> Option<Arc<CallbackSignal>> {
        let headers = self
            .headers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        headers
            .iter()
            .find(|entry| entry.native_header == native_header)
            .map(|entry| Arc::clone(&entry.signal))
    }

    fn enter(&self) -> ActiveCallback<'_> {
        self.active_callbacks.fetch_add(1, Ordering::AcqRel);
        ActiveCallback(self)
    }

    fn publish_simple(&self, signal: &CallbackSignal) {
        if !signal.publish(&self.sequences, None, None) {
            self.callback_failure.store(true, Ordering::Release);
        }
    }

    fn publish_completion(&self, native_header: usize) {
        let Some(signal) = self.header_signal(native_header) else {
            self.callback_failure.store(true, Ordering::Release);
            return;
        };
        let Some(submission) = signal.active_submission() else {
            self.callback_failure.store(true, Ordering::Release);
            return;
        };
        // Do not dereference the WAVEHDR on WinMM's callback thread. An
        // unprepare call may race with a late callback; the owner thread reads
        // the stable header only after the callback has returned.
        if !signal.publish(&self.sequences, Some(submission), None) {
            self.callback_failure.store(true, Ordering::Release);
        }
    }
}

struct ActiveCallback<'a>(&'a CallbackContext);

impl Drop for ActiveCallback<'_> {
    fn drop(&mut self) {
        let wake = Arc::clone(&self.0.wake);
        self.0.active_callbacks.fetch_sub(1, Ordering::AcqRel);
        // The owner may retire the context when the active count reaches zero.
        // Keep the independently owned wake alive and do not touch the context
        // after publishing quiescence.
        wake.notify();
    }
}

fn next_sequence(source: &AtomicU64) -> Option<u64> {
    let mut current = source.load(Ordering::Relaxed);
    loop {
        if current == 0 || current == u64::MAX {
            return None;
        }
        match source.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(current),
            Err(observed) => current = observed,
        }
    }
}

fn dispatch_callback(
    instance: usize,
    direction: Win16HostWaveDirection,
    message: u32,
    parameter1: usize,
) {
    if instance == 0 {
        return;
    }
    // SAFETY: CALLBACK_FUNCTION receives the stable Box address that this
    // owner retains through its actual close callback and active invocations.
    let context = unsafe { &*(instance as *const CallbackContext) };
    let _active = context.enter();
    if direction != context.direction {
        context.callback_failure.store(true, Ordering::Release);
        return;
    }
    match (direction, message) {
        (Win16HostWaveDirection::Output, 0x03bb) | (Win16HostWaveDirection::Input, 0x03be) => {
            context.publish_simple(&context.open_signal)
        }
        (Win16HostWaveDirection::Output, 0x03bc) | (Win16HostWaveDirection::Input, 0x03bf) => {
            context.close_seen.store(true, Ordering::Release);
            context.publish_simple(&context.close_signal);
        }
        (Win16HostWaveDirection::Output, 0x03bd) | (Win16HostWaveDirection::Input, 0x03c0) => {
            if parameter1 == 0 {
                context.callback_failure.store(true, Ordering::Release);
            } else {
                context.publish_completion(parameter1);
            }
        }
        _ => {}
    }
}

pub(super) unsafe extern "system" fn wave_out_callback(
    _handle: HWAVEOUT,
    message: u32,
    instance: usize,
    parameter1: usize,
    _parameter2: usize,
) {
    dispatch_callback(
        instance,
        Win16HostWaveDirection::Output,
        message,
        parameter1,
    );
}

pub(super) unsafe extern "system" fn wave_in_callback(
    _handle: HWAVEIN,
    message: u32,
    instance: usize,
    parameter1: usize,
    _parameter2: usize,
) {
    dispatch_callback(instance, Win16HostWaveDirection::Input, message, parameter1);
}

pub(super) unsafe fn header_state(header: *const WAVEHDR) -> Win16HostWaveHeaderState {
    // SAFETY: `header` points to a live WinMM WAVEHDR and fields are copied
    // unaligned because windows-sys models the SDK packed declaration.
    unsafe {
        Win16HostWaveHeaderState {
            flags: ptr::addr_of!((*header).dwFlags).read_unaligned(),
            bytes_recorded: ptr::addr_of!((*header).dwBytesRecorded).read_unaligned(),
        }
    }
}
