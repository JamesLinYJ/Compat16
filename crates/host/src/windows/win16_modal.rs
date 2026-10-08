//! Owner-thread cancellation for synchronous USER modal calls.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16NativeModalCancellation, Win16WindowResult,
};
use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_APP};

#[path = "win16_modal_hooks.rs"]
mod hooks;
pub(super) use hooks::ModalWorkerHooks;
#[path = "win16_modal_scope.rs"]
mod scope;
use scope::{MODAL_FRAMES, ModalKind, ModalToken, mark_system_modal_cancelled};
pub(in crate::windows) use scope::{
    ModalCancellationSignal, ModalDisposition, ModalScope, ModalScopeFinishError,
    modal_stack_is_empty,
};

#[path = "win16_modal_guest_work.rs"]
mod guest_work;
pub(super) use guest_work::{GuestWorkMarkerDisposition, ModalGuestWorkIdentity};

thread_local! {
    pub(super) static WORKER_CONTROL: RefCell<Option<Arc<ModalWorkerControl>>> = const {
        RefCell::new(None)
    };
}

const MODAL_WAKE_MESSAGE: u32 = WM_APP + 0x36D;
const MODAL_CANCEL_SENTINEL: isize = isize::MIN + 0x574D;
static NEXT_WORKER_NONCE: AtomicU64 = AtomicU64::new(1);

/// Shared state authorizes a cancellation wake for one worker generation.
pub(super) struct ModalWorkerControl {
    worker_nonce: usize,
    thread_id: AtomicU32,
    terminal_request: AtomicU64,
    wake_posted: AtomicU64,
    terminal: AtomicBool,
    quit_posted: AtomicBool,
    next_token: AtomicU64,
    publication: Mutex<()>,
    abort_dispatch_gate: Mutex<()>,
    guest_work_ready: AtomicBool,
    callback_failure: Mutex<Option<RuntimeError>>,
    registered_guest_work_message: AtomicU32,
    guest_mailbox: Mutex<guest_work::ModalGuestMailbox>,
    abort_dispatcher: Mutex<Option<Weak<super::win16_windows::ModalWakeDispatcher>>>,
}

impl ModalWorkerControl {
    pub(super) fn new() -> Result<Arc<Self>, RuntimeError> {
        let nonce = NEXT_WORKER_NONCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 USER worker identity space is exhausted",
                )
            })?;
        let worker_nonce = usize::try_from(nonce).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 USER worker identity does not fit the native message ABI",
            )
        })?;
        Ok(Arc::new(Self {
            worker_nonce,
            thread_id: AtomicU32::new(0),
            terminal_request: AtomicU64::new(0),
            wake_posted: AtomicU64::new(0),
            terminal: AtomicBool::new(false),
            quit_posted: AtomicBool::new(false),
            next_token: AtomicU64::new(1),
            publication: Mutex::new(()),
            abort_dispatch_gate: Mutex::new(()),
            guest_work_ready: AtomicBool::new(false),
            callback_failure: Mutex::new(None),
            registered_guest_work_message: AtomicU32::new(0),
            guest_mailbox: Mutex::new(guest_work::ModalGuestMailbox::new()),
            abort_dispatcher: Mutex::new(None),
        }))
    }

    /// Enqueue the command and publish terminal intent under the scope-entry gate.
    pub(super) fn enqueue_terminal(
        &self,
        enqueue: impl FnOnce(u64) -> Result<(), RuntimeError>,
    ) -> Result<u64, RuntimeError> {
        let _gate = self.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal terminal publication state",
            )
        })?;
        let request = self
            .terminal_request
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 modal terminal request identity space is exhausted",
                )
            })?;
        enqueue(request)?;
        self.wake_posted.store(0, Ordering::Relaxed);
        self.quit_posted.store(false, Ordering::Relaxed);
        self.terminal_request.store(request, Ordering::Release);
        self.terminal.store(true, Ordering::Release);
        Ok(request)
    }

    pub(super) fn post_terminal_wake(&self, request: u64) -> Result<(), RuntimeError> {
        let thread_id = self.thread_id.load(Ordering::Acquire);
        if thread_id == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal worker has no published owner-thread identity",
            ));
        }
        if !self.terminal_requested() || self.terminal_request.load(Ordering::Acquire) != request {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal wake does not match the published terminal request",
            ));
        }
        let native_request = LPARAM::try_from(request).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 modal request identity does not fit the native message ABI",
            )
        })?;
        // Publish the exact in-flight request before posting. The hook may
        // dequeue the message before PostThreadMessageW returns to this thread.
        self.wake_posted.store(request, Ordering::Release);
        // SAFETY: worker readiness publishes this thread ID only after its
        // USER queue and same-thread cancellation hooks have been installed.
        let posted = unsafe {
            PostThreadMessageW(
                thread_id,
                MODAL_WAKE_MESSAGE,
                self.worker_nonce,
                native_request,
            )
        };
        if posted == 0 {
            let _ =
                self.wake_posted
                    .compare_exchange(request, 0, Ordering::AcqRel, Ordering::Acquire);
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            let failure = RuntimeError::with_source(
                Kind::HostFailure,
                "post terminal cancellation to the Win16 USER owner thread",
                std::io::Error::from_raw_os_error(error as i32),
            );
            self.record_callback_failure(RuntimeError::with_source(
                Kind::HostFailure,
                "terminal wake was not delivered; the worker remains retained",
                std::io::Error::from_raw_os_error(error as i32),
            ));
            return Err(failure);
        }
        Ok(())
    }

    pub(super) fn wake_is_posted(&self, request: u64) -> bool {
        self.terminal.load(Ordering::Acquire)
            && self.terminal_request.load(Ordering::Acquire) == request
            && self.wake_posted.load(Ordering::Acquire) == request
    }

    pub(super) fn terminal_requested(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    fn bind_thread(&self, thread_id: u32) -> Result<(), RuntimeError> {
        self.thread_id
            .compare_exchange(0, thread_id, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal worker control was attached to more than one thread",
                )
            })
    }

    fn next_scope_token(&self) -> Result<ModalToken, RuntimeError> {
        let token = self
            .next_token
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 modal scope identity space is exhausted",
                )
            })?;
        usize::try_from(token).map(ModalToken).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 modal token does not fit the native message ABI",
            )
        })
    }

    pub(super) fn record_callback_failure(&self, error: RuntimeError) {
        let mut stored = self
            .callback_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *stored = Some(match stored.take() {
            Some(primary) => combine_failures(
                primary,
                error,
                "Win16 modal hook and cancellation handling both failed",
            ),
            None => error,
        });
    }

    pub(super) fn take_callback_failure(&self) -> Option<RuntimeError> {
        self.callback_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn owner_thread(&self) -> bool {
        (unsafe { GetCurrentThreadId() }) == self.thread_id.load(Ordering::Acquire)
    }
}

pub(super) fn current_control() -> Option<Arc<ModalWorkerControl>> {
    WORKER_CONTROL.with(|slot| {
        slot.try_borrow()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
    })
}

pub(super) fn clear_worker_control(control: &Arc<ModalWorkerControl>) {
    WORKER_CONTROL.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, control))
            {
                slot.take();
            }
        }
    });
}

#[derive(Debug)]
pub(super) struct MessageBoxCall<T> {
    pub(super) value: T,
    pub(super) disposition: ModalDisposition,
    pub(super) cleanup_error: Option<RuntimeError>,
    pub(super) retired_guest_work:
        Vec<runtime::Win16NativeModalGuestWorkRetirement>,
}

#[derive(Debug)]
pub(super) enum NativeModalInvocation<T> {
    NotStarted { operation_id: u64 },
    Returned(MessageBoxCall<T>),
}

pub(super) type NativeModalCall<T> = NativeModalInvocation<T>;

/// Keep an observed cancellation receipt beside any independent modal cleanup
/// failure until the USER worker records both in its terminal ledger.
pub(super) enum NativeModalOperationOutcome {
    Returned(Win16WindowResult),
    Cancelled {
        receipt: Win16NativeModalCancellation,
        cleanup_error: Option<RuntimeError>,
    },
}

/// Preserve the native result; callers capture GetLastError inside the closure.
pub(super) fn with_message_box<T>(
    operation_id: u64,
    call: impl FnOnce() -> T,
) -> Result<NativeModalInvocation<T>, RuntimeError> {
    with_native_modal_kind(operation_id, ModalKind::MessageBoxOk, call)
}

/// Register a known synchronous system-modal API whose HWND is not returned.
pub(super) fn with_native_modal<T>(
    operation_id: u64,
    call: impl FnOnce() -> T,
) -> Result<NativeModalCall<T>, RuntimeError> {
    with_native_modal_kind(operation_id, ModalKind::NativeSystemModal, call)
}

fn with_native_modal_kind<T>(
    operation_id: u64,
    kind: ModalKind,
    call: impl FnOnce() -> T,
) -> Result<NativeModalInvocation<T>, RuntimeError> {
    let Some(mut scope) = ModalScope::begin_with_kind(operation_id, kind)? else {
        return Ok(NativeModalInvocation::NotStarted { operation_id });
    };
    if !scope.native_call_started()? {
        drop(scope);
        return Ok(NativeModalInvocation::NotStarted { operation_id });
    }
    let result = catch_unwind(AssertUnwindSafe(call)).map_err(|_| {
        RuntimeError::new(
            Kind::HostFailure,
            "Win16 MessageBox wrapper panicked during the native call",
        )
    });
    let saved_disposition = scope.disposition();
    let finished = scope.finish();
    match result {
        Ok(value) => {
            let (disposition, cleanup_error, retired_guest_work) = match finished {
                Ok(retirement) => (
                    merge_disposition(saved_disposition, retirement.disposition),
                    None,
                    retirement.retired_guest_work,
                ),
                Err(mut error) => {
                    let retired_guest_work = std::mem::take(&mut error.retired_guest_work);
                    let cleanup_error = RuntimeError::with_source(
                        error.cause.kind(),
                        "finish Win16 native modal scope",
                        error,
                    );
                    (saved_disposition, Some(cleanup_error), retired_guest_work)
                }
            };
            Ok(NativeModalInvocation::Returned(MessageBoxCall {
                value,
                disposition,
                cleanup_error,
                retired_guest_work,
            }))
        }
        Err(error) => Err(match finished {
            Ok(_) => error,
            Err(cleanup) => {
                let cleanup_kind = cleanup.cause.kind();
                combine_failures(
                    error,
                    RuntimeError::with_source(
                        cleanup_kind,
                        "Win16 native modal scope cleanup retained its guest-work retirement receipts",
                        cleanup,
                    ),
                    "Win16 MessageBox call and modal cleanup both failed",
                )
            }
        }),
    }
}

fn merge_disposition(first: ModalDisposition, second: ModalDisposition) -> ModalDisposition {
    match (first, second) {
        (ModalDisposition::Cancelled { signal, scope_id }, _)
        | (_, ModalDisposition::Cancelled { signal, scope_id }) => {
            ModalDisposition::Cancelled { signal, scope_id }
        }
        _ => ModalDisposition::Returned,
    }
}

fn merge_failure(
    destination: &mut Option<RuntimeError>,
    additional: RuntimeError,
    context: &'static str,
) {
    *destination = Some(match destination.take() {
        Some(primary) => combine_failures(primary, additional, context),
        None => additional,
    });
}

fn combine_failures(
    primary: RuntimeError,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(additional.kind());
    RuntimeError::with_source(
        kind,
        context,
        ModalFailurePair {
            primary,
            additional,
        },
    )
}

#[derive(Debug)]
struct ModalFailurePair {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl std::fmt::Display for ModalFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; additional failure: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for ModalFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
