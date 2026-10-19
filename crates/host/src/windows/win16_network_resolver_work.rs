use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use runtime::Win16HostNetworkNameQuery;
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Threading::{
    CloseThreadpoolWork, CreateThreadpoolWork, PTP_WORK, SubmitThreadpoolWork,
    WaitForThreadpoolWorkCallbacks,
};

use super::super::super::win16_network_wake::NetworkWakeHub;
use super::super::query_native;
use super::ResolverWorkerState;

// Windows owns scheduling and worker reuse, while this lease preserves the
// Win16 request owner. The binding has no Rust owner for callback context, and
// exact guest ACK/retirement remains a separate source protocol. Only blocking
// WinSock resolver calls use this pool; CPU execution and COM STA work do not.
pub(super) struct ResolverWorkLease {
    work: Option<PTP_WORK>,
    context: Option<Box<ResolverWorkContext>>,
}

struct ResolverWorkContext {
    query: Mutex<Option<Win16HostNetworkNameQuery>>,
    state: Arc<Mutex<ResolverWorkerState>>,
    wake: NetworkWakeHub,
}

impl std::fmt::Debug for ResolverWorkLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolverWorkLease")
            .field("work_active", &self.work.is_some())
            .finish_non_exhaustive()
    }
}

impl ResolverWorkLease {
    pub(super) fn submit(
        query: Win16HostNetworkNameQuery,
        state: Arc<Mutex<ResolverWorkerState>>,
        wake: NetworkWakeHub,
    ) -> Result<Self, i32> {
        let mut context = Box::new(ResolverWorkContext {
            query: Mutex::new(Some(query)),
            state,
            wake,
        });
        let context_pointer = (&mut *context as *mut ResolverWorkContext).cast::<c_void>();
        // SAFETY: the callback signature matches PTP_WORK_CALLBACK, and the
        // boxed context stays at this address until the lease drains the work.
        // A null callback environment deliberately uses Windows' default pool.
        let work = unsafe {
            CreateThreadpoolWork(Some(resolver_callback), context_pointer, std::ptr::null())
        };
        if work == 0 {
            return Err(WSAENOBUFS);
        }
        let lease = Self {
            work: Some(work),
            context: Some(context),
        };
        // SAFETY: `work` is the live object just created above; this owner
        // submits it once and retains its context until callback retirement.
        unsafe {
            SubmitThreadpoolWork(work);
        }
        Ok(lease)
    }

    /// Keep callback context alive until Windows confirms every callback has
    /// returned or cancels a callback that has not begun.
    pub(super) fn retire(&mut self, cancel_pending: bool) {
        if let Some(work) = self.work.take() {
            // SAFETY: this lease owns `work`; waiting drains running callbacks
            // and optionally cancels callbacks not yet started before close.
            unsafe {
                WaitForThreadpoolWorkCallbacks(work, if cancel_pending { 1 } else { 0 });
                CloseThreadpoolWork(work);
            }
        }
        drop(self.context.take());
    }
}

impl Drop for ResolverWorkLease {
    fn drop(&mut self) {
        self.retire(true);
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn resolver_callback(
    _instance: windows_sys::Win32::System::Threading::PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _work: PTP_WORK,
) {
    // SAFETY: Windows invokes this callback with the context retained by the
    // owning lease until WaitForThreadpoolWorkCallbacks has drained this call.
    let Some(context) = (unsafe { context.cast::<ResolverWorkContext>().as_ref() }) else {
        return;
    };
    let should_query = {
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, ResolverWorkerState::Queued) {
            *state = ResolverWorkerState::Running;
            true
        } else {
            false
        }
    };
    if !should_query {
        return;
    }

    let query = context
        .query
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(query) = query else {
        record_callback_panic(context);
        return;
    };
    // Winsock resolver records are thread-local and may be invalidated by the
    // next resolver call, so query_native must deep-copy them inside this call.
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: query bytes are owned by this callback, and query_native
        // copies thread-local Winsock records before it returns.
        unsafe { query_native(&query) }.ok_or_else(|| {
            // SAFETY: this retrieves Winsock's last error from this worker thread.
            crate::windows::win32_safe::wsa_last_error()
        })
    }));
    drop(query);

    {
        let mut state = context
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = std::mem::replace(&mut *state, ResolverWorkerState::Panicked);
        match (current, result) {
            (ResolverWorkerState::Running, Ok(result)) => {
                *state = ResolverWorkerState::Completed(result);
            }
            (ResolverWorkerState::CancelledRunning, Ok(_)) => {
                *state = ResolverWorkerState::CancelledAfterRun;
            }
            (ResolverWorkerState::Running | ResolverWorkerState::CancelledRunning, Err(_)) => {}
            (_, _) => {}
        }
    }
    context.wake.request_poll();
}

fn record_callback_panic(context: &ResolverWorkContext) {
    let mut state = context
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if matches!(
        *state,
        ResolverWorkerState::Running | ResolverWorkerState::CancelledRunning
    ) {
        *state = ResolverWorkerState::Panicked;
    }
    drop(state);
    context.wake.request_poll();
}
