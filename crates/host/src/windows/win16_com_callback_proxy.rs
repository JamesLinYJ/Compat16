//! Generated COM callback proxies for the Win16 checked callback path.
//!
//! `windows_core::implement` supplies QueryInterface/AddRef/Release and the
//! selected generated SDK interface vtables. This module owns only the STA
//! callback routing, frame identities, and reply-domain checks.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::os::windows::io::AsRawHandle;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use compat_services::com::ComObjectId;
use runtime::{
    Win16ComHostAdviseSinkCall, Win16ComHostCallbackCall, Win16ComHostCallbackFailure,
    Win16ComHostCallbackFailureKind, Win16ComHostCallbackFrame, Win16ComHostCallbackOutcome,
    Win16ComHostCallbackReply, Win16ComHostCallbackRoute, Win16ComHostCallbackStep,
    Win16ComHostInterface, Win16ComHostOperationFailure, Win16ComHostOperationIdentity,
    Win16ComHostOwnerIdentity, Win16ComHostResume, Win16ComHostStep, Win16OleHostValue,
};
use windows_core::{BOOL, ComObject, HRESULT, Ref, Result as WindowsResult};

use super::com_bindings::generated::{
    FORMATETC, IAdviseSink, IAdviseSink_Impl, IMoniker, IOleClientSite, IOleClientSite_Impl,
    IOleContainer, STGMEDIUM,
};
use super::win16_com_callback_copy::{
    copy_callback_medium, copy_moniker_display_name, project_format,
};
use super::win16_com_objects::{NativeComError, Win16ComObjects};

#[path = "win16_com_callback_waiter.rs"]
pub(in crate::windows) mod callback_waiter;
#[path = "win16_com_callback_shutdown.rs"]
mod shutdown;

const E_NOINTERFACE: HRESULT = HRESULT(0x8000_4002u32 as i32);
const E_NOTIMPL: HRESULT = HRESULT(0x8000_4001u32 as i32);
const E_FAIL: HRESULT = HRESULT(0x8000_4005u32 as i32);
const E_UNEXPECTED: HRESULT = HRESULT(0x8000_ffffu32 as i32);

thread_local! {
    /// Exact native operation whose synchronous COM call caused this callback.
    static ACTIVE_OPERATION: Cell<Option<Win16ComHostOperationIdentity>> = const { Cell::new(None) };
}

/// Preserve the callback's native parent across nested OLE calls on the STA.
pub(super) fn with_active_operation<R>(
    operation: Win16ComHostOperationIdentity,
    call: impl FnOnce() -> R,
) -> R {
    struct Restore(Option<Win16ComHostOperationIdentity>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE_OPERATION.with(|active| active.set(self.0));
        }
    }

    let previous = ACTIVE_OPERATION.with(|active| active.replace(Some(operation)));
    let restore = Restore(previous);
    let result = call();
    drop(restore);
    result
}

struct PendingCallback {
    parent: Option<Win16ComHostOperationIdentity>,
    owner: Win16ComHostOwnerIdentity,
    route: Win16ComHostCallbackRoute,
    callback: Win16ComHostCallbackCall,
    reply: Option<SyncSender<Win16ComHostCallbackOutcome>>,
    acknowledgement: Option<Receiver<()>>,
    sealed_failure: Option<Win16ComHostCallbackFailure>,
}

struct CallbackPendingState {
    /// Closing and frame registration use the same mutex so a callback cannot
    /// be published after ingress shutdown has drained the current batch.
    closed: bool,
    frames: BTreeMap<Win16ComHostCallbackFrame, PendingCallback>,
    sealed_receipts: Vec<Win16ComHostStep>,
}

struct CallbackShared {
    owner: Win16ComHostOwnerIdentity,
    worker_wake: Arc<std::os::windows::io::OwnedHandle>,
    events: Sender<Win16ComHostStep>,
    pending: Mutex<CallbackPendingState>,
    endpoints: Mutex<BTreeMap<Win16ComHostCallbackRoute, Weak<CallbackEndpoint>>>,
    next_frame: AtomicU64,
    next_medium: AtomicU64,
    failures: Mutex<
        Vec<(
            Option<Win16ComHostOperationIdentity>,
            Win16ComHostCallbackRoute,
            Win16ComHostCallbackFailure,
        )>,
    >,
    active_native_dispatches: AtomicUsize,
}

/// Runtime side of the callback channel. A checked guest callback resumes its
/// exact waiting COM frame through channel state, independent of the STA's
/// command queue.
#[derive(Clone)]
pub(super) struct Win16ComCallbackRuntime {
    shared: Arc<CallbackShared>,
}

/// Single-consumer ingress polled by the runtime continuation scheduler.
pub(super) struct Win16ComCallbackIngress {
    events: Mutex<Receiver<Win16ComHostStep>>,
    shared: Arc<CallbackShared>,
}

struct CallbackEndpoint {
    shared: Arc<CallbackShared>,
    route: Win16ComHostCallbackRoute,
    client_site: OnceLock<ComObjectId>,
    advise_sink: OnceLock<ComObjectId>,
}

#[windows_core::implement(IOleClientSite, IAdviseSink, Agile = false)]
struct NativeCallbackProxy {
    endpoint: Arc<CallbackEndpoint>,
}

impl Drop for NativeCallbackProxy {
    fn drop(&mut self) {
        let Ok(mut endpoints) = self.endpoint.shared.endpoints.lock() else {
            return;
        };
        let route = self.endpoint.route;
        let is_this_endpoint = endpoints
            .get(&route)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, &self.endpoint));
        if is_this_endpoint {
            endpoints.remove(&route);
        }
    }
}

impl Win16ComCallbackRuntime {
    pub(super) fn new(
        owner: Win16ComHostOwnerIdentity,
        worker_wake: Arc<std::os::windows::io::OwnedHandle>,
    ) -> Result<(Self, Win16ComCallbackIngress), NativeComError> {
        if !owner.is_valid() {
            return Err(NativeComError::InvalidOwnerIdentity);
        }
        let (events, receiver) = mpsc::channel();
        let shared = Arc::new(CallbackShared {
            owner,
            worker_wake,
            events,
            pending: Mutex::new(CallbackPendingState {
                closed: false,
                frames: BTreeMap::new(),
                sealed_receipts: Vec::new(),
            }),
            endpoints: Mutex::new(BTreeMap::new()),
            next_frame: AtomicU64::new(1),
            next_medium: AtomicU64::new(1),
            failures: Mutex::new(Vec::new()),
            active_native_dispatches: AtomicUsize::new(0),
        });
        let ingress_shared = Arc::clone(&shared);
        Ok((
            Self { shared },
            Win16ComCallbackIngress {
                events: Mutex::new(receiver),
                shared: ingress_shared,
            },
        ))
    }

    pub(super) fn owner_identity(&self) -> Win16ComHostOwnerIdentity {
        self.shared.owner
    }

    /// Resume only the owner/operation/frame and callback result domain that
    /// the native stack registered before it blocked in the COM callback.
    pub(super) fn resume(
        &self,
        resume: Win16ComHostResume,
    ) -> Result<Win16ComHostStep, &'static str> {
        let outcome = resume.outcome;
        let (sender, acknowledgement, route, parent) = {
            let mut pending = self
                .shared
                .pending
                .lock()
                .map_err(|_| "callback state poisoned")?;
            if pending.closed {
                return Err("callback ingress is closed");
            }
            let frame = pending
                .frames
                .get_mut(&resume.frame)
                .ok_or("callback frame is not pending")?;
            if frame.owner != resume.owner || frame.owner != self.shared.owner {
                return Err("callback owner identity differs");
            }
            if frame.parent != resume.parent {
                return Err("callback parent operation differs");
            }
            let reply_matches = match &outcome {
                Win16ComHostCallbackOutcome::Reply(
                    Win16ComHostCallbackReply::ClientSiteSaveObjectHresult(_),
                ) => matches!(
                    frame.callback,
                    Win16ComHostCallbackCall::ClientSiteSaveObject { .. }
                ),
                Win16ComHostCallbackOutcome::Reply(
                    Win16ComHostCallbackReply::AdviseSinkClientWord(_),
                ) => matches!(frame.callback, Win16ComHostCallbackCall::AdviseSink { .. }),
                Win16ComHostCallbackOutcome::Failed(_) => true,
            };
            if !reply_matches {
                return Err("callback reply belongs to another ABI result domain");
            }
            (
                frame
                    .reply
                    .take()
                    .ok_or("callback frame was already resumed")?,
                frame
                    .acknowledgement
                    .take()
                    .ok_or("callback acknowledgement was already consumed")?,
                frame.route,
                frame.parent,
            )
        };
        let step_outcome = outcome.clone();
        sender
            .send(outcome)
            .map_err(|_| "native COM callback has retired")?;
        // Wake the STA's shared USER/native-input waiter after publishing.
        (crate::windows::win32_safe::set_event(self.shared.worker_wake.as_raw_handle() as _));
        acknowledgement
            .recv()
            .map_err(|_| "native COM callback did not acknowledge the reply")?;
        match step_outcome {
            Win16ComHostCallbackOutcome::Reply(_) => Ok(Win16ComHostStep::CallbackFrameComplete {
                frame: resume.frame,
                owner: resume.owner,
            }),
            Win16ComHostCallbackOutcome::Failed(failure) => Ok(Win16ComHostStep::CallbackFailed {
                frame: Some(resume.frame),
                parent,
                owner: resume.owner,
                route,
                failure,
            }),
        }
    }

    /// Fail outstanding frames when the runtime abandons callback execution.
    /// Each returned step carries the exact suspended frame and route; the
    /// native callback receives a typed failure solely to unwind its COM
    /// stack, never a fabricated WORD or successful HRESULT. This cancels
    /// only frames pending at this instant and leaves callback ingress open.
    pub(super) fn cancel_pending(&self, context: impl Into<String>) -> Vec<Win16ComHostStep> {
        shutdown::cancel_pending_frames(&self.shared, context.into(), false)
    }

    /// Permanently close callback ingress and fail its current pending frames.
    /// Registration and event publication are serialized with this close.
    pub(super) fn close_and_cancel_pending(
        &self,
        context: impl Into<String>,
    ) -> Vec<Win16ComHostStep> {
        {
            let mut pending = self
                .shared
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.closed = true;
        }
        self.cancel_pending(context)
    }

    pub(super) fn seal_and_cancel_pending(
        &self,
        context: &'static str,
    ) -> Result<(), runtime::RuntimeError> {
        shutdown::seal_and_cancel_pending(self, context)
    }

    pub(super) fn native_stacks_quiet(&self) -> bool {
        shutdown::native_stacks_quiet(&self.shared)
    }

    pub(super) fn sealed_receipts_polled(&self) -> bool {
        shutdown::sealed_receipts_polled(&self.shared)
    }

    pub(super) fn has_pending_failures(&self) -> bool {
        shutdown::has_pending_failures(&self.shared)
    }

    /// Create one windows-core object implementing both native callback
    /// interfaces, then register owned interface references under opaque IDs.
    pub(super) fn create_proxy(
        &self,
        objects: &Win16ComObjects,
        route: Win16ComHostCallbackRoute,
    ) -> Result<Win16OleHostValue, NativeComError> {
        if route.0 == 0 || objects.owner_identity() != self.shared.owner {
            return Err(NativeComError::InvalidOwnerIdentity);
        }
        let endpoint = Arc::new(CallbackEndpoint {
            shared: self.shared.clone(),
            route,
            client_site: OnceLock::new(),
            advise_sink: OnceLock::new(),
        });
        {
            let mut endpoints = self
                .shared
                .endpoints
                .lock()
                .map_err(|_| NativeComError::InvalidOwnerIdentity)?;
            if endpoints.get(&route).and_then(Weak::upgrade).is_some() {
                return Err(NativeComError::InvalidOwnerIdentity);
            }
            endpoints.remove(&route);
            endpoints.insert(route, Arc::downgrade(&endpoint));
        }

        let proxy = ComObject::new(NativeCallbackProxy {
            endpoint: endpoint.clone(),
        });
        let site = proxy.as_interface::<IOleClientSite>().to_owned();
        let sink = proxy.as_interface::<IAdviseSink>().to_owned();
        let site_id = match objects.insert_typed_owned(site) {
            Ok(id) => id,
            Err(error) => {
                shutdown::remove_endpoint(&self.shared, route, &endpoint);
                return Err(error);
            }
        };
        let sink_id = match objects.insert_typed_owned(sink) {
            Ok(id) => id,
            Err(error) => {
                let _ = objects.release(site_id);
                shutdown::remove_endpoint(&self.shared, route, &endpoint);
                return Err(error);
            }
        };
        if endpoint.client_site.set(site_id).is_err() || endpoint.advise_sink.set(sink_id).is_err()
        {
            let _ = objects.release(sink_id);
            let _ = objects.release(site_id);
            shutdown::remove_endpoint(&self.shared, route, &endpoint);
            return Err(NativeComError::InvalidOwnerIdentity);
        }
        Ok(Win16OleHostValue::CallbackInterfaces {
            client_site: Win16ComHostInterface {
                object: site_id,
                owner: self.shared.owner,
                iid: compat_services::com::IID_IOLE_CLIENT_SITE,
                disposition: compat_services::com::ReferenceDisposition::Owned,
            },
            advise_sink: Win16ComHostInterface {
                object: sink_id,
                owner: self.shared.owner,
                iid: compat_services::com::Guid::new(
                    0x0000_0110,
                    0,
                    0,
                    [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
                ),
                disposition: compat_services::com::ReferenceDisposition::Owned,
            },
        })
    }

    pub(super) fn take_operation_failures(
        &self,
        operation: Win16ComHostOperationIdentity,
    ) -> Vec<Win16ComHostOperationFailure> {
        let mut failures = match self.shared.failures.lock() {
            Ok(failures) => failures,
            // A prior callback panic may poison the journal mutex. Recover the
            // owned records rather than dropping the native result or skipping
            // the operation's terminal reconciliation.
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut selected = Vec::new();
        failures.retain(|(parent, route, failure)| {
            if *parent == Some(operation) {
                selected.push(Win16ComHostOperationFailure {
                    route: *route,
                    failure: failure.clone(),
                });
                false
            } else {
                true
            }
        });
        selected
    }
}

impl Win16ComCallbackIngress {
    pub(super) fn try_next(&self) -> Result<Option<Win16ComHostStep>, &'static str> {
        let disconnected = {
            // Match dispatch's pending-then-event order. A cancellation or
            // close that already removed a frame makes its queued event stale;
            // do not expose a continuation that can no longer be resumed.
            let mut pending = self
                .shared
                .pending
                .lock()
                .map_err(|_| "callback state poisoned")?;
            let events = self
                .events
                .lock()
                .map_err(|_| "callback ingress poisoned")?;
            if !pending.sealed_receipts.is_empty() {
                return Ok(Some(pending.sealed_receipts.remove(0)));
            }
            loop {
                match events.try_recv() {
                    Ok(Win16ComHostStep::Callback(callback))
                        if pending.closed
                            || !pending
                                .frames
                                .get(&callback.frame)
                                .is_some_and(|frame| frame.reply.is_some()) =>
                    {
                        continue;
                    }
                    Ok(event) => return Ok(Some(event)),
                    Err(mpsc::TryRecvError::Empty) => break false,
                    Err(mpsc::TryRecvError::Disconnected) => break true,
                }
            }
        };
        let mut failures = match self.shared.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(index) = failures.iter().position(|(parent, _, _)| parent.is_none()) else {
            if disconnected {
                return Err("callback ingress disconnected");
            }
            return Ok(None);
        };
        let (parent, route, failure) = failures.remove(index);
        Ok(Some(Win16ComHostStep::CallbackFailed {
            frame: None,
            parent,
            owner: self.shared.owner,
            route,
            failure,
        }))
    }
}

impl Drop for Win16ComCallbackIngress {
    fn drop(&mut self) {
        // The endpoint holds the reply sender while blocked in a callback, so
        // dropping the receiver alone cannot wake it. Send a typed transport
        // failure to every frame that has not already been claimed by resume.
        // This drop path is deliberately nonblocking; the native method's own
        // terminal step remains responsible for operation completion.
        let callbacks = Win16ComCallbackRuntime {
            shared: Arc::clone(&self.shared),
        };
        let _ = callbacks.close_and_cancel_pending(
            "runtime callback ingress was dropped before the frame resumed",
        );
    }
}

impl CallbackEndpoint {
    fn dispatch(
        &self,
        callback: Win16ComHostCallbackCall,
        expects_save_hresult: bool,
    ) -> Result<Win16ComHostCallbackReply, Win16ComHostCallbackFailure> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.shared);
        let frame =
            Win16ComHostCallbackFrame(allocate_id(&self.shared.next_frame).map_err(|reason| {
                callback_failure(Win16ComHostCallbackFailureKind::CallbackTransport, reason)
            })?);
        let parent = ACTIVE_OPERATION.with(Cell::get);
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let (acknowledgement_tx, acknowledgement_rx) = mpsc::sync_channel(1);
        let callback_step = Win16ComHostCallbackStep {
            frame,
            parent,
            owner: self.shared.owner,
            route: self.route,
            callback,
        };
        if !callback_step.has_valid_identity()
            || expects_save_hresult
                != matches!(
                    callback_step.callback,
                    Win16ComHostCallbackCall::ClientSiteSaveObject { .. }
                )
        {
            return Err(callback_failure(
                Win16ComHostCallbackFailureKind::CallbackImplementation,
                "callback identity is invalid",
            ));
        }
        {
            let mut pending = self.shared.pending.lock().map_err(|_| {
                callback_failure(
                    Win16ComHostCallbackFailureKind::CallbackTransport,
                    "callback state poisoned",
                )
            })?;
            if pending.closed {
                return Err(callback_failure(
                    Win16ComHostCallbackFailureKind::CallbackTransport,
                    "runtime callback ingress is closed",
                ));
            }
            if pending.frames.contains_key(&frame) {
                return Err(callback_failure(
                    Win16ComHostCallbackFailureKind::CallbackImplementation,
                    "callback frame identity was reused",
                ));
            }
            pending.frames.insert(
                frame,
                PendingCallback {
                    parent,
                    owner: self.shared.owner,
                    route: self.route,
                    callback: callback_step.callback.clone(),
                    reply: Some(reply_tx),
                    acknowledgement: Some(acknowledgement_rx),
                    sealed_failure: None,
                },
            );
            if self
                .shared
                .events
                .send(Win16ComHostStep::Callback(callback_step))
                .is_err()
            {
                pending.frames.remove(&frame);
                return Err(callback_failure(
                    Win16ComHostCallbackFailureKind::CallbackTransport,
                    "runtime callback receiver is unavailable",
                ));
            }
        }
        // The STA pumps worker commands/native messages while retaining this frame.
        let mut transport_failed = false;
        let outcome = loop {
            match reply_rx.try_recv() {
                Ok(outcome) => break outcome,
                Err(mpsc::TryRecvError::Disconnected) => {
                    transport_failed = true;
                    break Win16ComHostCallbackOutcome::Failed(callback_failure(
                        Win16ComHostCallbackFailureKind::CallbackTransport,
                        "runtime dropped the checked callback outcome",
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if let Err(error) = callback_waiter::wait_for_callback_reply() {
                        transport_failed = true;
                        break Win16ComHostCallbackOutcome::Failed(callback_failure(
                            Win16ComHostCallbackFailureKind::CallbackTransport,
                            format!("nested USER STA wait failed: {error}"),
                        ));
                    }
                }
            }
        };
        if let Ok(mut pending) = self.shared.pending.lock() {
            if transport_failed
                && let Some(callback) = pending.frames.get_mut(&frame)
                && let Win16ComHostCallbackOutcome::Failed(failure) = &outcome
            {
                callback.reply.take();
                callback.sealed_failure = Some(failure.clone());
            }
            let retain_for_seal = pending.frames.get(&frame).is_some_and(|callback| {
                callback.sealed_failure.is_some() && callback.acknowledgement.is_some()
            });
            if !retain_for_seal {
                pending.frames.remove(&frame);
            }
        }
        let _ = acknowledgement_tx.send(());
        match outcome {
            Win16ComHostCallbackOutcome::Reply(reply) => Ok(reply),
            Win16ComHostCallbackOutcome::Failed(failure) => Err(failure),
        }
    }

    fn record_failure(&self, failure: Win16ComHostCallbackFailure) {
        let parent = ACTIVE_OPERATION.with(Cell::get);
        let sealed_duplicate = self.shared.pending.lock().is_ok_and(|pending| {
            pending.closed
                && pending.frames.values().any(|callback| {
                    callback.owner == self.shared.owner
                        && callback.route == self.route
                        && callback.parent == parent
                        && callback.acknowledgement.is_some()
                        && callback.sealed_failure.as_ref().is_some_and(|sealed| {
                            sealed.kind == failure.kind && sealed.context == failure.context
                        })
                })
        });
        if sealed_duplicate {
            // The exact cancellation is already represented by the sealed
            // CallbackFailed step and retained acknowledgement receiver.
            return;
        }
        if parent.is_none() && failure.kind == Win16ComHostCallbackFailureKind::CheckedGuestCallback
        {
            // continue_operation already returns this exact frame failure to
            // the runtime; do not emit a duplicate unsolicited route failure.
            return;
        }
        let mut failures = match self.shared.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.push((parent, self.route, failure));
    }

    fn client_site_id(&self) -> Option<ComObjectId> {
        self.client_site.get().copied()
    }

    fn advise_sink_id(&self) -> Option<ComObjectId> {
        self.advise_sink.get().copied()
    }

    fn dispatch_sink(
        &self,
        method: Win16ComHostAdviseSinkCall,
    ) -> Result<(), Win16ComHostCallbackFailure> {
        let sink = self.advise_sink_id().ok_or_else(|| {
            callback_failure(
                Win16ComHostCallbackFailureKind::CallbackImplementation,
                "advise-sink identity unavailable",
            )
        })?;
        self.dispatch(
            Win16ComHostCallbackCall::AdviseSink {
                sink,
                object: None,
                method,
            },
            false,
        )?;
        Ok(())
    }
}

impl IOleClientSite_Impl for NativeCallbackProxy_Impl {
    fn SaveObject(&self) -> WindowsResult<()> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        let Some(site) = self.endpoint.client_site_id() else {
            self.endpoint.record_failure(callback_failure(
                Win16ComHostCallbackFailureKind::CallbackImplementation,
                "client-site identity unavailable",
            ));
            return Err(E_FAIL.into());
        };
        match self.endpoint.dispatch(
            Win16ComHostCallbackCall::ClientSiteSaveObject { site, object: None },
            true,
        ) {
            Ok(Win16ComHostCallbackReply::ClientSiteSaveObjectHresult(bits)) => {
                let result = HRESULT(bits as i32);
                // `windows_core::implement` maps `Ok(())` to exactly S_OK.
                // Return every nonzero HRESULT through its error channel so
                // successful nonzero codes such as S_FALSE are not rewritten.
                if result.0 == 0 {
                    Ok(())
                } else {
                    Err(result.into())
                }
            }
            Ok(Win16ComHostCallbackReply::AdviseSinkClientWord(_)) => {
                self.endpoint.record_failure(callback_failure(
                    Win16ComHostCallbackFailureKind::CallbackImplementation,
                    "runtime returned a WORD for IOleClientSite::SaveObject",
                ));
                Err(E_UNEXPECTED.into())
            }
            Err(failure) => {
                self.endpoint.record_failure(failure);
                Err(E_FAIL.into())
            }
        }
    }

    fn GetMoniker(&self, _dwassign: u32, _dwwhichmoniker: u32) -> WindowsResult<IMoniker> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        Err(E_NOTIMPL.into())
    }

    fn GetContainer(&self) -> WindowsResult<IOleContainer> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        Err(E_NOINTERFACE.into())
    }

    fn ShowObject(&self) -> WindowsResult<()> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        Err(E_NOTIMPL.into())
    }

    fn OnShowWindow(&self, _show: BOOL) -> WindowsResult<()> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        Err(E_NOTIMPL.into())
    }

    fn RequestNewObjectLayout(&self) -> WindowsResult<()> {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        Err(E_NOTIMPL.into())
    }
}

impl IAdviseSink_Impl for NativeCallbackProxy_Impl {
    fn OnDataChange(&self, format: *const FORMATETC, medium: *const STGMEDIUM) {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if format.is_null() || medium.is_null() {
                return Err(callback_failure(
                    Win16ComHostCallbackFailureKind::InvalidNativeCallbackArguments,
                    "IAdviseSink::OnDataChange received a null argument",
                ));
            }
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let format = unsafe { *format };
            // STGMEDIUM is provider-owned and deliberately not Copy. Borrow
            // its SDK union for the bounded deep copy; never move it out.
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let medium_value = unsafe { &*medium };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let projected = unsafe { project_format(format) }.map_err(|reason| {
                callback_failure(
                    Win16ComHostCallbackFailureKind::InvalidNativeCallbackArguments,
                    reason,
                )
            })?;
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let payload = unsafe { copy_callback_medium(medium_value) }.map_err(|reason| {
                callback_failure(
                    Win16ComHostCallbackFailureKind::InvalidNativeCallbackArguments,
                    reason,
                )
            })?;
            let id = allocate_id(&self.endpoint.shared.next_medium).map_err(|reason| {
                callback_failure(Win16ComHostCallbackFailureKind::CallbackTransport, reason)
            })?;
            self.endpoint
                .dispatch_sink(Win16ComHostAdviseSinkCall::OnDataChange {
                    format: projected,
                    medium: runtime::Win16ComHostMediumId(id),
                    payload,
                    tymed: medium_value.tymed,
                })
        }));
        if let Ok(Err(failure)) = result {
            self.endpoint.record_failure(failure);
        } else if result.is_err() {
            self.endpoint.record_failure(callback_failure(
                Win16ComHostCallbackFailureKind::CallbackImplementation,
                "OnDataChange callback panicked",
            ));
        }
    }

    fn OnViewChange(&self, aspect: u32, index: i32) {
        dispatch_sink_result(
            &self.endpoint,
            Win16ComHostAdviseSinkCall::OnViewChange { aspect, index },
        );
    }

    fn OnRename(&self, moniker: Ref<'_, IMoniker>) {
        let _native_dispatch = shutdown::enter_native_dispatch(&self.endpoint.shared);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let moniker = moniker.as_ref().ok_or_else(|| {
                callback_failure(
                    Win16ComHostCallbackFailureKind::InvalidNativeCallbackArguments,
                    "IAdviseSink::OnRename received a null moniker",
                )
            })?;
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let display_name = unsafe { copy_moniker_display_name(moniker) }?;
            self.endpoint
                .dispatch_sink(Win16ComHostAdviseSinkCall::OnRename { display_name })
        }));
        if let Ok(Err(failure)) = result {
            self.endpoint.record_failure(failure);
        } else if result.is_err() {
            self.endpoint.record_failure(callback_failure(
                Win16ComHostCallbackFailureKind::CallbackImplementation,
                "OnRename callback panicked",
            ));
        }
    }

    fn OnSave(&self) {
        dispatch_sink_result(&self.endpoint, Win16ComHostAdviseSinkCall::OnSave);
    }

    fn OnClose(&self) {
        dispatch_sink_result(&self.endpoint, Win16ComHostAdviseSinkCall::OnClose);
    }
}

fn dispatch_sink_result(endpoint: &CallbackEndpoint, method: Win16ComHostAdviseSinkCall) {
    let _native_dispatch = shutdown::enter_native_dispatch(&endpoint.shared);
    let result = catch_unwind(AssertUnwindSafe(|| endpoint.dispatch_sink(method)));
    if let Ok(Err(failure)) = result {
        endpoint.record_failure(failure);
    } else if result.is_err() {
        endpoint.record_failure(callback_failure(
            Win16ComHostCallbackFailureKind::CallbackImplementation,
            "IAdviseSink callback panicked",
        ));
    }
}

fn callback_failure(
    kind: Win16ComHostCallbackFailureKind,
    context: impl Into<String>,
) -> Win16ComHostCallbackFailure {
    Win16ComHostCallbackFailure {
        kind,
        context: context.into(),
    }
}

fn allocate_id(counter: &AtomicU64) -> Result<u64, &'static str> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| "COM callback identity space exhausted")
}
