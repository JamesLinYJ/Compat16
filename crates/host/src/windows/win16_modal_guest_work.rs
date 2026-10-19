//! Registered owner-thread ingress for newly available guest callbacks.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, RegisterWindowMessageW};

use super::{ModalWorkerControl, combine_failures};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct ModalGuestWorkIdentity {
    pub(in crate::windows) operation_id: u64,
    pub(in crate::windows) scope_id: u64,
    pub(in crate::windows) generation: u64,
    marker_id: Option<usize>,
    wake_generation: u64,
}

impl ModalGuestWorkIdentity {
    pub(in crate::windows) fn runtime_fields(
        self,
    ) -> Result<(u64, u64, u64, Option<u64>, Option<u64>), RuntimeError> {
        let marker_id = self
            .marker_id
            .map(u64::try_from)
            .transpose()
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain modal marker identity at the runtime boundary",
                    error,
                )
            })?;
        if self.operation_id == 0
            || self.scope_id == 0
            || self.generation == 0
            || marker_id == Some(0)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native modal guest-work identity has a zero operation, scope, generation, or marker",
            ));
        }
        Ok((
            self.operation_id,
            self.scope_id,
            self.generation,
            marker_id,
            (self.wake_generation != 0).then_some(self.wake_generation),
        ))
    }

    fn retirement_receipt(
        self,
    ) -> Result<runtime::Win16NativeModalGuestWorkRetirement, RuntimeError> {
        let (_, _, _, marker_id, wake_generation) = self.runtime_fields()?;
        let (Some(marker_id), Some(wake_generation)) = (marker_id, wake_generation) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native modal guest-work retirement has no posted marker or wake identity",
            ));
        };
        if self.operation_id == 0 || self.scope_id == 0 || self.generation == 0 || marker_id == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native modal guest-work retirement has an absent producer identity",
            ));
        }
        Ok(runtime::Win16NativeModalGuestWorkRetirement {
            operation_id: runtime::Win16HostWindowOperationId(self.operation_id),
            scope_id: self.scope_id,
            generation: self.generation,
            marker_id,
            wake_generation,
        })
    }
}

pub(in crate::windows) enum GuestWorkMarkerDisposition {
    Unknown,
    Stale,
    Current(ModalGuestWorkIdentity),
}

#[derive(Clone, Copy)]
pub(super) struct ModalScopeIdentity {
    pub(super) operation_id: u64,
    pub(super) scope_id: u64,
}

struct ModalMarker {
    work: ModalGuestWorkIdentity,
    posted: bool,
}

struct ModalIngressFailure {
    work: ModalGuestWorkIdentity,
    cause: Arc<RuntimeError>,
    delivered: bool,
    abort_resolved: bool,
}

#[derive(Default)]
pub(super) struct ModalGuestMailbox {
    pub(super) scopes: Vec<ModalScopeIdentity>,
    pending: Option<ModalMarker>,
    in_flight: Vec<ModalGuestWorkIdentity>,
    failure: Option<ModalIngressFailure>,
    next_generation: u64,
    next_marker_id: usize,
}

impl ModalGuestMailbox {
    pub(super) fn new() -> Self {
        Self {
            next_generation: 1,
            next_marker_id: 1,
            ..Self::default()
        }
    }
}

impl ModalWorkerControl {
    pub(in crate::windows) fn enqueue_modal_guest_work_resume(
        &self,
        enqueue: impl FnOnce() -> Result<(), RuntimeError>,
    ) -> Result<bool, RuntimeError> {
        let _gate = self.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal guest-work resume publication state",
            )
        })?;
        if self.terminal_requested() {
            return Ok(false);
        }
        enqueue()?;
        Ok(true)
    }

    pub(in crate::windows) fn bind_abort_dispatcher(
        &self,
        dispatcher: Weak<super::super::win16_windows::ModalWakeDispatcher>,
    ) {
        *self
            .abort_dispatcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(dispatcher);
    }

    pub(super) fn register_guest_work_message(&self) -> Result<u32, RuntimeError> {
        use std::os::windows::ffi::OsStrExt;

        let process_id = crate::windows::win32_safe::current_process_id();
        let name = format!("Win16.ModalGuestWork.{process_id}.{}", self.worker_nonce,);
        let mut wide = std::ffi::OsStr::new(&name)
            .encode_wide()
            .collect::<Vec<_>>();
        wide.push(0);
        // SAFETY: `RegisterWindowMessageW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let message = unsafe { RegisterWindowMessageW(wide.as_ptr()) };
        if !(0xC000..=0xFFFF).contains(&message) {
            let error = crate::windows::win32_safe::last_error();
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "register the private Win16 modal guest-work message",
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
        self.registered_guest_work_message
            .store(message, Ordering::Release);
        Ok(message)
    }

    pub(super) fn guest_work_message(&self) -> Option<u32> {
        match self.registered_guest_work_message.load(Ordering::Acquire) {
            0 => None,
            message => Some(message),
        }
    }

    pub(super) fn mark_guest_work_ready(&self) {
        self.guest_work_ready.store(true, Ordering::Release);
    }

    /// Close producer publication before the worker unhooks and retires its
    /// USER queue. The source mailbox remains producer-owned after this point.
    pub(super) fn close_guest_work_lane(&self) {
        let _gate = self
            .publication
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.guest_work_ready.store(false, Ordering::Release);
    }

    pub(in crate::windows) fn flush_ingress_failure_after_native_return(&self) {
        let _dispatch = self
            .abort_dispatch_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failure = {
            let mut mailbox = self
                .guest_mailbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if mailbox.scopes.is_empty() {
                mailbox.failure.take()
            } else {
                None
            }
        };
        if let Some(failure) = failure {
            self.record_callback_failure(shared_error(
                &failure.cause,
                "Win16 modal guest-work ingress failed before the real native return receipt",
            ));
        }
    }

    /// Publish the producer-owned mailbox before advancing MultimediaWake.
    /// The publication lock serializes scope entry, terminal close, and the
    /// epoch so a marker cannot observe a partially committed generation.
    pub(in crate::windows) fn publish_multimedia_wake(
        &self,
        multimedia_generation: &std::sync::atomic::AtomicU64,
    ) -> Result<(), RuntimeError> {
        let gate = self.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal guest-work publication state",
            )
        })?;
        if !self.guest_work_ready.load(Ordering::Acquire) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker modal guest-work lane is not ready or has closed",
            ));
        }
        if self.terminal_requested() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker is already handling terminal teardown; source ownership stays with the producer",
            ));
        }
        let mut mailbox = self.guest_mailbox.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal guest-work mailbox",
            )
        })?;
        let scope = mailbox.scopes.last().copied();
        let mut work = None;
        let mut failure = None;
        if let Some(scope) = scope {
            match publish_modal_marker(self, &mut mailbox, scope, 0) {
                Ok(identity) => work = Some(identity),
                Err((identity, error)) => {
                    work = Some(identity);
                    failure = Some(error);
                }
            }
        }

        // The hook takes the same mailbox lock. It cannot observe the marker
        // until its wake generation has advanced or its typed failure exists.
        let next_multimedia_generation = match multimedia_generation.try_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |value| value.checked_add(1),
        ) {
            Ok(previous) => Some(previous + 1),
            Err(_) => {
                let error = RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 USER worker wake generation is exhausted",
                );
                failure = Some(match failure.take() {
                    Some(primary) => {
                        combine_failures(primary, error, "modal wake publication failures combined")
                    }
                    None => error,
                });
                None
            }
        };
        if let (Some(identity), Some(generation)) = (work.as_mut(), next_multimedia_generation) {
            identity.wake_generation = generation;
            if let Some(pending) = mailbox.pending.as_mut()
                && pending.work.marker_id == identity.marker_id
            {
                pending.work.wake_generation = generation;
            }
            if let Some(in_flight) = mailbox
                .in_flight
                .iter_mut()
                .find(|in_flight| in_flight.marker_id == identity.marker_id)
            {
                in_flight.wake_generation = generation;
            }
        }

        let failure = match (work, failure) {
            (Some(work), Some(error)) => {
                remember_modal_failure(&mut mailbox, work, error);
                Some(work)
            }
            (Some(_), None) | (None, None) => None,
            (None, Some(error)) => {
                drop(mailbox);
                drop(gate);
                return Err(error);
            }
        };
        drop(mailbox);
        drop(gate);
        if let Some(work) = failure {
            return Err(self.dispatch_ingress_abort(work));
        }
        Ok(())
    }

    pub(super) fn activate_modal_scope(
        &self,
        operation_id: u64,
        scope_id: u64,
        pending_wake: bool,
        wake_generation: u64,
    ) -> Result<(), (ModalGuestWorkIdentity, RuntimeError)> {
        if !self.guest_work_ready.load(Ordering::Acquire) || self.terminal_requested() {
            return Err((
                empty_identity(operation_id, scope_id, wake_generation),
                RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 modal guest-work lane is not ready or terminal teardown has started",
                ),
            ));
        }
        let mut mailbox = self.guest_mailbox.lock().map_err(|_| {
            let work = empty_identity(operation_id, scope_id, wake_generation);
            (
                work,
                RuntimeError::new(Kind::InternalInvariant, "lock Win16 modal scope mailbox"),
            )
        })?;
        mailbox.scopes.try_reserve(1).map_err(|error| {
            let work = empty_identity(operation_id, scope_id, wake_generation);
            (
                work,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve an active Win16 modal scope identity",
                    error,
                ),
            )
        })?;
        let scope = ModalScopeIdentity {
            operation_id,
            scope_id,
        };
        mailbox.scopes.push(scope);
        if pending_wake {
            if let Err((work, error)) =
                publish_modal_marker(self, &mut mailbox, scope, wake_generation)
            {
                mailbox.scopes.pop();
                return Err((work, error));
            }
        }
        Ok(())
    }

    pub(super) fn retire_modal_scope(
        &self,
        operation_id: u64,
        scope_id: u64,
    ) -> Result<Vec<runtime::Win16NativeModalGuestWorkRetirement>, RuntimeError> {
        let gate = self.publication.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal scope retirement state",
            )
        })?;
        let mut mailbox = self.guest_mailbox.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal scope retirement mailbox",
            )
        })?;
        let Some(scope) = mailbox.scopes.last().copied() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal guest-work scope stack is empty at native return",
            ));
        };
        if scope.operation_id != operation_id || scope.scope_id != scope_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal guest-work scope returned outside its exact operation and LIFO identity",
            ));
        }
        let work_count = usize::from(mailbox.pending.as_ref().is_some_and(|pending| {
            pending.work.operation_id == operation_id && pending.work.scope_id == scope_id
        })) + mailbox
            .in_flight
            .iter()
            .filter(|work| work.operation_id == operation_id && work.scope_id == scope_id)
            .count();
        let mut retired = Vec::new();
        retired.try_reserve_exact(work_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact modal guest-work source retirement receipts",
                error,
            )
        })?;
        if let Some(pending) = mailbox.pending.as_ref().filter(|pending| {
            pending.work.operation_id == operation_id && pending.work.scope_id == scope_id
        }) {
            retired.push(pending.work.retirement_receipt()?);
        }
        for work in mailbox
            .in_flight
            .iter()
            .copied()
            .filter(|work| work.operation_id == operation_id && work.scope_id == scope_id)
        {
            retired.push(work.retirement_receipt()?);
        }
        mailbox.scopes.pop();
        if mailbox.pending.as_ref().is_some_and(|pending| {
            pending.work.operation_id == operation_id && pending.work.scope_id == scope_id
        }) {
            mailbox.pending = None;
        }
        mailbox
            .in_flight
            .retain(|work| work.operation_id != operation_id || work.scope_id != scope_id);
        if mailbox
            .failure
            .as_ref()
            .is_some_and(|failure| failure.work.scope_id == scope_id && failure.abort_resolved)
        {
            if let Some(failure) = mailbox.failure.take() {
                self.record_callback_failure(shared_error(
                    &failure.cause,
                    "Win16 modal guest-work ingress failed before native return",
                ));
            }
        }
        drop(mailbox);
        drop(gate);
        Ok(retired)
    }

    pub(super) fn classify_guest_work_marker(
        &self,
        marker_id: usize,
    ) -> GuestWorkMarkerDisposition {
        let mut mailbox = self
            .guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if marker_id == 0 || marker_id >= mailbox.next_marker_id {
            return GuestWorkMarkerDisposition::Unknown;
        }
        let Some(pending) = mailbox.pending.as_ref() else {
            return GuestWorkMarkerDisposition::Stale;
        };
        if pending.work.marker_id != Some(marker_id) || !pending.posted {
            return GuestWorkMarkerDisposition::Stale;
        }
        let work = pending.work;
        let active = mailbox.scopes.last().is_some_and(|scope| {
            scope.operation_id == work.operation_id && scope.scope_id == work.scope_id
        });
        mailbox.pending = None;
        if mailbox
            .failure
            .as_ref()
            .is_some_and(|failure| !failure.abort_resolved)
        {
            return GuestWorkMarkerDisposition::Stale;
        }
        if !active {
            return GuestWorkMarkerDisposition::Stale;
        }
        mailbox.in_flight.push(work);
        GuestWorkMarkerDisposition::Current(work)
    }

    pub(in crate::windows) fn active_modal_work_scope(&self) -> Option<(u64, u64)> {
        self.guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .scopes
            .last()
            .map(|scope| (scope.operation_id, scope.scope_id))
    }

    pub(in crate::windows) fn pending_modal_failure(
        &self,
        operation_id: u64,
        scope_id: u64,
    ) -> Option<(ModalGuestWorkIdentity, Arc<RuntimeError>)> {
        let mut mailbox = self
            .guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = mailbox
            .scopes
            .last()
            .is_some_and(|scope| scope.operation_id == operation_id && scope.scope_id == scope_id);
        let generation = mailbox.next_generation;
        let next_generation = generation.checked_add(1).filter(|next| *next != 0)?;
        let (wake_generation, cause) = {
            let failure = mailbox.failure.as_mut()?;
            if !active || failure.delivered || !failure.abort_resolved {
                return None;
            }
            failure.delivered = true;
            (failure.work.wake_generation, Arc::clone(&failure.cause))
        };
        mailbox.next_generation = next_generation;
        let work = ModalGuestWorkIdentity {
            operation_id,
            scope_id,
            generation,
            marker_id: None,
            wake_generation,
        };
        Some((work, cause))
    }

    pub(in crate::windows) fn complete_modal_guest_work(
        &self,
        work: ModalGuestWorkIdentity,
    ) -> Result<u64, RuntimeError> {
        let mut mailbox = self.guest_mailbox.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "lock Win16 modal guest-work completion state",
            )
        })?;
        if mailbox.in_flight.last().copied() != Some(work)
            || !mailbox.scopes.last().is_some_and(|scope| {
                scope.operation_id == work.operation_id && scope.scope_id == work.scope_id
            })
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal resume did not match the active in-flight guest-work tuple",
            ));
        }
        mailbox.in_flight.pop();
        Ok(work.wake_generation)
    }

    pub(super) fn abandon_modal_guest_work(&self, work: ModalGuestWorkIdentity) {
        let mut mailbox = self
            .guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if mailbox.in_flight.last().copied() == Some(work) {
            mailbox.in_flight.pop();
        }
    }

    pub(super) fn abort_after_ingress_failure(
        &self,
        work: ModalGuestWorkIdentity,
        failure: RuntimeError,
    ) -> RuntimeError {
        self.record_ingress_failure(work, Arc::new(failure));
        self.dispatch_ingress_abort(work)
    }

    fn dispatch_ingress_abort(&self, work: ModalGuestWorkIdentity) -> RuntimeError {
        let _dispatch = self
            .abort_dispatch_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dispatcher = self
            .abort_dispatcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);
        let abort_failure = match dispatcher {
            Some(dispatcher) => dispatcher.request_abort_for_modal_failure().err(),
            None => Some(RuntimeError::new(
                Kind::InternalInvariant,
                "modal guest-work ingress has no live terminal Abort response owner",
            )),
        };
        if let Some(abort_failure) = abort_failure {
            self.record_ingress_failure(work, Arc::new(abort_failure));
        }
        if let Some(failure) = self
            .guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure
            .as_mut()
        {
            failure.abort_resolved = true;
        }
        self.guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure
            .as_ref()
            .map_or_else(
                || RuntimeError::new(Kind::HostFailure, "Win16 modal guest-work ingress failed"),
                |failure| shared_error(&failure.cause, "Win16 modal guest-work ingress and Abort"),
            )
    }

    fn record_ingress_failure(&self, work: ModalGuestWorkIdentity, additional: Arc<RuntimeError>) {
        let mut mailbox = self
            .guest_mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(failure) = mailbox.failure.as_mut() {
            failure.cause = combine_shared_errors(
                Arc::clone(&failure.cause),
                additional,
                "Win16 modal marker and terminal Abort failures combined",
            );
        } else {
            mailbox.failure = Some(ModalIngressFailure {
                work,
                cause: additional,
                delivered: false,
                abort_resolved: false,
            });
        }
    }
}

fn publish_modal_marker(
    control: &ModalWorkerControl,
    mailbox: &mut ModalGuestMailbox,
    scope: ModalScopeIdentity,
    wake_generation: u64,
) -> Result<ModalGuestWorkIdentity, (ModalGuestWorkIdentity, RuntimeError)> {
    if let Some(pending) = mailbox.pending.as_mut()
        && pending.work.operation_id == scope.operation_id
        && pending.work.scope_id == scope.scope_id
    {
        let work = pending.work;
        if !pending.posted {
            return Err((
                work,
                RuntimeError::new(
                    Kind::HostFailure,
                    "previous Win16 modal guest-work marker remains retained after PostThreadMessageW failed",
                ),
            ));
        }
        if !control.guest_work_ready.load(Ordering::Acquire) {
            return Err((
                work,
                RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 modal guest-work lane is not ready or has closed",
                ),
            ));
        }
        mailbox.in_flight.try_reserve(1).map_err(|error| {
            (
                work,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve the nested Win16 modal guest-work continuation stack",
                    error,
                ),
            )
        })?;
        let next_generation = mailbox.next_generation;
        let Some(next) = next_generation.checked_add(1) else {
            return Err((
                work,
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 modal guest-work generation is exhausted",
                ),
            ));
        };
        mailbox.next_generation = next;
        let pending = mailbox
            .pending
            .as_mut()
            .expect("pending marker remains owned");
        pending.work.generation = next_generation;
        pending.work.wake_generation = wake_generation;
        return Ok(pending.work);
    }

    let generation = mailbox.next_generation;
    let Some(next_generation) = generation.checked_add(1) else {
        let work = empty_identity(scope.operation_id, scope.scope_id, wake_generation);
        return Err((
            work,
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 modal guest-work generation is exhausted",
            ),
        ));
    };
    let marker_id = mailbox.next_marker_id;
    let Some(next_marker_id) = marker_id
        .checked_add(1)
        .filter(|next| isize::try_from(marker_id).is_ok() && *next > marker_id)
    else {
        let work = empty_identity(scope.operation_id, scope.scope_id, wake_generation);
        return Err((
            work,
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 modal marker identity space is exhausted",
            ),
        ));
    };
    let work = ModalGuestWorkIdentity {
        operation_id: scope.operation_id,
        scope_id: scope.scope_id,
        generation,
        marker_id: Some(marker_id),
        wake_generation,
    };
    if !control.guest_work_ready.load(Ordering::Acquire) {
        return Err((
            work,
            RuntimeError::new(
                Kind::HostFailure,
                "Win16 modal guest-work lane is not ready or has closed",
            ),
        ));
    }
    mailbox.in_flight.try_reserve(1).map_err(|error| {
        (
            work,
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the nested Win16 modal guest-work continuation stack",
                error,
            ),
        )
    })?;
    let message = control
        .registered_guest_work_message
        .load(Ordering::Acquire);
    if message == 0 {
        return Err((
            work,
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal guest-work message was not registered before worker readiness",
            ),
        ));
    }
    let thread_id = control.thread_id.load(Ordering::Acquire);
    if thread_id == 0 {
        return Err((
            work,
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal guest-work marker has no owner-thread identity",
            ),
        ));
    }
    mailbox.next_generation = next_generation;
    mailbox.next_marker_id = next_marker_id;
    mailbox.pending = Some(ModalMarker { work, posted: true });
    let native_id = isize::try_from(marker_id).expect("checked above");
    // The private Windows message carries only the worker nonce and this
    // checked native-width scalar marker ID in WPARAM/LPARAM. No Rust struct
    // crosses the queue, so there is no custom byte codec or pointer payload.
    // SAFETY: PostThreadMessageW queues scalar parameters to a thread id.
    let posted = unsafe { PostThreadMessageW(thread_id, message, control.worker_nonce, native_id) };
    if posted == 0 {
        if let Some(pending) = mailbox.pending.as_mut()
            && pending.work.marker_id == Some(marker_id)
        {
            pending.posted = false;
        }
        let error = crate::windows::win32_safe::last_error();
        return Err((
            work,
            RuntimeError::with_source(
                Kind::HostFailure,
                "post the registered Win16 modal guest-work marker",
                std::io::Error::from_raw_os_error(error as i32),
            ),
        ));
    }
    Ok(work)
}

fn empty_identity(
    operation_id: u64,
    scope_id: u64,
    wake_generation: u64,
) -> ModalGuestWorkIdentity {
    ModalGuestWorkIdentity {
        operation_id,
        scope_id,
        generation: 0,
        marker_id: None,
        wake_generation,
    }
}

fn remember_modal_failure(
    mailbox: &mut ModalGuestMailbox,
    work: ModalGuestWorkIdentity,
    cause: RuntimeError,
) {
    let cause = Arc::new(cause);
    if let Some(failure) = mailbox.failure.as_mut() {
        failure.cause = combine_shared_errors(
            Arc::clone(&failure.cause),
            cause,
            "Win16 modal guest-work failures combined",
        );
    } else {
        mailbox.failure = Some(ModalIngressFailure {
            work,
            cause,
            delivered: false,
            abort_resolved: false,
        });
    }
}

fn shared_error(cause: &Arc<RuntimeError>, context: &'static str) -> RuntimeError {
    RuntimeError::with_source(cause.kind(), context, Arc::clone(cause))
}

fn combine_shared_errors(
    primary: Arc<RuntimeError>,
    additional: Arc<RuntimeError>,
    context: &'static str,
) -> Arc<RuntimeError> {
    let kind = primary.kind().with_cleanup(additional.kind());
    Arc::new(RuntimeError::with_source(
        kind,
        context,
        ModalIngressFailurePair {
            primary,
            additional,
        },
    ))
}

#[derive(Debug)]
struct ModalIngressFailurePair {
    primary: Arc<RuntimeError>,
    additional: Arc<RuntimeError>,
}

impl std::fmt::Display for ModalIngressFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; additional failure: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for ModalIngressFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary.as_ref())
    }
}
