//! Identities for suspended USER and other callback-capable operations.

use guest_core::Registers;

use super::{
    Win16State, WindowOperationFrame, WindowOperationLifecycle,
    windows::WindowReturn,
};
use crate::{DiagnosticKind as Kind, RuntimeError};
use crate::Win16HostWindowOperationId;

impl Win16State {
    /// A callback can suspend a wait while nested guest calls add more frames.
    /// Stack position and saved CS:IP are not identities: recursion can repeat
    /// both. Keep a non-reused runtime nonce for the exact original wait.
    pub(super) fn push_window_operation(
        &mut self,
        saved: Registers,
        return_to: (u16, u16, u32),
        mut result: WindowReturn,
    ) -> Result<(), RuntimeError> {
        let entry_context = self.window_dispatch_context.clone().or_else(|| {
            self.window_operations.last().map(|frame| frame.entry_context.clone())
        }).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 USER operation has no full context from a real guest entry",
        ))?;
        let id = self.next_window_operation;
        let Some(next) = id.checked_add(1) else {
            let error = RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 operation frame identities exhausted",
            );
            self.release_window_result_reservations(&mut result);
            return Err(error);
        };
        if let Err(cause) = self.window_operations.try_reserve(1) {
            let error = RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a Win16 operation frame",
                cause,
            );
            self.release_window_result_reservations(&mut result);
            return Err(error);
        }
        let cpu_call_owner = self.active_dispatch_call_owner.take();
        self.next_window_operation = next;
        self.window_operations.push(WindowOperationFrame {
            id,
            saved,
            return_to,
            result: Some(result),
            completion: None,
            dde_completion: None,
            pending_dde_callback: None,
            source_retired: None,
            source_retirement_consumed: false,
            prior_source_retirement: None,
            entry_context,
            cpu_call_owner,
            guest_return_transfer: None,
            native_source: None,
            lifecycle: WindowOperationLifecycle::GuestOnly,
            native_state: None,
            host_operation: None,
            worker_generation: None,
            terminal_started_failure: None,
            guest_callback_id: None,
            guest_callback_retired: false,
            pending_work: None,
            pending_modal_work: None,
            host_wait: None,
            host_modal_operation: None,
            terminal_modal_responses: Vec::new(),
            terminal_modal_error: None,
            terminal_resources_retired: false,
            terminal_context_restored: false,
            terminal_ack: None,
            terminal_ack_attempted: false,
            terminal_retired_callbacks: Vec::new(),
            terminal_source_acknowledged: false,
            terminal_error: None,
            terminal_retained_error: None,
            last_work_generation: 0,
            last_modal_work_generation: 0,
        });
        Ok(())
    }

    fn release_window_result_reservations(&mut self, result: &mut WindowReturn) {
        if let WindowReturn::UserFamily(continuation) = result {
            let count = continuation.take_clipboard_retirement_reservation();
            self.clipboard_state.release_retired_reservation(count);
        }
    }

    pub(super) fn bind_started_window_operation(
        &mut self,
        operation_id: Win16HostWindowOperationId,
        worker_generation: u64,
        kind: crate::Win16NativeWindowOperationKind,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "native USER begin returned an operation identity without a runtime owner",
        ))?;
        if operation_id.0 == 0 || worker_generation == 0
            || frame.native_source != Some(kind)
            || frame.host_operation.is_some()
            || frame.worker_generation.is_some()
            || frame.lifecycle != WindowOperationLifecycle::BeginPending
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native USER begin identity does not match the exact unbound runtime owner",
            ));
        }
        frame.host_operation = Some(operation_id);
        frame.worker_generation = Some(worker_generation);
        frame.lifecycle = WindowOperationLifecycle::Started;
        frame.native_state = Some(crate::Win16NativeWindowOperationState::Active);
        Ok(())
    }

    pub(super) fn mark_window_begin_pending(
        &mut self,
        kind: crate::Win16NativeWindowOperationKind,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 USER begin has no retained runtime operation",
        ))?;
        if frame.native_source != Some(kind)
            || frame.lifecycle != WindowOperationLifecycle::GuestOnly
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER begin changed its exact planned operation owner",
            ));
        }
        frame.lifecycle = WindowOperationLifecycle::BeginPending;
        Ok(())
    }

    pub(super) fn mark_window_begin_rejected(
        &mut self,
        cause: std::sync::Arc<RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "rejected Win16 USER begin lost its runtime owner",
        ))?;
        if frame.lifecycle != WindowOperationLifecycle::BeginPending
            || frame.host_operation.is_some()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER begin rejection conflicts with a real host operation identity",
            ));
        }
        frame.lifecycle = WindowOperationLifecycle::NeverStarted;
        frame.terminal_error = Some(cause);
        Ok(())
    }

    pub(super) fn record_started_window_operation_failure(
        &mut self,
        failure: std::sync::Arc<crate::Win16WindowOperationStartedFailure>,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "failed native USER response has no runtime operation owner",
        ))?;
        let operation_id = failure.operation.operation_id;
        let worker_generation = failure.worker_generation;
        let kind = failure.operation.kind;
        let state = failure.state;
        if operation_id.0 == 0 || worker_generation == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "host StartedFailure contains a zero enqueued operation identity"));
        }
        if frame.host_operation.is_none() {
            if frame.native_source != Some(kind)
                || frame.lifecycle != WindowOperationLifecycle::BeginPending
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed native USER response has an invalid real begin identity",
                ));
            }
            frame.host_operation = Some(operation_id);
            frame.worker_generation = Some(worker_generation);
        } else if frame.host_operation != Some(operation_id)
            || frame.worker_generation != Some(worker_generation)
            || frame.native_source != Some(kind)
            || !matches!(
                frame.lifecycle,
                WindowOperationLifecycle::Started
                    | WindowOperationLifecycle::ReturnedWithError
            )
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "failed native USER response changed its exact started operation identity",
            ));
        }
        if let Some(previous) = frame.terminal_started_failure.as_ref() {
            if !std::sync::Arc::ptr_eq(previous, &failure) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "USER StartedFailure retry did not preserve the host-created Arc identity"));
            }
        }
        frame.terminal_started_failure = Some(std::sync::Arc::clone(&failure));
        frame.native_state = Some(state);
        frame.lifecycle = match state {
            crate::Win16NativeWindowOperationState::Active => WindowOperationLifecycle::Started,
            crate::Win16NativeWindowOperationState::Returned => {
                WindowOperationLifecycle::ReturnedWithError
            }
        };
        frame.terminal_error = Some(std::sync::Arc::clone(&failure.cause));
        Ok(())
    }

    pub(super) fn validate_native_window_callback_owner(
        &self,
        operation_id: Win16HostWindowOperationId,
        callback: crate::Win16HostCallback,
        _source: crate::Win16NativeCallbackSource,
    ) -> Result<(), RuntimeError> {
        let mut matches = self.window_operations.iter().filter(|frame| {
            frame.host_operation == Some(operation_id)
        });
        let Some(frame) = matches.next() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native USER callback has no exact runtime operation identity",
            ));
        };
        if matches.next().is_some()
            || self.window_operations.last().map(|top| top.id) != Some(frame.id)
            || operation_id.0 == 0
            || callback.0 == 0
            || !frame.worker_generation.is_some_and(|generation| generation != 0)
            || frame.lifecycle != WindowOperationLifecycle::Started
            || frame.native_state != Some(crate::Win16NativeWindowOperationState::Active)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native USER callback changed its exact started operation owner",
            ));
        }
        Ok(())
    }
}
