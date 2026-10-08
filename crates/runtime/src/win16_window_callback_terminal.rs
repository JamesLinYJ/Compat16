//! Exact callback-source payload cleanup during USER teardown.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn cancel_window_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
    ) -> Result<WindowCallbackPayloadCleanup, RuntimeError> {
        if self.window_teardown_state != super::super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window callback cancellation preceded USER quiescence",
            ));
        }
        let callback_id = self.require_callback_top(CallbackKind::Window)?;
        let callback = self.window_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 window callback kind has no retained frame",
        ))?;
        if callback.callback_id != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal USER callback does not match its exact shared frame identity"));
        }
        let continuation = callback.continuation;
        let guest_owned = matches!(callback.continuation,
            super::WindowCallbackContinuation::GuestDispatch
                | super::WindowCallbackContinuation::GuestDialogDispatch { .. }
                | super::WindowCallbackContinuation::GuestTimer
                | super::WindowCallbackContinuation::GuestProcedureCall { .. });
        let callback_source = match (
            window_callback_host_token(continuation),
            callback.host_operation,
            callback.native_source,
        ) {
            (Some(token), Some(operation), Some(source)) => {
                self.validate_terminal_callback_source(token, operation, source)?;
                Some(crate::Win16NativeCallbackCancellation {
                    callback: token,
                    operation_id: operation,
                    source,
                })
            }
            (None, None, None) => None,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 callback source binding is incomplete at terminal retirement")),
        };
        let owner_index = self.window_operations.iter().rposition(|operation| {
            operation.guest_callback_id == Some(callback_id)
        });
        if guest_owned && owner_index.is_none() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "guest-only USER callback has no exact retained operation owner"));
        }
        let terminal_owner = callback_source.map(|cancellation| {
            self.prepare_terminal_callback_retirement(callback_id, cancellation)
        }).transpose()?;
        let cleanup = match super::payload_retirement::retire_terminal_window_callback_payload(self, ended) {
            Ok(WindowCallbackPayloadCleanup::RetainedInFrame) => {
                return Ok(WindowCallbackPayloadCleanup::RetainedInFrame);
            }
            Ok(cleanup) => cleanup,
            Err(error) => {
                let error = std::sync::Arc::new(error);
                if let Some(owner) = terminal_owner {
                    self.retain_callback_terminal_error(owner, std::sync::Arc::clone(&error))?;
                }
                return Err(super::super::callback_lifo::shared_runtime_error(error));
            }
        };
        if let (Some(owner), Some(cancellation)) = (terminal_owner, callback_source) {
            self.set_terminal_callback_phase(
                owner,
                callback_id,
                cancellation,
                |proof| proof.guest_payload_cleaned = true,
            )?;
        }
        if let Err(error) = self.retire_callback_binding(CallbackKind::Window, callback_id) {
            let error = std::sync::Arc::new(error);
            if let Some(owner) = terminal_owner {
                self.retain_callback_terminal_error(owner, std::sync::Arc::clone(&error))?;
            }
            return Err(super::super::callback_lifo::shared_runtime_error(error));
        }
        if let (Some(owner), Some(cancellation)) = (terminal_owner, callback_source) {
            self.set_terminal_callback_phase(
                owner,
                callback_id,
                cancellation,
                |proof| proof.runtime_frame_retired = true,
            )?;
        }
        if let Some(index) = owner_index {
            self.window_operations[index].guest_callback_retired = true;
        }
        let retired = self.window_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "terminal USER callback frame disappeared before its paired retirement",
        ))?;
        debug_assert_eq!(retired.callback_id, callback_id);
        Ok(cleanup)
    }

    pub(in crate::win16_runtime) fn prepare_terminal_callback_retirement(
        &mut self,
        callback_frame_id: super::CallbackFrameId,
        cancellation: crate::Win16NativeCallbackCancellation,
    ) -> Result<u64, RuntimeError> {
        let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "terminal callback proof has no retained USER abort receipt",
        ))?;
        if receipt.cancelled_callbacks.iter().filter(|item| **item == cancellation).count() != 1 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "terminal callback proof differs from its exact native cancellation receipt"));
        }
        let mut owner_index = None;
        for (index, frame) in self.window_operations.iter().enumerate() {
            if frame.host_operation == Some(cancellation.operation_id)
                && frame.worker_generation == Some(receipt.worker_generation)
            {
                if owner_index.replace(index).is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "terminal callback operation has multiple runtime owners"));
                }
            }
        }
        let index = owner_index.ok_or_else(|| RuntimeError::new(Kind::HostFailure,
            "terminal callback has no exact operation and worker-generation owner"))?;
        let owner = &mut self.window_operations[index];
        let frame_id = owner.id;
        if let Some(existing) = owner.terminal_retired_callbacks.iter().find(|proof| {
            proof.callback_frame_id == callback_frame_id
                || proof.cancellation.callback == cancellation.callback
        }) {
            if existing.callback_frame_id == callback_frame_id
                && existing.cancellation == cancellation
            {
                return Ok(frame_id);
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal callback retry changed its frame or native source identity"));
        }
        owner.terminal_retired_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact terminal callback proof before guest cleanup",
                error,
            )
        })?;
        owner.terminal_retired_callbacks.push(
            super::TerminalWindowCallbackRetirement {
                callback_frame_id,
                cancellation,
                guest_payload_cleaned: false,
                runtime_frame_retired: false,
                owner_context_restored: false,
                native_source_acknowledged: false,
            },
        );
        Ok(frame_id)
    }

    pub(in crate::win16_runtime) fn set_terminal_callback_phase(
        &mut self,
        owner_id: u64,
        callback_frame_id: super::CallbackFrameId,
        cancellation: crate::Win16NativeCallbackCancellation,
        update: impl FnOnce(&mut super::TerminalWindowCallbackRetirement),
    ) -> Result<(), RuntimeError> {
        let owner = self.window_operations.iter_mut().find(|frame| frame.id == owner_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "terminal callback phase lost its exact operation owner"))?;
        let proof = owner.terminal_retired_callbacks.iter_mut().find(|proof| {
            proof.callback_frame_id == callback_frame_id
                && proof.cancellation == cancellation
        }).ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "terminal callback phase has no pre-reserved proof"))?;
        update(proof);
        Ok(())
    }

    pub(in crate::win16_runtime) fn retain_callback_terminal_error(
        &mut self,
        owner_id: u64,
        error: std::sync::Arc<RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let owner = self.window_operations.iter_mut().find(|frame| frame.id == owner_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "callback cleanup error lost its exact operation owner"))?;
        if owner.terminal_retained_error.is_none() {
            owner.terminal_retained_error = Some(error);
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn validate_terminal_callback_source(
        &self,
        callback: crate::Win16HostCallback,
        operation: crate::Win16HostWindowOperationId,
        source: crate::Win16NativeCallbackSource,
    ) -> Result<(), RuntimeError> {
        let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "native callback cleanup has no retained USER abort receipt",
        ))?;
        if receipt.cancelled_callbacks.iter().filter(|item|
            item.callback == callback
                && item.operation_id == operation
                && item.source == source
        ).count() != 1 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native callback cleanup lacks its exact cancellation source proof"));
        }
        if self.window_operations.iter().filter(|frame|
            frame.host_operation == Some(operation)
                && frame.worker_generation == Some(receipt.worker_generation)
        ).count() != 1
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "native callback cleanup lacks its exact runtime operation owner"));
        }
        Ok(())
    }}

pub(in crate::win16_runtime) fn window_callback_host_token(
    continuation: super::WindowCallbackContinuation,
) -> Option<crate::Win16HostCallback> {
    use super::WindowCallbackContinuation as Continuation;
    match continuation {
        Continuation::Host { callback, .. }
        | Continuation::HostDialog { callback, .. }
        | Continuation::HostTimer { callback } => Some(callback),
        Continuation::GuestDispatch
        | Continuation::GuestDialogDispatch { .. }
        | Continuation::GuestTimer
        // A forwarded message grants access to the outer native callback;
        // it does not transfer cancellation or terminal-ACK ownership.
        // The enclosing Host/HostDialog frame remains its unique owner.
        | Continuation::GuestProcedureCall { .. } => None,
    }
}
