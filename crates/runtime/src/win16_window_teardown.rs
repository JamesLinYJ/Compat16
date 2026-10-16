//! USER native-owner quiescence and final window shutdown.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn close_windows(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.quiesce_window_callback_owner(host)?;
        if self.window_teardown_state == super::super::WindowTeardownState::Closed {
            return Ok(());
        }
        self.close_native_function_callbacks()?;
        if !self.window_callbacks.is_empty()
            || self.callback_kinds.contains(&CallbackKind::Window)
            || !self.window_operations.is_empty()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "USER callback owners remain outside callback LIFO teardown",
            ));
        }
        let mut first_error = None;
        let owned: Vec<_> = self.owned_window_handles.iter().copied().collect();
        for guest in owned {
            let Some(&native) = self.window_handles.get(&guest) else {
                continue;
            };
            match host.win16_destroy_window(native) {
                Ok(true) => {
                    if let Err(error) = self.retire_window_tree(guest) {
                        remember_window_cleanup_failure(&mut first_error, error);
                    }
                }
                Ok(false) => remember_window_cleanup_failure(
                    &mut first_error,
                    RuntimeError::new(Kind::HostFailure, "native Win16 window could not be closed"),
                ),
                Err(error) => remember_window_cleanup_failure(&mut first_error, error),
            }
        }
        // Failed destroys keep their guest handles and code roots for retry.
        if let Some(error) = first_error {
            return Err(error);
        }
        self.window_handles.clear();
        self.window_system_classes.clear();
        self.mdi_children.clear();
        self.window_creations.clear();
        self.window_parents.clear();
        self.window_parent_observations.clear();
        self.window_procedures.clear();
        self.dialog_procedures.clear();
        self.window_data.clear();
        self.guest_menus.clear();
        self.timers.clear();
        self.window_teardown_state = super::super::WindowTeardownState::Closed;
        Ok(())
    }

    pub(in crate::win16_runtime) fn quiesce_window_callback_owner(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match self.window_teardown_state {
            super::super::WindowTeardownState::Closed => return Ok(()),
            super::super::WindowTeardownState::Live => {
                self.window_teardown_state = super::super::WindowTeardownState::AbortPending;
                // Pending HDWPs contain only owned Rust positions. Abandon
                // them before native teardown can invoke or cancel callbacks.
                self.deferred_window_batches.clear();
            }
            super::super::WindowTeardownState::AbortPending
            | super::super::WindowTeardownState::NativeQuiescent => {}
        }
        if self.window_teardown_state == super::super::WindowTeardownState::AbortPending {
            if self.window_abort_receipt.is_none() {
                self.window_abort_receipt = Some(host.win16_window_abort()?);
            }
            let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 USER abort completed without retaining its terminal receipt",
                )
            })?;
            self.validate_window_abort_receipt(receipt)?;
            for (index, cancellation) in receipt.cancelled_modals.iter().enumerate() {
                let valid = match cancellation.signal {
                    crate::Win16NativeModalCancelSignal::BeforeEntry => {
                        cancellation.scope_id.is_none()
                            && cancellation.native_result.is_none()
                            && cancellation.native_last_error.is_none()
                    }
                    crate::Win16NativeModalCancelSignal::OwnerThreadQuit => {
                        cancellation.scope_id.is_some_and(|scope| scope != 0)
                            && cancellation.native_result.is_some()
                    }
                    crate::Win16NativeModalCancelSignal::DialogEnd => {
                        cancellation.scope_id.is_some_and(|scope| scope != 0)
                            && cancellation.native_result.is_some_and(|value| value != -1)
                    }
                };
                if cancellation.operation_id == 0 || !valid {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 USER worker returned an invalid native modal cancellation receipt",
                    ));
                }
                if receipt.cancelled_modals[..index].iter().any(|prior| {
                    prior.operation_id == cancellation.operation_id
                }) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 USER worker duplicated a native modal cancellation receipt",
                    ));
                }
                let index = self.modal_operation_index(cancellation.operation_id)?;
                let frame = &self.window_operations[index];
                if frame.host_modal_operation.is_some_and(|operation|
                    Some(operation) != frame.host_operation)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native modal receipt changed its exact runtime operation binding"));
                }
                if let Some(work) = &frame.pending_modal_work {
                    if cancellation.scope_id != Some(work.scope_id())
                        || cancellation.retired_guest_work.as_slice()
                            != work.terminal_retirement()?.as_slice()
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "native modal receipt does not match the exact retained guest-work source"));
                    }
                } else if !cancellation.retired_guest_work.is_empty() {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "native modal receipt retires guest work with no retained runtime source"));
                }
            }
            for frame in &mut self.window_operations {
                let count = receipt.cancelled_modals.iter().filter(|cancellation| {
                    frame.host_operation
                        == Some(crate::Win16HostWindowOperationId(cancellation.operation_id))
                }).count();
                frame.terminal_modal_responses.try_reserve(count).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "retain terminal Win16 modal cancellation responses",
                        error,
                    )
                })?;
            }
            for cancellation in &receipt.cancelled_modals {
                let index = self.modal_operation_index(cancellation.operation_id)?;
                let frame = &mut self.window_operations[index];
                if frame.terminal_modal_error.as_ref().is_some_and(|error| {
                    !super::modal_error_matches(error, cancellation)
                }) {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "native modal cancellation changed its cached typed terminal cause"));
                }
                if frame.terminal_modal_error.is_none() {
                    let error = RuntimeError::with_source(
                        Kind::HostFailure,
                        "native modal operation was terminally cancelled during USER teardown",
                        super::NativeModalCancellationFailure::from_response(cancellation),
                    );
                    let cause = std::sync::Arc::new(error);
                    frame.terminal_error.get_or_insert_with(|| std::sync::Arc::clone(&cause));
                    frame.terminal_modal_error = Some(cause);
                }
                frame.lifecycle = super::WindowOperationLifecycle::TerminalModalCancelled;
                frame.native_state = Some(crate::Win16NativeWindowOperationState::Returned);
                let slots = &mut frame.terminal_modal_responses;
                if let Some(previous) = slots.iter().find(|slot|
                    slot.operation_id == cancellation.operation_id)
                {
                    if previous != cancellation {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "retained Win16 modal slot changed its terminal result"));
                    }
                } else {
                    slots.push(cancellation.clone());
                }
            }
            self.window_teardown_state = super::super::WindowTeardownState::NativeQuiescent;
        }
        if self.window_teardown_state != super::super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window teardown proceeded without native quiescence",
            ));
        }
        Ok(())
    }

    fn modal_operation_index(&self, operation_id: u64) -> Result<usize, RuntimeError> {
        let host_operation = crate::Win16HostWindowOperationId(operation_id);
        let mut matches = self.window_operations.iter().enumerate().filter(|(_, frame)| {
            frame.host_operation == Some(host_operation)
                && frame.host_modal_operation.is_none_or(|bound| bound == host_operation)
        });
        let Some((index, _)) = matches.next() else {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native modal cancellation has no exact retained runtime operation slot",
            ));
        };
        if matches.next().is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native modal cancellation matches more than one runtime operation",
            ));
        }
        Ok(index)
    }

    fn validate_window_abort_receipt(
        &self,
        receipt: &crate::Win16WindowAbortReceipt,
    ) -> Result<(), RuntimeError> {
        if receipt.worker_generation == 0
            || receipt.request_id == 0
            || !receipt.active_operation_stack_empty
            || !receipt.callback_stack_empty
            || !receipt.modal_scope_stack_empty
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER abort receipt does not prove native callback and operation stacks quiesced"));
        }
        for frame in &self.window_operations {
            if frame.terminal_ack_attempted
                && (frame.terminal_ack.is_none()
                    || !frame.terminal_resources_retired
                    || !frame.terminal_context_restored)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "USER terminal ACK attempt has no cached exact proof and completed cleanup phases"));
            }
            if frame.terminal_source_acknowledged && !frame.terminal_ack_attempted {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "USER source retirement was recorded without an exact ACK attempt"));
            }
            let mut callback_frame_ids = std::collections::BTreeSet::new();
            let mut callback_tokens = std::collections::BTreeSet::new();
            for proof in &frame.terminal_retired_callbacks {
                if proof.callback_frame_id.0 == 0
                    || !callback_frame_ids.insert(proof.callback_frame_id.0)
                    || !callback_tokens.insert(proof.cancellation.callback.0)
                    || Some(proof.cancellation.operation_id) != frame.host_operation
                    || receipt.cancelled_callbacks.iter().filter(|item| {
                        **item == proof.cancellation
                    }).count() != 1
                    || (proof.runtime_frame_retired && !proof.guest_payload_cleaned)
                    || proof.owner_context_restored != frame.terminal_context_restored
                    || proof.native_source_acknowledged != frame.terminal_source_acknowledged
                {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "cached callback retirement phase differs from its exact frame, source, or operation proof"));
                }
            }
        }
        for (index, proof) in receipt.active_operations.iter().enumerate() {
            if proof.operation_id.0 == 0
                || receipt.active_operations[..index].iter().any(|prior|
                    prior.operation_id == proof.operation_id)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicates an active operation identity"));
            }
            let window_owners = self.window_operations.iter().filter(|frame| {
                frame.host_operation == Some(proof.operation_id)
                    && frame.worker_generation == Some(receipt.worker_generation)
                    && frame.native_source == Some(proof.kind)
                    && frame.lifecycle == super::WindowOperationLifecycle::Started
                    && frame.native_state == Some(crate::Win16NativeWindowOperationState::Active)
            }).count();
            let wave_owner = self.owns_terminal_wave_post_source(
                &crate::Win16WindowTerminalSourceTop::User {
                    operation: proof.operation_id,
                    kind: proof.kind,
                    state: crate::Win16NativeWindowOperationState::Active,
                    worker_generation: receipt.worker_generation,
                },
            )?;
            if window_owners + usize::from(wave_owner) != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native active operation proof has no unique exact USER-frame or WAVE source owner"));
            }
        }
        for frame in &self.window_operations {
            let active_count = receipt.active_operations.iter().filter(|proof|
                Some(proof.operation_id) == frame.host_operation
            ).count();
            if let Some(WindowReturn::Dde(continuation)) = frame.continuation() {
                if frame.lifecycle != super::WindowOperationLifecycle::BeginPending
                    || frame.native_source != Some(crate::Win16NativeWindowOperationKind::Dde)
                    || frame.host_operation.is_some()
                    || frame.worker_generation.is_some()
                    || frame.native_state.is_some()
                    || active_count != 0
                    || continuation.host_operation().is_some_and(|operation| operation.0 == 0)
                {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "DDE window frame has a forged USER identity or does not retain its separate DDE owner"));
                }
                continue;
            }
            match frame.lifecycle {
                super::WindowOperationLifecycle::GuestOnly => {
                    if frame.host_operation.is_some() || frame.worker_generation.is_some()
                        || active_count != 0 || frame.native_source.is_some()
                        || frame.terminal_started_failure.is_some()
                    {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "guest-only USER frame acquired a native operation identity"));
                    }
                }
                super::WindowOperationLifecycle::NeverStarted => {
                    if frame.host_operation.is_some() || frame.worker_generation.is_some()
                        || frame.terminal_error.is_none() || active_count != 0
                        || frame.terminal_started_failure.is_some()
                    {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "never-started USER frame lost its exact begin failure state"));
                    }
                }
                super::WindowOperationLifecycle::Started => {
                    let modal_count = receipt.cancelled_modals.iter().filter(|modal|
                        Some(crate::Win16HostWindowOperationId(modal.operation_id))
                            == frame.host_operation
                    ).count();
                    let modal_stop = modal_count == 1
                        && active_count == 0
                        && frame.terminal_started_failure.is_none()
                        && frame.native_state == Some(crate::Win16NativeWindowOperationState::Active);
                    if frame.host_operation.is_none()
                        || frame.worker_generation != Some(receipt.worker_generation)
                        || frame.native_source.is_none()
                        || frame.native_state != Some(crate::Win16NativeWindowOperationState::Active)
                        || !(active_count == 1 && modal_count == 0 || modal_stop)
                        || frame.terminal_started_failure.as_ref().is_some_and(|failure| {
                            Some(failure.operation.operation_id) != frame.host_operation
                                || Some(failure.operation.kind) != frame.native_source
                                || Some(failure.worker_generation) != frame.worker_generation
                                || failure.state != crate::Win16NativeWindowOperationState::Active
                                || frame.terminal_error.as_ref().is_none_or(|cause|
                                    !std::sync::Arc::ptr_eq(cause, &failure.cause))
                        })
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "started USER frame lacks its exact active native operation proof"));
                    }
                }
                super::WindowOperationLifecycle::TerminalModalCancelled => {
                    let mut modals = receipt.cancelled_modals.iter().filter(|modal|
                        Some(crate::Win16HostWindowOperationId(modal.operation_id))
                            == frame.host_operation
                    );
                    let modal = modals.next();
                    if frame.host_operation.is_none()
                        || frame.worker_generation != Some(receipt.worker_generation)
                        || frame.native_source.is_none()
                        || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
                        || active_count != 0
                        || frame.terminal_error.is_none()
                        || modals.next().is_some()
                        || modal.is_none_or(|modal| {
                            frame.terminal_modal_error.as_ref().is_none_or(|error|
                                !super::modal_error_matches(error, modal))
                                || frame.terminal_started_failure.is_some()
                                || frame.terminal_modal_responses.iter().any(|saved|
                                    saved != modal)
                        })
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "modal USER frame lacks its exact retained native cancellation result"));
                    }
                }
                super::WindowOperationLifecycle::ReturnedWithError => {
                    if frame.host_operation.is_none()
                        || frame.worker_generation != Some(receipt.worker_generation)
                        || frame.native_source.is_none()
                        || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
                        || frame.terminal_error.is_none()
                        || frame.terminal_started_failure.as_ref().is_none_or(|failure| {
                            Some(failure.operation.operation_id) != frame.host_operation
                                || Some(failure.operation.kind) != frame.native_source
                                || Some(failure.worker_generation) != frame.worker_generation
                                || failure.state != crate::Win16NativeWindowOperationState::Returned
                                || frame.terminal_error.as_ref().is_none_or(|cause|
                                    !std::sync::Arc::ptr_eq(cause, &failure.cause))
                        })
                        || active_count != 0
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "returned USER error frame lacks its exact retained host error proof"));
                    }
                }
                super::WindowOperationLifecycle::Returned => {
                    let proof = frame.source_retired.as_ref();
                    if frame.host_operation.is_none()
                        || frame.worker_generation != Some(receipt.worker_generation)
                        || frame.native_source.is_none()
                        || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
                        || proof.is_none_or(|proof| {
                            Some(proof.operation.operation_id) != frame.host_operation
                                || Some(proof.operation.kind) != frame.native_source
                                || Some(proof.worker_generation) != frame.worker_generation
                                || proof.state != crate::Win16NativeWindowOperationState::Returned
                        })
                        || frame.terminal_started_failure.is_some()
                        || active_count != 0
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "normally returned USER frame lacks its exact source-retirement proof"));
                    }
                }
                super::WindowOperationLifecycle::BeginPending => {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "Win16 USER teardown found a begin boundary without a real outcome"));
                }
            }
            if frame.host_operation.is_some_and(|operation| operation.0 == 0)
                || frame.worker_generation.is_some_and(|generation| generation == 0)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER frame contains a zero native identity"));
            }
        }

        for (index, cancellation) in receipt.cancelled_callbacks.iter().enumerate() {
            if cancellation.callback.0 == 0
                || cancellation.operation_id.0 == 0
                || receipt.cancelled_callbacks[..index].iter().any(|prior|
                    prior.callback == cancellation.callback)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicates or zeroes a callback source"));
            }
            let operation_count = self.window_operations.iter().filter(|frame|
                frame.host_operation == Some(cancellation.operation_id)
                    && frame.worker_generation == Some(receipt.worker_generation)
            ).count();
            if operation_count != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "cancelled callback has no exact runtime operation and worker generation"));
            }
            let window_matches = self.window_callbacks.iter().filter(|frame|
                frame.host_operation == Some(cancellation.operation_id)
                    && frame.native_source == Some(cancellation.source)
                    && window_callback_host_token(frame.continuation)
                        == Some(cancellation.callback)
            ).count();
            let function_matches = self.native_function_callbacks.iter().filter(|frame|
                self.terminal_native_function_callback_identity(frame.callback_id)
                    == Some((cancellation.callback, cancellation.operation_id, cancellation.source))
            ).count();
            let runtime_candidates = self.window_callbacks.iter().filter(|frame|
                frame.host_operation == Some(cancellation.operation_id)
                    || window_callback_host_token(frame.continuation)
                        == Some(cancellation.callback)
            ).count() + self.native_function_callbacks.iter().filter(|frame|
                self.terminal_native_function_callback_identity(frame.callback_id)
                    .is_some_and(|(callback, operation, _)|
                        operation == cancellation.operation_id || callback == cancellation.callback)
            ).count();
            let mut retired_proof_count = 0usize;
            let mut retired_proof_valid = true;
            for frame in self.window_operations.iter().filter(|frame| {
                frame.host_operation == Some(cancellation.operation_id)
                    && frame.worker_generation == Some(receipt.worker_generation)
            }) {
                for proof in &frame.terminal_retired_callbacks {
                    if proof.cancellation.callback == cancellation.callback {
                        retired_proof_count += 1;
                        let owner_phase_matches = self.window_operations.iter().filter(|owner| {
                            owner.host_operation == Some(cancellation.operation_id)
                                && owner.worker_generation == Some(receipt.worker_generation)
                        }).all(|owner| {
                            proof.owner_context_restored == owner.terminal_context_restored
                                && proof.native_source_acknowledged
                                    == owner.terminal_source_acknowledged
                        });
                        retired_proof_valid &= proof.callback_frame_id.0 != 0
                            && proof.cancellation == *cancellation
                            && proof.runtime_frame_retired == (runtime_candidates == 0)
                            && (runtime_candidates != 0 || proof.guest_payload_cleaned)
                            && owner_phase_matches;
                    }
                }
            }
            if window_matches + function_matches > 1
                || retired_proof_count > 1
                || (runtime_candidates != 0 && window_matches + function_matches != 1)
                || (runtime_candidates == 0 && retired_proof_count != 1)
                || !retired_proof_valid
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native callback cancellation differs from its exact runtime callback source"));
            }
        }
        for frame in &self.window_callbacks {
            let Some(callback) = window_callback_host_token(frame.continuation) else {
                if frame.host_operation.is_some() || frame.native_source.is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "guest-only callback unexpectedly retained a native source"));
                }
                continue;
            };
            let (Some(operation), Some(source)) = (frame.host_operation, frame.native_source) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native USER callback lost its operation or producer source"));
            };
            if receipt.cancelled_callbacks.iter().filter(|item|
                item.callback == callback && item.operation_id == operation && item.source == source
            ).count() != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native callback frame lacks its exact abort cancellation receipt"));
            }
        }
        for frame in &self.native_function_callbacks {
            let Some((callback, operation, source)) =
                self.terminal_native_function_callback_identity(frame.callback_id)
            else { continue; };
            if receipt.cancelled_callbacks.iter().filter(|item|
                item.callback == callback && item.operation_id == operation && item.source == source
            ).count() != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native property callback frame lacks its exact abort receipt"));
            }
        }
        for (index, cancellation) in receipt.cancelled_modals.iter().enumerate() {
            if cancellation.operation_id == 0
                || receipt.cancelled_modals[..index].iter().any(|prior|
                    prior.operation_id == cancellation.operation_id)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicates or zeroes a modal operation source"));
            }
            let index = self.modal_operation_index(cancellation.operation_id)?;
            let frame = &self.window_operations[index];
            if frame.host_modal_operation.is_some_and(|operation|
                Some(operation) != frame.host_operation)
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native modal slot does not match the exact runtime operation binding"));
            }
            let expected_work = frame.pending_modal_work.as_ref()
                .map(|work| work.terminal_retirement()).transpose()?.flatten();
            match expected_work {
                Some(work) if cancellation.retired_guest_work.as_slice() == [work]
                    && cancellation.scope_id == Some(work.scope_id) => {}
                None if cancellation.retired_guest_work.is_empty() => {}
                _ => return Err(RuntimeError::new(Kind::HostFailure,
                    "native modal receipt does not match its exact retained guest-work history")),
            }
        }
        Ok(())
    }

}

fn remember_window_cleanup_failure(
    failures: &mut Option<RuntimeError>,
    error: RuntimeError,
) {
    *failures = Some(match failures.take() {
        Some(primary) => primary.with_cleanup(
            "multiple Win16 window shutdown cleanup steps failed",
            error,
        ),
        None => error,
    });
}
