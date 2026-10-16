//! Exact owner-bound progression of native USER and DDE window steps.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn advance_window_operation(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        host: &mut impl RuntimeHost, step: Win16WindowStep,
    ) -> Result<(), RuntimeError> {
        let entry_frame_id = self.window_operations.last().map(|frame| frame.id);
        match self.advance_window_operation_inner(registers, memory, host, step) {
            Err(error) => {
                let kind = error.kind();
                let cause = Arc::new(error);
                if let Some(frame) = self.window_operations.last_mut()
                    .filter(|frame| Some(frame.id) == entry_frame_id)
                {
                    if frame.terminal_error.is_none() {
                        frame.terminal_error = Some(Arc::clone(&cause));
                    }
                    if let Some(completion) = frame.completion.as_mut()
                        && completion.journal.first_cause.is_none()
                    {
                        completion.journal.first_cause = Some(Arc::clone(&cause));
                    }
                }
                Err(RuntimeError::with_source(kind,
                    "Win16 operation progression failed with its owner retained", cause))
            }
            Ok(()) => Ok(()),
        }
    }

    fn advance_window_operation_inner(
        &mut self, registers: &mut Registers, memory: &mut Memory,
        host: &mut impl RuntimeHost, mut step: Win16WindowStep,
    ) -> Result<(), RuntimeError> {
        loop {
            step = match step {
                Win16WindowStep::Started {
                    operation_id,
                    worker_generation,
                    kind,
                    step: started,
                } => {
                    self.bind_started_window_operation(operation_id, worker_generation, kind)?;
                    *started
                }
                Win16WindowStep::StartedFailure(failure) => {
                    self.record_started_window_operation_failure(std::sync::Arc::clone(&failure))?;
                    return Err(RuntimeError::with_source(
                        failure.cause.kind(),
                        "native Win16 USER operation returned a host failure",
                        std::sync::Arc::clone(&failure.cause),
                    ));
                }
                Win16WindowStep::DdeStartedFailure(failure) => {
                    let top = self.window_operations.last_mut().ok_or_else(|| {
                        RuntimeError::new(Kind::InternalInvariant,
                            "accepted DDE failure has no exact retained runtime frame")
                    })?;
                    let Some(WindowReturn::Dde(continuation)) = top.continuation_mut() else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "accepted DDE failure does not match the top DDE continuation"));
                    };
                    continuation.bind_host_operation_identity(
                        failure.operation,
                        failure.owner,
                        failure.worker_generation,
                    )?;
                    continuation.bind_started_failure(std::sync::Arc::clone(&failure))?;
                    return Err(RuntimeError::with_source(
                        failure.cause.kind(),
                        "native Win16 DDE operation returned a host failure",
                        std::sync::Arc::clone(&failure.cause),
                    ));
                }
                Win16WindowStep::SourceRetired { proof, result } => {
                    let Win16WindowStep::Complete(result) = *result else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "normal USER source-retired carrier does not contain one Complete result"));
                    };
                    return self.retain_normal_window_completion(
                        std::sync::Arc::clone(&proof), result, host,
                    );
                }
                Win16WindowStep::DdeSourceRetired { proof, result } => {
                    let Win16WindowStep::Complete(Win16WindowResult::Dde(result)) = *result else {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "DDE source-retired carrier does not contain one DDE completion"));
                    };
                    return self.retain_dde_window_completion(proof, result);
                }
                step => step,
            };
            match step {
                carrier @ (Win16WindowStep::Started { .. }
                    | Win16WindowStep::StartedFailure(_)
                    | Win16WindowStep::DdeStartedFailure(_)
                    | Win16WindowStep::SourceRetired { .. }
                    | Win16WindowStep::DdeSourceRetired { .. }) => {
                    // A Started carrier may wrap a terminal source carrier.
                    // Process each owned layer through the identity checks at
                    // the top of the loop before handling the inner result.
                    step = carrier;
                    continue;
                }
                Win16WindowStep::NativeDropRetired(receipt) => {
                    let source_is_live = self.window_operations.last().is_some_and(|frame|
                        frame.host_operation.is_some()
                            && frame.native_state
                                == Some(crate::Win16NativeWindowOperationState::Active)
                            && frame.completion.is_none()
                            && frame.pending_work.is_none()
                            && frame.pending_modal_work.is_none());
                    if !source_is_live {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "native WM_DROPFILES retirement crossed a non-active USER source"));
                    }
                    self.retire_queued_drop_file_lease(receipt)?;
                    // Receipt transport ACK is independent of the callback
                    // or USER operation source. Only after exact lease cleanup
                    // and ACK may the host read the next response from this
                    // same pending operation; resume(None) would forge a
                    // callback/source acknowledgement here.
                    host.win16_ack_native_drop_retirement(receipt)?;
                    step = host.win16_window_receive_pending()?;
                }
                Win16WindowStep::DdeCallback(callback_step) => {
                    let top = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "native DDE callback has no suspended runtime window operation"))?;
                    let operation_id = top.id;
                    let origin = match callback_step.parent {
                        Some(parent) => {
                            let Some(WindowReturn::Dde(continuation)) = top.continuation_mut() else {
                                return Err(RuntimeError::new(Kind::InternalInvariant,
                                    "foreground DDE callback has no DDE window continuation"));
                            };
                            continuation.bind_host_operation_identity(
                                parent,
                                callback_step.owner,
                                callback_step.worker_generation,
                            )?;
                            Win16DdeCallbackOrigin::Foreground(parent)
                        }
                        None => Win16DdeCallbackOrigin::WindowWait { operation: operation_id },
                    };
                    if top.pending_dde_callback.is_some() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "native DDE callback reached an already retained dispatch owner"));
                    }
                    // This marshalling seam only borrows registers. Keep the
                    // real native carrier until the full CPU/DOS safe point
                    // can publish and enter its checked callback frame.
                    top.pending_dde_callback = Some((origin, callback_step));
                    return Ok(());
                }
                Win16WindowStep::Diagnostic(diagnostic) => {
                    host.report_diagnostic(&diagnostic);
                    step = host.win16_window_resume(None)?;
                }
                Win16WindowStep::PendingGuestWork { operation_id, generation } => {
                    self.park_window_guest_work(operation_id, generation)?;
                    return Ok(());
                }
                Win16WindowStep::PendingModalGuestWork {
                    operation_id,
                    scope_id,
                    generation,
                    marker_id,
                    wake_generation,
                    failure,
                } => {
                    self.park_modal_guest_work(
                        operation_id,
                        scope_id,
                        generation,
                        marker_id,
                        wake_generation,
                        failure,
                    )?;
                    return Ok(());
                }
                Win16WindowStep::Untranslated { message } => {
                    if self.untranslated_window_messages.insert(message) {
                        host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                            format!("native window message 0x{message:04X} has no Win16 conversion; Windows default processing was used")));
                    }
                    step = host.win16_window_resume(None)?;
                }
                Win16WindowStep::Callback {
                    operation_id, callback, creation, creation_data: retained_creation_data,
                    window: native, class, message, source,
                } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    if matches!(&message, Win16HostMessage::FindReplaceNotification(notification)
                        if !self.common_dialog_notification_is_live(memory, notification)?) {
                        step = host.win16_window_resume(Some(Win16WindowReply {
                            callback, result: crate::Win16HostMessageResult { dialog_result: None,
                                value: 0, output: crate::Win16HostMessageOutput::None },
                        }))?;
                        continue;
                    }
                    let notification_alias = match &message {
                        Win16HostMessage::GuestNotification(notification) => match notification.target {
                            crate::Win16GuestNotificationTarget::Window { window, guest_hwnd }
                                if window == native
                                    && self.window_handles.get(&guest_hwnd) == Some(&native) =>
                                        Some(guest_hwnd),
                            _ => {
                                step = host.win16_window_resume(Some(Win16WindowReply {
                                    callback, result: crate::Win16HostMessageResult {
                                        dialog_result: None, value: 0,
                                        output: crate::Win16HostMessageOutput::None,
                                    },
                                }))?;
                                continue;
                            }
                        },
                        _ => None,
                    };
                    let creation_data = match &message {
                        Win16HostMessage::Creation { data, .. } => Some(data),
                        _ => retained_creation_data.as_ref(),
                    };
                    let mdi_child_creation = match &message {
                        Win16HostMessage::MdiChildCreation { data, .. } => Some(data),
                        _ => None,
                    };
                    let (window, procedure) = self.callback_window(
                        native, class, creation, creation_data, mdi_child_creation,
                    )?;
                    if notification_alias.is_some_and(|alias| alias != window) {
                        step = host.win16_window_resume(Some(Win16WindowReply {
                            callback, result: crate::Win16HostMessageResult {
                                dialog_result: None, value: 0,
                                output: crate::Win16HostMessageOutput::None,
                            },
                        }))?;
                        continue;
                    }
                    let creation = self.window_operations.iter().rev().find_map(|frame| {
                        match frame.continuation() {
                            Some(WindowReturn::Create { request, window: Some(found), .. })
                                if *found == window => Some(request.clone()),
                            _ => None,
                        }
                    });
                    let destroyed = matches!(&message, Win16HostMessage::Scalar {
                        kind: Win16ScalarMessage::NcDestroy, ..
                    });
                    self.begin_host_window_callback(
                        registers, memory, host, operation_id, callback, native,
                        window, procedure, message, creation.as_ref(), source, destroyed,
                    )?;
                    return Ok(());
                }
                Win16WindowStep::NativeSubclassCallback {
                    operation_id, callback, window: native, message, source,
                } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    let (window, address, instance, root) =
                        self.native_subclass_callback_owner(native)?;
                    let destroyed = matches!(&message, Win16HostMessage::Scalar {
                        kind: Win16ScalarMessage::NcDestroy, ..
                    });
                    self.begin_host_procedure_callback(
                        registers, memory, host, operation_id, callback, native,
                        window, address, instance, root, message, None, source, destroyed,
                    )?;
                    return Ok(());
                }
                Win16WindowStep::DialogCallback {
                    operation_id, callback, window: native, message, source,
                } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    if matches!(&message, Win16HostDialogMessage::Message(
                        Win16HostMessage::FindReplaceNotification(notification))
                        if !self.common_dialog_notification_is_live(memory, notification)?) {
                        step = host.win16_window_resume(Some(Win16WindowReply {
                            callback, result: crate::Win16HostMessageResult { dialog_result: None,
                                value: 0, output: crate::Win16HostMessageOutput::None },
                        }))?;
                        continue;
                    }
                    if self.begin_dialog_callback(
                        registers, memory, host, operation_id, callback, native, message, source,
                    )? {
                        return Ok(());
                    }
                    let reply = Win16WindowReply {
                        callback,
                        result: crate::Win16HostMessageResult { dialog_result: None,
                            value: 0,
                            output: crate::Win16HostMessageOutput::None,
                        },
                    };
                    let default_owner = self.window_callbacks.last().filter(|frame| {
                        frame.host_operation == Some(operation_id)
                            && frame.callback_address == 0
                            && matches!(frame.continuation,
                                WindowCallbackContinuation::HostDialog { callback: owned, .. }
                                    if owned == callback)
                    }).map(|frame| frame.callback_id);
                    step = if let Some(callback_id) = default_owner {
                        // No guest code ran, so don't fabricate a FAR return.
                        // Keep this source on resume failure just like WndProc.
                        let next = self.resume_native_window_callback(reply, host)?;
                        self.retire_window_callback_frame(callback_id)?;
                        next
                    } else {
                        host.win16_window_resume(Some(reply))?
                    };
                }
                Win16WindowStep::Complete(result) => {
                    return self.complete_window_operation(registers, host, result);
                }
                Win16WindowStep::GuestTimerCallback {
                    operation_id, callback, window, host_timer_id, guest_w_param, guest_l_param,
                    time, source,
                } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    if self.begin_host_timer_callback(registers, memory, host, callback, window,
                        host_timer_id, guest_w_param, guest_l_param, time,
                        operation_id, source)? {
                        return Ok(());
                    }
                    step = host.win16_window_resume(Some(Win16WindowReply {
                        callback,
                        result: crate::Win16HostMessageResult { dialog_result: None, value: 0, output: crate::Win16HostMessageOutput::None },
                    }))?;
                }
                Win16WindowStep::WindowPropertyCallback {
                    operation_id, callback, window, name, data, source,
                } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    self.retain_window_property_callback(
                        registers, memory, host, callback, window, name, data, operation_id, source,
                    )?;
                    return Ok(());
                }
                Win16WindowStep::MetafileCallback { operation_id, callback, dc, record, object_count, source } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    self.retain_metafile_callback(registers, memory, host, callback, dc,
                        record, object_count, operation_id, source)?;
                    return Ok(());
                }
                Win16WindowStep::GrayStringCallback { operation_id, callback, dc, count, source } => {
                    self.validate_native_window_callback_owner(operation_id, callback, source)?;
                    if self.retain_gray_string_callback(registers, callback, dc, count,
                        operation_id, source)? {
                        return Ok(());
                    }
                    step = host.win16_window_resume(Some(Win16WindowReply {
                        callback,
                        result: crate::Win16HostMessageResult { dialog_result: None, value: 0,
                            output: crate::Win16HostMessageOutput::None },
                    }))?;
                }
            }
        }
    }

    fn retain_normal_window_completion(
        &mut self,
        proof: Arc<crate::Win16WindowSourceRetiredProof>,
        result: Win16WindowResult,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let frame_id = self.window_operations.last().map(|frame| frame.id)
            .ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "normal USER source retirement has no exact runtime operation frame",
            ))?;
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER source retirement has no exact runtime operation frame",
        ))?;
        let owner_phase_matches = match (
            frame.lifecycle,
            frame.native_state,
            frame.terminal_started_failure.as_ref(),
        ) {
            (WindowOperationLifecycle::Started,
                Some(crate::Win16NativeWindowOperationState::Active), None) => true,
            (WindowOperationLifecycle::ReturnedWithError,
                Some(crate::Win16NativeWindowOperationState::Returned), Some(failure)) => {
                    frame.host_operation == Some(failure.operation.operation_id)
                        && frame.native_source == Some(failure.operation.kind)
                        && frame.worker_generation == Some(failure.worker_generation)
                        && failure.state == crate::Win16NativeWindowOperationState::Returned
                }
            _ => false,
        };
        if matches!(&result, Win16WindowResult::Dde(_) | Win16WindowResult::NativeModalCancelled(_))
            || matches!(frame.continuation(), Some(WindowReturn::Dde(_)))
            || !owner_phase_matches
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "normal USER source proof was supplied for a DDE, modal, or mismatched owner phase"));
        }
        let operation = frame.host_operation.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER completion lost its real host operation identity",
        ))?;
        let kind = frame.native_source.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER completion lost its native API kind",
        ))?;
        let generation = frame.worker_generation.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER completion lost its worker generation",
        ))?;
        if proof.operation.operation_id != operation
            || proof.operation.kind != kind
            || proof.worker_generation != generation
            || proof.worker_generation == 0
            || proof.state != crate::Win16NativeWindowOperationState::Returned
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "normal USER source-retired proof differs from its exact runtime owner"));
        }
        if frame.source_retired.is_some() || frame.completion.is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "normal USER completion attempted to replace a retained host result or proof"));
        }

        // Store the host result and proof on the exact frame before any
        // projection or host readback can fail. Teardown can then retry or
        // retire this owner without re-executing the native operation.
        let continuation = frame.result.take().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER completion lost its original API continuation",
        ))?;
        let mut journal = WindowCompletionJournal::for_native_result(&continuation, &result);
        journal.first_cause = frame.terminal_started_failure.as_ref()
            .map(|failure| std::sync::Arc::clone(&failure.cause));
        frame.completion = Some(WindowOperationCompletion {
            continuation,
            result,
            journal,
            source: WindowOperationCompletionSource::NativeUser,
        });
        frame.source_retired = Some(std::sync::Arc::clone(&proof));
        frame.native_state = Some(crate::Win16NativeWindowOperationState::Returned);
        frame.lifecycle = WindowOperationLifecycle::Returned;

        let recorded = match host.win16_window_source_retirement(
            crate::Win16NativeWindowOperationProof {
                operation_id: operation,
                kind,
            },
            generation,
        ) {
            Ok(recorded) => recorded,
            Err(error) => return self.retain_window_completion_failure(frame_id, error),
        };
        match recorded {
            Some(recorded) if *recorded == *proof => Ok(()),
            Some(_) => self.retain_window_completion_failure(frame_id,
                RuntimeError::new(Kind::HostFailure,
                    "host normal source-retirement cache returned a different exact proof")),
            None => self.retain_window_completion_failure(frame_id,
                RuntimeError::new(Kind::HostFailure,
                    "host has not retired the exact USER source carried by its completion step")),
        }
    }

}
