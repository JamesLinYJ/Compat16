//! USER result journaling and normal source retirement.

use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindowOperationId, Win16WindowStep};

use super::operation_inputs::commit_update_region;
use super::win16_windows_dde::{PendingSource, SharedRuntimeFailure};
use super::{
    PendingGuestWorkContinuation, PendingModalGuestWorkContinuation, PendingUserCompletion,
    PendingUserCompletionPhase, Win16Objects, Win16Windows, worker_stopped,
};

impl Win16Windows {
    pub(super) fn receive_step_inner(
        &mut self,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let index = self.pending.len().checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window operation disappeared while waiting",
            )
        })?;
        let id = self.pending[index].id;
        self.require_source(
            PendingSource::User { id },
            "USER response wait does not match the top pending source",
        )?;
        if self.pending[index].completion.is_some() {
            return self.finish_cached_user_completion(index, objects);
        }
        let mut step = loop {
            if let Some(receipt) = self.take_native_drop_retirement() {
                break Win16WindowStep::NativeDropRetired(receipt);
            }
            let received = self.pending[index]
                .response
                .recv_timeout(Duration::from_millis(10));
            match received {
                Ok(Ok(step)) => break step,
                Ok(Err(error)) => {
                    let shared = Arc::new(error);
                    let error_kind = shared.kind();
                    {
                        let pending = self.pending.get_mut(index).ok_or_else(|| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "returned USER error lost its pending operation owner",
                            )
                        })?;
                        if pending.native_state != runtime::Win16NativeWindowOperationState::Active
                            || pending.response_error.is_some()
                        {
                            return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "USER worker returned a duplicate or conflicting error response",
                            ));
                        }
                        // A concrete response-channel Err proves the USER
                        // operation returned. It does not prove callback or
                        // modal-source retirement, so those owners stay live
                        // for the exact abort receipt and terminal ACK.
                        pending.native_state = runtime::Win16NativeWindowOperationState::Returned;
                        pending.response_error = Some(Arc::clone(&shared));
                    }
                    return Err(RuntimeError::with_source(
                        error_kind,
                        "native Win16 USER operation returned an error response",
                        SharedRuntimeFailure::new(shared),
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(worker_stopped("receive Win16 native window step"));
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(callback) = self.poll_dde_callback_inner()? {
                        return Ok(Win16WindowStep::DdeCallback(callback));
                    }
                }
            }
        };
        if matches!(&step, Win16WindowStep::Complete(_)) {
            let pending = self.pending.get_mut(index).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "returned USER completion lost its exact pending operation",
                )
            })?;
            if pending.completion.is_some()
                || pending.native_state != runtime::Win16NativeWindowOperationState::Active
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER worker returned a duplicate or conflicting Complete step",
                ));
            }
            pending.awaiting_source = None;
            pending.native_state = runtime::Win16NativeWindowOperationState::Returned;
            let modal_work_retirement = pending.resumed_modal_work.take();
            pending.completion = Some(PendingUserCompletion {
                step,
                phase: PendingUserCompletionPhase::ResultReceived,
                source_proof: None,
                modal_work_retirement,
                first_cause: None,
            });
            return self.finish_cached_user_completion(index, objects);
        }
        if !matches!(&step, Win16WindowStep::NativeDropRetired(_)) {
            self.pending[index].awaiting_source = None;
        }
        match &mut step {
            Win16WindowStep::Callback {
                operation_id,
                callback,
                source,
                ..
            }
            | Win16WindowStep::DialogCallback {
                operation_id,
                callback,
                source,
                ..
            }
            | Win16WindowStep::WindowPropertyCallback {
                operation_id,
                callback,
                source,
                ..
            }
            | Win16WindowStep::GuestTimerCallback {
                operation_id,
                callback,
                source,
                ..
            } => {
                if operation_id.0 != id || callback.0 == 0 {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "native USER callback source changed its exact operation identity",
                    ));
                }
                self.pending[index].awaiting = Some(*callback);
                self.pending[index].awaiting_source =
                    Some(runtime::Win16NativeCallbackCancellation {
                        callback: *callback,
                        operation_id: *operation_id,
                        source: *source,
                    });
            }
            Win16WindowStep::Untranslated { .. } | Win16WindowStep::Diagnostic(_) => {
                self.pending[index].awaiting = None;
            }
            Win16WindowStep::NativeDropRetired(_) => {}
            Win16WindowStep::DdeCallback(_) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback was incorrectly routed through the USER worker",
                ));
            }
            Win16WindowStep::PendingGuestWork {
                operation_id,
                generation,
            } => {
                if *operation_id != Win16HostWindowOperationId(id)
                    || *generation <= self.pending[index].last_guest_work_generation
                    || self.pending[index].awaiting.is_some()
                    || self.pending[index].pending_guest_work.is_some()
                    || self.pending[index].wait_kind.is_none()
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "pending guest work does not match the exact suspended USER wait",
                    ));
                }
                let kind = self.pending[index].wait_kind.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "pending guest work has no USER wait kind",
                    )
                })?;
                self.pending[index].pending_guest_work = Some(PendingGuestWorkContinuation {
                    operation_id: *operation_id,
                    generation: *generation,
                    kind,
                });
            }
            Win16WindowStep::PendingModalGuestWork {
                operation_id,
                scope_id,
                generation,
                marker_id,
                wake_generation,
                failure,
            } => {
                if *operation_id != Win16HostWindowOperationId(id)
                    || *scope_id == 0
                    || *generation <= self.pending[index].last_modal_guest_work_generation
                    || self.pending[index].awaiting.is_some()
                    || self.pending[index].pending_guest_work.is_some()
                    || self.pending[index].pending_modal_guest_work.is_some()
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "pending modal guest work does not match the exact suspended USER operation",
                    ));
                }
                match (*marker_id, *wake_generation) {
                    (Some(marker_id), Some(wake_generation))
                        if marker_id != 0 && wake_generation != 0 =>
                    {
                        self.pending[index]
                            .modal_work_history
                            .try_reserve(1)
                            .map_err(|error| {
                                RuntimeError::with_source(
                                    Kind::ResourceExhausted,
                                    "retain exact native modal guest-work source identity",
                                    error,
                                )
                            })?;
                        self.pending[index].modal_work_history.push(
                            runtime::Win16NativeModalGuestWorkRetirement {
                                operation_id: *operation_id,
                                scope_id: *scope_id,
                                generation: *generation,
                                marker_id,
                                wake_generation,
                            },
                        );
                    }
                    (None, Some(wake_generation)) if failure.is_some() && wake_generation != 0 => {}
                    (None, None) if failure.is_some() => {}
                    _ => {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "native modal guest-work source has incomplete identity fields",
                        ));
                    }
                }
                self.pending[index].last_modal_guest_work_generation = *generation;
                self.pending[index].pending_modal_guest_work =
                    Some(PendingModalGuestWorkContinuation {
                        operation_id: *operation_id,
                        scope_id: *scope_id,
                        generation: *generation,
                        marker_id: *marker_id,
                        wake_generation: *wake_generation,
                    });
            }
            Win16WindowStep::Complete(_) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER Complete bypassed its retained completion owner",
                ));
            }
            Win16WindowStep::Started { .. }
            | Win16WindowStep::StartedFailure(_)
            | Win16WindowStep::DdeStartedFailure(_)
            | Win16WindowStep::SourceRetired { .. }
            | Win16WindowStep::DdeSourceRetired { .. } => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 worker response contained a host-only started-operation or retirement wrapper",
                ));
            }
        }
        Ok(step)
    }

    fn finish_cached_user_completion(
        &mut self,
        index: usize,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let result = self.finish_cached_user_completion_inner(index, objects);
        match result {
            Ok(step) => Ok(step),
            Err(error) => {
                let shared = Arc::new(error);
                if let Some(completion) = self
                    .pending
                    .get_mut(index)
                    .and_then(|pending| pending.completion.as_mut())
                    && completion.first_cause.is_none()
                {
                    completion.first_cause = Some(Arc::clone(&shared));
                }
                let kind = shared.kind();
                Err(RuntimeError::with_source(
                    kind,
                    "normal USER completion remains retained after a source-retirement failure",
                    SharedRuntimeFailure::new(shared),
                ))
            }
        }
    }

    fn finish_cached_user_completion_inner(
        &mut self,
        index: usize,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let (id, kind, worker_generation) = {
            let pending = self.pending.get(index).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER completion lost its pending owner",
                )
            })?;
            (pending.id, pending.kind, pending.worker_generation)
        };
        if id == 0 || worker_generation == 0 {
            return self.retain_cached_user_completion_error(
                index,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "normal USER completion has a zero operation or worker identity",
                ),
            );
        }
        self.validate_cached_user_completion_top(index, id)?;

        let phase = self.pending[index]
            .completion
            .as_ref()
            .map(|completion| completion.phase)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER result disappeared before its completion phase",
                )
            })?;
        if !self.pending[index]
            .completion
            .as_ref()
            .is_some_and(|completion| matches!(&completion.step, Win16WindowStep::Complete(_)))
        {
            return self.retain_cached_user_completion_error(
                index,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER completion changed from Complete before retirement",
                ),
            );
        }
        self.project_control_color_completion(index, objects)?;
        if phase == PendingUserCompletionPhase::ResultReceived {
            let preflight = (|| -> Result<Option<usize>, RuntimeError> {
                let pending = self.pending.get(index).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER completion lost its operation before modal-source retirement",
                    )
                })?;
                let completion = pending.completion.as_ref().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER completion disappeared before modal-source retirement",
                    )
                })?;
                if pending.pending_modal_guest_work.is_some()
                    || pending.resumed_modal_work.is_some()
                {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "cached USER completion still has a live modal guest-work continuation",
                    ));
                }
                match completion.modal_work_retirement {
                    Some(retirement) => {
                        if pending
                            .modal_work_history
                            .iter()
                            .filter(|item| **item == retirement)
                            .count()
                            != 1
                        {
                            return Err(RuntimeError::new(
                                Kind::HostFailure,
                                "cached USER completion does not own one exact resumed modal source",
                            ));
                        }
                        pending
                            .modal_work_history
                            .iter()
                            .position(|item| *item == retirement)
                            .map(Some)
                            .ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "cached USER completion lost its exact modal history item",
                                )
                            })
                    }
                    None if pending.modal_work_history.is_empty() => Ok(None),
                    None => Err(RuntimeError::new(
                        Kind::HostFailure,
                        "cached USER completion has unretired modal guest-work identities",
                    )),
                }
            })();
            let modal_position = match preflight {
                Ok(position) => position,
                Err(error) => return self.retain_cached_user_completion_error(index, error),
            };
            // Preflight above proves every identity and required slot. Both
            // mutations below are infallible and form one host-side journal
            // commit before source proof preparation.
            let pending = self.pending.get_mut(index).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "preflighted USER completion owner disappeared before modal commit",
                )
            })?;
            let completion = pending.completion.as_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "preflighted USER completion disappeared before modal commit",
                )
            })?;
            completion.phase = PendingUserCompletionPhase::ModalWorkRetired;
            if let Some(position) = modal_position {
                pending.modal_work_history.remove(position);
            }
        }

        let phase = self.pending[index]
            .completion
            .as_ref()
            .map(|completion| completion.phase)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER completion disappeared before output commit",
                )
            })?;
        if phase == PendingUserCompletionPhase::ModalWorkRetired {
            let commit = {
                let pending = self.pending.get_mut(index).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER result disappeared before region output commit",
                    )
                })?;
                let completion = pending.completion.as_mut().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER result disappeared before region output commit",
                    )
                })?;
                match pending.region_output.as_ref() {
                    Some((token, region)) => match &mut completion.step {
                        Win16WindowStep::Complete(result) => {
                            commit_update_region(objects, *token, region, result)
                        }
                        _ => Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "cached USER result changed from Complete before output commit",
                        )),
                    },
                    None => Ok(()),
                }
            };
            if let Err(error) = commit {
                return self.retain_cached_user_completion_error(index, error);
            }
            self.pending[index]
                .completion
                .as_mut()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER result disappeared after output commit",
                    )
                })?
                .phase = PendingUserCompletionPhase::OutputCommitted;
        }

        let proof = {
            if self.pending[index]
                .completion
                .as_ref()
                .is_some_and(|completion| {
                    matches!(
                        completion.phase,
                        PendingUserCompletionPhase::OutputCommitted
                            | PendingUserCompletionPhase::SourceProofPrepared
                    )
                })
                && (self.pending[index].pending_modal_guest_work.is_some()
                    || self.pending[index].resumed_modal_work.is_some()
                    || !self.pending[index].modal_work_history.is_empty())
            {
                return self.retain_cached_user_completion_error(
                    index,
                    RuntimeError::new(
                        Kind::HostFailure,
                        "USER source proof preparation found live modal guest-work ownership",
                    ),
                );
            }
            let completion = self.pending[index].completion.as_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER result disappeared before proof preparation",
                )
            })?;
            if completion.phase == PendingUserCompletionPhase::OutputCommitted {
                let proof = Arc::new(runtime::Win16WindowSourceRetiredProof {
                    operation: runtime::Win16NativeWindowOperationProof {
                        operation_id: Win16HostWindowOperationId(id),
                        kind,
                    },
                    worker_generation,
                    state: runtime::Win16NativeWindowOperationState::Returned,
                });
                completion.source_proof = Some(Arc::clone(&proof));
                completion.phase = PendingUserCompletionPhase::SourceProofPrepared;
            }
            completion
                .source_proof
                .as_ref()
                .map(Arc::clone)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached USER completion proof phase has no exact proof",
                    )
                })?
        };
        if proof.operation.operation_id.0 != id
            || proof.operation.kind != kind
            || proof.worker_generation != worker_generation
            || proof.state != runtime::Win16NativeWindowOperationState::Returned
        {
            return self.retain_cached_user_completion_error(
                index,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "cached USER completion proof changed its operation identity",
                ),
            );
        }
        self.validate_cached_user_completion_top(index, id)?;

        let mut cached: Option<Arc<runtime::Win16WindowSourceRetiredProof>> = None;
        let mut duplicate = false;
        for candidate in &self.source_retirements {
            if candidate.operation.operation_id == proof.operation.operation_id {
                if cached.is_some() {
                    duplicate = true;
                } else {
                    cached = Some(Arc::clone(candidate));
                }
            }
        }
        if duplicate
            || cached
                .as_ref()
                .is_some_and(|cached| cached.as_ref() != proof.as_ref())
        {
            return self.retain_cached_user_completion_error(
                index,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "normal USER source tombstone conflicts with its retained completion proof",
                ),
            );
        }
        if cached.is_none() {
            if let Err(error) = self.source_retirements.try_reserve(1) {
                return self.retain_cached_user_completion_error(
                    index,
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve normal USER source-retirement proof before source pop",
                        error,
                    ),
                );
            }
        }

        // Everything that may fail has completed. The existing source proof
        // owns the retired identity before the exact paired LIFO pop.
        let completion = self.pending[index].completion.take().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "cached USER completion disappeared before its final source pop",
            )
        })?;
        if cached.is_none() {
            self.source_retirements.push(Arc::clone(&proof));
        }
        self.dde_sources.pending.pop();
        self.pending.pop();
        Ok(Win16WindowStep::SourceRetired {
            proof,
            result: Box::new(completion.step),
        })
    }

    fn project_control_color_completion(
        &mut self,
        index: usize,
        objects: &mut Win16Objects,
    ) -> Result<(), RuntimeError> {
        let slot = self
            .pending
            .get(index)
            .and_then(|pending| pending.control_color_return.clone());
        let Some(slot) = slot else {
            return Ok(());
        };
        #[derive(Clone, Copy)]
        enum Target {
            Missing,
            Empty,
            Ready(runtime::Win16HostControlColorBrush),
        }
        let target = {
            let step = &self.pending[index]
                .completion
                .as_ref()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "control-color result lost its retained USER completion",
                    )
                })?
                .step;
            let message_result = match step {
                Win16WindowStep::Complete(runtime::Win16WindowResult::Message(Some(result))) => {
                    Some(result)
                }
                Win16WindowStep::Complete(runtime::Win16WindowResult::UserService(
                    runtime::Win16HostUserServiceResult::Dialog(
                        runtime::Win16HostDialogResult::DefaultResult(Some(result)),
                    ),
                )) => Some(result),
                Win16WindowStep::Complete(runtime::Win16WindowResult::Message(None))
                | Win16WindowStep::Complete(runtime::Win16WindowResult::UserService(
                    runtime::Win16HostUserServiceResult::Dialog(
                        runtime::Win16HostDialogResult::DefaultResult(None),
                    ),
                )) => None,
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "control-color return slot belongs to a different USER result family",
                    ));
                }
            };
            match message_result {
                None => Target::Missing,
                Some(result) => match &result.output {
                    runtime::Win16HostMessageOutput::ControlColor(brush)
                        if result.value == 0 && result.dialog_result.is_none() =>
                    {
                        Target::Ready(*brush)
                    }
                    runtime::Win16HostMessageOutput::None
                        if result.value == 0 && result.dialog_result.is_none() =>
                    {
                        Target::Empty
                    }
                    _ => {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "control-color native result conflicts with its typed message output",
                        ));
                    }
                },
            }
        };
        if let Target::Ready(brush) = target {
            let expected =
                super::control_color_return::native_control_color_brush_result(objects, brush)?;
            if slot.load()? != Some(expected) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "materialized control-color result disagrees with its native HBRUSH identity",
                ));
            }
            return Ok(());
        }
        if matches!(target, Target::Missing) {
            if slot.load()?.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "control-color native result has no corresponding message result",
                ));
            }
            // No exact native request completed, so preserve None rather than
            // manufacturing a NULL brush that cannot match the empty slot.
            return Ok(());
        }
        let brush =
            match target {
                Target::Empty => {
                    let native = slot.load()?.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "control-color native call did not record its pointer-width HBRUSH result",
                ))?;
                    super::control_color_return::control_color_result_from_native(objects, native)?
                }
                Target::Missing | Target::Ready(_) => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "control-color completion target changed after validation",
                    ));
                }
            };
        let message_output = runtime::Win16HostMessageOutput::ControlColor(brush);
        let step = &mut self.pending[index]
            .completion
            .as_mut()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "control-color result lost its completion before output projection",
                )
            })?
            .step;
        match step {
            Win16WindowStep::Complete(runtime::Win16WindowResult::Message(Some(result))) => {
                result.value = 0;
                result.output = message_output;
            }
            Win16WindowStep::Complete(runtime::Win16WindowResult::Message(result @ None)) => {
                *result = Some(runtime::Win16HostMessageResult {
                    value: 0,
                    output: message_output,
                    dialog_result: None,
                });
            }
            Win16WindowStep::Complete(runtime::Win16WindowResult::UserService(
                runtime::Win16HostUserServiceResult::Dialog(
                    runtime::Win16HostDialogResult::DefaultResult(Some(result)),
                ),
            )) => {
                result.value = 0;
                result.output = message_output;
            }
            Win16WindowStep::Complete(runtime::Win16WindowResult::UserService(
                runtime::Win16HostUserServiceResult::Dialog(
                    runtime::Win16HostDialogResult::DefaultResult(result @ None),
                ),
            )) => {
                *result = Some(runtime::Win16HostMessageResult {
                    value: 0,
                    output: message_output,
                    dialog_result: None,
                });
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "control-color output projection lost its exact USER result variant",
                ));
            }
        }
        Ok(())
    }

    fn validate_cached_user_completion_top(
        &self,
        index: usize,
        id: u64,
    ) -> Result<(), RuntimeError> {
        if self.pending.last().map(|pending| pending.id) != Some(id)
            || self.dde_sources.pending.last() != Some(&PendingSource::User { id })
            || self
                .pending
                .iter()
                .filter(|pending| pending.id == id)
                .count()
                != 1
            || self
                .dde_sources
                .pending
                .iter()
                .filter(|source| **source == (PendingSource::User { id }))
                .count()
                != 1
            || self.pending.get(index).is_none_or(|pending| {
                pending.id != id
                    || pending.native_state != runtime::Win16NativeWindowOperationState::Returned
                    || pending.response_error.is_some()
                    || pending.awaiting.is_some()
                    || pending.awaiting_source.is_some()
                    || pending.pending_guest_work.is_some()
                    || pending.pending_modal_guest_work.is_some()
                    || pending.completion.is_none()
            })
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "normal USER completion is not the exact returned source-owner top",
            ));
        }
        Ok(())
    }

    fn retain_cached_user_completion_error<T>(
        &mut self,
        index: usize,
        error: RuntimeError,
    ) -> Result<T, RuntimeError> {
        let shared = Arc::new(error);
        if let Some(completion) = self
            .pending
            .get_mut(index)
            .and_then(|pending| pending.completion.as_mut())
            && completion.first_cause.is_none()
        {
            completion.first_cause = Some(Arc::clone(&shared));
        }
        let kind = shared.kind();
        Err(RuntimeError::with_source(
            kind,
            "normal USER completion retry retained its exact source and first cause",
            SharedRuntimeFailure::new(shared),
        ))
    }
}
