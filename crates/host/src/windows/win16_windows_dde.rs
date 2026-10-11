//! DDE and cross-worker continuation coordination for Win16 USER hosting.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, Win16HostDdeCall,
    Win16HostDdeCallbackStep, Win16HostDdeOperation, Win16HostDdeResume,
    Win16HostDdeStep,
    Win16HostMessageOutput, Win16WindowAbortReceipt, Win16WindowReply,
    Win16HostWindowOperationId, Win16WindowStep,
};

use super::super::win16_dde::{DdeBeginFailure, Win16DdeHost};
use super::{PendingWaitKind, Win16Objects, Win16Windows, WorkerCommand, worker_stopped};

#[path = "win16_windows_dde_completion.rs"]
mod completion;
#[path = "win16_windows_dde_retirement.rs"]
mod retirement;
#[cfg(test)]
#[path = "win16_windows_dde_completion_tests.rs"]
mod dde_completion_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingSource {
    User { id: u64 },
    Dde { operation: Win16HostDdeOperation },
}

pub(in crate::windows) fn allocate_shared_identity(source: &AtomicU64) -> Result<u64, RuntimeError> {
    source
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 USER and DDE operation/callback identities are exhausted",
            )
        })
}

#[derive(Debug)]
pub(super) struct SharedRuntimeFailure(Arc<RuntimeError>);

impl SharedRuntimeFailure {
    pub(super) fn new(cause: Arc<RuntimeError>) -> Self {
        Self(cause)
    }
}

impl fmt::Display for SharedRuntimeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl Error for SharedRuntimeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Debug)]
struct HostCleanupReceiptFailure {
    cause: RuntimeError,
    receipt: Win16WindowAbortReceipt,
}

impl fmt::Display for HostCleanupReceiptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; {} native modal cancellation receipt(s) retained",
            self.cause,
            self.receipt.cancelled_modals.len()
        )
    }
}

impl Error for HostCleanupReceiptFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Clone, Debug)]
pub(super) enum RetiredDdeOperationSource {
    Normal(Arc<runtime::Win16DdeSourceRetiredProof>),
    Shutdown(runtime::Win16DdeOperationRetirementProof),
}

impl RetiredDdeOperationSource {
    pub(super) fn operation(&self) -> Win16HostDdeOperation {
        match self {
            Self::Normal(proof) => proof.operation,
            Self::Shutdown(proof) => proof.cancellation.operation,
        }
    }
}

pub(super) struct PendingDdeCallbackSource {
    pub(super) step: Arc<Win16HostDdeCallbackStep>,
    pub(super) runtime_published: bool,
}

#[derive(Default)]
pub(super) struct DdeSourceLedger {
    pub(super) pending: Vec<PendingSource>,
    pub(super) callbacks: Vec<PendingDdeCallbackSource>,
    pub(super) retired_operations: Vec<RetiredDdeOperationSource>,
}

impl Win16Windows {
    pub(super) fn begin_dde_inner(
        &mut self,
        call: Win16HostDdeCall,
    ) -> Result<Win16WindowStep, RuntimeError> {
        if self.dde.is_none() {
            return Err(self.dde_start_failure());
        }
        let operation = Win16HostDdeOperation(allocate_shared_identity(&self.identity_source)?);
        let source = PendingSource::Dde { operation };
        self.dde_sources.pending.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 DDE pending-source ownership",
                error,
            )
        })?;
        self.reserve_dde_callback_source_capacity()?;
        self.dde_sources.pending.push(source);
        let step = match self.dde_host_mut()?.begin_owned_tracked(operation, call) {
            Ok(step) => step,
            Err(DdeBeginFailure::NotSubmitted(error)) => {
                self.pop_source(source)?;
                return Err(error);
            }
            Err(DdeBeginFailure::Submitted(failure)) => {
                return self.dde_started_failure_step(failure);
            }
        };
        self.dde_window_step(operation, step)
    }
    fn dde_started_failure_step(
        &self,
        failure: Arc<runtime::Win16DdeOperationStartedFailure>,
    ) -> Result<Win16WindowStep, RuntimeError> {
        self.require_source(
            PendingSource::Dde { operation: failure.operation },
            "DDE started-failure proof does not match the exact pending source",
        )?;
        let host = self.dde.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE started-failure lost its native owner",
        ))?;
        if failure.owner.0 == 0
            || failure.worker_generation == 0
            || !host.matches_owner_generation(failure.owner, failure.worker_generation)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE started-failure does not match its exact native owner generation"));
        }
        Ok(Win16WindowStep::DdeStartedFailure(failure))
    }
    /// Continue the innermost operation. Replies are accepted only for the
    /// callback token most recently emitted by that operation.
    pub(super) fn resume_inner(
        &mut self,
        reply: Option<Win16WindowReply>,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let source = self.dde_sources.pending.last().copied().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 continuation has no pending source",
            )
        })?;
        match source {
            PendingSource::Dde { operation } => {
                if reply.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "a USER callback reply cannot resume a pending DDE operation",
                    ));
                }
                if let Some(callback) = self.unpublished_dde_callback(Some(operation))? {
                    return Ok(Win16WindowStep::DdeCallback(callback));
                }
                if let Some(result) = self
                    .dde
                    .as_ref()
                    .and_then(|dde| dde.normal_completion_result(operation))
                {
                    return self.dde_window_step(
                        operation,
                        Win16HostDdeStep::Complete(result),
                    );
                }
                self.reserve_dde_callback_source_capacity()?;
                let step = match self.dde_host_mut()?.continue_operation(operation) {
                    Ok(step) => step,
                    Err(error) => {
                        let fallback = Arc::new(RuntimeError::with_source(
                            error.kind(),
                            "Win16 DDE continuation failed after its request was submitted",
                            error,
                        ));
                        if let Some(failure) = self
                            .dde
                            .as_ref()
                            .and_then(|dde| dde.started_failure_after_submission(
                                operation,
                                Arc::clone(&fallback),
                            ))
                        {
                            return Ok(Win16WindowStep::DdeStartedFailure(failure));
                        }
                        return Err(RuntimeError::with_source(
                            fallback.kind(),
                            "Win16 DDE continuation failed without a terminal source record",
                            SharedRuntimeFailure(fallback),
                        ));
                    }
                };
                self.dde_window_step(operation, step)
            }
            PendingSource::User { id } => self.resume_user(id, reply, objects),
        }
    }
    fn resume_user(
        &mut self,
        id: u64,
        reply: Option<Win16WindowReply>,
        objects: &mut Win16Objects,
    ) -> Result<Win16WindowStep, RuntimeError> {
        self.require_source(
            PendingSource::User { id },
            "USER continuation does not match the top pending source",
        )?;
        let index = self.pending.len().checked_sub(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 window continuation has no pending USER operation",
            )
        })?;
        if self.pending[index].id != id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "USER source and pending operation identities disagree",
            ));
        }
        let operation_id = self.pending[index].id;
        let awaiting = self.pending[index].awaiting;
        let awaiting_source = self.pending[index].awaiting_source;
        let pending_guest_work = self.pending[index].pending_guest_work;
        match (reply, pending_guest_work) {
            (Some(reply), work) => {
                if work.is_some()
                    || awaiting != Some(reply.callback)
                    || !awaiting_source.is_some_and(|source| {
                        source.callback == reply.callback
                            && source.operation_id == Win16HostWindowOperationId(operation_id)
                    })
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 window reply does not match a suspended native callback",
                    ));
                }
                let color_source = awaiting_source.is_some_and(|source| matches!(
                    source.source,
                    runtime::Win16NativeCallbackSource::WindowMessage {
                        message: 0x0132..=0x0138, ..
                    }
                ));
                let color_output = matches!(&reply.result.output,
                    Win16HostMessageOutput::ControlColor(_));
                if color_output && !color_source {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed HBRUSH result came from a non-control-color callback"));
                }
                let native_control_color_result =
                    super::control_color_return::native_control_color_result(objects, &reply)?;
                self.worker()?
                    .send(WorkerCommand::Resume {
                        id: operation_id,
                        reply,
                        native_control_color_result,
                    })
                    .map_err(|_| worker_stopped("resume Win16 callback"))?;
                self.pending[index].awaiting = None;
            }
            (None, Some(work)) => {
                if work.operation_id != Win16HostWindowOperationId(operation_id)
                    || work.generation <= self.pending[index].last_guest_work_generation
                    || awaiting.is_some()
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "pending guest work continuation identity or generation changed",
                    ));
                }
                let command = match work.kind {
                    PendingWaitKind::GetMessage => {
                        WorkerCommand::ContinueGetMessage { id: work.operation_id.0 }
                    }
                    PendingWaitKind::WaitMessage => {
                        WorkerCommand::ContinueWaitMessage { id: work.operation_id.0 }
                    }
                };
                self.worker()?
                    .send(command)
                    .map_err(|_| worker_stopped("continue the exact Win16 USER wait"))?;
                self.pending[index].last_guest_work_generation = work.generation;
                self.pending[index].pending_guest_work = None;
            }
            (None, None) if awaiting.is_some() => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 callback continuation is missing its guest reply",
                ));
            }
            (None, None) => {}
        }
        self.receive_step_inner(objects)
    }
    fn dde_window_step(
        &mut self,
        operation: Win16HostDdeOperation,
        step: Win16HostDdeStep,
    ) -> Result<Win16WindowStep, RuntimeError> {
        match step {
            Win16HostDdeStep::Complete(result) => {
                // Direct Begin/resume completions have no guest callback to
                // retire their parent source. The exact native result must
                // cross the same checked source boundary before publication.
                let retired = match self.retire_completed_dde_source_inner(operation, &result) {
                    Ok(retired) => retired,
                    Err(error) => {
                        let cause = Arc::new(error);
                        if let Some(failure) = self.dde_host_mut()?.source_retirement_failure(
                            operation, Arc::clone(&cause),
                        ) {
                            return self.dde_started_failure_step(failure);
                        }
                        return Err(RuntimeError::with_source(cause.kind(),
                            "DDE source retirement failed without an exact native completion record",
                            SharedRuntimeFailure(cause)));
                    }
                };
                self.dde_window_step(operation, retired)
            }
            Win16HostDdeStep::SourceRetired { proof, result } => {
                completion::source_retired_window_step(self, operation, proof, result)
            }
            Win16HostDdeStep::Callback(callback) => {
                self.require_source(
                    PendingSource::Dde { operation },
                    "DDE callback does not match the top pending source",
                )?;
                if callback.parent.is_some_and(|parent| parent != operation) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE callback belongs to a different foreground operation",
                    ));
                }
                self.remember_dde_callback(Arc::clone(&callback))?;
                Ok(Win16WindowStep::DdeCallback(callback))
            }
            Win16HostDdeStep::CallbackFrameComplete { .. } => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback-frame acknowledgement cannot complete a window API operation",
            )),
        }
    }
    pub(super) fn poll_dde_callback_inner(
        &mut self,
    ) -> Result<Option<Arc<Win16HostDdeCallbackStep>>, RuntimeError> {
        if self.dde.is_none() {
            return Ok(None);
        }
        self.reserve_dde_callback_source_capacity()?;
        let callback = self.dde_host_mut()?.poll_callback()?;
        if let Some(callback) = &callback {
            if callback.parent.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "unsolicited DDE polling returned a foreground callback",
                ));
            }
            self.remember_dde_callback(Arc::clone(callback))?;
        }
        Ok(callback)
    }
    pub(super) fn dde_callback_reply_inner(
        &mut self,
        resume: Win16HostDdeResume,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        let frame = resume.frame;
        let parent = self
            .dde_sources
            .callbacks
            .iter()
            .find(|source| source.step.frame == frame)
            .map(|source| source.step.parent)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback reply has no recorded pending source",
                )
            })?;
        if !self.dde_sources.callbacks.iter().any(|source| {
            source.step.frame == frame && source.runtime_published
        }) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE callback reply preceded publication of its exact source"));
        }
        if let Some(operation) = parent {
            self.require_source(
                PendingSource::Dde { operation },
                "DDE callback reply does not match its pending operation source",
            )?;
        }
        self.reserve_dde_callback_source_capacity()?;
        let step = self.dde_host_mut()?.resume(resume)?;
        match &step {
            Win16HostDdeStep::Complete(result) => {
                let Some(operation) = parent else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "parentless DDE callback returned a foreground operation result",
                    ));
                };
                if self.dde.as_ref().and_then(|dde|
                    dde.normal_completion_result(operation)).as_ref() != Some(result)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE callback completion differs from its exact native result record"));
                }
            }
            Win16HostDdeStep::SourceRetired { proof, result } => {
                let Some(operation) = parent else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "parentless DDE callback returned a foreground source-retirement proof"));
                };
                completion::validate_source_retired_step(self, operation, proof, result)?;
            }
            Win16HostDdeStep::Callback(callback) => {
                if callback.parent != parent {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "continued DDE callback changed its pending-source parent",
                    ));
                }
                if let Some(operation) = callback.parent {
                    self.require_source(
                        PendingSource::Dde { operation },
                        "continued DDE callback changed its foreground operation",
                    )?;
                }
                self.remember_dde_callback(Arc::clone(callback))?;
            }
            Win16HostDdeStep::CallbackFrameComplete { frame: completed } => {
                if *completed != frame || parent.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE callback-frame acknowledgement changed its source",
                    ));
                }
                // Keep the exact source until runtime cleanup and native ACK.
            }
        }
        Ok(step)
    }
    pub(super) fn abort_dde_inner(&mut self) -> Result<(), RuntimeError> {
        let receipt = self.dde_abort_receipt_inner();
        if receipt.is_quiesced() { Ok(()) } else { Err(receipt.as_error()) }
    }
    pub(super) fn take_dde_diagnostics_inner(&mut self) -> Vec<Diagnostic> {
        match self.dde.as_mut() {
            Some(dde) => dde.take_diagnostics(),
            None => Vec::new(),
        }
    }
    fn dde_start_failure(&self) -> RuntimeError {
        match &self.dde_start_error {
            Some(error) => RuntimeError::with_source(
                error.kind(),
                "Win16 DDE host initialization failed",
                SharedRuntimeFailure(Arc::clone(error)),
            ),
            None => RuntimeError::new(Kind::HostFailure, "Win16 DDE host is unavailable"),
        }
    }
    fn dde_host_mut(&mut self) -> Result<&mut Win16DdeHost, RuntimeError> {
        if self.dde.is_none() {
            return Err(self.dde_start_failure());
        }
        self.dde.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "initialized Win16 DDE host disappeared",
            )
        })
    }
    pub(super) fn require_source(
        &self,
        expected: PendingSource,
        message: &'static str,
    ) -> Result<(), RuntimeError> {
        if self.dde_sources.pending.last() == Some(&expected) {
            Ok(())
        } else {
            Err(RuntimeError::new(Kind::InternalInvariant, message))
        }
    }
    fn pop_source(&mut self, expected: PendingSource) -> Result<(), RuntimeError> {
        self.require_source(expected, "pending source stack was popped out of order")?;
        self.dde_sources.pending.pop();
        Ok(())
    }
    fn finish_cleanup(
        dde: Result<(), RuntimeError>,
        user: Result<Win16WindowAbortReceipt, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        match (dde, user) {
            (Ok(()), Ok(_receipt)) => Ok(()),
            (Err(error), Ok(receipt)) => Err(RuntimeError::with_source(
                error.kind(),
                "Win16 DDE cleanup failed after USER modal cancellation completed",
                HostCleanupReceiptFailure {
                    cause: error,
                    receipt,
                },
            )),
            (Ok(()), Err(error)) => Err(error),
            (Err(dde), Err(user)) => Err(dde.with_cleanup(
                "Win16 DDE and USER cleanup both failed", user,
            )),
        }
    }
    /// Stop callback delivery and wait for native calls to unwind. Cleanup
    /// destruction is then queued on this same worker thread.
    pub(super) fn shutdown_inner(&mut self) -> Result<(), RuntimeError> {
        if self.worker.is_none()
            && self.terminal_shutdown_retirement_matches_source()
        {
            self.require_user_terminal_sources_acknowledged()?;
            return Ok(());
        }
        if self.terminal_abort.is_none() {
            let canonical_abort = self.worker.as_ref()
                .map(super::WindowWorker::canonical_abort_before_shutdown)
                .transpose()?
                .flatten();
            if let Some((response, publication_failure)) = canonical_abort {
                let receipt = match response {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        let worker_failure = RuntimeError::with_source(
                            error.kind(),
                            "retained canonical Win16 USER Abort before shutdown",
                            error,
                        );
                        return Err(match publication_failure {
                            Some(publication_failure) => worker_failure.with_cleanup(
                                "canonical USER Abort publication and worker failures both failed",
                                publication_failure,
                            ),
                            None => worker_failure,
                        });
                    }
                };
                self.validate_terminal_abort_receipt(&receipt)?;
                self.retain_terminal_modal_operation_states(&receipt)?;
                self.aborted = true;
                self.terminal_abort = Some(receipt.clone());
                if let Some(cause) = publication_failure {
                    return Err(RuntimeError::with_source(
                        cause.kind(),
                        "Win16 USER Abort receipt retained after wake publication failure",
                        HostCleanupReceiptFailure { cause, receipt },
                    ));
                }
            }
        }
        // Shutdown joins and retires the worker, which makes exact terminal
        // source ACKs impossible to complete if any USER owner is still live.
        // Check the paired host-operation/source ledgers before touching DDE,
        // the worker, or its retained receipt/backing state.
        self.require_user_terminal_sources_acknowledged()?;
        self.aborted = true;
        let dde_result = match self.dde.as_mut() {
            Some(dde) => dde.shutdown(),
            None => Ok(()),
        };
        let (user_result, worker_stopped) = match self.worker.as_mut() {
            Some(worker) => {
                let result = worker.shutdown();
                (result, !worker.has_join_handle())
            }
            None => (Err(self.worker_start_failure()), true),
        };
        if let Ok(receipt) = &user_result {
            self.retain_shutdown_retirement_proof(receipt)?;
        }
        if worker_stopped {
            self.worker.take();
        }
        if self.worker.is_none()
            && (!self.pending.is_empty()
                || self.dde_sources.pending.iter().any(|source|
                    matches!(source, PendingSource::User { .. })))
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker stopped while exact operation sources still await terminal ACK",
            ));
        }
        Self::finish_cleanup(dde_result, user_result)
    }

    fn require_user_terminal_sources_acknowledged(&self) -> Result<(), RuntimeError> {
        let mut unacknowledged = 0usize;
        for (pending_index, pending) in self.pending.iter().enumerate() {
            if pending.id == 0
                || self.pending.iter().enumerate().any(|(other_index, other)| {
                    other_index != pending_index && other.id == pending.id
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER shutdown found a duplicate or zero pending operation identity"));
            }
            let source_count = self.dde_sources.pending.iter().filter(|source| {
                matches!(source, PendingSource::User { id } if *id == pending.id)
            }).count();
            if source_count != 1 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER shutdown found no unique exact source for a pending operation"));
            }
            unacknowledged += 1;
        }

        for (source_index, source) in self.dde_sources.pending.iter().enumerate() {
            let PendingSource::User { id } = source else {
                continue;
            };
            if *id == 0
                || self.dde_sources.pending.iter().enumerate().any(|(other_index, other)| {
                    other_index != source_index
                        && matches!(other, PendingSource::User { id: other_id } if other_id == id)
                })
                || self.pending.iter().filter(|pending| pending.id == *id).count() != 1
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER shutdown found a duplicate or orphaned terminal source identity"));
            }
        }

        if unacknowledged != 0 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER shutdown requires exact terminal ACKs for all retained USER sources"));
        }
        Ok(())
    }

    fn retain_shutdown_retirement_proof(
        &mut self,
        receipt: &Win16WindowAbortReceipt,
    ) -> Result<(), RuntimeError> {
        let worker_generation = self.worker.as_ref()
            .map(super::WindowWorker::worker_generation)
            .ok_or_else(|| self.worker_start_failure())?;
        if receipt.worker_generation != worker_generation
            || receipt.worker_generation == 0
            || receipt.request_id == 0
            || !receipt.active_operation_stack_empty
            || !receipt.callback_stack_empty
            || !receipt.modal_scope_stack_empty
            || receipt.resource_retirement != runtime::Win16NativeResourceRetirement::Retired
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER shutdown did not prove this worker generation joined and retired"));
        }

        let source_request_id = if let Some(abort) = &self.terminal_abort {
            if abort.worker_generation != worker_generation
                || abort.request_id == 0
                || abort.request_id == receipt.request_id
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "Win16 USER shutdown retirement changed its retained abort identity"));
            }
            // Shutdown has its own request ID and is only a join/resource
            // retirement proof. The first abort remains the exact source/ACK
            // evidence, including its original modal cancellation payload.
            abort.request_id
        } else {
            // When orderly shutdown is the first terminal request, its exact
            // receipt is also the only available source/ACK proof.
            self.validate_terminal_abort_receipt(receipt)?;
            self.retain_terminal_modal_operation_states(receipt)?;
            self.terminal_abort = Some(receipt.clone());
            receipt.request_id
        };
        let proof = super::TerminalShutdownRetirementProof {
            worker_generation,
            source_request_id,
            shutdown_request_id: receipt.request_id,
        };
        if self.terminal_shutdown_retirement.is_some_and(|cached| cached != proof) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER shutdown retirement proof changed its worker or source identity"));
        }
        self.terminal_shutdown_retirement = Some(proof);
        Ok(())
    }

    fn terminal_shutdown_retirement_matches_source(&self) -> bool {
        let (Some(proof), Some(abort)) =
            (self.terminal_shutdown_retirement, self.terminal_abort.as_ref())
        else {
            return false;
        };
        proof.worker_generation == abort.worker_generation
            && proof.source_request_id == abort.request_id
            && proof.shutdown_request_id != 0
    }
    pub(super) fn abort_inner(&mut self) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
        let dde_result = self.abort_dde_inner();
        let user_result = self.abort_user_worker();
        match (dde_result, user_result) {
            (Ok(()), Ok(receipt)) => Ok(receipt),
            (Err(error), Ok(receipt)) => Err(RuntimeError::with_source(
                error.kind(),
                "Win16 DDE abort failed after USER modal cancellation completed",
                HostCleanupReceiptFailure {
                    cause: error,
                    receipt,
                },
            )),
            (Ok(()), Err(error)) => Err(error),
            (Err(dde), Err(user)) => Err(dde.with_cleanup(
                "Win16 DDE and USER abort both failed", user,
            )),
        }
    }
    fn abort_user_worker(&mut self) -> Result<runtime::Win16WindowAbortReceipt, RuntimeError> {
        if let Some(receipt) = &self.terminal_abort {
            return Ok(receipt.clone());
        }
        if self.aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker was aborted without a retained terminal receipt",
            ));
        }
        let worker = self.worker()?;
        let response = worker.request_abort()?;
        let receipt = response.map_err(|error| {
            RuntimeError::with_source(error.kind(), "Win16 native callback abort", error)
        })?;
        self.validate_terminal_abort_receipt(&receipt)?;
        self.retain_terminal_modal_operation_states(&receipt)?;
        self.aborted = true;
        self.terminal_abort = Some(receipt.clone());
        Ok(receipt)
    }
}
