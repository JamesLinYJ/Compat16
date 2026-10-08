use super::*;

#[path = "win16_mci_worker_client_quiesce_entered_failure.rs"]
mod entered_failure;
use entered_failure::{retain_entered_yield_failure_owners, retain_owner};
#[path = "win16_mci_worker_client_quiesce_retain.rs"]
mod retain;
use retain::{retained_request_capacity, retain_request_owners, retain_step_owners, retain_yield_owner};

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn quiesce_owned(
        &mut self,
        request: Win16HostMciQuiesceRequest,
    ) -> Result<Win16HostMciQuiescenceReceipt, RuntimeError> {
        let wake_error = match self.drain_deferred_receipts() {
            Ok(error) => error.map(Arc::new),
            Err(error) => Some(Arc::new(error)),
        };
        let mut retry_index = None;
        let mut prior_cause = None;
        if let Some(index) = self
            .completed_quiescences
            .iter()
            .position(|receipt| receipt.request == request)
        {
            if let Some(error) = wake_error.as_ref() {
                // A newer reconciliation error cannot consume a cached native receipt.
                return Err(retained_quiescence_error(
                    error,
                    "MCI quiescence preserves its exact completed result while owner errors are reported",
                ));
            }
            match &mut self.completed_quiescences[index] {
                completed if completed.result.is_ok() => {
                    if let (Ok(receipt), Some(cause)) =
                        (&mut completed.result, completed.first_cause.as_ref())
                    {
                        preserve_resolved_cause(receipt, cause)?;
                    }
                    let completed = self.completed_quiescences.swap_remove(index);
                    let Ok(receipt) = completed.result else {
                        unreachable!("cached MCI quiescence result remained successful")
                    };
                    return Ok(receipt);
                }
                completed if !completed.result_delivered => {
                    let Some(error) = completed.result.as_ref().err().cloned() else {
                        unreachable!("undelivered MCI quiescence error has an error result")
                    };
                    completed.result_delivered = true;
                    return Err(retained_quiescence_error(
                        &error,
                        "deferred MCI quiescence returned its original native error",
                    ));
                }
                completed if completed.phase == MciQuiescencePhase::PreEffectFailure => {
                    prior_cause = completed.first_cause.clone().or_else(|| {
                        completed.result.as_ref().err().cloned()
                    });
                    retry_index = Some(index);
                }
                completed => {
                    let Some(error) = completed.result.as_ref().err() else {
                        unreachable!("unknown MCI quiescence phase has an error result")
                    };
                    return Err(retained_quiescence_error(
                        error,
                        "MCI quiescence outcome is retained because native effects may have started",
                    ));
                }
            }
        }
        let begin_pending = !request.pending_begins.is_empty()
            || self.deferred_receipts.iter().any(|receipt| {
                matches!(receipt, DeferredWorkerReceipt::Begin { .. })
            })
            || self.unclaimed.iter().any(|receipt| {
                receipt.source_frame.is_none()
                    && matches!(
                        &receipt.outcome,
                        UnclaimedMciOutcome::Step(_)
                            | UnclaimedMciOutcome::UnexpectedBeginStep { .. }
                            | UnclaimedMciOutcome::Failure { frame: None, .. }
                    )
            });
        let resume_pending = self.deferred_receipts.iter().any(|receipt| {
            matches!(receipt, DeferredWorkerReceipt::Resume { .. })
        }) || self.unclaimed.iter().any(|receipt| {
            receipt.source_frame.is_some()
                || entered_failure::has_exact_yield_frame(&receipt.outcome)
        }) || self.pending.values().any(|pending| pending.resume_in_flight.is_some());
        let quiescence_pending = self
            .deferred_receipts
            .iter()
            .any(|receipt| matches!(receipt, DeferredWorkerReceipt::Quiesce { .. }))
            || self
                .completed_quiescences
                .iter()
                .any(|completed| completed.request != request)
            || self.pending_producer_quiescence.is_some()
            || self.completed_producer_quiescence.is_some();
        if begin_pending || resume_pending || quiescence_pending {
            let mut receipt = retained_pending_receipt(self, request, wake_error.clone())?;
            if let Some(cause) = prior_cause.as_ref() {
                preserve_resolved_cause(&mut receipt, cause)?;
            }
            return Ok(receipt);
        }
        if let Some(error) = wake_error.as_ref() {
            return Err(retained_quiescence_error(
                error,
                "native MCI owner receipt reconciliation failed before quiescence could be enqueued",
            ));
        }
        self.deferred_receipts.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI quiescence response ownership",
                error,
            )
        })?;
        self.completed_quiescences.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native MCI quiescence result reconciliation",
                error,
            )
        })?;
        let (response, receive) = mpsc::channel();
        self.enqueue(WorkerCommand::Quiesce {
            request: request.clone(),
            response,
        })?;
        if let Some(index) = retry_index {
            self.completed_quiescences.swap_remove(index);
        }
        if let Err(error) = self.wake_owner() {
            let wake_cause = Arc::new(error);
            let first_cause = prior_cause.or_else(|| Some(Arc::clone(&wake_cause)));
            self.deferred_receipts.push(DeferredWorkerReceipt::Quiesce {
                request,
                response: receive,
                first_cause,
                phase: MciQuiescencePhase::Enqueued,
            });
            return Err(retained_quiescence_error(
                &wake_cause,
                "native MCI quiescence is enqueued with its exact response owner retained",
            ));
        }
        match receive.recv() {
            Ok(Ok(mut receipt)) => {
                if let Some(cause) = prior_cause.as_ref() {
                    if let Err(error) = preserve_resolved_cause(&mut receipt, cause) {
                        self.completed_quiescences.push(CompletedMciQuiescence {
                            request,
                            result: Ok(receipt),
                            phase: MciQuiescencePhase::ReceiptReady,
                            first_cause: Some(Arc::clone(cause)),
                            result_delivered: false,
                        });
                        return Err(error);
                    }
                }
                return Ok(receipt);
            }
            Ok(Err(error)) => {
                let error = Arc::new(error);
                self.completed_quiescences.push(CompletedMciQuiescence {
                    request,
                    result: Err(Arc::clone(&error)),
                    phase: MciQuiescencePhase::PreEffectFailure,
                    first_cause: prior_cause.or_else(|| Some(Arc::clone(&error))),
                    result_delivered: true,
                });
                return Err(retained_quiescence_error(
                    &error,
                    "native MCI quiescence failed before its first native effect",
                ));
            }
            Err(error) => {
                let error = Arc::new(RuntimeError::with_source(
                    Kind::HostFailure,
                    "receive native MCI quiescence receipt; exact request remains retained",
                    error,
                ));
                self.completed_quiescences.push(CompletedMciQuiescence {
                    request,
                    result: Err(Arc::clone(&error)),
                    phase: MciQuiescencePhase::OutcomeUnknown,
                    first_cause: prior_cause.or_else(|| Some(Arc::clone(&error))),
                    result_delivered: true,
                });
                return Err(retained_quiescence_error(
                    &error,
                    "MCI quiescence response channel disconnected with native phase unknown",
                ));
            }
        }
    }
}

fn retained_quiescence_error(cause: &Arc<RuntimeError>, context: &'static str) -> RuntimeError {
    RuntimeError::with_source(
        cause.kind(),
        context,
        super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(cause)),
    )
}

fn preserve_resolved_cause(
    receipt: &mut Win16HostMciQuiescenceReceipt,
    cause: &Arc<RuntimeError>,
) -> Result<(), RuntimeError> {
    if receipt
        .resolved_causes
        .iter()
        .any(|existing| Arc::ptr_eq(existing, cause))
    {
        return Ok(());
    }
    receipt.resolved_causes.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "preserve the first MCI quiescence cause with its exact successful receipt",
            error,
        )
    })?;
    receipt.resolved_causes.push(Arc::clone(cause));
    Ok(())
}

fn retained_pending_receipt(
    worker: &Win16MciWorker,
    request: Win16HostMciQuiesceRequest,
    wake_error: Option<Arc<RuntimeError>>,
) -> Result<Win16HostMciQuiescenceReceipt, RuntimeError> {
    let deferred_owner_capacity = worker.deferred_receipts.iter().fold(0usize, |capacity, receipt| {
        capacity.saturating_add(match receipt {
            DeferredWorkerReceipt::Begin { .. } => 2,
            DeferredWorkerReceipt::Resume { .. } => 5,
            DeferredWorkerReceipt::Quiesce { request, .. } => retained_request_capacity(request),
        })
    });
    let unclaimed_owner_capacity = worker.unclaimed.iter().fold(0usize, |capacity, receipt| {
        let amount = match &receipt.outcome {
            UnclaimedMciOutcome::AwaitingYieldResult { .. } => 5,
            UnclaimedMciOutcome::Step(_) | UnclaimedMciOutcome::UnexpectedBeginStep { .. } => 6,
            UnclaimedMciOutcome::UnexpectedStep { .. } => 10,
            UnclaimedMciOutcome::Failure { frame: Some(_), .. } => 6,
            // A frame-less entered failure may still own its exact device,
            // registration, and last returned yield alongside the operation.
            UnclaimedMciOutcome::Failure { frame: None, .. } => 6,
        };
        capacity.saturating_add(amount)
    });
    let completed_quiescence_owner_capacity = worker
        .completed_quiescences
        .iter()
        .map(|completed| retained_request_capacity(&completed.request))
        .fold(0usize, usize::saturating_add);
    let producer_owner_capacity = worker
        .pending_producer_quiescence
        .as_ref()
        .map(|pending| retained_request_capacity(&pending.request.owners).saturating_add(2))
        .unwrap_or(0)
        .saturating_add(
            worker
                .completed_producer_quiescence
                .as_ref()
                .map(|completed| retained_request_capacity(&completed.request.owners).saturating_add(2))
                .unwrap_or(0),
        );
    let completed_quiescence_cause_capacity = worker
        .completed_quiescences
        .iter()
        .map(|completed| match &completed.result {
            Ok(receipt) => receipt.causes.len().saturating_add(1),
            Err(_) => 1,
        })
        .fold(0usize, usize::saturating_add);
    let completed_quiescence_resolved_capacity = worker
        .completed_quiescences
        .iter()
        .filter(|completed| completed.first_cause.is_some())
        .count();
    let deferred_quiescence_resolved_capacity = worker
        .deferred_receipts
        .iter()
        .filter(|receipt| {
            matches!(receipt, DeferredWorkerReceipt::Quiesce { first_cause: Some(_), .. })
        })
        .count();
    let producer_resolved_capacity = usize::from(
        worker
            .pending_producer_quiescence
            .as_ref()
            .is_some_and(|pending| pending.first_cause.is_some()),
    )
        .saturating_add(worker.pending_producer_quiescence.as_ref()
            .map_or(0, |pending| pending.prior_causes.len()))
        .saturating_add(usize::from(
            worker
                .completed_producer_quiescence
                .as_ref()
                .is_some_and(|completed| completed.first_cause.is_some()),
        ))
        .saturating_add(worker.completed_producer_quiescence.as_ref()
            .map_or(0, |completed| completed.prior_causes.len()));
    let in_flight_resume_count = worker
        .pending
        .values()
        .filter(|pending| pending.resume_in_flight.is_some())
        .count();
    let owner_capacity = request
        .devices
        .len()
        .saturating_add(request.registrations.len())
        .saturating_add(request.pending_begins.len().saturating_mul(3))
        .saturating_add(request.active_yields.len().saturating_mul(2))
        .saturating_add(request.returned_yields.len())
        .saturating_add(request.completed_operations.len())
        .saturating_add(deferred_owner_capacity)
        .saturating_add(unclaimed_owner_capacity)
        .saturating_add(completed_quiescence_owner_capacity)
        .saturating_add(producer_owner_capacity)
        .saturating_add(in_flight_resume_count.saturating_mul(5))
        .saturating_add(2);
    let cause_capacity = request
        .pending_begins
        .len()
        .saturating_add(worker.deferred_receipts.len().saturating_mul(2))
        .saturating_add(worker.unclaimed.len())
        .saturating_add(completed_quiescence_cause_capacity)
        .saturating_add(worker.pending_producer_quiescence.as_ref().map_or(0, |pending| {
            usize::from(pending.first_cause.is_some()).saturating_add(1)
        }))
        .saturating_add(worker.completed_producer_quiescence.as_ref().map_or(0, |completed| {
            completed.result.as_ref().map_or(1, |result| match result {
                Ok(receipt) => receipt.barrier_causes.len()
                    .saturating_add(receipt.source_causes.len())
                    .saturating_add(1),
                Err(_) => 1,
            })
        }))
        .saturating_add(in_flight_resume_count)
        .saturating_add(usize::from(wake_error.is_some()))
        .saturating_add(1);
    let mut receipt = Win16HostMciQuiescenceReceipt {
        request,
        status: Win16HostMciQuiescenceStatus::Retained,
        confirmed: Vec::new(),
        retained: Vec::new(),
        causes: Vec::new(),
        resolved_causes: Vec::new(),
    };
    receipt.retained.try_reserve_exact(owner_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact host MCI owners while Begin or Resume reconciliation is pending",
            error,
        )
    })?;
    receipt.causes.try_reserve_exact(cause_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve typed causes while Begin or Resume reconciliation is pending",
            error,
        )
    })?;
    receipt
        .resolved_causes
        .try_reserve_exact(
            receipt
                .request
                .resolved_causes
                .len()
                .saturating_add(completed_quiescence_resolved_capacity)
                .saturating_add(deferred_quiescence_resolved_capacity)
                .saturating_add(producer_resolved_capacity),
        )
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain prior MCI quiescence causes while Begin or Resume is pending",
                error,
            )
        })?;
    receipt
        .resolved_causes
        .extend(receipt.request.resolved_causes.iter().cloned());
    for completed in &worker.completed_quiescences {
        match &completed.result {
            Ok(cached) => {
                retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::OwnerThread);
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::NotificationSink,
                );
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "a different exact MCI quiescence request still owns a cached result",
                )));
                receipt.causes.extend(cached.causes.iter().cloned());
            }
            Err(cause) => {
                retain_request_owners(&mut receipt.retained, &completed.request);
                receipt.causes.push(Arc::clone(cause));
            }
        }
        if let Some(cause) = completed.first_cause.as_ref() {
            if !receipt
                .resolved_causes
                .iter()
                .any(|existing| Arc::ptr_eq(existing, cause))
            {
                receipt.resolved_causes.push(Arc::clone(cause));
            }
        }
    }

    for device in &receipt.request.devices {
        retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::Device(*device));
    }
    for registration in &receipt.request.registrations {
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::Registration(*registration),
        );
    }
    for operation in &receipt.request.pending_begins {
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::PendingBegin(*operation),
        );
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::Operation(*operation),
        );
    }
    for active in &receipt.request.active_yields {
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::ActiveYield(*active),
        );
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::Operation(active.operation),
        );
    }
    for returned in &receipt.request.returned_yields {
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::YieldReturn(*returned),
        );
    }
    for completed in &receipt.request.completed_operations {
        retain_owner(
            &mut receipt.retained,
            Win16HostMciRetainedOwner::CompletedOperation(*completed),
        );
    }

    for operation in &receipt.request.pending_begins {
        let exact_result_ready = worker.unclaimed.iter().any(|unclaimed| {
            unclaimed.operation == *operation
                && unclaimed.source_frame.is_none()
                && matches!(
                    &unclaimed.outcome,
                    UnclaimedMciOutcome::Step(_) | UnclaimedMciOutcome::UnexpectedBeginStep { .. }
                )
        });
        if !exact_result_ready {
            let deferred = worker.deferred_receipts.iter().any(|pending| {
                matches!(pending, DeferredWorkerReceipt::Begin { operation: current, .. } if current == operation)
            });
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                if deferred {
                    format!(
                        "MCI operation {} is still awaiting its original Begin result; no yield-frame identity is inferred",
                        operation.0
                    )
                } else {
                    format!(
                        "runtime retains MCI operation {} and its exact cached Begin result until guest projection completes",
                        operation.0
                    )
                },
            )));
        }
    }

    for deferred in &worker.deferred_receipts {
        match deferred {
            DeferredWorkerReceipt::Begin { operation, .. } => {
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::PendingBegin(*operation),
                );
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::Operation(*operation),
                );
                if !receipt.request.pending_begins.contains(operation) {
                    receipt.causes.push(Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        format!(
                            "native MCI Begin operation {} is absent from the runtime quiescence request",
                            operation.0
                        ),
                    )));
                }
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI operation {} is still awaiting its original Begin result; any yield frame remains unknown",
                        operation.0
                    ),
                )));
            }
            DeferredWorkerReceipt::Resume {
                operation,
                frame,
                expected,
                ..
            } => {
                retain_yield_owner(worker, &mut receipt.retained, *operation, *frame);
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI operation {} frame {} retains submitted guest WORD {} while the original Resume result is pending; this is not proof that YIELDPROC returned, and Runtime must reconcile it before yield-source retirement",
                        operation.0, frame.0, expected.guest_return
                    ),
                )));
            }
            DeferredWorkerReceipt::Quiesce {
                request,
                first_cause,
                phase,
                ..
            } => {
                retain_request_owners(&mut receipt.retained, request);
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "an earlier exact MCI quiescence request remains in phase {phase:?}; no duplicate request was enqueued"
                    ),
                )));
                if let Some(cause) = first_cause.as_ref() {
                    if !receipt
                        .resolved_causes
                        .iter()
                        .any(|existing| Arc::ptr_eq(existing, cause))
                    {
                        receipt.resolved_causes.push(Arc::clone(cause));
                    }
                }
            }
        }
    }
    if let Some(pending) = &worker.pending_producer_quiescence {
        retain_request_owners(&mut receipt.retained, &pending.request.owners);
        retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::OwnerThread);
        retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::NotificationSink);
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::CompatibilityGap,
            "MCI producer barrier remains enqueued with its exact response channel retained",
        )));
        if let Some(cause) = pending.first_cause.as_ref()
            && !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause))
        {
            receipt.resolved_causes.push(Arc::clone(cause));
        }
        for cause in &pending.prior_causes {
            if !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause)) {
                receipt.resolved_causes.push(Arc::clone(cause));
            }
        }
    }
    if let Some(completed) = &worker.completed_producer_quiescence {
        retain_request_owners(&mut receipt.retained, &completed.request.owners);
        retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::OwnerThread);
        retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::NotificationSink);
        match completed.result.as_ref() {
            Some(Ok(producer_receipt)) => {
                receipt.causes.extend(producer_receipt.barrier_causes.iter().cloned());
                receipt.causes.extend(producer_receipt.source_causes.iter().cloned());
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "MCI producer-barrier receipt remains retained for runtime reconciliation",
                )));
            }
            Some(Err(error)) => receipt.causes.push(Arc::clone(error)),
            None => receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI producer-barrier result was temporarily absent from its retained owner",
            ))),
        }
        if let Some(cause) = completed.first_cause.as_ref()
            && !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause))
        {
            receipt.resolved_causes.push(Arc::clone(cause));
        }
        for cause in &completed.prior_causes {
            if !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause)) {
                receipt.resolved_causes.push(Arc::clone(cause));
            }
        }
    }
    for unclaimed in &worker.unclaimed {
        match &unclaimed.outcome {
            UnclaimedMciOutcome::Step(step) if unclaimed.source_frame.is_none() => {
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::Operation(unclaimed.operation),
                );
                retain_step_owners(&mut receipt.retained, unclaimed.operation, step);
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI operation {} has an exact unclaimed Begin result that Runtime must consume before quiescence",
                        unclaimed.operation.0
                    ),
                )));
            }
            UnclaimedMciOutcome::Step(step) if unclaimed.source_frame.is_some() => {
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::Operation(unclaimed.operation),
                );
                retain_step_owners(&mut receipt.retained, unclaimed.operation, step);
                let frame = unclaimed
                    .source_frame
                    .expect("resume result retains its submitted source frame");
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI operation {} frame {} has an exact unclaimed Resume result that Runtime must consume before yield-source retirement",
                        unclaimed.operation.0, frame.0
                    ),
                )));
            }
            UnclaimedMciOutcome::UnexpectedBeginStep { actual, error }
                if unclaimed.source_frame.is_none() =>
            {
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::Operation(unclaimed.operation),
                );
                retain_step_owners(&mut receipt.retained, unclaimed.operation, actual);
                receipt.causes.push(Arc::clone(error));
            }
            UnclaimedMciOutcome::AwaitingYieldResult { expected } => {
                retain_yield_owner(
                    worker,
                    &mut receipt.retained,
                    unclaimed.operation,
                    expected.owner.frame,
                );
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI operation {} frame {} is awaiting the original native Resume result for submitted guest WORD {}; native YIELDPROC return is unproven",
                        unclaimed.operation.0,
                        expected.owner.frame.0,
                        expected.guest_return
                    ),
                )));
            }
            UnclaimedMciOutcome::UnexpectedStep { expected, actual, error } => {
                retain_yield_owner(
                    worker,
                    &mut receipt.retained,
                    unclaimed.operation,
                    expected.owner.frame,
                );
                retain_step_owners(&mut receipt.retained, unclaimed.operation, actual);
                receipt.causes.push(Arc::clone(error));
            }
            UnclaimedMciOutcome::Failure { error, frame, submitted_return } => {
                retain_owner(
                    &mut receipt.retained,
                    Win16HostMciRetainedOwner::Operation(unclaimed.operation),
                );
                if let Some(failure) = super::reconcile::entered_yield_failure(error) {
                    retain_entered_yield_failure_owners(
                        &mut receipt.retained,
                        unclaimed.operation,
                        failure,
                    );
                }
                if let Some(frame) = frame {
                    retain_yield_owner(
                        worker,
                        &mut receipt.retained,
                        unclaimed.operation,
                        *frame,
                    );
                } else if receipt.request.pending_begins.contains(&unclaimed.operation) {
                    retain_owner(
                        &mut receipt.retained,
                        Win16HostMciRetainedOwner::PendingBegin(unclaimed.operation),
                    );
                }
                let detail = match (frame, submitted_return) {
                    (Some(frame), Some(submitted)) => format!(
                        "MCI operation {} frame {} failed while reconciling submitted guest WORD {}; native YIELDPROC return remains unproven: {}",
                        unclaimed.operation.0,
                        frame.0,
                        submitted.guest_return,
                        error
                    ),
                    (Some(frame), None) => format!(
                        "MCI operation {} frame {} failed while reconciling its native Resume result; YIELDPROC return remains unproven: {}",
                        unclaimed.operation.0, frame.0, error
                    ),
                    (None, _) => format!(
                        "MCI operation {} retains its original worker failure: {}",
                        unclaimed.operation.0, error
                    ),
                };
                receipt.causes.push(Arc::new(RuntimeError::with_source(
                    error.kind(),
                    detail,
                    super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(error)),
                )));
            }
            _ => {}
        }
    }
    for (operation, pending) in &worker.pending {
        if let Some(frame) = pending.resume_in_flight {
            retain_yield_owner(worker, &mut receipt.retained, *operation, frame);
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "MCI operation {} frame {} marks Resume in flight without its exact submitted WORD receipt",
                    operation.0, frame.0
                ),
            )));
        }
    }
    retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::OwnerThread);
    retain_owner(&mut receipt.retained, Win16HostMciRetainedOwner::NotificationSink);
    if let Some(error) = wake_error {
        receipt.causes.push(error);
    }
    if receipt.causes.is_empty() {
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::CompatibilityGap,
            "MCI native owner remains retained until its exact Begin, Resume, or quiescence result and runtime consumer phase reconcile",
        )));
    }
    Ok(receipt)
}
