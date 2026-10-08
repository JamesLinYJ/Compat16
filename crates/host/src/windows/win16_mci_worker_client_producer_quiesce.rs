use super::*;
use std::sync::mpsc::TryRecvError;

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn quiesce_producers(
        &mut self,
        request: Win16HostMciProducerQuiescenceRequest,
    ) -> Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        let mut prior_cause = None;
        let mut prior_causes = Vec::new();
        if let Some(mut completed) = self.completed_producer_quiescence.take() {
            if completed.request != request {
                self.completed_producer_quiescence = Some(completed);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "a different exact MCI producer-barrier receipt remains retained",
                ));
            }
            if completed.outcome_unknown {
                let error = completed
                    .result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .cloned()
                    .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "unknown MCI producer-barrier outcome lost its typed cause",
                    )
                })?;
                self.completed_producer_quiescence = Some(completed);
                return Err(RuntimeError::with_source(
                    error.kind(),
                    "MCI producer barrier retains an unknown native outcome and will not be duplicated",
                    error,
                ));
            }
            if let Some(Err(error)) = completed.result.as_ref() {
                // A worker-returned error is emitted only before the source
                // gate is closed. Retry that exact request, carrying forward
                // both the original failure and any earlier wake failure.
                let error = Arc::clone(error);
                if !completed.prior_causes.iter().any(|cause| Arc::ptr_eq(cause, &error)) {
                    if let Err(reserve_error) = completed.prior_causes.try_reserve(1) {
                        self.completed_producer_quiescence = Some(completed);
                        return Err(RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "retain the original MCI producer-barrier failure before retry",
                            reserve_error,
                        ));
                    }
                    completed.prior_causes.push(Arc::clone(&error));
                }
                prior_cause = completed
                    .first_cause
                    .clone()
                    .or_else(|| Some(error));
                prior_causes = completed.prior_causes;
            } else {
                let Some(Ok(receipt)) = completed.result.as_mut() else {
                    unreachable!("MCI producer receipt was checked as successful")
                };
                if let Err(error) = append_producer_causes(
                    receipt,
                    completed.first_cause.as_ref(),
                    &completed.prior_causes,
                ) {
                    self.completed_producer_quiescence = Some(completed);
                    return Err(error);
                }
                let Ok(receipt) = completed.result.take().expect(
                    "successful MCI producer receipt remains cached until it is delivered",
                )
                else {
                    unreachable!("successful MCI producer receipt remained successful")
                };
                return Ok(receipt);
            }
        }

        if let Some(pending) = self.pending_producer_quiescence.take() {
            if pending.request != request {
                self.pending_producer_quiescence = Some(pending);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "a different exact MCI producer-barrier response remains in flight",
                ));
            }
            return self.finish_pending_producer_quiescence(pending);
        }

        let command_request = try_clone_producer_request(&request)?;
        let (response, receive) = mpsc::channel();
        self.enqueue(WorkerCommand::QuiesceProducers {
            request: command_request,
            response,
        })?;
        match self.wake_owner() {
            Ok(()) => match receive.recv() {
                Ok(result) => self.deliver_producer_quiescence(
                    request,
                    result,
                    prior_cause,
                    prior_causes,
                ),
                Err(error) => {
                    let error = Arc::new(RuntimeError::with_source(
                        Kind::HostFailure,
                        "receive MCI producer-barrier result; its native outcome is unknown",
                        error,
                    ));
                    self.completed_producer_quiescence = Some(
                        CompletedMciProducerQuiescence {
                            request,
                            result: Some(Err(Arc::clone(&error))),
                            first_cause: prior_cause.or(Some(Arc::clone(&error))),
                            prior_causes,
                            outcome_unknown: true,
                        },
                    );
                    Err(RuntimeError::with_source(
                        error.kind(),
                        "MCI producer barrier retains its exact request after response loss",
                        error,
                    ))
                }
            },
            Err(error) => {
                let cause = Arc::new(error);
                self.pending_producer_quiescence = Some(PendingMciProducerQuiescence {
                    request,
                    response: receive,
                    first_cause: prior_cause.or_else(|| Some(Arc::clone(&cause))),
                    prior_causes,
                });
                Err(RuntimeError::with_source(
                    cause.kind(),
                    "MCI producer barrier is enqueued; its exact response owner remains retained",
                    cause,
                ))
            }
        }
    }

    fn finish_pending_producer_quiescence(
        &mut self,
        mut pending: PendingMciProducerQuiescence,
    ) -> Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        match pending.response.try_recv() {
            Ok(result) => self.deliver_producer_quiescence(
                pending.request,
                result,
                pending.first_cause,
                pending.prior_causes,
            ),
            Err(TryRecvError::Disconnected) => {
                let error = Arc::new(RuntimeError::new(
                    Kind::HostFailure,
                    "MCI producer-barrier response channel disconnected; native outcome is unknown",
                ));
                self.completed_producer_quiescence = Some(CompletedMciProducerQuiescence {
                    request: pending.request,
                    result: Some(Err(Arc::clone(&error))),
                    first_cause: pending.first_cause.or(Some(Arc::clone(&error))),
                    prior_causes: pending.prior_causes,
                    outcome_unknown: true,
                });
                Err(RuntimeError::with_source(
                    error.kind(),
                    "MCI producer barrier retains its exact request after response loss",
                    error,
                ))
            }
            Err(TryRecvError::Empty) => match self.wake_owner() {
                Err(error) => {
                    let cause = Arc::new(error);
                    if pending.first_cause.is_none() {
                        pending.first_cause = Some(Arc::clone(&cause));
                    }
                    self.pending_producer_quiescence = Some(pending);
                    Err(RuntimeError::with_source(
                        cause.kind(),
                        "MCI producer barrier still owns its exact pending worker response",
                        cause,
                    ))
                }
                Ok(()) => match pending.response.recv() {
                    Ok(result) => self.deliver_producer_quiescence(
                        pending.request,
                        result,
                        pending.first_cause,
                        pending.prior_causes,
                    ),
                    Err(error) => {
                        let error = Arc::new(RuntimeError::with_source(
                            Kind::HostFailure,
                            "receive retained MCI producer-barrier response; native outcome is unknown",
                            error,
                        ));
                        self.completed_producer_quiescence = Some(
                            CompletedMciProducerQuiescence {
                                request: pending.request,
                                result: Some(Err(Arc::clone(&error))),
                                first_cause: pending.first_cause.or(Some(Arc::clone(&error))),
                                prior_causes: pending.prior_causes,
                                outcome_unknown: true,
                            },
                        );
                        Err(RuntimeError::with_source(
                            error.kind(),
                            "MCI producer barrier retains its exact request after response loss",
                            error,
                        ))
                    }
                },
            },
        }
    }

    fn deliver_producer_quiescence(
        &mut self,
        request: Win16HostMciProducerQuiescenceRequest,
        result: Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError>,
        first_cause: Option<Arc<RuntimeError>>,
        prior_causes: Vec<Arc<RuntimeError>>,
    ) -> Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
        match result {
            Ok(mut receipt) => {
                if receipt.request != request {
                    let error = Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "MCI producer-barrier worker receipt changed the exact owner request",
                    ));
                    self.completed_producer_quiescence = Some(CompletedMciProducerQuiescence {
                        request,
                        result: Some(Err(Arc::clone(&error))),
                        first_cause: Some(Arc::clone(&error)),
                        prior_causes,
                        outcome_unknown: true,
                    });
                    return Err(RuntimeError::with_source(
                        error.kind(),
                        "MCI producer barrier retains a mismatched native receipt",
                        error,
                    ));
                }
                if let Err(error) = append_producer_causes(
                    &mut receipt,
                    first_cause.as_ref(),
                    &prior_causes,
                ) {
                    self.completed_producer_quiescence = Some(CompletedMciProducerQuiescence {
                        request,
                        result: Some(Ok(receipt)),
                        first_cause,
                        prior_causes,
                        outcome_unknown: false,
                    });
                    return Err(error);
                }
                Ok(receipt)
            }
            Err(error) => {
                let error = Arc::new(error);
                let first_cause = first_cause.or_else(|| Some(Arc::clone(&error)));
                self.completed_producer_quiescence = Some(CompletedMciProducerQuiescence {
                    request,
                    result: Some(Err(Arc::clone(&error))),
                    first_cause: first_cause.clone(),
                    prior_causes,
                    outcome_unknown: false,
                });
                let reported = RuntimeError::with_source(
                    error.kind(),
                    "MCI producer barrier retains its exact pre-effect failure for retry",
                    Arc::clone(&error),
                );
                if let Some(first) = first_cause.filter(|first| !Arc::ptr_eq(first, &error)) {
                    Err(reported.with_cleanup(
                        "MCI producer barrier also retained an earlier owner or wake failure",
                        RuntimeError::with_source(
                            first.kind(),
                            "first MCI producer-barrier failure",
                            first,
                        ),
                    ))
                } else {
                    Err(reported)
                }
            }
        }
    }
}

fn append_producer_causes(
    receipt: &mut Win16HostMciProducerQuiescenceReceipt,
    first_cause: Option<&Arc<RuntimeError>>,
    prior_causes: &[Arc<RuntimeError>],
) -> Result<(), RuntimeError> {
    let mut missing = 0usize;
    for cause in prior_causes.iter().chain(first_cause.into_iter()) {
        if !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause)) {
            missing = missing.saturating_add(1);
        }
    }
    receipt.resolved_causes.try_reserve(missing).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain prior MCI producer-barrier failure and wake causes",
            error,
        )
    })?;
    for cause in prior_causes.iter().chain(first_cause.into_iter()) {
        if !receipt.resolved_causes.iter().any(|existing| Arc::ptr_eq(existing, cause)) {
            receipt.resolved_causes.push(Arc::clone(cause));
        }
    }
    Ok(())
}

fn try_clone_producer_request(
    request: &Win16HostMciProducerQuiescenceRequest,
) -> Result<Win16HostMciProducerQuiescenceRequest, RuntimeError> {
    let source = &request.owners;
    let mut owners = Win16HostMciQuiesceRequest::default();
    owners.devices.try_reserve_exact(source.devices.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer device owners", error)
    })?;
    owners.registrations.try_reserve_exact(source.registrations.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer registrations", error)
    })?;
    owners.pending_begins.try_reserve_exact(source.pending_begins.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer Begin owners", error)
    })?;
    owners.active_yields.try_reserve_exact(source.active_yields.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer active yields", error)
    })?;
    owners.returned_yields.try_reserve_exact(source.returned_yields.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer returned yields", error)
    })?;
    owners.completed_operations.try_reserve_exact(source.completed_operations.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer completions", error)
    })?;
    owners.resolved_causes.try_reserve_exact(source.resolved_causes.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI producer cause history", error)
    })?;
    owners.devices.extend_from_slice(&source.devices);
    owners.registrations.extend_from_slice(&source.registrations);
    owners.pending_begins.extend_from_slice(&source.pending_begins);
    owners.active_yields.extend_from_slice(&source.active_yields);
    owners.returned_yields.extend_from_slice(&source.returned_yields);
    owners.completed_operations.extend_from_slice(&source.completed_operations);
    owners.resolved_causes.extend(source.resolved_causes.iter().cloned());
    Ok(Win16HostMciProducerQuiescenceRequest { owners })
}
