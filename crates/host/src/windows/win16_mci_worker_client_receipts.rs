use super::*;

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn drain_deferred_receipts(
        &mut self,
    ) -> Result<Option<RuntimeError>, RuntimeError> {
        let wake_error = if self.deferred_receipts.is_empty() {
            None
        } else {
            self.wake_owner().err()
        };
        enum Ready {
            Begin(Result<MciWorkerStep, RuntimeError>),
            BeginDisconnected,
            Resume(Result<(), RuntimeError>),
            ResumeDisconnected,
                Quiesce(Result<Win16HostMciQuiescenceReceipt, RuntimeError>),
                QuiesceDisconnected,
        }
        let mut index = 0;
        while index < self.deferred_receipts.len() {
            let ready = match &self.deferred_receipts[index] {
                DeferredWorkerReceipt::Begin { response, .. } => match response.try_recv() {
                    Ok(result) => Some(Ready::Begin(result)),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => Some(Ready::BeginDisconnected),
                },
                DeferredWorkerReceipt::Resume { accepted, .. } => match accepted.try_recv() {
                    Ok(result) => Some(Ready::Resume(result)),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => Some(Ready::ResumeDisconnected),
                },
                DeferredWorkerReceipt::Quiesce { response, .. } => match response.try_recv() {
                    Ok(result) => Some(Ready::Quiesce(result)),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => Some(Ready::QuiesceDisconnected),
                },
            };
            let Some(ready) = ready else {
                index += 1;
                continue;
            };
            let receipt = self.deferred_receipts.swap_remove(index);
            match (receipt, ready) {
                (
                    DeferredWorkerReceipt::Begin {
                        operation,
                        response,
                    },
                    Ready::Begin(result),
                ) => match result {
                    Ok(worker_step @ MciWorkerStep {
                        step: Win16HostMciStep::Complete(_),
                        ..
                    }) => {
                        self.unclaimed.push(UnclaimedMciOperation {
                            operation,
                            source_frame: None,
                            outcome: UnclaimedMciOutcome::Step(worker_step),
                        });
                    }
                    Ok(worker_step @ MciWorkerStep {
                        step: Win16HostMciStep::Yield(_),
                        ..
                    }) => {
                        let Win16HostMciStep::Yield(event) = &worker_step.step else {
                            unreachable!("matched MCI worker yield step")
                        };
                        let frame = event.frame;
                        let device = event.device;
                        self.pending.insert(
                            operation,
                            PendingOperation {
                                response,
                                frame,
                                device,
                                registration: event.registration,
                                resume_in_flight: None,
                            },
                        );
                        self.unclaimed.push(UnclaimedMciOperation {
                            operation,
                            source_frame: None,
                            outcome: UnclaimedMciOutcome::Step(worker_step),
                        });
                    }
                    Err(error) => self.unclaimed.push(UnclaimedMciOperation {
                        operation,
                        source_frame: None,
                        outcome: UnclaimedMciOutcome::Failure {
                            error: Arc::new(error),
                            frame: None,
                            submitted_return: None,
                        },
                    }),
                },
                (
                    DeferredWorkerReceipt::Begin {
                        operation,
                        response: _,
                    },
                    Ready::BeginDisconnected,
                ) => self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: None,
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::new(RuntimeError::new(
                            Kind::HostFailure,
                            "deferred MCI begin response channel disconnected before reconciliation",
                        )),
                        frame: None,
                        submitted_return: None,
                    },
                }),
                (
                    DeferredWorkerReceipt::Resume {
                        operation,
                        frame,
                        expected,
                        accepted: _,
                    },
                    Ready::Resume(Ok(())),
                ) => self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: Some(frame),
                    outcome: UnclaimedMciOutcome::AwaitingYieldResult { expected },
                }),
                (
                    DeferredWorkerReceipt::Resume {
                        operation,
                        frame,
                        expected,
                        accepted: _,
                    },
                    Ready::Resume(Err(error)),
                ) => self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: Some(frame),
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::new(error),
                        frame: Some(frame),
                        submitted_return: Some(expected),
                    },
                }),
                (
                    DeferredWorkerReceipt::Resume {
                        operation,
                        frame,
                        expected,
                        accepted: _,
                    },
                    Ready::ResumeDisconnected,
                ) => self.unclaimed.push(UnclaimedMciOperation {
                    operation,
                    source_frame: Some(frame),
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::new(RuntimeError::new(
                            Kind::HostFailure,
                            "deferred MCI resume acceptance channel disconnected before reconciliation",
                        )),
                        frame: Some(frame),
                        submitted_return: Some(expected),
                    },
                }),
                (
                    DeferredWorkerReceipt::Quiesce {
                        request,
                        first_cause,
                        phase,
                        ..
                    },
                    Ready::Quiesce(result),
                ) => {
                    if phase != MciQuiescencePhase::Enqueued {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "deferred MCI quiescence changed phase before its response was reconciled",
                        ));
                    }
                    // quiesce_requested reports allocation/snapshot Errs before effects; later native outcomes stay in its typed Ok receipt.
                    let phase = if result.is_ok() {
                        MciQuiescencePhase::ReceiptReady
                    } else {
                        MciQuiescencePhase::PreEffectFailure
                    };
                    let result = result.map_err(Arc::new);
                    let first_cause = first_cause.or_else(|| result.as_ref().err().cloned());
                    self.completed_quiescences.push(CompletedMciQuiescence {
                        request,
                        result,
                        phase,
                        first_cause,
                        result_delivered: false,
                    });
                }
                (
                    DeferredWorkerReceipt::Quiesce {
                        request,
                        first_cause,
                        phase,
                        ..
                    },
                    Ready::QuiesceDisconnected,
                ) => {
                    if phase != MciQuiescencePhase::Enqueued {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "deferred MCI quiescence disconnected outside its enqueued phase",
                        ));
                    }
                    let error = Arc::new(RuntimeError::new(
                        Kind::HostFailure,
                        "deferred MCI quiescence response channel disconnected; exact native owners remain retained",
                    ));
                    self.completed_quiescences.push(CompletedMciQuiescence {
                        request,
                        result: Err(Arc::clone(&error)),
                        phase: MciQuiescencePhase::OutcomeUnknown,
                        first_cause: first_cause.or(Some(error)),
                        result_delivered: false,
                    });
                }
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "deferred MCI receipt kind changed while polling its exact response channel",
                    ));
                }
            }
        }
        match self.drain_pending_receipts() {
            Ok(()) => Ok(wake_error),
            Err(receipt_error) => match wake_error {
                Some(wake_error) => Err(combine_worker_failures(
                    "deferred MCI receipt reconciliation and owner wake both failed",
                    "deferred receipt reconciliation",
                    receipt_error,
                    "native owner wake",
                    wake_error,
                )),
                None => Err(receipt_error),
            },
        }
    }

    fn drain_pending_receipts(&mut self) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < self.unclaimed.len() {
            let (operation, expected) = match &self.unclaimed[index].outcome {
                UnclaimedMciOutcome::AwaitingYieldResult { expected } => {
                    (self.unclaimed[index].operation, *expected)
                }
                _ => {
                    index += 1;
                    continue;
                }
            };
            let response = self
                .pending
                .get(&operation)
                .map(|pending| pending.response.try_recv());
            match response {
                Some(Ok(Ok(actual))) => {
                    let returned_matches = actual.returned_yield == Some(expected);
                    let operation_matches = matches!(
                        &actual.step,
                        Win16HostMciStep::Complete(_)
                    ) || matches!(
                        &actual.step,
                        Win16HostMciStep::Yield(event) if event.operation == operation
                    );
                    if !returned_matches || !operation_matches {
                        let error = Arc::new(RuntimeError::new(
                            Kind::InternalInvariant,
                            if !returned_matches {
                                "deferred MCI step does not ACK the exact accepted operation/frame/device/WORD"
                            } else {
                                "deferred MCI nested yield changed its operation identity"
                            },
                        ));
                        self.unclaimed[index].outcome = UnclaimedMciOutcome::UnexpectedStep {
                            expected,
                            actual,
                            error,
                        };
                        index += 1;
                        continue;
                    }
                    match &actual.step {
                        Win16HostMciStep::Yield(event) => {
                            let pending = self.pending.get_mut(&operation).ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "MCI yield owner disappeared while reconciling its deferred response",
                                )
                            })?;
                            pending.frame = event.frame;
                            pending.device = event.device;
                            pending.registration = event.registration;
                            pending.resume_in_flight = None;
                        }
                        Win16HostMciStep::Complete(_) => {
                            self.pending.remove(&operation);
                        }
                    }
                    self.unclaimed[index].outcome = UnclaimedMciOutcome::Step(actual);
                    index += 1;
                }
                Some(Ok(Err(error))) => {
                    self.unclaimed[index].outcome = UnclaimedMciOutcome::Failure {
                        error: Arc::new(error),
                        frame: Some(expected.owner.frame),
                        submitted_return: Some(expected),
                    };
                    index += 1;
                }
                Some(Err(TryRecvError::Empty)) => {
                    self.unclaimed[index].outcome = UnclaimedMciOutcome::AwaitingYieldResult {
                        expected,
                    };
                    index += 1;
                }
                Some(Err(TryRecvError::Disconnected)) => {
                    self.unclaimed[index].outcome = UnclaimedMciOutcome::Failure {
                        error: Arc::new(RuntimeError::new(
                            Kind::HostFailure,
                            "deferred MCI continuation response channel disconnected before reconciliation",
                        )),
                        frame: Some(expected.owner.frame),
                        submitted_return: Some(expected),
                    };
                    index += 1;
                }
                None => {
                    self.unclaimed[index].outcome = UnclaimedMciOutcome::Failure {
                        error: Arc::new(RuntimeError::new(
                            Kind::InternalInvariant,
                            "deferred MCI resume lost its retained operation response owner",
                        )),
                        frame: Some(expected.owner.frame),
                        submitted_return: Some(expected),
                    };
                    index += 1;
                }
            }
        }
        Ok(())
    }
}
