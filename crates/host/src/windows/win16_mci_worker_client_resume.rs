use super::*;

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn resume(
        &mut self,
        resume: Win16HostMciResume,
    ) -> Result<Win16HostMciResumeReceipt, RuntimeError> {
        let wake_error = self.drain_deferred_receipts()?;
        if let Some(index) = self
            .unclaimed
            .iter()
            .position(|operation| operation.operation == resume.operation)
        {
            if self.unclaimed[index].source_frame != Some(resume.frame) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "reconciled MCI result belongs to a different submitted yield frame",
                ));
            }
            return match &self.unclaimed[index].outcome {
                UnclaimedMciOutcome::Step(worker_step) => {
                    let returned_yield = worker_step.returned_yield.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "reconciled MCI resume step omitted its exact worker ACK tombstone",
                        )
                    })?;
                    if returned_yield.owner.operation != resume.operation
                        || returned_yield.owner.frame != resume.frame
                        || returned_yield.guest_return != resume.return_value
                    {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "reconciled MCI step does not ACK the exact operation/frame/WORD submitted",
                        ));
                    }
                    if matches!(
                        &worker_step.step,
                        Win16HostMciStep::Yield(event) if event.operation != resume.operation
                    ) {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "reconciled MCI nested yield changed its operation identity; full native receipt remains retained",
                        ));
                    }
                    if matches!(&worker_step.step, Win16HostMciStep::Yield(_))
                        && !self.pending.contains_key(&resume.operation)
                    {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "reconciled MCI nested yield lost its exact operation owner; full step remains retained",
                        ));
                    }
                    if let Some(error) = wake_error {
                        return Err(error);
                    }
                    let worker_step = match self.unclaimed.swap_remove(index).outcome {
                        UnclaimedMciOutcome::Step(step) => step,
                        _ => unreachable!("checked MCI resume outcome remains a step"),
                    };
                    match worker_step.step {
                        Win16HostMciStep::Yield(event) => {
                            let pending = self.pending.get_mut(&resume.operation).ok_or_else(|| {
                                RuntimeError::new(
                                    Kind::InternalInvariant,
                                    "reconciled MCI yield lost its exact operation owner",
                                )
                            })?;
                            pending.frame = event.frame;
                            pending.device = event.device;
                            pending.registration = event.registration;
                            pending.resume_in_flight = None;
                            Ok(Win16HostMciResumeReceipt {
                                returned_yield,
                                step: Win16HostMciStep::Yield(event),
                            })
                        }
                        complete @ Win16HostMciStep::Complete(_) => {
                            self.pending.remove(&resume.operation);
                            Ok(Win16HostMciResumeReceipt {
                                returned_yield,
                                step: complete,
                            })
                        }
                    }
                }
                UnclaimedMciOutcome::UnexpectedStep {
                    expected,
                    error,
                    ..
                } => {
                    let pending = self.pending.get(&resume.operation).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "unexpected MCI step lost its exact pending operation owner",
                        )
                    })?;
                    let submitted = Win16HostMciYieldReturn {
                        owner: Win16HostMciActiveYield {
                            operation: resume.operation,
                            frame: resume.frame,
                            device: pending.device,
                        },
                        guest_return: resume.return_value,
                    };
                    if *expected != submitted {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "unexpected MCI receipt remains attached to a different submitted response",
                        ));
                    }
                    if let Some(error) = wake_error {
                        return Err(error);
                    }
                    Err(RuntimeError::with_source(
                        error.kind(),
                        "native MCI returned an unexpected exact step; operation and receipt remain retained",
                        super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(error)),
                    ))
                }
                UnclaimedMciOutcome::UnexpectedBeginStep { error, .. } => {
                    Err(RuntimeError::with_source(
                        error.kind(),
                        "native MCI begin receipt remains unexpected and retained",
                        super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(error)),
                    ))
                }
                UnclaimedMciOutcome::Failure {
                    error,
                    frame,
                    ..
                } => {
                    Err(RuntimeError::with_source(
                        error.kind(),
                        format!(
                            "MCI resume for operation {} frame {} retains its original worker failure",
                            resume.operation.0,
                            (*frame).map_or(resume.frame.0, |frame| frame.0)
                        ),
                        super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(error)),
                    ))
                }
                UnclaimedMciOutcome::AwaitingYieldResult { .. } => {
                    Err(self.receipt_blocker(wake_error))
                }
            };
        }
        if !self.deferred_receipts.is_empty()
            || !self.completed_quiescences.is_empty()
            || !self.unclaimed.is_empty()
        {
            return Err(self.receipt_blocker(wake_error));
        }
        if let Some(error) = wake_error {
            return Err(error);
        }
        let Some(pending) = self.pending.get(&resume.operation) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI resume references an operation without retained response ownership",
            ));
        };
        if pending.frame != resume.frame && pending.resume_in_flight != Some(resume.frame) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI resume references a different yield frame than the owner retains",
            ));
        }
        let expected = Win16HostMciYieldReturn {
            owner: Win16HostMciActiveYield {
                operation: resume.operation,
                frame: resume.frame,
                device: pending.device,
            },
            guest_return: resume.return_value,
        };
        if pending.resume_in_flight.is_none() {
            self.deferred_receipts.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MCI resume receipt owner",
                    error,
                )
            })?;
            self.unclaimed.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve retained MCI continuation reconciliation",
                    error,
                )
            })?;
            let (accepted, receive_acceptance) = mpsc::channel();
            self.enqueue(WorkerCommand::Resume { resume, accepted })?;
            self.pending
                .get_mut(&resume.operation)
                .expect("validated MCI operation remains pending")
                .resume_in_flight = Some(resume.frame);
            if let Err(error) = self.wake_owner() {
                self.deferred_receipts.push(DeferredWorkerReceipt::Resume {
                    operation: resume.operation,
                    frame: resume.frame,
                    expected,
                    accepted: receive_acceptance,
                });
                return Err(error.with_context(format!(
                    "MCI resume for operation {} frame {} is enqueued with acceptance retained",
                    resume.operation.0, resume.frame.0
                )));
            }
            match receive_acceptance.recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let error = Arc::new(error);
                    self.unclaimed.push(UnclaimedMciOperation {
                        operation: resume.operation,
                        source_frame: Some(resume.frame),
                outcome: UnclaimedMciOutcome::Failure {
                    error: Arc::clone(&error),
                    frame: Some(resume.frame),
                    submitted_return: Some(expected),
                },
                    });
                    return Err(RuntimeError::with_source(
                        error.kind(),
                        "native MCI worker rejected the exact submitted yield-frame response",
                        super::super::quarantine::RetainedMciRuntimeError::new(error),
                    ));
                }
                Err(error) => {
                    self.deferred_receipts.push(DeferredWorkerReceipt::Resume {
                        operation: resume.operation,
                        frame: resume.frame,
                        expected,
                        accepted: receive_acceptance,
                    });
                    return Err(RuntimeError::with_source(
                        Kind::HostFailure,
                        "receive MCI yield-frame acceptance; exact submitted response remains retained",
                        error,
                    ));
                }
            }
        }
        let response = self
            .pending
            .get(&resume.operation)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI operation disappeared while resuming",
                )
            })?
            .response
            .recv();
        let worker_step = match response {
            Ok(Ok(step)) => step,
            Ok(Err(error)) => {
                let error = Arc::new(error);
                self.unclaimed.push(UnclaimedMciOperation {
                    operation: resume.operation,
                    source_frame: Some(resume.frame),
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::clone(&error),
                        frame: Some(resume.frame),
                        submitted_return: Some(expected),
                    },
                });
                return Err(RuntimeError::with_source(
                    error.kind(),
                    "native MCI continuation failed; exact operation and yield frame remain retained",
                    super::super::quarantine::RetainedMciRuntimeError::new(error),
                ));
            }
            Err(error) => {
                let error = Arc::new(RuntimeError::with_source(
                    Kind::HostFailure,
                    "receive native MCI yield continuation; exact operation and frame remain retained",
                    error,
                ));
                self.unclaimed.push(UnclaimedMciOperation {
                    operation: resume.operation,
                    source_frame: Some(resume.frame),
                    outcome: UnclaimedMciOutcome::Failure {
                        error: Arc::clone(&error),
                        frame: Some(resume.frame),
                        submitted_return: Some(expected),
                    },
                });
                return Err(RuntimeError::with_source(
                    error.kind(),
                    "native MCI response channel disconnected with an exact operation owner retained",
                    super::super::quarantine::RetainedMciRuntimeError::new(error),
                ));
            }
        };
        if worker_step.returned_yield != Some(expected) {
            let error = Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI worker step does not ACK the exact operation/frame/device/WORD submitted",
            ));
            self.unclaimed.push(UnclaimedMciOperation {
                operation: resume.operation,
                source_frame: Some(resume.frame),
                outcome: UnclaimedMciOutcome::UnexpectedStep {
                    expected,
                    actual: worker_step,
                    error: Arc::clone(&error),
                },
            });
            return Err(RuntimeError::with_source(
                error.kind(),
                "native MCI worker step does not ACK the exact submitted response; full native receipt remains retained",
                super::super::quarantine::RetainedMciRuntimeError::new(error),
            ));
        }
        if matches!(
            &worker_step.step,
            Win16HostMciStep::Yield(event) if event.operation != resume.operation
        ) {
            let error = Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI nested yield changed its operation identity",
            ));
            self.unclaimed.push(UnclaimedMciOperation {
                operation: resume.operation,
                source_frame: Some(resume.frame),
                outcome: UnclaimedMciOutcome::UnexpectedStep {
                    expected,
                    actual: worker_step,
                    error: Arc::clone(&error),
                },
            });
            return Err(RuntimeError::with_source(
                error.kind(),
                "MCI nested yield changed its operation identity; full native receipt remains retained",
                super::super::quarantine::RetainedMciRuntimeError::new(error),
            ));
        }
        match worker_step.step {
            Win16HostMciStep::Yield(event) => {
                let pending = self.pending.get_mut(&resume.operation).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "MCI operation disappeared during nested yield",
                    )
                })?;
                pending.frame = event.frame;
                pending.device = event.device;
                pending.registration = event.registration;
                pending.resume_in_flight = None;
                Ok(Win16HostMciResumeReceipt {
                    returned_yield: expected,
                    step: Win16HostMciStep::Yield(event),
                })
            }
            complete @ Win16HostMciStep::Complete(_) => {
                self.pending.remove(&resume.operation);
                Ok(Win16HostMciResumeReceipt {
                    returned_yield: expected,
                    step: complete,
                })
            }
        }
    }
}
