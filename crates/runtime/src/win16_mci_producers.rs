use std::sync::Arc;

use super::{
    Win16MciNotificationPost, Win16MciPendingNotification, Win16State,
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostMciProducerQuiescenceFailure, Win16HostMciProducerQuiescenceRequest,
    Win16HostMciQuiesceRequest, Win16HostMciQuiescenceEvidence,
    Win16WindowAbortReceipt, Win16WindowTerminalSourceTop,
};

fn producer_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, message)
}

impl Win16State {
    /// Retire only already accepted MCI events after USER source admission has
    /// been aborted. This path never starts a new POST operation.
    pub(in crate::win16_runtime) fn retire_mci_notifications_after_windows_abort(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self
            .window_abort_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.request_id != 0 && receipt.worker_generation != 0)
            || !self
                .mci
                .producer_quiescence_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.producers_stopped())
        {
            return Err(producer_error(
                "MCI notification retirement requires the exact USER abort receipt and producer barrier",
            ));
        }
        loop {
            if self.mci.pending_notification.is_none() {
                let Some(event) = host.win16_mci_peek_notification()? else {
                    return Ok(true);
                };
                self.mci.pending_notification = Some(Win16MciPendingNotification {
                    event,
                    post: Win16MciNotificationPost::ResolveTarget,
                });
            }
            let event = self
                .mci
                .pending_notification
                .as_ref()
                .expect("MCI event is installed before teardown retirement")
                .event;
            if event.source.id == 0
                || event.source.id == u64::MAX
                || event.source.generation == 0
                || event.source.generation != event.device.generation
                || event.device.token == 0
                || event.source.sequence == 0
                || event.source.sequence != event.id.0
            {
                return Err(producer_error(
                    "retained MCI event changed its exact shared source identity during USER abort",
                ));
            }
            let post = std::mem::replace(
                &mut self.mci.pending_notification.as_mut().expect("MCI event exists").post,
                Win16MciNotificationPost::ResolveTarget,
            );
            macro_rules! restore_post {
                ($post:expr) => {
                    self.mci
                        .pending_notification
                        .as_mut()
                        .expect("MCI event remains owned until exact MCI source ACK")
                        .post = $post
                };
            }
            match post {
                Win16MciNotificationPost::ResolveTarget => {
                    // No USER operation was started for this accepted MCI
                    // event; retire its exact MCI FIFO source directly.
                    restore_post!(Win16MciNotificationPost::ResolveTarget);
                    self.acknowledge_mci_source_after_abort(event, host)?;
                }
                ready @ Win16MciNotificationPost::Ready(_) => {
                    // Preserve the concrete notification while retiring only
                    // its exact native MCI source after task abort.
                    restore_post!(ready);
                    self.acknowledge_mci_source_after_abort(event, host)?;
                }
                Win16MciNotificationPost::NormalProof {
                    notification,
                    proof,
                    result,
                    posted,
                } => {
                    let result_posted = match result.as_ref() {
                        crate::Win16WindowStep::Complete(
                            crate::Win16WindowResult::NotificationPosted(value),
                        ) => Some(*value),
                        _ => None,
                    };
                    if proof.operation.kind
                        != crate::Win16NativeWindowOperationKind::PostGuestNotification
                        || proof.operation.operation_id.0 == 0
                        || proof.worker_generation == 0
                        || proof.state != crate::Win16NativeWindowOperationState::Returned
                        || result_posted != Some(posted)
                    {
                        restore_post!(Win16MciNotificationPost::NormalProof {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        return Err(producer_error(
                            "MCI POST proof lost its exact returned USER operation or concrete result",
                        ));
                    }
                    let readback = match host.win16_window_source_retirement(
                        proof.operation,
                        proof.worker_generation,
                    ) {
                        Ok(readback) => readback,
                        Err(error) => {
                            restore_post!(Win16MciNotificationPost::NormalProof {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            return Err(error);
                        }
                    };
                    if !readback
                        .as_ref()
                        .is_some_and(|recorded| std::sync::Arc::ptr_eq(recorded, &proof))
                    {
                        restore_post!(Win16MciNotificationPost::NormalProof {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        return Err(producer_error(
                            "MCI POST carrier lacks the same exact retained USER source proof",
                        ));
                    }
                    if let Err(error) = host.win16_window_source_retirement_consumed(&proof) {
                        restore_post!(Win16MciNotificationPost::NormalProof {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        return Err(error);
                    }
                    restore_post!(Win16MciNotificationPost::NormalConsumed {
                        notification,
                        proof,
                        result,
                        posted,
                    });
                }
                Win16MciNotificationPost::NormalConsumed {
                    notification,
                    proof,
                    result,
                    posted,
                } => {
                    if posted {
                        restore_post!(Win16MciNotificationPost::NormalConsumed {
                            notification,
                            proof,
                            result,
                            posted,
                        });
                        self.acknowledge_mci_source_after_abort(event, host)?;
                        continue;
                    }
                    match host.win16_host_window_liveness(event.target) {
                        Ok(crate::Win16HostWindowLiveness::Retired) => {
                            restore_post!(Win16MciNotificationPost::RetiredTarget);
                            self.acknowledge_mci_source_after_abort(event, host)?;
                        }
                        Ok(crate::Win16HostWindowLiveness::Live) => {
                            // USER proof has been consumed. Preserve this same
                            // MCI event for the next safe point; abort forbids
                            // re-submitting the POST during teardown.
                            restore_post!(Win16MciNotificationPost::Ready(notification));
                            return Ok(true);
                        }
                        Err(error) => {
                            restore_post!(Win16MciNotificationPost::NormalConsumed {
                                notification,
                                proof,
                                result,
                                posted,
                            });
                            return Err(error);
                        }
                    }
                }
                Win16MciNotificationPost::TerminalFailure(failure) => {
                    let acknowledgement = crate::Win16WindowTerminalAck {
                        worker_generation: failure.worker_generation,
                        operation: failure.operation.clone(),
                        state: failure.state,
                        callbacks: Vec::new(),
                        modals: Vec::new(),
                    };
                    let abort = self
                        .window_abort_receipt
                        .as_ref()
                        .expect("validated USER abort receipt remains cached");
                    match host.win16_window_terminal_acknowledged(abort, &acknowledgement) {
                        Ok(true) => {
                            restore_post!(Win16MciNotificationPost::TerminalAcknowledged(
                                Arc::clone(&failure),
                            ));
                            self.acknowledge_mci_source_after_abort(event, host)?;
                        }
                        Ok(false) => {
                            restore_post!(Win16MciNotificationPost::TerminalFailure(failure));
                            return Ok(false);
                        }
                        Err(error) => {
                            restore_post!(Win16MciNotificationPost::TerminalFailure(failure));
                            return Err(error);
                        }
                    }
                }
                Win16MciNotificationPost::TerminalAcknowledged(failure) => {
                    restore_post!(Win16MciNotificationPost::TerminalAcknowledged(failure));
                    self.acknowledge_mci_source_after_abort(event, host)?;
                }
                Win16MciNotificationPost::RetiredTarget => {
                    restore_post!(Win16MciNotificationPost::RetiredTarget);
                    self.acknowledge_mci_source_after_abort(event, host)?;
                }
                Win16MciNotificationPost::Unexpected { proof, step } => {
                    let error = super::unexpected_mci_post_error(proof.as_ref(), step.as_ref());
                    restore_post!(Win16MciNotificationPost::Unexpected { proof, step });
                    return Err(error);
                }
            }
        }
    }

    fn acknowledge_mci_source_after_abort(
        &mut self,
        event: crate::Win16HostMciNotification,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !self
            .mci
            .pending_notification
            .as_ref()
            .is_some_and(|pending| pending.event == event)
        {
            return Err(producer_error(
                "MCI event owner changed before its exact post-abort source ACK",
            ));
        }
        host.win16_mci_ack_notification(event.source)
            .map_err(|error| error.with_context("retire exact accepted MCI event after USER abort"))?;
        self.mci.pending_notification = None;
        Ok(())
    }

    /// Stop new native MCI notification/yield sources without closing devices
    /// or consuming the exact MCI event that owns a terminal USER POST.
    pub(in crate::win16_runtime) fn quiesce_mci_producers(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.mci.producer_quiescence_request.is_none() {
            let owners = self.mci_quiesce_request()?;
            self.mci.producer_quiescence_request = Some(
                Win16HostMciProducerQuiescenceRequest { owners },
            );
        }
        let request = self
            .mci
            .producer_quiescence_request
            .as_ref()
            .expect("MCI producer request remains owned until full native quiescence");
        self.mci
            .retired_yield_sources
            .try_reserve(request.owners.registrations.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MCI yield-source tombstones before producer quiescence",
                    error,
                )
            })?;
        self.mci
            .resolved_finish_causes
            .try_reserve(
                request
                    .owners
                    .resolved_causes
                    .len()
                    .saturating_add(request.owners.registrations.len()),
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MCI producer-resolution cause history before the host barrier",
                    error,
                )
            })?;
        self.mci.quiescence_causes.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI producer-barrier host failure before native effects",
                error,
            )
        })?;
        let host_request = clone_producer_request(request)?;
        let receipt = match host.win16_mci_quiesce_producers(host_request) {
            Ok(receipt) => receipt,
            Err(error) => {
                let cause = std::sync::Arc::new(error);
                self.mci.quiescence_causes.push(std::sync::Arc::clone(&cause));
                return Err(RuntimeError::with_source(
                    cause.kind(),
                    "MCI producer barrier retains its exact request and host outcome",
                    cause,
                ));
            }
        };
        let receipt = std::sync::Arc::new(receipt);
        self.mci.producer_quiescence_receipt = Some(std::sync::Arc::clone(&receipt));
        if &receipt.request != request {
            return Err(producer_failure(receipt));
        }

        for evidence in &receipt.source_disable_evidence {
            let Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                owner,
                observed_installed: false,
                ..
            } = evidence
            else {
                continue;
            };
            if self.mci.yield_procedures.get(&owner.device).is_some_and(|entry| {
                entry.registration == owner.registration
            }) {
                self.mci.yield_procedures.remove(&owner.device);
            }
            if !self.mci.retired_yield_sources.contains(owner) {
                self.mci.retired_yield_sources.push(*owner);
            }
        }
        for cause in &receipt.resolved_causes {
            if !self
                .mci
                .resolved_finish_causes
                .iter()
                .any(|existing| std::sync::Arc::ptr_eq(existing, cause))
            {
                self.mci.resolved_finish_causes.push(std::sync::Arc::clone(cause));
            }
        }
        if !receipt.producers_stopped() {
            return Err(producer_failure(receipt));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn owns_terminal_mci_post_source(
        &self,
        top: &Win16WindowTerminalSourceTop,
    ) -> Result<bool, RuntimeError> {
        if !self
            .mci
            .producer_quiescence_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.producers_stopped())
        {
            return Err(producer_error(
                "MCI terminal POST owner remains retained until the producer barrier is confirmed",
            ));
        }
        let Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top
        else {
            return Ok(false);
        };
        if *kind != crate::Win16NativeWindowOperationKind::PostGuestNotification {
            return Ok(false);
        }
        let Some(pending) = self.mci.pending_notification.as_ref() else {
            return Ok(false);
        };
        let Win16MciNotificationPost::TerminalFailure(failure) = &pending.post else {
            return Ok(false);
        };
        Ok(failure.operation.operation_id == *operation
            && failure.operation.kind == *kind
            && failure.state == *state
            && failure.worker_generation == *worker_generation)
    }

    pub(in crate::win16_runtime) fn retire_mci_terminal_post_source(
        &mut self,
        receipt: &Win16WindowAbortReceipt,
        top: &Win16WindowTerminalSourceTop,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.owns_terminal_mci_post_source(top)? {
            return Ok(false);
        }
        if self.window_abort_receipt.as_ref() != Some(receipt) {
            return Err(producer_error(
                "MCI terminal POST was offered a USER abort receipt other than its exact cached receipt",
            ));
        }
        let Win16WindowTerminalSourceTop::User {
            operation,
            kind,
            state,
            worker_generation,
        } = top
        else {
            return Ok(false);
        };
        let pending = self.mci.pending_notification.as_ref().ok_or_else(|| {
            producer_error("MCI terminal POST row disappeared after exact-top preflight")
        })?;
        let event = pending.event;
        let Win16MciNotificationPost::TerminalFailure(failure) = &pending.post else {
            return Ok(false);
        };
        let failure = std::sync::Arc::clone(failure);
        if failure.operation.operation_id != *operation
            || failure.operation.kind != *kind
            || failure.state != *state
            || failure.worker_generation != *worker_generation
            || event.source.id == 0
            || event.source.id == u64::MAX
            || event.source.generation == 0
            || event.source.generation != event.device.generation
            || event.source.sequence == 0
            || event.source.sequence != event.id.0
        {
            return Err(producer_error(
                "MCI terminal POST source changed its exact USER operation or native event identity",
            ));
        }
        // The shared helper re-reads this exact cached abort receipt and the
        // USER top, then performs only the USER terminal ACK. MCI retains its
        // event owner until its separate exact source ACK below.
        self.acknowledge_started_post_failure(&failure, host)?;
        let acknowledgement = crate::Win16WindowTerminalAck {
            worker_generation: failure.worker_generation,
            operation: failure.operation.clone(),
            state: failure.state,
            callbacks: Vec::new(),
            modals: Vec::new(),
        };
        if !host.win16_window_terminal_acknowledged(receipt, &acknowledgement)? {
            return Err(producer_error(
                "USER terminal ACK returned without the exact cached tombstone readback",
            ));
        }
        let pending = self.mci.pending_notification.as_mut().ok_or_else(|| {
            producer_error("MCI terminal POST owner disappeared after USER source retirement")
        })?;
        if pending.event != event
            || !matches!(&pending.post,
                Win16MciNotificationPost::TerminalFailure(current)
                    if std::sync::Arc::ptr_eq(current, &failure))
        {
            return Err(producer_error(
                "MCI terminal POST USER ACK lost its exact MCI event owner",
            ));
        }
        pending.post = Win16MciNotificationPost::TerminalAcknowledged(std::sync::Arc::clone(&failure));
        if let Err(error) = host.win16_mci_ack_notification(event.source) {
            return Err(error.with_context("retire exact MCI source after USER terminal ACK"));
        }
        if !self.mci.pending_notification.as_ref().is_some_and(|pending| {
            pending.event == event
                && matches!(&pending.post,
                    Win16MciNotificationPost::TerminalAcknowledged(current)
                        if std::sync::Arc::ptr_eq(current, &failure))
        }) {
            return Err(producer_error(
                "MCI exact source ACK lost its retained terminal event owner",
            ));
        }
        self.mci.pending_notification = None;
        Ok(true)
    }
}

fn producer_failure(
    receipt: std::sync::Arc<crate::Win16HostMciProducerQuiescenceReceipt>,
) -> RuntimeError {
    let kind = receipt
        .barrier_causes
        .first()
        .or_else(|| receipt.source_causes.first())
        .map_or(Kind::CompatibilityGap, |cause| cause.kind());
    RuntimeError::with_source(
        kind,
        "MCI producer barrier retains exact native source, event, and active-operation owners",
        Win16HostMciProducerQuiescenceFailure { receipt },
    )
}

fn clone_producer_request(
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
