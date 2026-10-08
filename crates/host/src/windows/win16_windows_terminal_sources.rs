//! USER host ownership, ACK, and source-retirement receipts.

use super::*;

impl Win16Windows {
    pub(in crate::windows) fn retain_terminal_modal_operation_states(
        &mut self,
        receipt: &Win16WindowAbortReceipt,
    ) -> Result<(), RuntimeError> {
        if receipt.worker_generation == 0 || receipt.request_id == 0 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "modal terminal owner cache requires a real USER abort receipt"));
        }
        if self.terminal_abort.as_ref().is_some_and(|cached| cached != receipt) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "modal terminal owner cache received a changed abort receipt"));
        }

        let mut updates = Vec::new();
        updates.try_reserve_exact(receipt.cancelled_modals.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact modal operation-owner bindings", error)
        })?;
        for (modal_index, modal) in receipt.cancelled_modals.iter().enumerate() {
            if modal.operation_id == 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "modal terminal receipt contains a zero operation identity"));
            }
            let mut matches = self.pending.iter().enumerate().filter(|(_, pending)| {
                pending.id == modal.operation_id
            });
            let Some((pending_index, pending)) = matches.next() else {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "modal cancellation has no retained USER operation owner"));
            };
            if matches.next().is_some()
                || pending.worker_generation != receipt.worker_generation
                || pending.modal_work_history != modal.retired_guest_work
                || pending.terminal_modal_receipt_index.is_some_and(|prior| prior != modal_index)
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "modal response does not match one exact pending USER owner and work history"));
            }
            let active_for_id = receipt.active_operations.iter().filter(|proof| {
                proof.operation_id.0 == modal.operation_id
            }).count();
            match pending.native_state {
                Win16NativeWindowOperationState::Active
                    if active_for_id == 0
                        && pending.response_error.is_none()
                        && pending.terminal_started_failure.is_none() => {}
                Win16NativeWindowOperationState::Returned
                    if active_for_id == 0
                        && pending.terminal_started_failure.as_ref().is_none_or(|failure| {
                            failure.operation.operation_id.0 == pending.id
                                && failure.operation.kind == pending.kind
                                && failure.worker_generation == pending.worker_generation
                                && failure.state == Win16NativeWindowOperationState::Returned
                        })
                        && pending.completion.is_none()
                        && pending.terminal_modal_receipt_index
                            .is_none_or(|prior| prior == modal_index) => {}
                _ => return Err(RuntimeError::new(Kind::HostFailure,
                    "modal cancellation lacks a real stopped USER operation phase")),
            }
            updates.push((pending_index, modal_index));
        }

        // All owner and receipt checks are complete before changing a phase.
        for (pending_index, modal_index) in updates {
            let pending = &mut self.pending[pending_index];
            pending.native_state = Win16NativeWindowOperationState::Returned;
            pending.terminal_modal_receipt_index = Some(modal_index);
        }
        Ok(())
    }

    pub(in crate::windows) fn terminal_ack(
        &mut self,
        ack: Win16WindowTerminalAck,
    ) -> Result<(), RuntimeError> {
        if let Some(previous) = self.terminal_acknowledgements.iter().find(|item| {
            item.operation.operation_id == ack.operation.operation_id
        }) {
            return if previous == &ack {
                Ok(())
            } else {
                Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER terminal operation was acknowledged with a changed receipt"))
            };
        }
        let receipt = self.terminal_abort.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 USER terminal source acknowledgement preceded its retained abort receipt",
        ))?;
        if ack.worker_generation == 0
            || ack.worker_generation != receipt.worker_generation
            || ack.operation.operation_id.0 == 0
            || receipt.worker_generation == 0
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER terminal acknowledgement changed its worker or operation identity"));
        }
        let mut pending_matches = self.pending.iter().enumerate().filter(|(_, pending)| {
            pending.id == ack.operation.operation_id.0
        });
        let Some((pending_index, pending)) = pending_matches.next() else {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal operation owner is no longer retained by the host"));
        };
        if pending_matches.next().is_some()
            || pending.kind != ack.operation.kind
            || pending.worker_generation != ack.worker_generation
            || pending.completion.is_some()
            || self.pending.last().map(|operation| operation.id)
                != Some(ack.operation.operation_id.0)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER terminal operation is not the exact top pending host owner"));
        }
        let active_proofs = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == ack.operation.operation_id
                && proof.kind == ack.operation.kind
        }).count();
        let active_for_id = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == ack.operation.operation_id
        }).count();
        match ack.state {
            Win16NativeWindowOperationState::Active
                if active_proofs == 1 && active_for_id == 1
                    && pending.native_state == Win16NativeWindowOperationState::Active
                    && pending.response_error.is_none()
                    && pending.terminal_modal_receipt_index.is_none() => {}
            Win16NativeWindowOperationState::Returned
                if active_for_id == 0
                    && pending.native_state == Win16NativeWindowOperationState::Returned
                    && (pending.terminal_started_failure.as_ref().is_some_and(|failure| {
                        failure.operation.operation_id == ack.operation.operation_id
                            && failure.operation.kind == ack.operation.kind
                            && failure.worker_generation == ack.worker_generation
                            && failure.state == Win16NativeWindowOperationState::Returned
                            && pending.terminal_modal_receipt_index.is_none()
                    }) || self.pending_modal_cancellation_matches(
                        pending, receipt, ack.operation.operation_id.0,
                    )) => {}
            _ => return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal ACK lacks the operation's exact stopped-state proof")),
        }

        let mut expected_callbacks = Vec::new();
        expected_callbacks.try_reserve_exact(receipt.cancelled_callbacks.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact USER callback source ACK list",
            error,
        ))?;
        expected_callbacks.extend(receipt.cancelled_callbacks.iter().copied().filter(|item| {
            item.operation_id == ack.operation.operation_id
        }));
        if ack.callbacks != expected_callbacks
            || expected_callbacks.len() > 1
            || expected_callbacks.first().is_some_and(|source| {
                pending.awaiting != Some(source.callback)
                    || pending.awaiting_source != Some(*source)
            })
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER callback source ACK does not match the cancelled native callback"));
        }

        let mut expected_modals = Vec::new();
        expected_modals.try_reserve_exact(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id.0
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact USER modal source ACK list",
            error,
        ))?;
        expected_modals.extend(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id.0
        }).cloned());
        if ack.modals != expected_modals || expected_modals.len() > 1 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER modal slot ACK does not match its exact retained cancellation result"));
        }
        if let Some(modal) = expected_modals.first() {
            if modal.retired_guest_work != pending.modal_work_history {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "Win16 modal cancellation does not retire the exact retained guest-work identities"));
            }
        } else if !pending.modal_work_history.is_empty() {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 modal guest-work source has no matching terminal cancellation receipt"));
        }

        let mut source_matches = self.dde_sources.pending.iter().enumerate().filter(|(_, source)| {
            matches!(source, PendingSource::User { id }
                if *id == ack.operation.operation_id.0)
        });
        let Some((source_index, _)) = source_matches.next() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER operation source ledger does not contain one exact pending identity"));
        };
        if source_matches.next().is_some()
            || self.dde_sources.pending.last() != Some(&PendingSource::User {
                id: ack.operation.operation_id.0,
            })
            || source_index + 1 != self.dde_sources.pending.len()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER operation source is not the exact LIFO top identity"));
        }
        self.terminal_acknowledgements.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain exact Win16 USER terminal ACK for retry-safe replay",
                error,
            )
        })?;

        // All identity, callback, modal, and worker-state checks precede the
        // paired source-stack retirement. Nothing fallible follows the first
        // removal, so a negative ACK leaves both owners intact.
        self.dde_sources.pending.remove(source_index);
        self.pending.remove(pending_index);
        self.terminal_acknowledgements.push(ack);
        Ok(())
    }

    /// Read back whether this exact terminal ACK already retired its source.
    /// `false` is returned only after validating the same ACK against the
    /// current exact source top and pending host owner; unknown or changed
    /// identities are errors rather than evidence that an ACK is absent.
    pub(in crate::windows) fn terminal_acknowledged(
        &self,
        receipt: &Win16WindowAbortReceipt,
        ack: &Win16WindowTerminalAck,
    ) -> Result<bool, RuntimeError> {
        if self.terminal_abort.as_ref() != Some(receipt)
            || receipt.worker_generation == 0
            || receipt.request_id == 0
            || ack.worker_generation != receipt.worker_generation
            || ack.operation.operation_id.0 == 0
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal ACK readback changed its cached receipt identity"));
        }
        let mut cached = self.terminal_acknowledgements.iter().filter(|previous| {
            previous.operation.operation_id == ack.operation.operation_id
        });
        if let Some(previous) = cached.next() {
            if cached.next().is_some() || previous != ack {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "Win16 USER terminal ACK readback found a changed or duplicate tombstone"));
            }
            return Ok(true);
        }

        let top = self.terminal_source_top(receipt)?;
        if top != Some(Win16WindowTerminalSourceTop::User {
            operation: ack.operation.operation_id,
            kind: ack.operation.kind,
            state: ack.state,
            worker_generation: ack.worker_generation,
        }) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal ACK readback is not the exact live shared-source top"));
        }
        let mut owners = self.pending.iter().filter(|pending| {
            pending.id == ack.operation.operation_id.0
        });
        let pending = owners.next().ok_or_else(|| RuntimeError::new(Kind::HostFailure,
            "Win16 USER terminal ACK readback has no exact live operation owner"))?;
        if owners.next().is_some()
            || self.pending.last().map(|item| item.id) != Some(pending.id)
            || pending.kind != ack.operation.kind
            || pending.worker_generation != ack.worker_generation
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal ACK readback is not the exact top host operation"));
        }

        let mut expected_callbacks = Vec::new();
        expected_callbacks.try_reserve_exact(receipt.cancelled_callbacks.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve USER terminal ACK readback callback identities",
            error,
        ))?;
        expected_callbacks.extend(receipt.cancelled_callbacks.iter().copied().filter(|item| {
            item.operation_id == ack.operation.operation_id
        }));
        let mut expected_modals = Vec::new();
        expected_modals.try_reserve_exact(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id.0
        }).count()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve USER terminal ACK readback modal identities",
            error,
        ))?;
        expected_modals.extend(receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == ack.operation.operation_id.0
        }).cloned());
        if expected_callbacks.len() > 1
            || expected_modals.len() > 1
            || ack.callbacks != expected_callbacks
            || ack.modals != expected_modals
            || expected_callbacks.first().is_some_and(|source| {
                pending.awaiting != Some(source.callback)
                    || pending.awaiting_source != Some(*source)
            })
            || expected_modals.first().is_some_and(|modal| {
                modal.retired_guest_work != pending.modal_work_history
            })
            || expected_modals.is_empty() && !pending.modal_work_history.is_empty()
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER terminal ACK readback differs from exact callback or modal sources"));
        }
        Ok(false)
    }

    pub(in crate::windows) fn terminal_source_top(
        &self,
        receipt: &Win16WindowAbortReceipt,
    ) -> Result<Option<Win16WindowTerminalSourceTop>, RuntimeError> {
        if self.terminal_abort.as_ref() != Some(receipt)
            || receipt.worker_generation == 0
            || receipt.request_id == 0
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER/DDE source-top query changed the cached abort receipt identity"));
        }
        match self.dde_sources.pending.last().copied() {
            Some(PendingSource::User { id }) => {
                if id == 0 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 USER/DDE source ledger has a zero USER operation identity"));
                }
                let mut owners = self.pending.iter().filter(|pending| pending.id == id);
                let pending = owners.next().ok_or_else(|| RuntimeError::new(Kind::HostFailure,
                    "shared source ledger top has no exact pending USER owner"))?;
                if owners.next().is_some() || pending.worker_generation != receipt.worker_generation {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "shared source ledger top has a duplicate or foreign USER owner"));
                }
                let operation = Win16HostWindowOperationId(id);
                let active_count = receipt.active_operations.iter().filter(|proof| {
                    proof.operation_id == operation && proof.kind == pending.kind
                }).count();
                let active_for_id = receipt.active_operations.iter().filter(|proof| {
                    proof.operation_id == operation
                }).count();
                let state = if pending.native_state == Win16NativeWindowOperationState::Returned {
                    let returned_failure = pending.terminal_started_failure.as_ref()
                        .is_some_and(|failure| {
                            failure.operation.operation_id == operation
                                && failure.operation.kind == pending.kind
                                && failure.worker_generation == pending.worker_generation
                                && failure.state == Win16NativeWindowOperationState::Returned
                        }) && pending.terminal_modal_receipt_index.is_none();
                    let returned_modal = self.pending_modal_cancellation_matches(
                        pending, receipt, id,
                    );
                    if active_for_id != 0 || !(returned_failure || returned_modal)
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "returned USER source top lacks its exact failure or modal cancellation proof"));
                    }
                    Win16NativeWindowOperationState::Returned
                } else {
                    let failure_matches = pending.terminal_started_failure.as_ref().is_none_or(|failure| {
                        failure.operation.operation_id == operation
                            && failure.operation.kind == pending.kind
                            && failure.worker_generation == pending.worker_generation
                            && failure.state == Win16NativeWindowOperationState::Active
                    });
                    if active_count != 1 || active_for_id != 1
                        || pending.response_error.is_some()
                        || pending.terminal_modal_receipt_index.is_some()
                        || !failure_matches
                    {
                        return Err(RuntimeError::new(Kind::HostFailure,
                            "active USER source top lacks one exact native operation proof"));
                    }
                    Win16NativeWindowOperationState::Active
                };
                Ok(Some(Win16WindowTerminalSourceTop::User {
                    operation,
                    kind: pending.kind,
                    state,
                    worker_generation: pending.worker_generation,
                }))
            }
            Some(PendingSource::Dde { operation }) => {
                if operation.0 == 0 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "shared source ledger has a zero DDE operation identity"));
                }
                Ok(Some(Win16WindowTerminalSourceTop::Dde { operation }))
            }
            None if self.pending.is_empty() => Ok(None),
            None => Err(RuntimeError::new(Kind::HostFailure,
                "shared source ledger is empty while a pending USER operation remains")),
        }
    }

    fn pending_modal_cancellation_matches(
        &self,
        pending: &PendingOperation,
        receipt: &Win16WindowAbortReceipt,
        operation_id: u64,
    ) -> bool {
        let Some(index) = pending.terminal_modal_receipt_index else {
            return false;
        };
        let Some(modal) = receipt.cancelled_modals.get(index) else {
            return false;
        };
        pending.terminal_started_failure.is_none()
            && pending.native_state == Win16NativeWindowOperationState::Returned
            && pending.response_error.is_none()
            && modal.operation_id == operation_id
            && modal.retired_guest_work == pending.modal_work_history
            && receipt.cancelled_modals.iter().filter(|candidate| {
                candidate.operation_id == operation_id
            }).count() == 1
    }

    pub(in crate::windows) fn source_retirement(
        &self,
        operation: Win16NativeWindowOperationProof,
        worker_generation: u64,
    ) -> Result<Option<Arc<Win16WindowSourceRetiredProof>>, RuntimeError> {
        if operation.operation_id.0 == 0 || worker_generation == 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 normal source proof query has a zero operation or worker identity"));
        }
        let mut cached = self.source_retirements.iter().filter(|proof| {
            proof.operation == operation && proof.worker_generation == worker_generation
        });
        if let Some(proof) = cached.next() {
            if cached.next().is_some()
                || proof.state != Win16NativeWindowOperationState::Returned
                || self.pending.iter().any(|pending| {
                    pending.id == operation.operation_id.0
                })
                || self.dde_sources.pending.iter().any(|source| {
                    *source == (PendingSource::User {
                        id: operation.operation_id.0,
                    })
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 normal source proof cache contains a duplicate, live, or non-returned owner"));
            }
            return Ok(Some(Arc::clone(proof)));
        }
        if self.source_retirements.iter().any(|proof| {
            proof.operation.operation_id == operation.operation_id
        }) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 normal source proof query changed kind or worker generation"));
        }

        let mut owners = self.pending.iter().filter(|pending| {
            pending.id == operation.operation_id.0
        });
        let pending = owners.next().ok_or_else(|| RuntimeError::new(Kind::HostFailure,
            "Win16 normal source proof query names neither a live operation nor a retired source"))?;
        if owners.next().is_some()
            || pending.kind != operation.kind
            || pending.worker_generation != worker_generation
            || pending.response_error.is_some()
            || self.dde_sources.pending.last() != Some(&PendingSource::User {
                id: operation.operation_id.0,
            })
            || self.dde_sources.pending.iter().filter(|source| {
                **source == (PendingSource::User {
                    id: operation.operation_id.0,
                })
            }).count() != 1
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 normal source proof query does not match one exact live USER owner"));
        }
        let source_is_live = match pending.native_state {
            Win16NativeWindowOperationState::Active => pending.completion.is_none()
                && pending.terminal_started_failure.is_none(),
            Win16NativeWindowOperationState::Returned => {
                let Some(completion) = pending.completion.as_ref() else {
                    return Err(RuntimeError::new(Kind::HostFailure,
                        "returned USER owner has neither a cached completion nor source tombstone"));
                };
                let failure_matches = pending.terminal_started_failure.as_ref().is_none_or(|failure| {
                    failure.operation == operation
                        && failure.worker_generation == worker_generation
                        && failure.state == Win16NativeWindowOperationState::Returned
                });
                failure_matches
                    && matches!(&completion.step, Win16WindowStep::Complete(_))
                    && completion.source_proof.as_ref().is_none_or(|proof| {
                        proof.operation == operation
                            && proof.worker_generation == worker_generation
                            && proof.state == Win16NativeWindowOperationState::Returned
                    })
            }
        };
        if !source_is_live {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 normal source proof query does not match one exact live USER owner"));
        }
        Ok(None)
    }

    pub(in crate::windows) fn source_retirement_consumed(
        &mut self,
        proof: &Win16WindowSourceRetiredProof,
    ) -> Result<(), RuntimeError> {
        if proof.operation.operation_id.0 == 0
            || proof.worker_generation == 0
            || proof.state != Win16NativeWindowOperationState::Returned
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 normal source tombstone release has an invalid returned proof"));
        }
        let mut exact = self.source_retirements.iter().enumerate().filter(|(_, cached)| {
            cached.as_ref() == proof
        });
        let Some((index, _)) = exact.next() else {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 normal source tombstone release has no exact cached proof"));
        };
        if exact.next().is_some()
            || self.source_retirements.iter().enumerate().any(|(other, cached)| {
                other != index
                    && cached.operation.operation_id == proof.operation.operation_id
            })
            || self.pending.iter().any(|pending| {
                pending.id == proof.operation.operation_id.0
            })
            || self.dde_sources.pending.iter().any(|source| {
                *source == (PendingSource::User {
                    id: proof.operation.operation_id.0,
                })
            })
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 normal source proof cache has duplicate or live owner identities"));
        }
        self.source_retirements.remove(index);
        Ok(())
    }

    pub(super) fn validate_terminal_abort_receipt(
        &self,
        receipt: &Win16WindowAbortReceipt,
    ) -> Result<(), RuntimeError> {
        let generation = self.worker.as_ref().map(WindowWorker::worker_generation)
            .ok_or_else(|| self.worker_start_failure())?;
        if receipt.worker_generation == 0
            || receipt.request_id == 0
            || receipt.worker_generation != generation
            || !receipt.active_operation_stack_empty
            || !receipt.callback_stack_empty
            || !receipt.modal_scope_stack_empty
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "Win16 USER abort receipt does not prove the exact worker's native stacks quiesced"));
        }
        for (index, proof) in receipt.active_operations.iter().enumerate() {
            if proof.operation_id.0 == 0
                || receipt.active_operations[..index].iter().any(|prior| {
                    prior.operation_id == proof.operation_id
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicated an active host operation"));
            }
            let matching = self.pending.iter().filter(|pending| {
                pending.id == proof.operation_id.0
                    && pending.kind == proof.kind
                    && pending.worker_generation == receipt.worker_generation
                    && pending.native_state == Win16NativeWindowOperationState::Active
                    && pending.response_error.is_none()
            }).count();
            if matching != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native USER operation proof has no exact pending host operation source"));
            }
        }
        for pending in &self.pending {
            if pending.worker_generation != receipt.worker_generation {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "pending USER operation belongs to a different worker generation"));
            }
            if (pending.pending_modal_guest_work.is_some()
                && pending.resumed_modal_work.is_some())
                || pending.resumed_modal_work.is_some_and(|work| {
                    work.operation_id.0 != pending.id
                        || pending.modal_work_history.iter()
                            .filter(|item| **item == work).count() != 1
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "pending USER modal continuation differs from its exact retained history"));
            }
            let active = receipt.active_operations.iter().any(|proof| {
                proof.operation_id.0 == pending.id
            });
            let mut modal_matches = receipt.cancelled_modals.iter().enumerate().filter(|(_, modal)| {
                modal.operation_id == pending.id
            });
            let modal_match = modal_matches.next();
            if modal_matches.next().is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "pending USER operation has duplicate modal cancellation responses"));
            }
            let modal_index = modal_match.map(|(index, _)| index);
            let phase_matches = match pending.native_state {
                Win16NativeWindowOperationState::Active => {
                    (active && pending.response_error.is_none()
                        && pending.terminal_modal_receipt_index.is_none()
                        && modal_index.is_none())
                        || (!active && pending.response_error.is_none()
                            && pending.terminal_started_failure.is_none()
                            && pending.terminal_modal_receipt_index.is_none()
                            && modal_index.is_some())
                }
                Win16NativeWindowOperationState::Returned => {
                    let failure_matches = pending.terminal_started_failure.as_ref().is_some_and(|failure| {
                            failure.operation.operation_id.0 == pending.id
                                && failure.operation.kind == pending.kind
                                && failure.worker_generation == pending.worker_generation
                                && failure.state == Win16NativeWindowOperationState::Returned
                        });
                    let has_modal_owner = pending.pending_modal_guest_work.is_some()
                        || pending.resumed_modal_work.is_some()
                        || !pending.modal_work_history.is_empty();
                    !active && (
                        failure_matches
                            && (modal_index.is_some() || !has_modal_owner)
                        || pending.terminal_started_failure.is_none()
                            && modal_index.is_some()
                    )
                }
            };
            if !phase_matches {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "pending USER operation has no exact active or returned terminal state"));
            }
        }
        for (index, callback) in receipt.cancelled_callbacks.iter().enumerate() {
            if callback.callback.0 == 0
                || callback.operation_id.0 == 0
                || receipt.cancelled_callbacks[..index].iter().any(|prior| {
                    prior.callback == callback.callback
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicated or zeroed a callback source"));
            }
            let matching = self.pending.iter().filter(|pending| {
                pending.id == callback.operation_id.0
                    && pending.awaiting == Some(callback.callback)
                    && pending.awaiting_source == Some(*callback)
            }).count();
            if matching != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native USER callback source has no exact pending callback ACK owner"));
            }
        }
        for pending in &self.pending {
            if pending.awaiting.is_some() && !receipt.cancelled_callbacks.iter().any(|item| {
                item.operation_id.0 == pending.id && Some(item.callback) == pending.awaiting
            }) {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "pending USER callback has no exact native cancellation source proof"));
            }
        }
        for (index, modal) in receipt.cancelled_modals.iter().enumerate() {
            if modal.operation_id == 0
                || receipt.cancelled_modals[..index].iter().any(|prior| {
                    prior.operation_id == modal.operation_id
                })
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 USER abort receipt duplicated or zeroed a modal operation"));
            }
            let matching = self.pending.iter().filter(|pending| {
                pending.id == modal.operation_id
                    && pending.worker_generation == receipt.worker_generation
                    && pending.modal_work_history == modal.retired_guest_work
            }).count();
            if matching != 1 {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "native modal cancellation has no exact retained owner or work history"));
            }
        }
        Ok(())
    }
}
