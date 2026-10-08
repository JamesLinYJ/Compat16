use super::*;

impl Win16Ole1ClientDdeJournal {
    pub(in crate::win16_runtime) fn committed_event(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Option<&Win16Ole1ClientDdeCommittedEvent> {
        self.committed_events.iter().find(|event| {
            event.event_id == event_id && event.owner == owner && event.endpoint == endpoint
        })
    }

    pub(in crate::win16_runtime) fn pending_call_for_operation(
        &self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
    ) -> Result<Win16Ole1ClientDdeCallId, &'static str> {
        let mut calls = self
            .pending
            .iter()
            .filter(|pending| pending.operation == Some(operation) && pending.owner == owner);
        let call = calls
            .next()
            .ok_or("OLE1 operation has no pending DDE transaction")?;
        if calls.next().is_some() {
            return Err("OLE1 operation has more than one pending DDE transaction");
        }
        Ok(call.id)
    }

    pub(in crate::win16_runtime) fn pending_call_matches(
        &self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        call: Win16Ole1ClientDdeCallId,
    ) -> bool {
        self.pending.iter().any(|pending| {
            pending.id == call && pending.operation == Some(operation) && pending.owner == owner
        })
    }

    /// Reserve the public OLE operation and DDE response correlation before
    /// issuing a real host Post. The returned disposition only means a typed
    /// host operation is ready; terminal acceptance still has to bind the
    /// exact transaction and, for EXECUTE, HGLOBAL transfer receipt.
    pub(in crate::win16_runtime) fn prepare_post_transaction(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        sent_message: u16,
        expected: Win16Ole1ExpectedReply,
        message: Win16ClassicDdeMessage,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        let message_matches = matches!(
            (&expected, &message),
            (
                Win16Ole1ExpectedReply::ExecuteAck,
                Win16ClassicDdeMessage::Execute { .. }
            ) | (
                Win16Ole1ExpectedReply::ItemAck { .. },
                Win16ClassicDdeMessage::Advise { .. }
            ) | (
                Win16Ole1ExpectedReply::ItemAck { .. },
                Win16ClassicDdeMessage::Unadvise { .. }
            ) | (
                Win16Ole1ExpectedReply::ItemAck { .. },
                Win16ClassicDdeMessage::Poke { .. }
            )
        );
        if !message_matches {
            return Err("OLE1 DDE host message does not match its transaction contract");
        }
        let call = self.reserve_call(
            Some(operation),
            owner,
            endpoint,
            peer,
            conversation,
            sent_message,
            expected,
        )?;
        let action = Win16Ole1ClientHostAction::PostTransaction {
            owner,
            endpoint,
            peer,
            conversation,
            call,
            sent_message,
        };
        if let Err(error) = self.queue_host_action(operation, action) {
            self.cancel_call(call)?;
            return Err(error);
        }
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation,
            call: Win16HostClassicDdeCall::Post {
                owner,
                endpoint,
                target: peer,
                conversation,
                transaction: None,
                message,
            },
            resume_callback: None,
        })
    }

    pub(in crate::win16_runtime) fn reserve_call(
        &mut self,
        operation: Option<Win16Ole1OperationId>,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        sent_message: u16,
        expected: Win16Ole1ExpectedReply,
    ) -> Result<Win16Ole1ClientDdeCallId, &'static str> {
        let message_matches_reply = match &expected {
            Win16Ole1ExpectedReply::ExecuteAck => sent_message == WM_DDE_EXECUTE,
            Win16Ole1ExpectedReply::ItemAck { .. } => {
                matches!(sent_message, WM_DDE_ADVISE | WM_DDE_UNADVISE | WM_DDE_POKE)
            }
        };
        if !message_matches_reply {
            return Err("OLE1 DDE request message does not match its declared reply contract");
        }
        if !self.conversations.iter().any(|current| {
            current.owner == owner
                && current.endpoint == endpoint
                && current.peer == peer
                && current.id == conversation
        }) {
            return Err("OLE1 DDE call has no exact live peer conversation");
        }
        // One outstanding call for each wire-visible response shape avoids
        // guessing when a peer omits the internal transaction correlation.
        if self.pending.iter().any(|current| {
            current.owner == owner
                && current.endpoint == endpoint
                && current.peer == peer
                && current.conversation == conversation
                && current.sent_message == sent_message
                && current.expected == expected
        }) {
            return Err("an indistinguishable OLE1 DDE call is already pending");
        }
        let value = self
            .next_call_id
            .ok_or("OLE1 DDE call identifiers are exhausted")?;
        let next = value.checked_add(1);
        self.pending
            .try_reserve(1)
            .map_err(|_| "OLE1 DDE pending-call table cannot grow")?;
        let id = Win16Ole1ClientDdeCallId(value);
        self.pending.push(Win16Ole1ClientDdePendingCall {
            id,
            operation,
            owner,
            endpoint,
            peer,
            conversation,
            sent_message,
            expected,
            transaction: None,
            transfer: None,
        });
        self.next_call_id = next;
        Ok(id)
    }

    /// Bind a transaction returned by the host to the exact call that caused
    /// it. Queue acceptance is recorded here only as correlation metadata; it
    /// is not a completion result.
    pub(in crate::win16_runtime) fn bind_post_receipt(
        &mut self,
        call_id: Win16Ole1ClientDdeCallId,
        receipt: &Win16HostClassicDdePostReceipt,
    ) -> Result<(), &'static str> {
        let call = self.pending_call_mut(call_id)?;
        if receipt.owner != call.owner
            || receipt.endpoint != call.endpoint
            || receipt.peer != call.peer
            || receipt.conversation != Some(call.conversation)
            || receipt.message != call.sent_message
            || !receipt.queued
        {
            return Err("classic DDE post receipt does not match the exact OLE1 call");
        }
        Self::bind_receipt_ids(call, receipt.transaction, receipt.transfer)
    }

    /// Inspect an inbound event without consuming it. The caller commits the
    /// higher-level OLE operation and only then acknowledges EventId delivery.
    pub(in crate::win16_runtime) fn correlate(
        &self,
        event: &Win16HostClassicDdeEvent,
    ) -> Win16Ole1ClientDdeMatch {
        let Some(conversation_id) = event.conversation else {
            return Win16Ole1ClientDdeMatch::NotOwned;
        };
        let mut matched = None;
        for call in &self.pending {
            if call.owner != event.owner
                || call.endpoint != event.endpoint
                || call.peer != event.peer
                || call.conversation != conversation_id
                || call.transaction.is_none()
            {
                continue;
            }
            if event.transaction.is_some() && event.transaction != call.transaction {
                continue;
            }
            let Some(response) = response_for(call, event) else {
                continue;
            };
            if matched.is_some() {
                return Win16Ole1ClientDdeMatch::Ambiguous;
            }
            matched = Some(response);
        }
        matched.map_or(
            Win16Ole1ClientDdeMatch::NotOwned,
            Win16Ole1ClientDdeMatch::Matched,
        )
    }

    /// Correlate one owned queued host event and retain its exact response
    /// before the caller acknowledges this EventId.
    /// A repeated EventId after a failed business step or delivery ACK is
    /// idempotent and cannot consume another pending call or lose its payload.
    pub(in crate::win16_runtime) fn commit_queued_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
    ) -> Result<Win16Ole1ClientDdeEventCommit, RuntimeError> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
        }
        if let Some(committed) = self
            .committed_events
            .iter()
            .find(|committed| committed.event_id == event.event_id)
        {
            if committed.owner != event.owner
                || committed.endpoint != event.endpoint
                || committed.peer != event.peer
                || Some(committed.conversation) != event.conversation
                || committed.transaction != event.transaction
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "classic DDE EventId was reused for another OLE1 transaction",
                ));
            }
            return Ok(Win16Ole1ClientDdeEventCommit::AlreadyCommitted(
                event.event_id,
            ));
        }
        if matches!(event.message, Win16ClassicDdeMessage::Terminate) {
            return self.commit_client_termination(event);
        }
        let selected = match self.correlate(&event) {
            Win16Ole1ClientDdeMatch::NotOwned => {
                return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
            }
            Win16Ole1ClientDdeMatch::Ambiguous => {
                return Ok(Win16Ole1ClientDdeEventCommit::Ambiguous(event));
            }
            Win16Ole1ClientDdeMatch::Matched(Win16Ole1ClientDdeResponse::Ack {
                operation,
                call,
                raw_status,
                acknowledged,
                busy,
                application_return_code,
            }) => SelectedResponse::Ack {
                operation,
                call,
                raw_status,
                acknowledged,
                busy,
                application_return_code,
            },
        };
        let Some(conversation) = event.conversation else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "matched OLE1 DDE response lost its conversation identity",
            ));
        };
        self.committed_events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve committed OLE1 DDE event journal",
                error,
            )
        })?;
        let response = match selected {
            SelectedResponse::Ack {
                operation,
                call,
                raw_status,
                acknowledged,
                busy,
                application_return_code,
            } => {
                self.complete_call(call)
                    .map_err(|message| RuntimeError::new(Kind::InternalInvariant, message))?;
                Win16Ole1ClientDdeCommittedResponse::Ack {
                    operation,
                    call,
                    raw_status,
                    acknowledged,
                    busy,
                    application_return_code,
                }
            }
        };
        let committed = Win16Ole1ClientDdeCommittedEvent {
            event_id: event.event_id,
            owner: event.owner,
            endpoint: event.endpoint,
            peer: event.peer,
            conversation,
            transaction: event.transaction,
            response,
        };
        let event_id = committed.event_id;
        self.committed_events.push(committed);
        Ok(Win16Ole1ClientDdeEventCommit::Committed(event_id))
    }

    /// Retire an exact retained response after its business continuation and
    /// host delivery acknowledgement have committed.
    pub(in crate::win16_runtime) fn acknowledge_committed_event(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<(), &'static str> {
        let Some(index) = self.committed_events.iter().position(|event| {
            event.event_id == event_id && event.owner == owner && event.endpoint == endpoint
        }) else {
            return Err("classic DDE delivery acknowledgement has no exact committed OLE1 event");
        };
        self.committed_events.remove(index);
        Ok(())
    }

    /// Consume only a call whose exact event has already been matched and
    /// whose event identity was committed by the caller's business journal.
    pub(in crate::win16_runtime) fn complete_call(
        &mut self,
        call_id: Win16Ole1ClientDdeCallId,
    ) -> Result<Win16Ole1ClientDdePendingCall, &'static str> {
        let Some(index) = self.pending.iter().position(|call| call.id == call_id) else {
            return Err("OLE1 DDE completion has no exact pending call");
        };
        Ok(self.pending.remove(index))
    }

    /// Drop a transaction only when its host Post failed before accepting the
    /// message. This is not used for a queued Post or an unreceived ACK.
    pub(in crate::win16_runtime) fn cancel_call(
        &mut self,
        call_id: Win16Ole1ClientDdeCallId,
    ) -> Result<Win16Ole1ClientDdePendingCall, &'static str> {
        let Some(index) = self.pending.iter().position(|call| call.id == call_id) else {
            return Err("OLE1 DDE cancellation has no exact pending call");
        };
        Ok(self.pending.remove(index))
    }

    fn pending_call_mut(
        &mut self,
        call_id: Win16Ole1ClientDdeCallId,
    ) -> Result<&mut Win16Ole1ClientDdePendingCall, &'static str> {
        self.pending
            .iter_mut()
            .find(|call| call.id == call_id)
            .ok_or("classic DDE receipt has no exact pending OLE1 call")
    }

    fn bind_receipt_ids(
        call: &mut Win16Ole1ClientDdePendingCall,
        transaction: Option<Win16ClassicDdeTransactionId>,
        transfer: Option<Win16ClassicDdeTransferId>,
    ) -> Result<(), &'static str> {
        if transaction.is_none() {
            return Err("OLE1 DDE call has no exact host transaction identity");
        }
        if matches!(call.expected, Win16Ole1ExpectedReply::ExecuteAck) && transfer.is_none() {
            return Err("OLE1 execute call has no exact transferred HGLOBAL identity");
        }
        if call.transaction.is_some() && call.transaction != transaction {
            return Err("OLE1 DDE transaction identity changed after binding");
        }
        if call.transfer.is_some() && call.transfer != transfer {
            return Err("OLE1 DDE transfer identity changed after binding");
        }
        call.transaction = transaction;
        call.transfer = transfer;
        Ok(())
    }
}

enum SelectedResponse {
    Ack {
        operation: Option<Win16Ole1OperationId>,
        call: Win16Ole1ClientDdeCallId,
        raw_status: u16,
        acknowledged: bool,
        busy: bool,
        application_return_code: u8,
    },
}

fn response_for(
    call: &Win16Ole1ClientDdePendingCall,
    event: &Win16HostClassicDdeEvent,
) -> Option<Win16Ole1ClientDdeResponse> {
    match (&call.expected, &event.message) {
        (
            Win16Ole1ExpectedReply::ExecuteAck,
            Win16ClassicDdeMessage::Ack {
                status,
                value: Win16ClassicDdeAckValue::ExecuteTransfer(Some(actual)),
            },
        ) if call.transfer == Some(*actual) => Some(Win16Ole1ClientDdeResponse::Ack {
            operation: call.operation,
            call: call.id,
            raw_status: status.raw,
            acknowledged: status.acknowledged,
            busy: status.busy,
            application_return_code: status.application_return_code,
        }),
        (
            Win16Ole1ExpectedReply::ItemAck { item_atom, .. },
            Win16ClassicDdeMessage::Ack {
                status,
                value: Win16ClassicDdeAckValue::ItemAtom(Some(atom)),
            },
        ) if atom_guest_word_matches(atom, *item_atom) => Some(Win16Ole1ClientDdeResponse::Ack {
            operation: call.operation,
            call: call.id,
            raw_status: status.raw,
            acknowledged: status.acknowledged,
            busy: status.busy,
            application_return_code: status.application_return_code,
        }),
        _ => None,
    }
}

fn atom_guest_word_matches(atom: &Win16ClassicDdeAtom, expected: u16) -> bool {
    atom_guest_word(atom) == Some(expected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16Ole1AtomIdentity {
    Match,
    Mismatch,
    Pending,
}

pub(super) fn atom_matches_or_waits(
    atom: &Win16ClassicDdeAtom,
    expected: u16,
) -> Win16Ole1AtomIdentity {
    match atom {
        Win16ClassicDdeAtom::Name {
            guest_value: Some(actual),
            ..
        } if *actual == expected => Win16Ole1AtomIdentity::Match,
        Win16ClassicDdeAtom::Name {
            guest_value: Some(_),
            ..
        }
        | Win16ClassicDdeAtom::Integer(_) => Win16Ole1AtomIdentity::Mismatch,
        Win16ClassicDdeAtom::Name {
            guest_value: None, ..
        } => Win16Ole1AtomIdentity::Pending,
    }
}

fn atom_guest_word(atom: &Win16ClassicDdeAtom) -> Option<u16> {
    match atom {
        Win16ClassicDdeAtom::Name { guest_value, .. } => *guest_value,
        Win16ClassicDdeAtom::Integer(_) => None,
    }
}
