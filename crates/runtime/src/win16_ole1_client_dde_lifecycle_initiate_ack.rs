use super::*;

pub(super) fn observe(
    journal: &mut Win16Ole1ClientDdeJournal,
    event: &Win16HostClassicDdeEvent,
    causal_parents: &[Win16ClassicDdeOperationIdentity],
) -> Result<Win16Ole1InitiateAckDecision, &'static str> {
    let Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id,
        callback,
        frame,
    } = event.delivery
    else {
        return Ok(Win16Ole1InitiateAckDecision::NotOwned);
    };
    let host = Win16ClassicDdeOperationIdentity {
        owner: event.owner,
        id: operation_id,
        worker_generation: event.worker_generation,
    };
    let Some(index) = journal.initiate_attempts.iter().position(|attempt| {
        attempt.host == Some(host)
            && attempt.owner == event.owner
            && attempt.endpoint == event.endpoint
    }) else {
        return Ok(Win16Ole1InitiateAckDecision::NotOwned);
    };
    let attempt = &journal.initiate_attempts[index];
    let (Some(application_atom), Some(topic_atom)) = (attempt.application_atom, attempt.topic_atom)
    else {
        return Ok(Win16Ole1InitiateAckDecision::AtomIdentityPending);
    };
    let matched = Win16Ole1ClientDdeJournal::match_initiate_ack(
        event,
        attempt.owner,
        attempt.endpoint,
        application_atom,
        topic_atom,
    );
    let matched = match matched {
        Win16Ole1InitiateAtomMatch::NotMatch => {
            return Ok(Win16Ole1InitiateAckDecision::NotOwned);
        }
        Win16Ole1InitiateAtomMatch::GuestIdentityPending => {
            return Ok(Win16Ole1InitiateAckDecision::AtomIdentityPending);
        }
        Win16Ole1InitiateAtomMatch::Matched(matched) => matched,
    };
    let application = clone_atom(matched.application)?;
    let topic = clone_atom(matched.topic)?;
    let candidate = Win16Ole1InitiateCandidate {
        operation: attempt.operation,
        source_operation: host,
        endpoint: attempt.endpoint,
        event_id: event.event_id,
        peer: matched.peer,
        callback,
        frame,
        causal_parents: {
            let mut parents = Vec::new();
            parents
                .try_reserve_exact(causal_parents.len())
                .map_err(|_| "OLE1 DDE callback causal chain cannot grow")?;
            parents.extend_from_slice(causal_parents);
            parents
        },
        application,
        topic,
    };
    let attempt = &journal.initiate_attempts[index];
    if let Some(first) = attempt.first_responder {
        if first.peer == candidate.peer {
            return Ok(Win16Ole1InitiateAckDecision::DuplicateResponder);
        }
        if attempt
            .pending_extra_responders
            .iter()
            .any(|pending| pending.peer == candidate.peer)
        {
            // Another callback for this peer may have a distinct frame,
            // but its pending BindConversation has not committed yet.
            // Keep that exact callback parked until the pending bind commits.
            return Ok(Win16Ole1InitiateAckDecision::BindingInProgress);
        }
        if attempt
            .extra_responders
            .iter()
            .any(|extra| extra.peer == candidate.peer)
        {
            return Ok(Win16Ole1InitiateAckDecision::DuplicateResponder);
        }
        let pending = clone_initiate_candidate(&candidate)?;
        journal.initiate_attempts[index]
            .pending_extra_responders
            .try_reserve(1)
            .map_err(|_| "OLE1 extra INITIATE responder table cannot grow")?;
        journal.initiate_attempts[index]
            .pending_extra_responders
            .push(pending);
        Ok(Win16Ole1InitiateAckDecision::ExtraResponder(candidate))
    } else if attempt.pending_first_responder.is_some() {
        // The first BindConversation terminal chooses the owning responder;
        // do not let concurrent binds reorder the first accepted peer.
        Ok(Win16Ole1InitiateAckDecision::BindingInProgress)
    } else {
        let pending = clone_initiate_candidate(&candidate)?;
        journal.initiate_attempts[index].pending_first_responder = Some(pending);
        Ok(Win16Ole1InitiateAckDecision::FirstResponder(candidate))
    }
}
