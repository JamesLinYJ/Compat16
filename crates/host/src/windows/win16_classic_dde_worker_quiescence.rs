use super::*;

pub(super) fn quiesce_owner(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    requested_id: Option<runtime::Win16ClassicDdeQuiescenceId>,
) -> Result<runtime::Win16HostClassicDdeResult, RuntimeError> {
    if identity.owner != owner || identity.worker_generation == 0 {
        return Err(invariant("classic DDE owner quiescence crossed owner or worker generation"));
    }
    let id = {
        let mut worker = state.borrow_mut();
        if worker.worker_retirement_id != identity.worker_generation {
            return Err(invariant("classic DDE quiescence worker generation changed"));
        }
        match worker.classic_dde_quiescing_owners.get(&owner) {
            Some(existing) => {
                if requested_id.is_some_and(|requested| requested != existing.id)
                    || existing.worker_generation != identity.worker_generation
                {
                    return Err(RuntimeError::new(Kind::InvalidInput,
                        "classic DDE quiescence retry changed its exact owner barrier"));
                }
                existing.id
            }
            None => {
                if requested_id.is_some() {
                    return Err(RuntimeError::new(Kind::InvalidInput,
                        "classic DDE quiescence supplied an unissued owner barrier"));
                }
                let id = runtime::Win16ClassicDdeQuiescenceId(identity.id.0);
                worker.classic_dde_quiescing_owners.try_reserve(1).map_err(|error|
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve classic DDE owner quiescence barrier", error))?;
                worker.classic_dde_quiescing_owners.insert(owner,
                    super::super::NativeClassicDdeQuiescence {
                        id, worker_generation: identity.worker_generation, quiesced: false,
                    });
                id
            }
        }
    };

    let snapshot = snapshot_owner_quiescence(state, identity, owner, id)?;
    if snapshot.endpoints.is_empty() && snapshot.active_operations.is_empty() {
        let mut worker = state.borrow_mut();
        let barrier = worker.classic_dde_quiescing_owners.get_mut(&owner).ok_or_else(||
            invariant("classic DDE owner barrier disappeared before worker proof"))?;
        if barrier.id != id || barrier.worker_generation != identity.worker_generation {
            return Err(invariant("classic DDE owner barrier changed before worker proof"));
        }
        barrier.quiesced = true;
        return Ok(runtime::Win16HostClassicDdeResult::OwnerQuiesced(
            runtime::Win16HostClassicDdeOwnerQuiesced {
                owner,
                worker_generation: identity.worker_generation,
                id,
                operation: identity,
            },
        ));
    }
    Ok(runtime::Win16HostClassicDdeResult::OwnerQuiescing(snapshot))
}

pub(super) fn snapshot_owner_quiescence(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    id: runtime::Win16ClassicDdeQuiescenceId,
) -> Result<runtime::Win16HostClassicDdeOwnerQuiescence, RuntimeError> {
    let worker = state.borrow();
    let barrier = worker.classic_dde_quiescing_owners.get(&owner).ok_or_else(||
        invariant("classic DDE owner quiescence snapshot has no installed barrier"))?;
    if barrier.id != id || barrier.worker_generation != identity.worker_generation {
        return Err(invariant("classic DDE owner quiescence snapshot changed barrier identity"));
    }

    // A queued ingress without its endpoint cannot be polled or retired by
    // the runtime. Never omit it from the bounded inventory and then issue an
    // empty-worker proof.
    if worker.pending_classic_dde_ingress.iter().any(|ingress|
        ingress.event.owner == owner
            && ingress.event.worker_generation == identity.worker_generation
            && !worker.classic_dde_endpoints.get(&ingress.endpoint).is_some_and(|record|
                record.owner == owner
                    && record.worker_generation == identity.worker_generation))
    {
        return Err(invariant(
            "classic DDE pending ingress lost its exact owner endpoint during quiescence",
        ));
    }

    let endpoint_count = worker.classic_dde_endpoints.values().filter(|record|
        record.owner == owner && record.worker_generation == identity.worker_generation).count();
    let mut endpoints = Vec::new();
    endpoints.try_reserve(endpoint_count).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "reserve classic DDE quiescence endpoint snapshot", error))?;
    for (endpoint_id, record) in &worker.classic_dde_endpoints {
        if record.owner != owner || record.worker_generation != identity.worker_generation {
            continue;
        }
        let pending_ingress = worker.pending_classic_dde_ingress.iter().filter(|ingress|
            ingress.event.owner == owner && ingress.endpoint == *endpoint_id
                && ingress.event.worker_generation == identity.worker_generation).count();
        let mut pending_events = Vec::new();
        pending_events.try_reserve(record.events.len().saturating_add(pending_ingress))
            .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE quiescence event IDs", error))?;
        pending_events.extend(record.events.iter().map(|entry| entry.event.event_id));
        pending_events.extend(worker.pending_classic_dde_ingress.iter().filter(|ingress|
            ingress.event.owner == owner && ingress.endpoint == *endpoint_id
                && ingress.event.worker_generation == identity.worker_generation)
            .map(|ingress| ingress.event.event_id));

        let mut callbacks = Vec::new();
        callbacks.try_reserve(record.synchronous_frames.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE quiescence callback IDs", error))?;
        for ((operation_id, frame_id), frame) in &record.synchronous_frames {
            callbacks.push(runtime::Win16HostClassicDdePendingCallback {
                operation: Win16ClassicDdeOperationIdentity {
                    owner,
                    id: *operation_id,
                    worker_generation: identity.worker_generation,
                },
                callback: frame.callback_step.callback,
                frame: *frame_id,
                event_id: frame.event.event_id,
                peer: frame.event.peer,
            });
        }
        callbacks.sort_by_key(|callback| (callback.operation.id, callback.frame));

        let mut transfers = Vec::new();
        transfers.try_reserve(record.transfers.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE quiescence transfer IDs", error))?;
        transfers.extend(record.transfers.iter().map(|(transfer_id, transfer)|
            runtime::Win16HostClassicDdePendingTransfer {
                id: *transfer_id,
                peer: transfer.peer,
                conversation: transfer.conversation,
                message: transfer.message,
            }));

        let mut conversations = Vec::new();
        conversations.try_reserve(record.conversations.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE quiescence conversation IDs", error))?;
        conversations.extend(record.conversations.iter().map(|(conversation_id, conversation)|
            runtime::Win16HostClassicDdePendingConversation {
                id: *conversation_id,
                peer: conversation.peer,
            }));

        let mut transactions = Vec::new();
        transactions.try_reserve(record.transactions.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE quiescence transaction IDs", error))?;
        transactions.extend(record.transactions.iter().map(|(transaction_id, transaction)|
            runtime::Win16HostClassicDdePendingTransaction {
                id: *transaction_id,
                peer: transaction.peer,
                conversation: transaction.conversation,
                message: transaction.message,
                transfer: transaction.transfer,
            }));

        endpoints.push(runtime::Win16HostClassicDdeEndpointQuiescence {
            endpoint: *endpoint_id,
            parent: record.parent,
            pending_events,
            callbacks,
            transfers,
            conversations,
            transactions,
        });
    }

    let active_count = worker.active_classic_dde_operations.iter().filter(|active|
        active.identity.owner == owner
            && active.identity.worker_generation == identity.worker_generation
            && active.identity != identity).count();
    let mut active_operations = Vec::new();
    active_operations.try_reserve(active_count).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "reserve classic DDE quiescence operation IDs", error))?;
    active_operations.extend(worker.active_classic_dde_operations.iter()
        .filter(|active| active.identity.owner == owner
            && active.identity.worker_generation == identity.worker_generation
            && active.identity != identity)
        .map(|active| active.identity));

    Ok(runtime::Win16HostClassicDdeOwnerQuiescence {
        owner,
        worker_generation: identity.worker_generation,
        id,
        endpoints,
        active_operations,
    })
}
