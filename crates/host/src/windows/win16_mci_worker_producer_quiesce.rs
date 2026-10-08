use super::*;

pub(super) fn quiesce_producers_requested(
    state: &WorkerThreadState,
    request: Win16HostMciProducerQuiescenceRequest,
) -> Result<Win16HostMciProducerQuiescenceReceipt, RuntimeError> {
    let (devices, registrations) = {
        let registry = state.devices.lock().unwrap_or_else(PoisonError::into_inner);
        (registry.snapshot()?, registry.yield_registration_snapshot()?)
    };
    let mut device_identities = Vec::new();
    device_identities
        .try_reserve_exact(devices.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain exact live MCI devices across producer quiescence",
                error,
            )
        })?;
    device_identities.extend(devices.iter().map(|(device, _)| *device));
    let (active_operations, active_yields) = ACTIVE_YIELDS.with(|active| -> Result<_, RuntimeError> {
        let active = active.borrow();
        let mut operations = Vec::new();
        operations.try_reserve_exact(active.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot active MCI operations before producer quiescence",
                error,
            )
        })?;
        let yield_count = active.iter().filter(|entry| entry.active_yield.is_some()).count();
        let mut yields = Vec::new();
        yields.try_reserve_exact(yield_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot active MCI yield owners before producer quiescence",
                error,
            )
        })?;
        for entry in active.iter() {
            operations.push(entry.operation);
            yields.extend(entry.active_yield);
        }
        Ok((operations, yields))
    })?;
    // Keep the ledger locked through all fallible preflight allocations. Once
    // admission is sealed below, the snapshot and the closed gate describe
    // one atomic source-ownership boundary to native callback threads.
    let mut notification_ledger = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let (accepted_routes, queued_notifications, source_causes) =
        notification_ledger.source_snapshot()?;

    let owner_count = request
        .owners
        .registrations
        .len()
        .saturating_add(registrations.len());
    let mut source_disable_evidence = Vec::new();
    source_disable_evidence
        .try_reserve_exact(owner_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact MCI producer-disable evidence",
                error,
            )
        })?;
    let mismatch_capacity = request
        .owners
        .registrations
        .len()
        .saturating_add(registrations.len())
        .saturating_add(registrations.len())
        .saturating_add(devices.len())
        .saturating_add(active_operations.len())
        .saturating_add(active_yields.len())
        .saturating_add(2);
    let mut barrier_causes = Vec::new();
    barrier_causes.try_reserve_exact(mismatch_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact MCI producer-barrier causes",
            error,
        )
    })?;
    let mut resolved_causes = Vec::new();
    resolved_causes
        .try_reserve_exact(request.owners.resolved_causes.len().saturating_add(registrations.len()))
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain exact MCI producer-barrier resolved causes",
                error,
            )
        })?;
    resolved_causes.extend(request.owners.resolved_causes.iter().cloned());
    let mut live_yield_sources = Vec::new();
    live_yield_sources
        .try_reserve_exact(registrations.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain MCI registrations that remain installed after producer disable",
                error,
            )
        })?;

    for owner in &request.owners.registrations {
        if let Some(evidence) = state.prior_yield_source_evidence(*owner) {
            source_disable_evidence.push(evidence);
        } else if !registrations.contains(owner) {
            barrier_causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "MCI producer request references registration {} for device {}:{} without a live source or exact disable tombstone",
                    owner.registration.0, owner.device.token, owner.device.generation
                ),
            )));
        }
    }
    for owner in &registrations {
        if !request.owners.registrations.contains(owner) {
            barrier_causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "native MCI producer registration {} for device {}:{} is absent from the runtime owner request",
                    owner.registration.0, owner.device.token, owner.device.generation
                ),
            )));
        }
    }
    for (device, _) in &devices {
        if !request.owners.devices.contains(device) {
            barrier_causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "native MCI device {}:{} is absent from the producer-barrier owner request",
                    device.token, device.generation
                ),
            )));
        }
    }
    for operation in &active_operations {
        if !request.owners.pending_begins.contains(operation)
            && !request
                .owners
                .active_yields
                .iter()
                .any(|owner| owner.operation == *operation)
        {
            barrier_causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "active native MCI operation {} is absent from the exact runtime producer-barrier request",
                    operation.0
                ),
            )));
        }
    }
    for active in &active_yields {
        if !request.owners.active_yields.contains(active) {
            barrier_causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "active MCI yield operation {} frame {} is absent from the exact runtime producer-barrier request",
                    active.operation.0, active.frame.0
                ),
            )));
        }
    }

    state.reserve_yield_source_evidence_batch(&registrations)?;

    // Close both API admission and route reservation before disabling native
    // callbacks. Existing route/event rows remain in the receipt and ledger.
    state.producer_admission_closed.set(true);
    notification_ledger.close_source_admission();
    drop(notification_ledger);
    for owner in &registrations {
        match native::disable_yield_registration(state, *owner) {
            Ok(evidence @ Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                set_result,
                observed_installed,
                ..
            }) => {
                if !source_disable_evidence.iter().any(|previous| previous == &evidence) {
                    source_disable_evidence.push(evidence.clone());
                }
                if observed_installed {
                    live_yield_sources.push(*owner);
                    barrier_causes.push(Arc::new(RuntimeError::new(
                        Kind::HostFailure,
                        format!(
                            "MCI producer registration {} for device {}:{} remains installed after native disable",
                            owner.registration.0, owner.device.token, owner.device.generation
                        ),
                    )));
                } else if set_result == 0 {
                    resolved_causes.push(Arc::new(RuntimeError::new(
                        Kind::HostFailure,
                        format!(
                            "mciSetYieldProc returned FALSE for registration {} although mciGetYieldProc confirmed the runtime source absent",
                            owner.registration.0
                        ),
                    )));
                }
            }
            Ok(_) => {
                live_yield_sources.push(*owner);
                barrier_causes.push(Arc::new(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI producer barrier received evidence for a different source phase",
                )));
            }
            Err(error) => {
                live_yield_sources.push(*owner);
                barrier_causes.push(Arc::new(error));
            }
        }
    }

    // A YIELDPROC already entered stays an exact live owner; it is never
    // converted into a synthetic returned-WORD proof by this admission barrier.
    Ok(Win16HostMciProducerQuiescenceReceipt {
        request,
        source_admission_closed: state.producer_admission_closed.get(),
        source_disable_evidence,
        live_yield_sources,
        active_operations,
        active_yields,
        devices: device_identities,
        accepted_routes,
        queued_notifications,
        source_causes,
        barrier_causes,
        resolved_causes,
    })
}
