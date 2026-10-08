use super::*;

pub(super) fn active_yield_shutdown_error(state: &WorkerThreadState) -> RuntimeError {
    let (active_count, pending_begin_count, returned_count) = ACTIVE_YIELDS.with(|active| {
        let active = active.borrow();
        (
            active
                .iter()
                .filter(|invocation| invocation.active_yield.is_some())
                .count(),
            active.iter().filter(|invocation| {
                invocation.active_yield.is_none() && invocation.last_returned_yield.is_none()
            }).count(),
            active.iter().filter(|invocation| {
                invocation.active_yield.is_none() && invocation.last_returned_yield.is_some()
            }).count(),
        )
    });
    let mut active_yields = Vec::new();
    if let Err(error) = active_yields.try_reserve_exact(active_count) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain active MCI yield identities during worker shutdown",
            error,
        );
    }
    let mut pending_begins = Vec::new();
    if let Err(error) = pending_begins.try_reserve_exact(pending_begin_count) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain exact in-flight MCI Begin operation identities during shutdown",
            error,
        );
    }
    let mut returned_yields = Vec::new();
    if let Err(error) = returned_yields.try_reserve_exact(returned_count) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain exact native MCI yield returns during worker shutdown",
            error,
        );
    }
    ACTIVE_YIELDS.with(|active| {
        for invocation in active.borrow().iter() {
            if let Some(owner) = invocation.active_yield {
                active_yields.push(owner);
            } else if let Some(returned) = invocation.last_returned_yield {
                if !returned_yields.contains(&returned) {
                    returned_yields.push(returned);
                }
            } else if !pending_begins.contains(&invocation.operation) {
                pending_begins.push(invocation.operation);
            }
        }
    });
    let mut request = Win16HostMciQuiesceRequest::default();
    if let Err(error) = request.active_yields.try_reserve_exact(active_yields.len()) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain exact active MCI shutdown identities",
            error,
        );
    }
    if let Err(error) = request.pending_begins.try_reserve_exact(pending_begins.len()) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain in-flight MCI Begin identities in shutdown receipt",
            error,
        );
    }
    if let Err(error) = request.returned_yields.try_reserve_exact(returned_yields.len()) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain exact returned MCI yields in shutdown receipt",
            error,
        );
    }
    if let Err(error) = request.devices.try_reserve_exact(
        active_yields.len().saturating_add(returned_yields.len()),
    ) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain MCI device identities during shutdown",
            error,
        );
    }
    if let Err(error) = request.registrations.try_reserve_exact(
        active_yields.len().saturating_add(returned_yields.len()),
    ) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain MCI yield registrations during shutdown",
            error,
        );
    }
    let mut retained = Vec::new();
    if let Err(error) = retained.try_reserve_exact(
        active_yields
            .len()
            .saturating_mul(4)
            .saturating_add(pending_begins.len().saturating_mul(2))
            .saturating_add(returned_yields.len().saturating_mul(4))
            .saturating_add(2)
            .max(1),
    ) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain typed MCI worker shutdown blockers",
            error,
        );
    }
    let mut causes = Vec::new();
    if let Err(error) = causes.try_reserve_exact(
        active_yields
            .len()
            .saturating_add(pending_begins.len())
            .saturating_add(returned_yields.len())
            .max(1),
    ) {
        return RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain MCI worker shutdown causes",
            error,
        );
    }
    for owner in active_yields {
        if !request.active_yields.contains(&owner) {
            request.active_yields.push(owner);
        }
        if !retained.contains(&Win16HostMciRetainedOwner::Operation(owner.operation)) {
            retained.push(Win16HostMciRetainedOwner::Operation(owner.operation));
        }
        if !request.devices.contains(&owner.device) {
            request.devices.push(owner.device);
        }
        let registration = state.current_yield_registration(owner.device).map(|registration| {
            Win16HostMciYieldRegistration {
                device: owner.device,
                registration,
            }
        });
        if let Some(registration) = registration.filter(|registration| {
            !request.registrations.contains(registration)
        }) {
            request.registrations.push(registration);
        }
    }
    request.pending_begins.extend_from_slice(&pending_begins);
    retained.extend(request.devices.iter().copied().map(Win16HostMciRetainedOwner::Device));
    retained.extend(request.registrations.iter().copied().map(Win16HostMciRetainedOwner::Registration));
    retained.extend(request.pending_begins.iter().copied().map(Win16HostMciRetainedOwner::PendingBegin));
    retained.extend(request.active_yields.iter().copied().map(Win16HostMciRetainedOwner::ActiveYield));
    for operation in &request.pending_begins {
        if !retained.contains(&Win16HostMciRetainedOwner::Operation(*operation)) {
            retained.push(Win16HostMciRetainedOwner::Operation(*operation));
        }
        causes.push(Arc::new(RuntimeError::new(
            Kind::CompatibilityGap,
            format!(
                "MCI operation {} is still inside its original native Begin call; any YIELDPROC frame is unknown until the exact result arrives",
                operation.0
            ),
        )));
    }
    for owner in &request.active_yields {
        causes.push(Arc::new(RuntimeError::new(
            Kind::CompatibilityGap,
            format!(
                "MCI operation {} frame {} remains inside native YIELDPROC; no documented cancellation WORD is available",
                owner.operation.0, owner.frame.0
            ),
        )));
    }
    for returned in returned_yields {
        if !request.returned_yields.contains(&returned) {
            request.returned_yields.push(returned);
        }
        if !request.devices.contains(&returned.owner.device) {
            request.devices.push(returned.owner.device);
        }
        let registration = state.current_yield_registration(returned.owner.device).map(|registration| {
            Win16HostMciYieldRegistration {
                device: returned.owner.device,
                registration,
            }
        });
        if let Some(registration) = registration.filter(|registration| {
            !request.registrations.contains(registration)
        }) {
            request.registrations.push(registration);
        }
        if !retained.contains(&Win16HostMciRetainedOwner::YieldReturn(returned)) {
            retained.push(Win16HostMciRetainedOwner::YieldReturn(returned));
        }
        if !retained.contains(&Win16HostMciRetainedOwner::Operation(returned.owner.operation)) {
            retained.push(Win16HostMciRetainedOwner::Operation(returned.owner.operation));
        }
        causes.push(Arc::new(RuntimeError::new(
            Kind::CompatibilityGap,
            format!(
                "MCI operation {} has returned exact yield frame {} with WORD 0x{:04X}; its next native step is still pending and operation completion is not confirmed",
                returned.owner.operation.0, returned.owner.frame.0, returned.guest_return
            ),
        )));
    }
    if !retained.contains(&Win16HostMciRetainedOwner::OwnerThread) {
        retained.push(Win16HostMciRetainedOwner::OwnerThread);
    }
    if !retained.contains(&Win16HostMciRetainedOwner::NotificationSink) {
        retained.push(Win16HostMciRetainedOwner::NotificationSink);
    }
    RuntimeError::with_source(
        Kind::CompatibilityGap,
        "MCI worker shutdown retains the exact active native yield owner",
        Win16HostMciQuiescenceFailure {
            receipt: Win16HostMciQuiescenceReceipt {
                request,
                status: Win16HostMciQuiescenceStatus::Retained,
                confirmed: Vec::new(),
                retained,
                causes,
                resolved_causes: Vec::new(),
            },
        },
    )
}
