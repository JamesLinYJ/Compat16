use super::*;

pub(super) fn retained_request_capacity(request: &Win16HostMciQuiesceRequest) -> usize {
    request
        .devices
        .len()
        .saturating_add(request.registrations.len())
        .saturating_add(request.pending_begins.len().saturating_mul(2))
        .saturating_add(request.active_yields.len().saturating_mul(2))
        .saturating_add(request.returned_yields.len())
        .saturating_add(request.completed_operations.len())
}

pub(super) fn retain_request_owners(
    retained: &mut Vec<Win16HostMciRetainedOwner>,
    request: &Win16HostMciQuiesceRequest,
) {
    for owner in &request.devices {
        retain_owner(retained, Win16HostMciRetainedOwner::Device(*owner));
    }
    for owner in &request.registrations {
        retain_owner(retained, Win16HostMciRetainedOwner::Registration(*owner));
    }
    for owner in &request.pending_begins {
        retain_owner(retained, Win16HostMciRetainedOwner::PendingBegin(*owner));
    }
    for owner in &request.active_yields {
        retain_owner(retained, Win16HostMciRetainedOwner::ActiveYield(*owner));
        retain_owner(retained, Win16HostMciRetainedOwner::Operation(owner.operation));
    }
    for owner in &request.returned_yields {
        retain_owner(retained, Win16HostMciRetainedOwner::YieldReturn(*owner));
    }
    for owner in &request.completed_operations {
        retain_owner(retained, Win16HostMciRetainedOwner::CompletedOperation(*owner));
    }
}

pub(super) fn retain_yield_owner(
    worker: &Win16MciWorker,
    retained: &mut Vec<Win16HostMciRetainedOwner>,
    operation: Win16HostMciOperationId,
    frame: Win16HostMciYieldFrame,
) {
    if let Some(pending) = worker.pending.get(&operation) {
        retain_owner(
            retained,
            Win16HostMciRetainedOwner::ActiveYield(Win16HostMciActiveYield {
                operation,
                frame,
                device: pending.device,
            }),
        );
        retain_owner(
            retained,
            Win16HostMciRetainedOwner::Registration(Win16HostMciYieldRegistration {
                device: pending.device,
                registration: pending.registration,
            }),
        );
        retain_owner(retained, Win16HostMciRetainedOwner::Device(pending.device));
    }
    retain_owner(retained, Win16HostMciRetainedOwner::Operation(operation));
}

pub(super) fn retain_step_owners(
    retained: &mut Vec<Win16HostMciRetainedOwner>,
    operation: Win16HostMciOperationId,
    step: &MciWorkerStep,
) {
    match &step.step {
        Win16HostMciStep::Yield(event) => {
            retain_owner(
                retained,
                Win16HostMciRetainedOwner::ActiveYield(Win16HostMciActiveYield {
                    operation: event.operation,
                    frame: event.frame,
                    device: event.device,
                }),
            );
            retain_owner(
                retained,
                Win16HostMciRetainedOwner::Registration(Win16HostMciYieldRegistration {
                    device: event.device,
                    registration: event.registration,
                }),
            );
            retain_owner(retained, Win16HostMciRetainedOwner::Device(event.device));
        }
        Win16HostMciStep::Complete(result) => {
            retain_owner(
                retained,
                Win16HostMciRetainedOwner::CompletedOperation(Win16HostMciOperationCompletion {
                    operation,
                    native_return_value: result.return_value,
                }),
            );
            match &result.output {
                runtime::Win16HostMciOutput::Device { device, .. } => retain_owner(
                    retained,
                    Win16HostMciRetainedOwner::Device(*device),
                ),
                runtime::Win16HostMciOutput::StringCommand { opened, closed, .. } => {
                    if let Some((device, _)) = opened {
                        retain_owner(retained, Win16HostMciRetainedOwner::Device(*device));
                    }
                    if let Some(device) = closed {
                        retain_owner(retained, Win16HostMciRetainedOwner::Device(*device));
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(returned) = step.returned_yield {
        retain_owner(retained, Win16HostMciRetainedOwner::YieldReturn(returned));
    }
}
