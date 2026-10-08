use super::super::*;

pub(super) fn has_exact_yield_frame(outcome: &UnclaimedMciOutcome) -> bool {
    matches!(outcome, UnclaimedMciOutcome::Failure { frame: Some(_), .. })
}

// Multiple receipt paths can name the same exact native owner; keep one row.
pub(super) fn retain_owner(retained: &mut Vec<Win16HostMciRetainedOwner>, owner: Win16HostMciRetainedOwner) {
    if !retained.contains(&owner) {
        retained.push(owner);
    }
}

pub(super) fn retain_entered_yield_failure_owners(
    retained: &mut Vec<Win16HostMciRetainedOwner>,
    operation: Win16HostMciOperationId,
    failure: MciEnteredYieldFailure,
) {
    if let Some(device) = failure.device {
        retain_owner(retained, Win16HostMciRetainedOwner::Device(device));
        if let Some(registration) = failure.registration {
            retain_owner(
                retained,
                Win16HostMciRetainedOwner::Registration(Win16HostMciYieldRegistration {
                    device,
                    registration,
                }),
            );
        }
        if let Some(frame) = failure.frame {
            retain_owner(
                retained,
                Win16HostMciRetainedOwner::ActiveYield(Win16HostMciActiveYield {
                    operation,
                    frame,
                    device,
                }),
            );
        }
    }
    if let Some(returned_yield) = failure.returned_yield {
        retain_owner(retained, Win16HostMciRetainedOwner::YieldReturn(returned_yield));
    }
}
