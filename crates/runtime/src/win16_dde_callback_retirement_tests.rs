//! Callback retirement retains exact pending readback source ownership.

use super::super::super::runtime_dde::{
    Win16DdeCallbackReadback, Win16DdeFollowUpOwner, Win16DdeFollowUpPhase,
};
use super::*;
use crate::*;

#[test]
fn callback_pop_retains_normal_history_including_not_yet_submitted_followup() {
    let host_frame = Win16HostDdeCallbackFrame(51);
    let origin = Win16DdeCallbackOrigin::GuestExecution { frame: host_frame };
    let owner = Win16DdeFollowUpOwner::Callback {
        callback_id: CallbackFrameId(3),
        host_frame,
        parent: None,
        owner: Win16HostDdeOwner(7),
        worker_generation: 3,
        origin,
    };
    let mut continuation = Win16DdeContinuation::wildconnect_readback(
        Some(1),
        Win16DdeCallbackReadback {
            origin,
            frame: host_frame,
            source_data: 9,
            source_host: Win16HostDdeData(91),
            expected_size: None,
        },
    )
    .unwrap();
    let proof = std::sync::Arc::new(Win16DdeSourceRetiredProof {
        operation: Win16HostDdeOperation(41),
        owner: Win16HostDdeOwner(7),
        worker_generation: 3,
    });
    continuation
        .cache_normal_source_retirement(
            std::sync::Arc::clone(&proof),
            Win16HostDdeResult {
                value: Win16HostDdeValue::GetData {
                    bytes: Vec::new(),
                    copied: 8,
                },
                dde_error: 0,
                transaction_result: None,
                data_transfer: None,
            },
        )
        .unwrap();
    let mut follow_up = super::super::Win16DdeCallbackFollowUp {
        owner,
        call: Win16HostDdeCall::GetData {
            data: Win16HostDdeData(91),
            capacity: None,
            offset: 0,
        },
        continuation: Some(Box::new(continuation)),
        phase: Win16DdeFollowUpPhase::Prepared(owner),
        completed_step: None,
        callback_reply: None,
        callback_reply_step: None,
        pending_child_callback: None,
    };
    assert!(require_follow_up_sources_retired(&follow_up).is_err());
    let prior = follow_up.continuation.as_ref().unwrap();
    let mut next = Win16DdeContinuation::wildconnect_readback(
        Some(1),
        Win16DdeCallbackReadback {
            origin,
            frame: host_frame,
            source_data: 9,
            source_host: Win16HostDdeData(91),
            expected_size: Some(8),
        },
    )
    .unwrap();
    next.inherit_source_retirements_from(prior).unwrap();
    assert_eq!(next.host_operation(), None);
    follow_up.continuation = Some(Box::new(next));
    assert!(require_follow_up_sources_retired(&follow_up).is_err());
    let continuation = follow_up.continuation.as_mut().unwrap();
    assert_eq!(continuation.normal_source_retirements().len(), 1);
    continuation
        .mark_source_retirement_consumed(&proof)
        .unwrap();
    assert!(require_follow_up_sources_retired(&follow_up).is_ok());
}
