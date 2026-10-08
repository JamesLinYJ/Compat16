//! Exact DDE operation failure and normal source-retirement proofs.

use std::sync::Arc;

use crate::RuntimeError;

use super::{
    Win16DdeCallbackCall, Win16DdeCallbackReply, Win16HostDdeCallbackFrame,
    Win16HostDdeOperation, Win16HostDdeOwner, Win16HostDdeResult,
};

/// Native progress observed when a DDE Begin call returns an error after its
/// operation request has been submitted. The later abort receipt supplies the
/// exact shutdown request ID; this value never invents one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DdeOperationRequestPhase {
    SubmittedPending,
    NativeCompleteError,
    NativeCompleteReturned,
}

/// Typed failure returned only when the exact DDE operation was submitted.
/// The host owner/generation and operation identity remain available for
/// teardown even when Begin fails before it emits a callback step.
#[derive(Clone, Debug)]
pub struct Win16DdeOperationStartedFailure {
    pub operation: Win16HostDdeOperation,
    pub owner: Win16HostDdeOwner,
    pub worker_generation: u64,
    pub request_phase: Win16DdeOperationRequestPhase,
    pub cause: Arc<RuntimeError>,
}

impl PartialEq for Win16DdeOperationStartedFailure {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.owner == other.owner
            && self.worker_generation == other.worker_generation
            && self.request_phase == other.request_phase
            && Arc::ptr_eq(&self.cause, &other.cause)
    }
}

impl Eq for Win16DdeOperationStartedFailure {}

/// Exact proof that one DDE source was returned by a real native Complete
/// event and popped from the shared DDE source stack. This is source evidence
/// only; it says nothing about guest memory, transfer guards, or instance
/// teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16DdeSourceRetiredProof {
    pub operation: Win16HostDdeOperation,
    pub owner: Win16HostDdeOwner,
    pub worker_generation: u64,
}

impl Win16DdeSourceRetiredProof {
    pub fn has_valid_identity(&self) -> bool {
        self.operation.0 != 0
            && self.owner.0 != 0
            && self.worker_generation != 0
    }
}

/// DDE operations may synchronously call guest code. The host adapter returns
/// this step, the runtime runs a checked typed callback, then resumes the
/// retained host operation with a validated scalar or host data token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDdeCallbackStep {
    pub frame: Win16HostDdeCallbackFrame,
    /// `None` identifies a DDE callback delivered while the owner thread was
    /// pumping outside a foreground DDE API call.
    pub parent: Option<Win16HostDdeOperation>,
    /// Stable owner and worker incarnation that emitted this exact callback.
    pub owner: super::Win16HostDdeOwner,
    pub worker_generation: u64,
    pub callback: Win16DdeCallbackCall,
}

impl Win16HostDdeCallbackStep {
    pub fn has_valid_identity(&self) -> bool {
        self.frame.0 != 0
            && self.owner.0 != 0
            && self.worker_generation != 0
            && self.parent.is_none_or(|operation| operation.0 != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostDdeStep {
    Complete(Win16HostDdeResult),
    /// The exact native Complete source was reserved and retired by the host
    /// before this carrier was returned. This does not prove guest-resource
    /// or callback-owner retirement.
    SourceRetired {
        proof: Arc<Win16DdeSourceRetiredProof>,
        result: Win16HostDdeResult,
    },
    Callback(Arc<Win16HostDdeCallbackStep>),
    /// A suspended callback with no foreground DDE API parent completed.
    CallbackFrameComplete { frame: Win16HostDdeCallbackFrame },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDdeResume {
    pub frame: Win16HostDdeCallbackFrame,
    pub reply: Win16DdeCallbackReply,
}
