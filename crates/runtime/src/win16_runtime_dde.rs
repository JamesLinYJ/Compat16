//! DDEML export marshalling over the owner-thread window pump.
//!
//! Guest handles stay in `Win16DdeState`; only checked opaque host tokens
//! enter the typed DDE worker protocol. This module only prepares operations;
//! completion and compensation live in the child module.

use std::sync::Arc;

use guest_core::{Registers, memory::Memory};
use win16_abi::{Win16DdeBuffer, Win16DdeRequest, Win16ReturnKind};

use super::{Win16State, guest_ranges::GuestOutputRange, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16GuestCallbackToken,
    Win16HostDdeCall, Win16HostDdeContext, Win16HostDdeData, Win16HostDdeInstance,
    Win16HostDdeString, Win16WindowOperation,
};
use compat_services::win16_dde::{DdeConvContext16, error as dde_error};

#[path = "win16_runtime_dde_prepare.rs"]
mod prepare;
#[path = "win16_runtime_dde_snapshot.rs"]
mod snapshot;
#[path = "win16_runtime_dde_retirement.rs"]
mod retirement;
#[path = "win16_runtime_dde_source.rs"]
mod source_lifecycle;

pub(in crate::win16_runtime) use retirement::prepare_dde_window_operation_retirement;
pub(in crate::win16_runtime) use completion::DdeCompletionAccess;
use source_lifecycle::Win16DdeNormalCompletion;
use source_lifecycle::Win16DdeSourceRetirementRecord;
pub(in crate::win16_runtime) use source_lifecycle::consume_source_retirements;

use huge::DdeHugeOutputRange;

const DDE_CALLBACK_OWNER: guest_core::OwnerId = guest_core::OwnerId(1);

#[derive(Clone, Copy)]
struct DdeCallbackCandidate {
    guest_instance: u32,
    callback: u32,
    route: u64,
    token: Win16GuestCallbackToken,
    reinitializing: bool,
}

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) struct DdeDataTransferGuard {
    guard_id: u64,
    guest_data: u32,
    host_data: Win16HostDdeData,
    owner: u32,
    origin: crate::win16_dde::Win16DdeDataOrigin,
    previously_transferred: bool,
    /// Only guest-created handles are provisionally marked read-only while
    /// DDEML may re-enter the guest. Borrowed callback data and transaction
    /// results are copied by the host adapter and retain their source state.
    transfer_marked: bool,
}

#[derive(Clone, Default)]
pub(in crate::win16_runtime) struct DdeOutputs {
    instance: Option<GuestOutputRange>,
    conversation_info: Option<GuestOutputRange>,
    transaction_result: Option<GuestOutputRange>,
    data: Option<DdeHugeOutputRange>,
    access_size: Option<GuestOutputRange>,
    string: Option<GuestOutputRange>,
}

/// One DDE API continuation. The native operation ID is distinct from any
/// callback frame currently nested under it.
#[derive(Clone)]
pub(in crate::win16_runtime) struct Win16DdeContinuation {
    pub(in crate::win16_runtime) request: Win16DdeRequest,
    pub(in crate::win16_runtime) return_kind: Win16ReturnKind,
    host_operation: Option<crate::Win16HostDdeOperation>,
    host_owner: Option<crate::Win16HostDdeOwner>,
    worker_generation: Option<u64>,
    started_failure: Option<Arc<crate::Win16DdeOperationStartedFailure>>,
    instance: Option<u32>,
    outputs: DdeOutputs,
    callback_candidate: Option<DdeCallbackCandidate>,
    data_transfer_guard: Option<DdeDataTransferGuard>,
    operation_retirement_proof: Option<crate::Win16DdeOperationRetirementProof>,
    transfer_guard_retired: bool,
    operation_retirement_acknowledged: bool,
    normal_source_retirements: Vec<Win16DdeSourceRetirementRecord>,
    guest_return_transfers: Vec<Win16DdeGuestReturnTransfer>,
    cached_normal_completion: Option<Win16DdeNormalCompletion>,
    finish_failure: Option<Arc<RuntimeError>>,
    purpose: Win16DdeCompletionPurpose,
    /// A successful AccessData lease whose guest snapshot could not be
    /// published. A typed UnaccessData operation must balance it first.
    cleanup_error: Option<Arc<RuntimeError>>,
}

/// The instruction event actually observed when one exact DDE callback
/// returned through the runtime's guest callback gate. This is only the
/// control-transfer half of the CPU boundary; the CPU continuation ticket is
/// checked and consumed by the central callback owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16DdeGuestReturnTransfer {
    operation: crate::Win16HostDdeOperation,
    callback_frame: crate::Win16HostDdeCallbackFrame,
    transfer: x86_cpu::ControlTransfer,
}

/// Distinguishes the two canonical owners that may submit a DDE follow-up.
/// The runtime window frame and callback frame IDs are intentionally separate
/// identities and are never converted into one another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16DdeFollowUpOwner {
    Operation {
        window_frame_id: u64,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    },
    Callback {
        callback_id: super::CallbackFrameId,
        host_frame: crate::Win16HostDdeCallbackFrame,
        parent: Option<crate::Win16HostDdeOperation>,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
        origin: super::win16_dde_callback::Win16DdeCallbackOrigin,
    },
}

impl Win16DdeFollowUpOwner {
    pub(in crate::win16_runtime) fn window_frame_id(self) -> Option<u64> {
        match self {
            Self::Operation { window_frame_id, .. } => Some(window_frame_id),
            Self::Callback { .. } => None,
        }
    }

    pub(in crate::win16_runtime) fn native_owner_identity(
        self,
    ) -> Option<(crate::Win16HostDdeOwner, u64)> {
        match self {
            Self::Operation { owner, worker_generation, .. }
            | Self::Callback { owner, worker_generation, .. } => {
                Some((owner, worker_generation))
            }
        }
    }
}

/// Only these DDE-specific host steps may be cached by a follow-up owner.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) enum Win16DdeFollowUpCarrier {
    Callback(Arc<crate::Win16HostDdeCallbackStep>),
    StartedFailure(Arc<crate::Win16DdeOperationStartedFailure>),
    SourceRetired {
        proof: Arc<crate::Win16DdeSourceRetiredProof>,
        result: crate::Win16HostDdeResult,
    },
}

#[derive(Debug)]
pub(in crate::win16_runtime) enum Win16DdeFollowUpPhase {
    /// The operation-frame caller still has to bind its exact frame identity.
    UnboundPrepared,
    Prepared(Win16DdeFollowUpOwner),
    /// Native submission returned; the exact carrier is retained before any
    /// continuation binding or owner transfer can fail.
    Submitted {
        owner: Win16DdeFollowUpOwner,
        carrier: Win16DdeFollowUpCarrier,
    },
    /// The next continuation was bound and committed in-place to the same
    /// owner. Replays return the carrier without submitting another call.
    Committed {
        owner: Win16DdeFollowUpOwner,
        carrier: Win16DdeFollowUpCarrier,
    },
    /// An unexpected returned step remains attached to its owner for review;
    /// it is never discarded and never causes a second begin.
    Rejected {
        owner: Win16DdeFollowUpOwner,
        step: Box<crate::Win16WindowStep>,
        cause: Arc<RuntimeError>,
    },
}

/// A DDE completion either returns to the original export or starts one
/// owner-thread compensation call before reporting the saved result.
pub(in crate::win16_runtime) enum Win16DdeFinish {
    Return {
        value: u32,
        return_kind: Win16ReturnKind,
    },
    FollowUp {
        call: Win16HostDdeCall,
        continuation: Option<Box<Win16DdeContinuation>>,
        phase: Win16DdeFollowUpPhase,
    },
    ResumeCallback {
        origin: super::win16_dde_callback::Win16DdeCallbackOrigin,
        step: crate::Win16HostDdeStep,
    },
}

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) struct Win16DdeCallbackReadback {
    pub origin: super::win16_dde_callback::Win16DdeCallbackOrigin,
    pub frame: crate::Win16HostDdeCallbackFrame,
    pub source_data: u32,
    pub source_host: Win16HostDdeData,
    pub expected_size: Option<u32>,
}

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) enum Win16DdeCompletionPurpose {
    GuestApi,
    WildConnectReadback(Win16DdeCallbackReadback),
}

impl Win16DdeContinuation {
    /// Construct the typed internal GetData stages used to rebuild a Win16
    /// WILDCONNECT HSZPAIR reply. The fields stay private to this module so
    /// sibling callback code cannot fabricate unrelated DDE continuations.
    pub(in crate::win16_runtime) fn wildconnect_readback(
        instance: Option<u32>,
        readback: Win16DdeCallbackReadback,
    ) -> Result<Self, RuntimeError> {
        let mut continuation = Self {
            request: Win16DdeRequest::GetData {
                data: readback.source_data,
                output: Win16DdeBuffer {
                    far_pointer: 0,
                    capacity: readback.expected_size.unwrap_or(0),
                },
                offset: 0,
            },
            return_kind: Win16ReturnKind::Dword,
            host_operation: None,
            host_owner: None,
            worker_generation: None,
            started_failure: None,
            instance,
            outputs: DdeOutputs::default(),
            callback_candidate: None,
            data_transfer_guard: None,
            operation_retirement_proof: None,
            transfer_guard_retired: false,
            operation_retirement_acknowledged: false,
            normal_source_retirements: Vec::new(),
            guest_return_transfers: Vec::new(),
            cached_normal_completion: None,
            finish_failure: None,
            purpose: Win16DdeCompletionPurpose::WildConnectReadback(readback),
            cleanup_error: None,
        };
        continuation.reserve_source_retirement_record()?;
        Ok(continuation)
    }

    pub(in crate::win16_runtime) fn instance(&self) -> Option<u32> {
        self.instance
    }

    pub(in crate::win16_runtime) fn guest_instance(&self) -> Option<u32> {
        self.instance
    }

    pub(in crate::win16_runtime) fn operation_retirement_proof(
        &self,
    ) -> Option<&crate::Win16DdeOperationRetirementProof> {
        self.operation_retirement_proof.as_ref()
    }

    pub(in crate::win16_runtime) fn purpose(&self) -> Win16DdeCompletionPurpose {
        self.purpose
    }

    pub(in crate::win16_runtime) fn host_operation(&self) -> Option<crate::Win16HostDdeOperation> {
        self.host_operation
    }

    pub(in crate::win16_runtime) fn host_owner_identity(
        &self,
    ) -> Option<(crate::Win16HostDdeOwner, u64)> {
        match (self.host_owner, self.worker_generation) {
            (Some(owner), Some(generation)) => Some((owner, generation)),
            _ => None,
        }
    }

    pub(in crate::win16_runtime) fn started_failure(
        &self,
    ) -> Option<&Arc<crate::Win16DdeOperationStartedFailure>> {
        self.started_failure.as_ref()
    }

    pub(in crate::win16_runtime) fn retain_finish_failure(
        &mut self,
        error: RuntimeError,
    ) -> RuntimeError {
        if let Some(primary) = self.finish_failure.as_ref() {
            return error.with_cleanup(
                "DDE completion retry retained its original typed failure",
                super::callback_lifo::shared_runtime_error(Arc::clone(primary)),
            );
        }
        let primary = Arc::new(error);
        self.finish_failure = Some(Arc::clone(&primary));
        super::callback_lifo::shared_runtime_error(primary)
    }

    pub(in crate::win16_runtime) fn bind_started_failure(
        &mut self,
        failure: Arc<crate::Win16DdeOperationStartedFailure>,
    ) -> Result<(), RuntimeError> {
        if failure.owner.0 == 0
            || failure.worker_generation == 0
            || self.normal_source_retirements.iter().any(|entry| {
                entry.proof().owner != failure.owner
                    || entry.proof().worker_generation != failure.worker_generation
            })
            || self.operation_retirement_proof.as_ref().is_some_and(|proof| {
                proof.owner != failure.owner
                    || proof.worker_generation != failure.worker_generation
            })
        {
            return Err(invariant(
                "DDE started failure changed the retained owner or worker generation",
            ));
        }
        self.bind_host_owner_identity(failure.owner, failure.worker_generation)?;
        match self.host_operation {
            None => self.host_operation = Some(failure.operation),
            Some(operation) if operation == failure.operation => {}
            Some(_) => return Err(invariant(
                "DDE Begin failure changed the exact native operation identity",
            )),
        }
        if let Some(existing) = self.started_failure.as_ref() {
            if !Arc::ptr_eq(existing, &failure) {
                return Err(invariant(
                    "DDE continuation received a different started-failure owner proof",
                ));
            }
            return Ok(());
        }
        self.started_failure = Some(failure);
        Ok(())
    }

    pub(in crate::win16_runtime) fn bind_host_operation(
        &mut self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<(), RuntimeError> {
        match self.host_operation {
            None => {
                self.host_operation = Some(operation);
                Ok(())
            }
            Some(existing) if existing == operation => Ok(()),
            Some(_) => Err(invariant(
                "DDE callback parent operation changed while suspended",
            )),
        }
    }

    pub(in crate::win16_runtime) fn bind_host_owner_identity(
        &mut self,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        if owner.0 == 0 || worker_generation == 0 {
            return Err(invariant(
                "DDE host owner and worker generation do not identify one native owner",
            ));
        }
        match (self.host_owner, self.worker_generation) {
            (None, None) => {
                self.host_owner = Some(owner);
                self.worker_generation = Some(worker_generation);
                Ok(())
            }
            (Some(existing_owner), Some(existing_generation))
                if existing_owner == owner && existing_generation == worker_generation => Ok(()),
            _ => Err(invariant(
                "DDE continuation changed its exact native owner or worker generation",
            )),
        }
    }

    pub(in crate::win16_runtime) fn bind_host_operation_identity(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        owner: crate::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<(), RuntimeError> {
        self.bind_host_operation(operation)?;
        self.bind_host_owner_identity(owner, worker_generation)
    }

    pub(in crate::win16_runtime) fn reserve_guest_return_transfer(
        &mut self,
    ) -> Result<(), RuntimeError> {
        if self.guest_return_transfers.len() == self.guest_return_transfers.capacity() {
            self.guest_return_transfers.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact DDE callback return provenance before guest entry",
                    error,
                )
            })?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cache_guest_return_transfer(
        &mut self,
        operation: crate::Win16HostDdeOperation,
        callback_frame: crate::Win16HostDdeCallbackFrame,
        transfer: x86_cpu::ControlTransfer,
    ) -> Result<(), RuntimeError> {
        if operation.0 == 0
            || callback_frame.0 == 0
            || !transfer.is_call_return()
            || self.host_operation != Some(operation)
        {
            return Err(invariant(
                "DDE guest-return transfer lacks an exact foreground operation and return event",
            ));
        }
        if let Some(existing) = self.guest_return_transfers.iter().find(|entry| {
            entry.operation == operation && entry.callback_frame == callback_frame
        }) {
            if existing.transfer == transfer {
                return Ok(());
            }
            return Err(invariant(
                "DDE callback retry changed its observed CPU return event",
            ));
        }
        if self
            .guest_return_transfers
            .iter()
            .any(|entry| entry.callback_frame == callback_frame)
        {
            return Err(invariant(
                "DDE callback return event changed its exact operation or frame owner",
            ));
        }
        if self.guest_return_transfers.len() == self.guest_return_transfers.capacity() {
            return Err(invariant(
                "DDE guest-return provenance was not reserved before callback entry",
            ));
        }
        self.guest_return_transfers.push(Win16DdeGuestReturnTransfer {
            operation,
            callback_frame,
            transfer,
        });
        Ok(())
    }

    /// Read the one validated guest-return event owned by this operation.
    /// The callback frame is returned from the recorded entry; it is never
    /// reconstructed from the operation ID or current register contents.
    pub(in crate::win16_runtime) fn guest_return_transfer_for_operation(
        &self,
        operation: crate::Win16HostDdeOperation,
    ) -> Result<Option<(crate::Win16HostDdeCallbackFrame, x86_cpu::ControlTransfer)>, RuntimeError>
    {
        let mut transfers = self
            .guest_return_transfers
            .iter()
            .filter(|entry| entry.operation == operation);
        let Some(first) = transfers.next() else {
            return Ok(None);
        };
        if transfers.next().is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation has more than one cached callback return event",
            ));
        }
        Ok(Some((first.callback_frame, first.transfer)))
    }
}

#[path = "win16_runtime_dde_api.rs"]
mod api;
use api::{
    PrepareFailure, PrepareResult, PreparedDde, api_error, callback_registration_error,
    decode_context,
};

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[path = "win16_runtime_dde_follow_up.rs"]
mod follow_up;
pub(in crate::win16_runtime) use follow_up::{
    callback_owned_follow_up_origin, follow_up_carrier_step,
    submit_callback_owned_dde_follow_up,
    submit_dde_follow_up_in_place,
};

#[path = "win16_runtime_dde_completion.rs"]
mod completion;
pub(in crate::win16_runtime) use completion::finish_dde_operation;
#[path = "win16_runtime_dde_huge.rs"]
mod huge;
