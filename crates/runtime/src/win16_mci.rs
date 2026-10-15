//! Runtime ownership for the Win16 MCI call family.

#[path = "win16_mci_calls.rs"]
mod calls;
#[path = "win16_mci_begin_retry.rs"]
mod begin_retry;
#[path = "win16_mci_completion.rs"]
mod completion;
#[path = "win16_mci_active_finish.rs"]
mod active_finish;
#[path = "win16_mci_errors.rs"]
mod errors;
#[path = "win16_mci_lifecycle.rs"]
mod lifecycle;
#[path = "win16_mci_notifications.rs"]
mod notifications;
#[path = "win16_mci_producers.rs"]
mod producers;
#[path = "win16_mci_parameters.rs"]
mod parameters;
#[path = "win16_mci_retry.rs"]
mod retry;
#[path = "win16_mci_yield.rs"]
mod yield_callback;
#[path = "win16_mci_devices.rs"]
mod devices;
#[path = "win16_mci_wire.rs"]
mod wire;

use std::collections::{HashMap, HashSet};
use std::error::Error;

use guest_core::{Registers, memory::Memory};
use win16_abi::{Win16MciRequest, Win16ReturnKind};

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::{CallbackKind, Win16State};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostMciDevice,
    Win16HostMciStep, Win16HostMciYieldEvent,
};

const MCI_ALL_DEVICE_ID: u16 = 0xffff;

#[derive(Default)]
pub(super) struct Win16MciState {
    next_guest_id: u16,
    devices: HashMap<u16, Win16MciDeviceEntry>,
    driver_data: HashMap<Win16HostMciDevice, u32>,
    reserved_guest_ids: HashSet<u16>,
    yield_procedures: HashMap<Win16HostMciDevice, Win16MciYieldProcedure>,
    active: Vec<Win16MciContinuation>,
    orphan_devices: Vec<Win16HostMciDevice>,
    pending_cleanup: Vec<Win16MciPendingCleanup>,
    pending_begin: Option<Win16MciPendingBegin>,
    retired_yield_sources: Vec<crate::Win16HostMciYieldRegistration>,
    completed_yields: Vec<crate::Win16HostMciYieldReturn>,
    completed_operations: Vec<crate::Win16HostMciOperationCompletion>,
    resolved_finish_causes: Vec<std::sync::Arc<RuntimeError>>,
    quiescence_causes: Vec<std::sync::Arc<RuntimeError>>,
    pending_notification: Option<Win16MciPendingNotification>,
    producer_quiescence_request: Option<crate::Win16HostMciProducerQuiescenceRequest>,
    producer_quiescence_receipt:
        Option<std::sync::Arc<crate::Win16HostMciProducerQuiescenceReceipt>>,
}

struct Win16MciPendingNotification {
    event: crate::Win16HostMciNotification,
    post: Win16MciNotificationPost,
}

enum Win16MciNotificationPost {
    ResolveTarget,
    Ready(crate::Win16GuestNotification),
    NormalProof {
        notification: crate::Win16GuestNotification,
        proof: std::sync::Arc<crate::Win16WindowSourceRetiredProof>,
        result: Box<crate::Win16WindowStep>,
        posted: bool,
    },
    NormalConsumed {
        notification: crate::Win16GuestNotification,
        proof: std::sync::Arc<crate::Win16WindowSourceRetiredProof>,
        result: Box<crate::Win16WindowStep>,
        posted: bool,
    },
    TerminalFailure(std::sync::Arc<crate::Win16WindowOperationStartedFailure>),
    TerminalAcknowledged(std::sync::Arc<crate::Win16WindowOperationStartedFailure>),
    RetiredTarget,
    Unexpected {
        proof: Option<std::sync::Arc<crate::Win16WindowSourceRetiredProof>>,
        step: Box<crate::Win16WindowStep>,
    },
}

struct Win16MciPendingBegin {
    request: Win16MciRequest,
    callback_id: super::CallbackFrameId,
    operation: crate::Win16HostMciOperationId,
    phase: crate::Win16HostMciBeginFailurePhase,
    cause: std::sync::Arc<RuntimeError>,
    retry_failure: Option<std::sync::Arc<RuntimeError>>,
    cached_step: Option<Win16HostMciStep>,
    cached_step_failure: Option<std::sync::Arc<RuntimeError>>,
    cpu_context: x86_cpu::CpuContext,
    caller_code: u32,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
}

struct MciBeginFailureView {
    operation: crate::Win16HostMciOperationId,
    phase: crate::Win16HostMciBeginFailurePhase,
    cause: std::sync::Arc<RuntimeError>,
}

fn find_mci_begin_failure(error: &RuntimeError) -> Option<MciBeginFailureView> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(failure) = current.downcast_ref::<crate::Win16HostMciBeginFailure>() {
            return Some(MciBeginFailureView {
                operation: failure.operation,
                phase: failure.phase,
                cause: std::sync::Arc::clone(&failure.cause),
            });
        }
        source = current.source();
    }
    None
}

#[derive(Clone, Copy)]
struct Win16MciDeviceEntry {
    host: Win16HostMciDevice,
    device_type: Option<u32>,
    creator_task: u16,
    closed: bool,
}

#[derive(Clone, Copy)]
struct Win16MciYieldProcedure {
    procedure: u32,
    pointer: win16_abi::SegmentedPointer,
    registration: crate::Win16HostMciYieldRegistrationId,
}

fn unexpected_mci_post_error(
    proof: Option<&std::sync::Arc<crate::Win16WindowSourceRetiredProof>>,
    step: &crate::Win16WindowStep,
) -> RuntimeError {
    let step_kind = match step {
        crate::Win16WindowStep::Started { .. } => "Started",
        crate::Win16WindowStep::StartedFailure(_) => "StartedFailure",
        crate::Win16WindowStep::DdeStartedFailure(_) => "DdeStartedFailure",
        crate::Win16WindowStep::SourceRetired { .. } => "SourceRetired",
        crate::Win16WindowStep::DdeSourceRetired { .. } => "DdeSourceRetired",
        crate::Win16WindowStep::PendingGuestWork { .. } => "PendingGuestWork",
        crate::Win16WindowStep::NativeDropRetired(_) => "NativeDropRetired",
        crate::Win16WindowStep::PendingModalGuestWork { .. } => "PendingModalGuestWork",
        crate::Win16WindowStep::DdeCallback(_) => "DdeCallback",
        crate::Win16WindowStep::Callback { .. } => "Callback",
        crate::Win16WindowStep::NativeSubclassCallback { .. } => "NativeSubclassCallback",
        crate::Win16WindowStep::DialogCallback { .. } => "DialogCallback",
        crate::Win16WindowStep::GuestTimerCallback { .. } => "GuestTimerCallback",
        crate::Win16WindowStep::WindowPropertyCallback { .. } => "WindowPropertyCallback",
        crate::Win16WindowStep::GrayStringCallback { .. } => "GrayStringCallback",
        crate::Win16WindowStep::Untranslated { .. } => "Untranslated",
        crate::Win16WindowStep::Diagnostic(_) => "Diagnostic",
        crate::Win16WindowStep::Complete(_) => "Complete",
    };
    let message = match proof {
        Some(proof) => format!(
            "MCI event retains unexpected USER {step_kind} for operation {} generation {} in {} state; its source remains owned",
            proof.operation.operation_id.0,
            proof.worker_generation,
            match proof.state {
                crate::Win16NativeWindowOperationState::Active => "active",
                crate::Win16NativeWindowOperationState::Returned => "returned",
            },
        ),
        None => format!(
            "MCI event retains unexpected USER {step_kind} without an exact source-retirement proof; its source remains owned",
        ),
    };
    RuntimeError::new(Kind::HostFailure, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Win16MciFinishPhase {
    PreEntryPending,
    PreEntryAborted,
    GuestCallback,
    GuestReturnValidation,
    RestoreCaller,
    ResumeNative,
    EnterNextCallback,
    CompleteGuestCall,
    UnexpectedHostStep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Win16MciGuestReturnSnapshot {
    cs: u16,
    ip: u16,
    ss: u16,
    sp: u16,
    ax: u16,
    dx: u16,
}

impl Win16MciGuestReturnSnapshot {
    fn capture(registers: &Registers) -> Self {
        Self {
            cs: registers.cs,
            ip: registers.ip(),
            ss: registers.ss,
            sp: registers.sp(),
            ax: registers.ax(),
            dx: registers.dx(),
        }
    }
}

struct Win16MciContinuation {
    request: Win16MciRequest,
    callback_id: super::CallbackFrameId,
    next_callback_id: Option<super::CallbackFrameId>,
    operation: crate::Win16HostMciOperationId,
    event: Win16HostMciYieldEvent,
    active_call: Option<Win16FarCallbackFrame>,
    cpu_context: x86_cpu::CpuContext,
    caller_code: u32,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    finish_phase: Win16MciFinishPhase,
    guest_return: Option<u16>,
    next_event: Option<Win16HostMciYieldEvent>,
    completed_result: Option<crate::Win16HostMciResult>,
    unexpected_step: Option<crate::Win16HostMciResumeReceipt>,
    finish_failure: Option<std::sync::Arc<RuntimeError>>,
    invalid_return_snapshot: Option<Win16MciGuestReturnSnapshot>,
    returned_yields: Vec<crate::Win16HostMciYieldReturn>,
}

struct Win16MciPendingCleanup {
    continuation: Win16MciContinuation,
    unexpected_step: Option<crate::Win16HostMciResumeReceipt>,
}

impl Win16MciState {
    pub(super) fn callback_top_matches(&self, id: super::CallbackFrameId) -> bool {
        self.active
            .last()
            .is_some_and(|continuation| continuation.callback_id == id)
    }
}

impl Win16State {
    pub(super) fn begin_mci_request(
        &mut self,
        mut request: Win16MciRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        cpu_context: x86_cpu::CpuContext,
    ) -> Result<Option<u8>, RuntimeError> {
        if self.mci.pending_begin.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "a retained MCI Begin owner must be reconciled before dispatching another MCI request",
            ));
        }
        self.mci.active.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 MCI continuation",
                error,
            )
        })?;
        self.mci.completed_operations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact native MCI completion proof before Begin",
                error,
            )
        })?;
        if matches!(
            &request,
            Win16MciRequest::SetYieldProc { procedure: 0, .. }
                | Win16MciRequest::SendCommand { message: 0x0804, .. }
                | Win16MciRequest::SendString { .. }
                | Win16MciRequest::Execute { .. }
        ) {
            self.mci
                .retired_yield_sources
                .try_reserve(self.mci.yield_procedures.len().max(1))
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve retired MCI yield-source identities before native close or disable",
                        error,
                    )
                })?;
        }
        if matches!(
            &request,
            Win16MciRequest::SendCommand { message: 0x0804, .. }
                | Win16MciRequest::SendString { .. }
                | Win16MciRequest::Execute { .. }
        ) {
            self.mci
                .orphan_devices
                .try_reserve(self.mci.devices.len().saturating_add(1))
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve closed MCI device identities before native close",
                        error,
                    )
                })?;
        }
        if matches!(
            &request,
            Win16MciRequest::SetYieldProc { procedure, .. } if *procedure != 0
        ) {
            self.mci.yield_procedures.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI yield registration owner before native install",
                    error,
                )
            })?;
        }
        let yield_callback_id = self.reserve_callback_frame_id()?;
        self.mci.pending_cleanup.try_reserve(2).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 MCI yield cleanup ownership",
                error,
            )
        })?;
        if let Win16MciRequest::SendCommand {
            message: 0x0803,
            reserved_device_id,
            ..
        } = &mut request
        {
            // MCI_OPEN is a native side effect. Reserve every runtime owner slot
            // before entering WinMM so a successful open can always be retained.
            self.mci.orphan_devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI orphan-device owner",
                    error,
                )
            })?;
            *reserved_device_id = Some(self.reserve_mci_guest_id()?);
        }
        if matches!(
            &request,
            Win16MciRequest::GetDeviceId { .. }
                | Win16MciRequest::GetDeviceIdFromElement { .. }
        ) {
            // Lookup returns the worker's stable host identity. Reserve the
            // runtime map and orphan fallback before entering the host so a
            // failed alias allocation cannot lose ownership of that identity.
            self.mci.devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI lookup alias map",
                    error,
                )
            })?;
            self.mci.orphan_devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI lookup owner",
                    error,
                )
            })?;
        }
        if matches!(
            &request,
            Win16MciRequest::SendString { .. } | Win16MciRequest::Execute { .. }
        ) {
            // Reserve the fallback owner even when the shared parser does not
            // classify an OPEN. The host receipt is authoritative if parser
            // classifications ever diverge after a native string side effect.
            self.mci.devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI string-device alias map",
                    error,
                )
            })?;
            self.mci.orphan_devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI string-device fallback owner",
                    error,
                )
            })?;
        }
        if let Win16MciRequest::SendString {
            command,
            reserved_device_id,
            ..
        } = &mut request
        {
            if calls::string_open_needs_owner(command)? {
                self.mci.orphan_devices.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve Win16 MCI string-open owner",
                        error,
                    )
                })?;
                *reserved_device_id = Some(self.reserve_mci_guest_id()?);
            }
        }
        if let Win16MciRequest::Execute {
            command,
            reserved_device_id,
        } = &mut request
            && calls::string_open_needs_owner(command)?
        {
            self.mci.orphan_devices.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 MCI execute-open owner",
                    error,
                )
            })?;
            *reserved_device_id = Some(self.reserve_mci_guest_id()?);
        }
        let prepared = match calls::prepare(self, &request, memory, host) {
            Ok(value) => value,
            Err(error) => {
                self.release_reserved_from_request(&request);
                return Err(error);
            }
        };
        let step = match prepared {
            calls::PreparedMciCall::Immediate(result) => Win16HostMciStep::Complete(result),
            calls::PreparedMciCall::Host(call) => match host.win16_mci_call(call) {
                Ok(step) => step,
                Err(error) => {
                    if let Some(failure) = find_mci_begin_failure(&error) {
                        let retry_failure = (failure.operation.0 == 0).then(|| {
                            std::sync::Arc::new(RuntimeError::new(
                                Kind::InternalInvariant,
                                "host marked an MCI Begin enqueued without supplying a nonzero operation identity; its request and original CPU context remain retained",
                            ))
                        });
                        self.mci.pending_begin = Some(Win16MciPendingBegin {
                            request,
                            callback_id: yield_callback_id,
                            operation: failure.operation,
                            phase: failure.phase,
                            cause: failure.cause,
                            retry_failure,
                            cached_step: None,
                            cached_step_failure: None,
                            cpu_context,
                            caller_code: (u32::from(registers.cs) << 16)
                                | u32::from(registers.ip()),
                            return_to,
                            return_kind,
                        });
                    } else {
                        self.release_reserved_from_request(&request);
                    }
                    return Err(error.with_context(
                        "MCI host failure retains any exact enqueued Begin result owner",
                    ));
                }
            },
        };
        self.route_mci_step(
            request,
            step,
            registers,
            memory,
            host,
            return_to,
            return_kind,
            cpu_context,
            yield_callback_id,
        )
    }

    fn route_mci_step(
        &mut self,
        request: Win16MciRequest,
        step: Win16HostMciStep,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
        cpu_context: x86_cpu::CpuContext,
        callback_id: super::CallbackFrameId,
    ) -> Result<Option<u8>, RuntimeError> {
        match step {
            Win16HostMciStep::Complete(result) => completion::complete(
                self,
                request,
                result,
                registers,
                memory,
                host,
                return_to,
                return_kind,
            ),
            Win16HostMciStep::Yield(event) => {
                let continuation = Win16MciContinuation {
                    request,
                    callback_id,
                    next_callback_id: None,
                    operation: event.operation,
                    event,
                    active_call: None,
                    cpu_context,
                    caller_code: (u32::from(registers.cs) << 16)
                        | u32::from(registers.ip()),
                    return_to,
                    return_kind,
                    finish_phase: Win16MciFinishPhase::PreEntryPending,
                    guest_return: None,
                    next_event: None,
                    completed_result: None,
                    unexpected_step: None,
                    finish_failure: None,
                    invalid_return_snapshot: None,
                    returned_yields: Vec::new(),
                };
                self.publish_mci_yield_callback(continuation, registers, memory)?;
                Ok(None)
            }
        }
    }

    fn prepare_yield_callback(
        &mut self,
        event: Win16HostMciYieldEvent,
        registers: &mut Registers,
        memory: &mut Memory,
    ) -> Result<Win16FarCallbackFrame, RuntimeError> {
        if event.operation.0 == 0 || event.frame.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host MCI yield supplied a zero operation or frame identity",
            ));
        }
        let guest_device = self
            .mci
            .devices
            .iter()
            .find_map(|(guest, entry)| (entry.host == event.device).then_some(*guest))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI yield device has no live Win16 device alias",
                )
            })?;
        let callback = self
            .mci
            .yield_procedures
            .get(&event.device)
            .copied()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI called a yield procedure that has no live guest registration",
                )
            })?;
        if callback.registration != event.registration {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native MCI yield frame names a different guest registration generation",
            ));
        }
        if self
            .selectors
            .pointer_from_far(callback.procedure)
            .map_err(crate::runtime_error)?
            != callback.pointer
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "registered MCI yield FAR no longer names its captured selector generation",
            ));
        }
        self.selectors
            .translate(callback.pointer, win16_abi::Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        let arguments = [
            Win16FarCallbackArgument::Word(guest_device),
            Win16FarCallbackArgument::Dword(event.data),
        ];
        self.enter_guest_far_callback(
            registers,
            memory,
            callback.procedure,
            &arguments,
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )
    }

    pub(super) fn finish_mci_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        retry::finish_callback(self, cpu, memory, host)
    }

    pub(crate) fn retry_mci_callback_progress(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        retry::retry_on_run_entry(self, cpu, memory, host)
    }

}
