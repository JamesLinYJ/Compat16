//! Typed client OLEOBJECT methods whose host COM projections are exact.
//!
//! The 39 public client slots still enter through the checked FAR gate. This
//! module wires SetHostNames, Close and Release to the owning STA. Release is
//! a staged close/unadvise/detach/hands-off/reference-release transaction;
//! the guest proxy is retired only after every exact terminal is reconciled.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::Win16ReturnKind;
use x86_cpu::Cpu;
#[path = "win16_ole1_object_method_continuation.rs"]
mod continuation;

use super::{
    OLE1_BUSY, OLE1_ERROR_ADDRESS, OLE1_OK, Win16Ole1PendingOperation, Win16Ole1Status,
    Win16State,
};
use super::object_proxy::Win16Ole1NativeObjectProxyRecord;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ComHostInterface,
    Win16ComHostRequest, Win16ComHostResult, Win16ComHostStep,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectMethodStage {
    SetHostNames,
    Close,
    Update,
    ReleaseClose,
    ReleaseUnadvise,
    ReleaseDetachSite,
    ReleaseHandsOffStorage,
    ReleaseInterface(usize),
    Return,
}

#[derive(Debug)]
pub(super) struct Win16Ole1ObjectMethodSequence {
    pub(super) owner: crate::Win16ComHostOwnerIdentity,
    pub(super) record: Win16Ole1NativeObjectProxyRecord,
    pub(super) callback_depth: usize,
    return_to: (u16, u16, u32),
    return_kind: Win16ReturnKind,
    pub(super) slot: u8,
    guest_status: Win16Ole1Status,
    stage: ObjectMethodStage,
    current: Option<super::super::com_operations::Win16ComGuestOperationId>,
    host_application: Vec<u16>,
    host_document: Vec<u16>,
    release_interfaces: [Option<Win16ComHostInterface>; 4],
    stranded_result: Option<Win16ComHostResult>,
    stranded_step: Option<Win16ComHostStep>,
    stranded_failure: Option<String>,
}

impl Win16State {
    /// Start one typed method after the checked 39-slot FAR gate has verified
    /// its stack signature, `this`, proxy allocation, vtable gates and owner.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::win16_runtime::ole1) fn begin_ole1_typed_object_method(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        record: Win16Ole1NativeObjectProxyRecord,
        slot: u8,
        arguments: &[win16_abi::Win16Argument],
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if self
            .ole1_client_documents
            .pending_object_methods
            .iter()
            .any(|sequence| sequence.record.id == record.id)
        {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_BUSY),
                Win16ReturnKind::Word,
            );
        }
        if slot == 1 && self.object_release_is_blocked(record) {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_BUSY),
                Win16ReturnKind::Word,
            );
        }
        let owner = record.object.owner;
        if !owner.is_valid() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 method proxy has an invalid COM owner incarnation",
            ));
        }

        let mut application = Vec::new();
        let mut document = Vec::new();
        if slot == 11 {
            let (Some(win16_abi::Win16Argument::Dword(application_far)),
                Some(win16_abi::Win16Argument::Dword(document_far))) =
                (arguments.get(1), arguments.get(2))
            else {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(OLE1_ERROR_ADDRESS),
                    Win16ReturnKind::Word,
                );
            };
            application = match self.decode_method_host_name(*application_far, host, memory) {
                Ok(name) => name,
                Err(error) if matches!(error.kind(), Kind::InvalidInput | Kind::GuestFault) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(OLE1_ERROR_ADDRESS),
                        Win16ReturnKind::Word,
                    );
                }
                Err(error) => return Err(error),
            };
            document = match self.decode_method_host_name(*document_far, host, memory) {
                Ok(name) => name,
                Err(error) if matches!(error.kind(), Kind::InvalidInput | Kind::GuestFault) => {
                    return self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(OLE1_ERROR_ADDRESS),
                        Win16ReturnKind::Word,
                    );
                }
                Err(error) => return Err(error),
            };
        }
        let stage = match slot {
            1 => ObjectMethodStage::ReleaseClose,
            11 => ObjectMethodStage::SetHostNames,
            20 => ObjectMethodStage::Close,
            21 => ObjectMethodStage::Update,
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "unmapped OLE1 object method reached the typed COM adapter",
                ));
            }
        };
        self.ole1_client_documents
            .pending_object_methods
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 object-method continuation",
                    error,
                )
            })?;
        let mut sequence = Win16Ole1ObjectMethodSequence {
            owner,
            record,
            callback_depth: self.ole1_callbacks.len(),
            return_to,
            return_kind: Win16ReturnKind::Word,
            slot,
            guest_status: OLE1_OK,
            stage,
            current: None,
            host_application: application,
            host_document: document,
            release_interfaces: [
                Some(record.object),
                record.storage,
                Some(record.client_site),
                Some(record.advise_sink),
            ],
            stranded_result: None,
            stranded_step: None,
            stranded_failure: None,
        };
        let request = self.object_method_request(&sequence)?;
        let current = self.reserve_com_guest_operation(
            cpu,
            dos,
            memory,
            owner,
            record.callback_route,
            return_to,
            Win16ReturnKind::Word,
            super::super::com_operations::Win16ComOperationOrigin::Ole1ObjectMethod {
                proxy_id: record.id,
                slot,
            },
            request,
        )?;
        sequence.current = Some(current);
        self.ole1_client_documents
            .pending_object_methods
            .push(sequence);
        Ok(None)
    }

    fn decode_method_host_name(
        &self,
        far: u32,
        host: &impl RuntimeHost,
        memory: &mut Memory,
    ) -> Result<Vec<u16>, RuntimeError> {
        if far == 0 {
            return Ok(Vec::new());
        }
        let bytes = self.ole1_read_string(far, memory).map_err(|status| {
            RuntimeError::new(
                Kind::InvalidInput,
                format!("OLE1 SetHostNames string is invalid (status {status})"),
            )
        })?;
        let text = host.decode_win16_ansi(&bytes)?;
        Ok(text.encode_utf16().collect())
    }

    fn object_release_is_blocked(&self, record: Win16Ole1NativeObjectProxyRecord) -> bool {
        let canonical = self
            .ole1_client_documents
            .canonical_object(record.object_far);
        let pending_operation = self
            .ole1_client_documents
            .documents
            .get(&record.document)
            .is_some_and(|document| {
                document.pending_operations.iter().any(|operation| match *operation {
                    Win16Ole1PendingOperation::Creation {
                        source_object,
                        release_object,
                        ..
                    } => {
                        source_object.is_some_and(|object| {
                            self.ole1_client_documents.canonical_object(object) == canonical
                        }) || release_object.is_some_and(|object| {
                            self.ole1_client_documents.canonical_object(object) == canonical
                        })
                    }
                    Win16Ole1PendingOperation::Release { object_far, .. } => {
                        self.ole1_client_documents.canonical_object(object_far) == canonical
                    }
                })
            });
        let release_delivery = self
            .ole1_client_documents
            .release_deliveries
            .iter()
            .any(|delivery| {
                self.ole1_client_documents
                    .canonical_object(delivery.evidence.object_far)
                    == canonical
            });
        let active_callback = self.ole1_callbacks.iter().any(|frame| match frame.stage {
            super::Win16Ole1CallbackStage::ClientComAdviseNotification { call, callback } => {
                call.proxy_id == record.client_proxy_id || callback.route == record.callback_route
            }
            super::Win16Ole1CallbackStage::ClientProxyQueryStatus(call)
            | super::Win16Ole1CallbackStage::ClientProxyQueryError(call)
            | super::Win16Ole1CallbackStage::ClientProxyQueryMethod(call)
            | super::Win16Ole1CallbackStage::ClientProxyNotification { call, .. } => {
                call.proxy_id == record.client_proxy_id
            }
            _ => false,
        });
        pending_operation || release_delivery || active_callback
    }

    pub(in crate::win16_runtime) fn service_pending_ole1_object_method(
        &mut self,
        index: usize,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let sequence = &self.ole1_client_documents.pending_object_methods[index];
        if let Some(result) = &sequence.stranded_result {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!("OLE1 slot {} retained an unreconciled COM result: {result:?}", sequence.slot),
            ));
        }
        if let Some(step) = &sequence.stranded_step {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!("OLE1 slot {} retained an unrelated host step: {step:?}", sequence.slot),
            ));
        }
        if let Some(failure) = &sequence.stranded_failure {
            return Err(RuntimeError::new(Kind::HostFailure, failure.clone()));
        }
        let callback_depth = self.ole1_callbacks.len();
        if callback_depth > sequence.callback_depth {
            return Ok(false);
        }
        let current = sequence.current.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 typed object method has no exact COM continuation",
            )
        })?;
        let progress = match self.advance_com_guest_operation(current, host)? {
            super::super::com_operations::SafePointResult::Progress(progress) => progress,
            super::super::com_operations::SafePointResult::UnownedStep(step) => {
                self.ole1_client_documents.pending_object_methods[index].stranded_step =
                    Some(step.clone());
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!("OLE1 typed method received unrelated host step: {step:?}"),
                ));
            }
        };
        match progress {
            super::super::com_operations::Progress::Prepared { .. }
            | super::super::com_operations::Progress::Starting { .. }
            | super::super::com_operations::Progress::Running { .. }
            | super::super::com_operations::Progress::CallbackResuming { .. } => Ok(true),
            super::super::com_operations::Progress::Callback { step, .. } => {
                let step = (*step).clone();
                if let Err(primary) =
                    self.begin_ole1_com_advise_callback(cpu, dos, memory, &step)
                {
                    let resume = crate::Win16ComHostResume {
                        frame: step.frame,
                        parent: step.parent,
                        owner: step.owner,
                        outcome: crate::Win16ComHostCallbackOutcome::Failed(
                            crate::Win16ComHostCallbackFailure {
                                kind: crate::Win16ComHostCallbackFailureKind::CallbackImplementation,
                                context: primary.to_string(),
                            },
                        ),
                    };
                    self.queue_ole1_com_callback_resume(resume)?;
                    self.resume_pending_ole1_com_callback(host)?;
                }
                Ok(true)
            }
            super::super::com_operations::Progress::Terminal { step, .. } => {
                let step = (*step).clone();
                self.consume_object_method_terminal(index, current, &step, cpu, dos, memory, host)
            }
            super::super::com_operations::Progress::StartFailed { failure, .. } => {
                let failure_kind = failure.kind();
                let failure_text = failure.to_string();
                self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                    Some(failure_text.clone());
                Err(RuntimeError::new(failure_kind, failure_text))
            }
            super::super::com_operations::Progress::CallbackFailed { failure, .. } => {
                let failure_text = format!("OLE1 guest callback failed: {}", failure.context);
                self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                    Some(failure_text.clone());
                Err(RuntimeError::new(Kind::HostFailure, failure_text))
            }
            super::super::com_operations::Progress::GuestReturned { .. } => Err(
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 object method retained an already returned COM call",
                ),
            ),
        }
    }

    fn consume_object_method_terminal(
        &mut self,
        index: usize,
        current: super::super::com_operations::Win16ComGuestOperationId,
        step: &Win16ComHostStep,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let result = match step {
            Win16ComHostStep::Complete(completion) if completion.operation == current.host => {
                completion.result.clone()
            }
            Win16ComHostStep::OperationFailed {
                operation,
                result,
                execution_failure,
                failures,
            } if *operation == current.host => {
                self.ole1_client_documents.pending_object_methods[index].stranded_step =
                    Some(step.clone());
                if let Some(result) = result {
                    self.ole1_client_documents.pending_object_methods[index].stranded_result =
                        Some(result.clone());
                }
                let context = execution_failure
                    .as_ref()
                    .map(|failure| failure.context.clone())
                    .or_else(|| failures.first().map(|failure| failure.failure.context.clone()))
                    .unwrap_or_else(|| "native COM method failed".to_string());
                let mut primary = RuntimeError::new(
                    execution_failure
                        .as_ref()
                        .map_or(Kind::HostFailure, |failure| failure.kind),
                    format!("OLE1 slot {}: {context}", self.ole1_client_documents.pending_object_methods[index].slot),
                );
                if let Err(cleanup) = self.acknowledge_com_guest_terminal(current, host) {
                    primary = primary.with_cleanup(
                        "acknowledging failed OLE1 object-method terminal",
                        cleanup,
                    );
                }
                self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                    Some(primary.to_string());
                return Err(primary);
            }
            _ => {
                let failure = RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 method terminal does not match its exact COM operation",
                );
                self.ole1_client_documents.pending_object_methods[index].stranded_step =
                    Some(step.clone());
                self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                    Some(failure.to_string());
                return Err(failure);
            }
        };
        self.ole1_client_documents.pending_object_methods[index].stranded_result =
            Some(result.clone());
        if let Err(primary) = self.reconcile_object_method_result(index, result, host) {
            return match self.acknowledge_com_guest_terminal(current, host) {
                Ok(()) => {
                    self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                        Some(primary.to_string());
                    Err(primary)
                }
                Err(cleanup) => {
                    let primary = primary.with_cleanup(
                        "acknowledging OLE1 object-method terminal after result reconciliation failed",
                        cleanup,
                    );
                    self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                        Some(primary.to_string());
                    Err(primary)
                }
            };
        }
        self.acknowledge_com_guest_terminal(current, host)?;
        self.ole1_client_documents.pending_object_methods[index].stranded_result = None;
        let final_stage = self.ole1_client_documents.pending_object_methods[index].stage
            == ObjectMethodStage::Return;
        if final_stage {
            if self.ole1_client_documents.pending_object_methods[index].slot == 1 {
                if let Err(primary) = self.finish_ole1_object_release(index) {
                    self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                        Some(primary.to_string());
                    return Err(primary);
                }
            }
            if let Err(primary) =
                self.return_ole1_object_method(index, current, cpu, dos, memory)
            {
                self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                    Some(primary.to_string());
                return Err(primary);
            }
            return Ok(true);
        }
        if let Err(primary) =
            self.retire_acknowledged_object_method_step(index, current, dos, memory)
        {
            self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                Some(primary.to_string());
            return Err(primary);
        }
        if let Err(primary) = self.prepare_next_object_method_step(index, cpu, dos, memory) {
            self.ole1_client_documents.pending_object_methods[index].stranded_failure =
                Some(primary.to_string());
            return Err(primary);
        }
        Ok(true)
    }

    fn reconcile_object_method_result(
        &mut self,
        index: usize,
        result: Win16ComHostResult,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let sequence = &mut self.ole1_client_documents.pending_object_methods[index];
        let stage = sequence.stage;
        match stage {
            ObjectMethodStage::ReleaseInterface(interface_index) => {
                let expected = sequence.release_interfaces[interface_index]
                    .ok_or_else(|| protocol_error("OLE1 Release lost an interface token"))?;
                let Win16ComHostResult::ObjectReferenceReleased {
                    object,
                    owner,
                    ..
                } = result
                else {
                    return Err(protocol_error("ReleaseObject returned the wrong typed result"));
                };
                if object != expected.object || owner != sequence.owner {
                    return Err(protocol_error(
                        "ReleaseObject terminal changed the owned object or owner incarnation",
                    ));
                }
                let next = interface_index + 1;
                sequence.stage = if sequence.release_interfaces[next..]
                    .iter()
                    .all(Option::is_none)
                {
                    ObjectMethodStage::Return
                } else {
                    ObjectMethodStage::ReleaseInterface(next)
                };
            }
            ObjectMethodStage::SetHostNames
            | ObjectMethodStage::Close
            | ObjectMethodStage::Update
            | ObjectMethodStage::ReleaseClose
            | ObjectMethodStage::ReleaseUnadvise
            | ObjectMethodStage::ReleaseDetachSite
            | ObjectMethodStage::ReleaseHandsOffStorage => {
                let Win16ComHostResult::Ole(reply) = result else {
                    return Err(protocol_error("OLE1 method returned a non-OLE typed result"));
                };
                if !matches!(reply.value, crate::Win16OleHostValue::None) {
                    return Err(protocol_error(
                        "OLE1 method returned an unexpected value for a void COM method",
                    ));
                }
                if (reply.status as i32) < 0 {
                    if !matches!(
                        stage,
                        ObjectMethodStage::SetHostNames
                            | ObjectMethodStage::Close
                            | ObjectMethodStage::Update
                    ) {
                        return Err(hresult_failure(sequence.slot, stage, reply.status));
                    }
                    sequence.guest_status = match sequence.slot {
                        11 => super::OLE1_ERROR_NAME,
                        20 => super::OLE1_ERROR_TERMINATE,
                        21 => super::OLE1_ERROR_UPDATE,
                        _ => {
                            return Err(protocol_error(
                                "OLE1 method HRESULT has no guest status mapping",
                            ));
                        }
                    };
                    host.report_diagnostic(&Diagnostic::warning(
                        Kind::HostFailure,
                        format!(
                            "OLE1 object method slot {} returned HRESULT {:#010x}; returning guest status {}",
                            sequence.slot, reply.status as u32, sequence.guest_status
                        ),
                    ));
                    sequence.stage = ObjectMethodStage::Return;
                    return Ok(());
                }
                sequence.stage = match stage {
                    ObjectMethodStage::SetHostNames
                    | ObjectMethodStage::Close
                    | ObjectMethodStage::Update => {
                        ObjectMethodStage::Return
                    }
                    ObjectMethodStage::ReleaseClose => {
                        if sequence.record.advise_cookie.is_some() {
                            ObjectMethodStage::ReleaseUnadvise
                        } else {
                            ObjectMethodStage::ReleaseDetachSite
                        }
                    }
                    ObjectMethodStage::ReleaseUnadvise => ObjectMethodStage::ReleaseDetachSite,
                    ObjectMethodStage::ReleaseDetachSite => {
                        if sequence.record.storage.is_some() {
                            ObjectMethodStage::ReleaseHandsOffStorage
                        } else {
                            ObjectMethodStage::ReleaseInterface(0)
                        }
                    }
                    ObjectMethodStage::ReleaseHandsOffStorage => {
                        ObjectMethodStage::ReleaseInterface(0)
                    }
                    _ => unreachable!(),
                };
            }
            ObjectMethodStage::Return => {
                return Err(protocol_error("OLE1 object method received an extra terminal"));
            }
        }
        Ok(())
    }

    fn object_method_request(
        &self,
        sequence: &Win16Ole1ObjectMethodSequence,
    ) -> Result<Win16ComHostRequest, RuntimeError> {
        let object = sequence.record.object.object;
        let request = match sequence.stage {
            ObjectMethodStage::SetHostNames => Win16ComHostRequest::InterfaceCall {
                object,
                call: crate::Win16ComHostInterfaceCall::OleSetHostNames {
                    application: sequence.host_application.clone(),
                    document: sequence.host_document.clone(),
                },
            },
            ObjectMethodStage::Update => Win16ComHostRequest::InterfaceCall {
                object,
                call: crate::Win16ComHostInterfaceCall::OleUpdate,
            },
            ObjectMethodStage::Close | ObjectMethodStage::ReleaseClose => {
                Win16ComHostRequest::InterfaceCall {
                    object,
                    call: crate::Win16ComHostInterfaceCall::OleClose { save_option: 1 },
                }
            }
            ObjectMethodStage::ReleaseUnadvise => Win16ComHostRequest::InterfaceCall {
                object,
                call: crate::Win16ComHostInterfaceCall::OleUnadvise {
                    cookie: sequence.record.advise_cookie.ok_or_else(|| {
                        protocol_error("OLE1 Release lost its recorded Advise cookie")
                    })?,
                },
            },
            ObjectMethodStage::ReleaseDetachSite => Win16ComHostRequest::InterfaceCall {
                object,
                call: crate::Win16ComHostInterfaceCall::OleSetClientSite { site: None },
            },
            ObjectMethodStage::ReleaseHandsOffStorage if sequence.record.storage.is_some() => {
                Win16ComHostRequest::InterfaceCall {
                    object,
                    call: crate::Win16ComHostInterfaceCall::PersistStorageHandsOff,
                }
            }
            ObjectMethodStage::ReleaseHandsOffStorage => {
                return Err(protocol_error(
                    "OLE1 Release requested storage hands-off without a storage reference",
                ));
            }
            ObjectMethodStage::ReleaseInterface(index) => {
                let Some(interface) = sequence.release_interfaces.get(index).copied().flatten()
                else {
                    return Err(protocol_error("OLE1 Release interface slot is absent"));
                };
                Win16ComHostRequest::ReleaseObject {
                    object: interface.object,
                    owner: sequence.owner,
                }
            }
            ObjectMethodStage::Return => {
                return Err(protocol_error("OLE1 object method cannot issue a request after return"));
            }
        };
        Ok(request)
    }

    fn prepare_next_object_method_step(
        &mut self,
        index: usize,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut interface_index = match self.ole1_client_documents.pending_object_methods[index].stage {
            ObjectMethodStage::ReleaseInterface(index) => Some(index),
            _ => None,
        };
        if let Some(mut position) = interface_index.take() {
            while position < 4
                && self.ole1_client_documents.pending_object_methods[index].release_interfaces
                    [position]
                    .is_none()
            {
                position += 1;
            }
            if position == 4 {
                self.ole1_client_documents.pending_object_methods[index].stage =
                    ObjectMethodStage::Return;
                return Ok(());
            }
            self.ole1_client_documents.pending_object_methods[index].stage =
                ObjectMethodStage::ReleaseInterface(position);
        }
        let sequence = &self.ole1_client_documents.pending_object_methods[index];
        let request = self.object_method_request(sequence)?;
        let (owner, route, return_to, return_kind, proxy_id, slot) = (
            sequence.owner,
            sequence.record.callback_route,
            sequence.return_to,
            sequence.return_kind,
            sequence.record.id,
            sequence.slot,
        );
        let current = self.reserve_com_guest_operation(
            cpu,
            dos,
            memory,
            owner,
            route,
            return_to,
            return_kind,
            super::super::com_operations::Win16ComOperationOrigin::Ole1ObjectMethod {
                proxy_id,
                slot,
            },
            request,
        )?;
        self.ole1_client_documents.pending_object_methods[index].current = Some(current);
        Ok(())
    }



}

fn protocol_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

fn hresult_failure(slot: u8, stage: ObjectMethodStage, status: u32) -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        format!("OLE1 slot {slot} COM stage {stage:?} returned HRESULT 0x{status:08X}"),
    )
}
