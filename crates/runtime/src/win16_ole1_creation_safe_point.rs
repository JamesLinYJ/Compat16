//! COM owner safe-point driver for typed OLE1 creation.

use super::*;
use super::validation::{
    hresult_failure, iid_iadvise_sink, iid_ole_object, owned_interface, protocol_error,
    status_runtime,
};

impl Win16State {
    pub(in crate::win16_runtime) fn service_pending_ole1_com_work(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.pending_ole1_com_callback_resume().is_some() {
            self.resume_pending_ole1_com_callback(host)?;
            return Ok(true);
        }
        let callback_depth = self.ole1_callbacks.len();
        let creation_index = self
            .ole1_client_documents
            .pending_creations
            .iter()
            .position(|sequence| callback_depth <= sequence.callback_depth);
        let method_index = self
            .ole1_client_documents
            .pending_object_methods
            .iter()
            .position(|sequence| callback_depth <= sequence.callback_depth);
        let service_method_first = match (creation_index, method_index) {
            (Some(_), Some(_)) => {
                let prefer_method = self.ole1_client_documents.prefer_object_method_safe_point;
                self.ole1_client_documents.prefer_object_method_safe_point = !prefer_method;
                prefer_method
            }
            (None, Some(_)) => true,
            _ => false,
        };
        if service_method_first {
            if let Some(index) = method_index {
                if self.service_pending_ole1_object_method(index, cpu, dos, memory, host)? {
                    return Ok(true);
                }
            }
        }
        let Some(index) = creation_index else {
            if let Some(index) = method_index {
                return self.service_pending_ole1_object_method(index, cpu, dos, memory, host);
            }
            return Ok(false);
        };
        if self.ole1_client_documents.pending_creations[index]
            .stranded_result
            .is_some()
            || self.ole1_client_documents.pending_creations[index]
                .stranded_step
                .is_some()
            || self.ole1_client_documents.pending_creations[index]
                .stranded_failure
                .is_some()
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "OLE1 create retained an unreconciled native result; owner teardown stays pending",
            ));
        }
        if self.ole1_client_documents.pending_creations[index].stage == CreateStage::PublishProxy {
            self.publish_pending_creation_proxy(index, memory)?;
            return Ok(true);
        }
        if self.ole1_client_documents.pending_creations[index].stage == CreateStage::Return {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 create reached return without an exact final COM operation",
            ));
        }
        let current = self.ole1_client_documents.pending_creations[index]
            .current
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 creation stage has no prepared exact COM operation",
                )
            })?;
        let progress = match self.advance_com_guest_operation(current, host)? {
            super::super::super::com_operations::SafePointResult::Progress(progress) => progress,
            super::super::super::com_operations::SafePointResult::UnownedStep(step) => {
                self.ole1_client_documents.pending_creations[index].stranded_step =
                    Some(step.clone());
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!("OLE1 COM safe point received an unrelated host step: {step:?}"),
                ));
            }
        };
        match progress {
            super::super::super::com_operations::Progress::Prepared { .. }
            | super::super::super::com_operations::Progress::Starting { .. }
            | super::super::super::com_operations::Progress::Running { .. }
            | super::super::super::com_operations::Progress::CallbackResuming { .. } => Ok(true),
            super::super::super::com_operations::Progress::Callback { step, .. } => {
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
            super::super::super::com_operations::Progress::Terminal { step, .. } => {
                let step = (*step).clone();
                self.consume_creation_terminal(index, current, &step, cpu, dos, memory, host)
            }
            super::super::super::com_operations::Progress::StartFailed { failure, .. } => {
                let failure = RuntimeError::new(failure.kind(), failure.to_string());
                self.ole1_client_documents.pending_creations[index].stranded_failure =
                    Some(failure.to_string());
                Err(failure)
            }
            super::super::super::com_operations::Progress::CallbackFailed { failure, .. } => {
                Err(RuntimeError::new(
                    Kind::HostFailure,
                    format!("OLE1 guest callback failed: {}", failure.context),
                ))
            }
            super::super::super::com_operations::Progress::GuestReturned { .. } => Err(
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 create sequence retained an already returned COM operation",
                ),
            ),
        }
    }

    pub(super) fn preflight_creation_output(
        &self,
        far: u32,
        memory: &Memory,
    ) -> Result<SegmentedPointer, u16> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        self.selectors
            .address_within(pointer, Access::Write, 4, memory.size_bytes())
            .map_err(|_| OLE1_ERROR_ADDRESS)?;
        Ok(pointer)
    }

    pub(super) fn clear_creation_output(&self, far: u32, memory: &mut Memory) -> Result<(), u16> {
        let pointer = self.preflight_creation_output(far, memory)?;
        self.selectors
            .write(memory, pointer, &[0; 4])
            .map_err(|_| OLE1_ERROR_ADDRESS)
    }

    fn publish_pending_creation_proxy(
        &mut self,
        index: usize,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let sequence = &self.ole1_client_documents.pending_creations[index];
        let (Some(object), Some(storage), Some(client_site), Some(advise_sink)) = (
            sequence.object,
            sequence.storage,
            sequence.client_site,
            sequence.advise_sink,
        ) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 create cannot publish before all owned setup interfaces arrive",
            ));
        };
        let resources = Win16Ole1NativeObjectResources {
            callback_route: sequence.route,
            object,
            storage: Some(storage),
            client_site,
            advise_sink,
            kind: Win16Ole1NativeObjectKind::Embedded,
            link_update_options: 0,
        };
        let object_far = self
            .publish_ole1_native_object_proxy(
                sequence.document,
                sequence.client_far,
                sequence.client_proxy_id,
                sequence.operation_id,
                resources,
                memory,
            )
            .map_err(|error| match error.status_or_runtime() {
                Ok(status) => status_runtime(status),
                Err(runtime) => runtime,
            })?;
        let record = self
            .ole1_client_documents
            .native_object_proxies
            .iter()
            .find(|record| record.object_far == object_far)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "published OLE1 FAR object has no exact native proxy record",
                )
            })?;
        let _record_id = record.id;
        let Some(sequence) = self
            .ole1_client_documents
            .pending_creations
            .get_mut(index)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 create disappeared during checked proxy publication",
            ));
        };
        sequence.object_far = Some(object_far);
        sequence.stage = CreateStage::SetClientSite;
        Ok(())
    }

    fn consume_creation_terminal(
        &mut self,
        index: usize,
        current: super::super::super::com_operations::Win16ComGuestOperationId,
        step: &Win16ComHostStep,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let stage = self.ole1_client_documents.pending_creations[index].stage;
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
                self.ole1_client_documents.pending_creations[index].stranded_step =
                    Some(step.clone());
                if let Some(result) = result {
                    self.ole1_client_documents.pending_creations[index].stranded_result =
                        Some(result.clone());
                }
                let context = execution_failure
                    .as_ref()
                    .map(|failure| failure.context.clone())
                    .or_else(|| failures.first().map(|failure| failure.failure.context.clone()))
                    .unwrap_or_else(|| "native COM operation failed".to_string());
                let mut primary = RuntimeError::new(
                    execution_failure
                        .as_ref()
                        .map_or(Kind::HostFailure, |failure| failure.kind),
                    format!("OLE1 create {stage:?}: {context}"),
                );
                if let Err(cleanup) = self.acknowledge_com_guest_terminal(current, host) {
                    primary = primary.with_cleanup(
                        "acknowledging failed OLE1 creation terminal",
                        cleanup,
                    );
                    self.ole1_client_documents.pending_creations[index].stranded_failure =
                        Some(primary.to_string());
                    return Err(primary);
                }
                if let Err(cleanup) =
                    self.retire_acknowledged_creation_step(index, current, dos, memory)
                {
                    primary = primary.with_cleanup(
                        "retiring failed OLE1 creation step after terminal acknowledgement",
                        cleanup,
                    );
                }
                self.ole1_client_documents.pending_creations[index].stranded_failure =
                    Some(primary.to_string());
                return Err(primary);
            }
            _ => {
                let failure = RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 create terminal does not match its exact host operation",
                );
                self.ole1_client_documents.pending_creations[index].stranded_step =
                    Some(step.clone());
                self.ole1_client_documents.pending_creations[index].stranded_failure =
                    Some(failure.to_string());
                return Err(failure);
            }
        };
        self.ole1_client_documents.pending_creations[index].stranded_result =
            Some(match step {
                Win16ComHostStep::Complete(completion) => completion.result.clone(),
                _ => unreachable!(),
            });
        if let Win16ComHostResult::Ole(reply) = &result {
            let guest_status = match stage {
                CreateStage::Clsid if (reply.status as i32) < 0 => {
                    Some(super::super::OLE1_ERROR_CLASS)
                }
                CreateStage::CreateObject if (reply.status as i32) < 0 => {
                    Some(super::super::OLE1_ERROR_EDIT)
                }
                _ => None,
            };
            if let Some(guest_status) = guest_status {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::HostFailure,
                    format!(
                        "OLE1 creation stage {stage:?} returned HRESULT {:#010x}; returning guest OLE status {guest_status}",
                        reply.status as u32
                    ),
                ));
            }
        }
        let conversion = self.reconcile_creation_result(index, stage, result);
        if matches!(&conversion, Ok(None)) && stage == CreateStage::Advise {
            let sequence = &self.ole1_client_documents.pending_creations[index];
            let (Some(object_far), Some(cookie)) = (sequence.object_far, sequence.advise_cookie)
            else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "successful OleAdvise lost its exact cookie or guest object identity",
                ));
            };
            let record = self
                .ole1_client_documents
                .native_object_proxies
                .iter_mut()
                .find(|record| record.object_far == object_far)
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "successful OleAdvise lost its exact native object proxy",
                    )
                })?;
            record.advise_cookie = Some(cookie);
        }
        let guest_failure = match conversion {
            Ok(Some(status)) => {
                self.acknowledge_com_guest_terminal(current, host)?;
                Some(status)
            }
            Ok(None) => {
                self.acknowledge_com_guest_terminal(current, host)?;
                None
            }
            Err(mut primary) => {
                if let Err(cleanup) = self.acknowledge_com_guest_terminal(current, host) {
                    primary = primary.with_cleanup(
                        "acknowledging OLE1 creation terminal after result reconciliation failed",
                        cleanup,
                    );
                    self.ole1_client_documents.pending_creations[index].stranded_failure =
                        Some(primary.to_string());
                    return Err(primary);
                }
                if let Err(cleanup) =
                    self.retire_acknowledged_creation_step(index, current, dos, memory)
                {
                    primary = primary.with_cleanup(
                        "retiring OLE1 creation step after result reconciliation failed",
                        cleanup,
                    );
                }
                self.ole1_client_documents.pending_creations[index].stranded_failure =
                    Some(primary.to_string());
                return Err(primary);
            }
        };
        if let Some(status) = guest_failure {
            self.return_failed_creation(index, current, status, cpu, dos, memory)?;
            return Ok(true);
        }
        self.ole1_client_documents.pending_creations[index].stranded_result = None;
        if stage == CreateStage::Advise {
            let returned = (|| -> Result<(), RuntimeError> {
                let (saved, return_to, return_kind, frame) = {
                    let continuation =
                        self.checked_creation_com_continuation(index, current)?;
                    (
                        continuation.saved_registers.clone(),
                        continuation.return_to,
                        continuation.return_kind,
                        continuation.legacy_cpu_frame,
                    )
                };
                let output = self.ole1_client_documents.pending_creations[index].output;
                let object_far = self.ole1_client_documents.pending_creations[index]
                    .object_far
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "completed OLE1 create has no published guest object FAR",
                        )
                    })?;
                self.selectors
                    .write(memory, output, &object_far.to_le_bytes())
                    .map_err(crate::runtime_error)
                    .map_err(|error| {
                        error.with_context("publish checked OleCreate object output")
                    })?;
                let operation_id =
                    self.ole1_client_documents.pending_creations[index].operation_id;
                self.ole1_client_documents.finish_operation(operation_id);
                let target = super::super::super::call_return::checked_return_target(
                    &saved,
                    return_to,
                    u32::from(OLE1_OK),
                    return_kind,
                );
                self.return_legacy_cpu_call_frame(
                    frame,
                    cpu,
                    memory,
                    CallEffectPolicy::PreserveX87,
                    CallResumeBoundary::NoGuestExecution,
                    target,
                )?;
                self.mark_com_guest_returned(current)?;
                self.release_legacy_cpu_frame(frame, dos, memory)?;
                self.retire_returned_com_guest_call(current, frame)?;
                self.ole1_client_documents.pending_creations.remove(index);
                Ok(())
            })();
            if let Err(primary) = returned {
                self.ole1_client_documents.pending_creations[index].stranded_failure =
                    Some(primary.to_string());
                return Err(primary);
            }
            return Ok(true);
        }
        if let Err(primary) =
            self.retire_acknowledged_creation_step(index, current, dos, memory)
        {
            self.ole1_client_documents.pending_creations[index].stranded_failure =
                Some(primary.to_string());
            return Err(primary);
        }
        if self.ole1_client_documents.pending_creations[index].stage != CreateStage::PublishProxy {
            self.prepare_next_creation_step(index, cpu, dos, memory)?;
        }
        Ok(true)
    }

    fn reconcile_creation_result(
        &mut self,
        index: usize,
        stage: CreateStage,
        result: Win16ComHostResult,
    ) -> Result<Option<u16>, RuntimeError> {
        let sequence = &mut self.ole1_client_documents.pending_creations[index];
        match (stage, result) {
            (CreateStage::Clsid, Win16ComHostResult::Ole(reply)) => {
                if (reply.status as i32) < 0 {
                    return Ok(Some(super::super::OLE1_ERROR_CLASS));
                }
                let Win16OleHostValue::Guid(guid) = reply.value else {
                    return Err(protocol_error("CLSIDFromProgID returned a non-GUID value"));
                };
                sequence.class_id = Some(guid);
                sequence.stage = CreateStage::CreateObject;
            }
            (CreateStage::CreateObject, Win16ComHostResult::Ole(reply)) => {
                if (reply.status as i32) < 0 {
                    if matches!(&reply.value, Win16OleHostValue::Object(_)) {
                        return Err(protocol_error(
                            "failed CoCreateInstance retained an unexpected owned IOleObject token",
                        ));
                    }
                    return Ok(Some(super::super::OLE1_ERROR_EDIT));
                }
                let Win16OleHostValue::Object(object) = reply.value else {
                    return Err(protocol_error("CoCreateInstance returned no IOleObject"));
                };
                if object.owner != sequence.owner
                    || object.iid != iid_ole_object()
                    || object.disposition
                        != compat_services::com::ReferenceDisposition::Owned
                {
                    return Err(protocol_error(
                        "CoCreateInstance returned an unowned or mismatched IOleObject",
                    ));
                }
                sequence.object = Some(object);
                sequence.stage = CreateStage::CallbackProxy;
            }
            (CreateStage::CallbackProxy, Win16ComHostResult::Ole(reply)) => {
                if (reply.status as i32) < 0 {
                    return Err(hresult_failure("Create OLE callback proxy", reply.status));
                }
                let Win16OleHostValue::CallbackInterfaces {
                    client_site,
                    advise_sink,
                } = reply.value
                else {
                    return Err(protocol_error(
                        "Create OLE callback proxy returned the wrong interface pair",
                    ));
                };
                if !owned_interface(
                    client_site,
                    sequence.owner,
                    compat_services::com::IID_IOLE_CLIENT_SITE,
                ) || !owned_interface(advise_sink, sequence.owner, iid_iadvise_sink())
                {
                    return Err(protocol_error(
                        "OLE callback proxy returned an unowned or mismatched interface",
                    ));
                }
                sequence.client_site = Some(client_site);
                sequence.advise_sink = Some(advise_sink);
                sequence.stage = CreateStage::Storage;
            }
            (CreateStage::Storage, Win16ComHostResult::Storage(reply)) => {
                if (reply.hresult as i32) < 0 {
                    return Err(hresult_failure("StgCreateDocfileOnILockBytes", reply.hresult));
                }
                let Some(storage) = reply.storage else {
                    return Err(protocol_error("memory docfile creation returned no IStorage"));
                };
                if !owned_interface(
                    storage,
                    sequence.owner,
                    compat_services::com::IID_ISTORAGE,
                ) {
                    return Err(protocol_error(
                        "memory docfile creation returned an unowned or mismatched IStorage",
                    ));
                }
                sequence.storage = Some(storage);
                sequence.stage = CreateStage::PublishProxy;
            }
            (CreateStage::SetClientSite, Win16ComHostResult::Ole(reply))
            | (CreateStage::SetHostNames, Win16ComHostResult::Ole(reply))
            | (CreateStage::InitializeStorage, Win16ComHostResult::Ole(reply)) => {
                if (reply.status as i32) < 0 {
                    return Err(hresult_failure("IOleObject setup method", reply.status));
                }
                sequence.stage = match stage {
                    CreateStage::SetClientSite => CreateStage::SetHostNames,
                    CreateStage::SetHostNames => CreateStage::InitializeStorage,
                    CreateStage::InitializeStorage => CreateStage::Advise,
                    _ => unreachable!(),
                };
            }
            (CreateStage::Advise, Win16ComHostResult::Ole(reply)) => {
                if (reply.status as i32) < 0 {
                    return Err(hresult_failure("IOleObject::Advise", reply.status));
                }
                let Win16OleHostValue::Scalar(cookie) = reply.value else {
                    return Err(protocol_error("IOleObject::Advise returned no cookie"));
                };
                if cookie == 0 {
                    return Err(protocol_error("IOleObject::Advise returned a zero cookie"));
                }
                sequence.advise_cookie = Some(cookie);
                sequence.stage = CreateStage::Return;
            }
            (_, result) => {
                sequence.stranded_result = Some(result);
                return Err(protocol_error(
                    "OLE1 creation stage received an incompatible typed COM result",
                ));
            }
        }
        Ok(None)
    }

    fn return_failed_creation(
        &mut self,
        index: usize,
        current: super::super::super::com_operations::Win16ComGuestOperationId,
        status: u16,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let (saved, return_to, return_kind, frame, operation_id, client_proxy_id) = {
            let continuation = self.checked_creation_com_continuation(index, current)?;
            let sequence = &self.ole1_client_documents.pending_creations[index];
            (
                continuation.saved_registers.clone(),
                continuation.return_to,
                continuation.return_kind,
                continuation.legacy_cpu_frame,
                sequence.operation_id,
                sequence.client_proxy_id,
            )
        };
        self.ole1_client_documents.finish_operation(operation_id);
        self.retire_ole1_client_operation_proxy(client_proxy_id)?;
        let target = super::super::super::call_return::checked_return_target(
            &saved,
            return_to,
            u32::from(status),
            return_kind,
        );
        self.return_legacy_cpu_call_frame(
            frame,
            cpu,
            memory,
            CallEffectPolicy::PreserveX87,
            CallResumeBoundary::NoGuestExecution,
            target,
        )?;
        self.mark_com_guest_returned(current)?;
        self.release_legacy_cpu_frame(frame, dos, memory)?;
        self.retire_returned_com_guest_call(current, frame)?;
        self.ole1_client_documents.pending_creations.remove(index);
        Ok(())
    }

    fn prepare_next_creation_step(
        &mut self,
        index: usize,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let sequence = &self.ole1_client_documents.pending_creations[index];
        let (request, origin) = match sequence.stage {
            CreateStage::CreateObject => (
                Win16ComHostRequest::Ole(Win16OleHostOperation::CreateInstance {
                    clsid: sequence.class_id.ok_or_else(|| {
                        protocol_error("OleCreate lost its exact ProgID class identity")
                    })?,
                    outer: None,
                    context: CLSCTX_SERVER,
                    iid: iid_ole_object(),
                }),
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::CallbackProxy => (
                Win16ComHostRequest::CreateCallbackProxy {
                    route: sequence.route,
                },
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::Storage => (
                Win16ComHostRequest::Storage(Win16StorageHostOperation::CreateMemoryDocFile {
                    mode: STGM_READWRITE_SHARE_EXCLUSIVE,
                    reserved: 0,
                }),
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::SetClientSite => (
                Win16ComHostRequest::InterfaceCall {
                    object: sequence.object.ok_or_else(|| {
                        protocol_error("OleCreate lost the IOleObject before setting its site")
                    })?.object,
                    call: crate::Win16ComHostInterfaceCall::OleSetClientSite {
                        site: Some(sequence.client_site.ok_or_else(|| {
                            protocol_error("OleCreate lost its owned IOleClientSite")
                        })?.object),
                    },
                },
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::SetHostNames => (
                Win16ComHostRequest::InterfaceCall {
                    object: sequence.object.ok_or_else(|| {
                        protocol_error("OleCreate lost the IOleObject before setting host names")
                    })?.object,
                    call: crate::Win16ComHostInterfaceCall::OleSetHostNames {
                        application: sequence.host_application.clone(),
                        document: sequence.host_document.clone(),
                    },
                },
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::InitializeStorage => (
                Win16ComHostRequest::InterfaceCall {
                    object: sequence.object.ok_or_else(|| {
                        protocol_error("OleCreate lost the IOleObject before storage init")
                    })?.object,
                    call: crate::Win16ComHostInterfaceCall::PersistStorageInitNew {
                        storage: sequence.storage.ok_or_else(|| {
                            protocol_error("OleCreate lost its owned IStorage")
                        })?.object,
                    },
                },
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::Advise => (
                Win16ComHostRequest::InterfaceCall {
                    object: sequence.object.ok_or_else(|| {
                        protocol_error("OleCreate lost the IOleObject before advising")
                    })?.object,
                    call: crate::Win16ComHostInterfaceCall::OleAdvise {
                        sink: sequence.advise_sink.ok_or_else(|| {
                            protocol_error("OleCreate lost its owned IAdviseSink")
                        })?.object,
                    },
                },
                super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                    client_operation: sequence.operation_id.0,
                },
            ),
            CreateStage::Clsid | CreateStage::PublishProxy | CreateStage::Return => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 create stage cannot prepare a native COM request",
                ));
            }
        };
        let (owner, route, return_to, return_kind) = (
            sequence.owner,
            sequence.route,
            sequence.return_to,
            sequence.return_kind,
        );
        let operation = self.reserve_com_guest_operation(
            cpu,
            dos,
            memory,
            owner,
            route,
            return_to,
            return_kind,
            origin,
            request,
        )?;
        self.ole1_client_documents.pending_creations[index].current = Some(operation);
        Ok(())
    }

    fn retire_acknowledged_creation_step(
        &mut self,
        index: usize,
        current: super::super::super::com_operations::Win16ComGuestOperationId,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let frame = self
            .checked_creation_com_continuation(index, current)?
            .legacy_cpu_frame;
        self.release_legacy_cpu_frame(frame, dos, memory)?;
        self.retire_acknowledged_com_guest_step(current, frame)?;
        self.ole1_client_documents.pending_creations[index].current = None;
        Ok(())
    }

    fn checked_creation_com_continuation(
        &self,
        index: usize,
        current: super::super::super::com_operations::Win16ComGuestOperationId,
    ) -> Result<super::super::super::com_operations::GuestContinuation<'_>, RuntimeError> {
        let sequence = self
            .ole1_client_documents
            .pending_creations
            .get(index)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 creation continuation has no exact caller sequence",
                )
            })?;
        self.checked_ole1_com_continuation(
            current,
            sequence.owner,
            sequence.route,
            sequence.return_to,
            sequence.return_kind,
            super::super::super::com_operations::Win16ComOperationOrigin::Ole1Creation {
                client_operation: sequence.operation_id.0,
            },
        )
    }
}
