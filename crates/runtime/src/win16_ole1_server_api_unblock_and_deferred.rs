impl Win16State {

    fn unblock_server_api(
        &mut self,
        owner: guest_core::OwnerId,
        server_long: i32,
        output_far: u32,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let handle = Ole1ServerHandle::from_guest_long(server_long as u32);
        if self.ole1_server_state.server(owner, handle).is_none() {
            return Ok(u32::from(OLE_ERROR_HANDLE));
        }
        let output = match self.ole1_checked_output_pointer(output_far, 2, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        if !self
            .ole1_server_state
            .has_deferred_classic_dde_event(owner, handle)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer lost its exact registration ({status})"),
                )
            })?
        {
            let more = self
                .ole1_server_state
                .unblock_step(owner, handle, false)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("OleUnblockServer lost its exact registration ({status})"),
                    )
                })?;
            self.write_unblock_result(memory, output, more)?;
            return Ok(u32::from(OLE_OK));
        }
        if self
            .ole1_server_state
            .deferred_front_is_initiate(owner, handle)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer could not inspect its queued message ({status})"),
                )
            })? == Some(false)
        {
            // The queue and blocked state are unchanged. This API path knows
            // how to resume only INITIATE; returning OLE_ERROR_COMMAND is a
            // recoverable protocol status, not a fabricated callback result.
            return Ok(u32::from(OLE_ERROR_COMMAND));
        }
        let deferred = self
            .ole1_server_state
            .begin_unblock_classic_dde_event(owner, handle)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer could not dequeue its exact DDE message ({status})"),
                )
            })?
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OleUnblockServer lost a previously observed deferred DDE message",
                )
            })?;
        let event_id = deferred.event.event_id;
        if let Err(primary) =
            self.process_deferred_server_initiate(&deferred, cpu, dos, memory, host)
        {
            if let Err(rollback) = self
                .ole1_server_state
                .restore_unblock_classic_dde_event(owner, handle, event_id)
            {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!(
                        "deferred OLE1 DDE dispatch failed ({primary}); restore also failed ({rollback})"
                    ),
                ));
            }
            return Err(primary);
        }
        self.ole1_server_state
            .finish_unblock_classic_dde_event(owner, handle, event_id)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer lost its completed DDE message ({status})"),
                )
            })?;
        let has_pending = self
            .ole1_server_state
            .has_deferred_classic_dde_event(owner, handle)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer lost its DDE queue ({status})"),
                )
            })?;
        let more = self
            .ole1_server_state
            .unblock_step(owner, handle, has_pending)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OleUnblockServer lost its exact registration ({status})"),
                )
            })?;
        self.write_unblock_result(memory, output, more)?;
        Ok(u32::from(OLE_OK))
    }

    fn write_unblock_result(
        &self,
        memory: &mut Memory,
        output: SegmentedPointer,
        more: bool,
    ) -> Result<(), RuntimeError> {
        self.selectors
            .write(memory, output, &u16::from(more).to_le_bytes())
            .map_err(|error| {
                super::super::win16_ole1_server_wire::into_runtime_error(
                    selector_error(error, OLE_ERROR_ADDRESS),
                    "write OleUnblockServer output after state transition",
                )
            })
    }

    fn process_deferred_server_initiate(
        &mut self,
        deferred: &super::super::win16_ole1_server_state::Ole1DeferredClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if deferred.step.event != deferred.event
            || deferred.step.owner != deferred.event.owner
            || deferred.step.endpoint != deferred.event.endpoint
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OleUnblockServer queue entry lost its exact host callback source",
            ));
        }
        let disposition =
            self.route_classic_dde_callback(&deferred.step, cpu, dos, memory, host)?;
        let resume =
            self.finish_deferred_server_initiate_disposition(disposition, cpu, dos, memory, host)?;
        let mut step = host.win16_classic_dde_resume(resume.clone())?;
        loop {
            match step {
                Win16HostClassicDdeStep::Started(operation) if operation == resume.operation => {
                    step = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
                        operation,
                        reply: None,
                    })?;
                }
                Win16HostClassicDdeStep::Complete { .. } => {
                    super::super::win16_ole1_server_callback::validate_ole1_server_callback_resume(
                        &resume, &step,
                    )?;
                    return Ok(());
                }
                _ => {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OleUnblockServer callback resume lost its exact operation receipt",
                    ));
                }
            }
        }
    }

    fn finish_deferred_server_initiate_disposition(
        &mut self,
        disposition: super::super::win16_ole1_server_dde::Ole1ServerDdeDisposition,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostClassicDdeResume, RuntimeError> {
        let super::super::win16_ole1_server_dde::Ole1ServerDdeDisposition::HostCall {
            call,
            continuation: Some(continuation),
            ..
        } = disposition
        else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "unblocked OLE1 INITIATE did not produce its exact host continuation",
            ));
        };
        self.drive_server_initiate_host_call(call, continuation, cpu, dos, memory, host)
    }

    fn drive_server_initiate_host_call(
        &mut self,
        call: Win16HostClassicDdeCall,
        continuation: super::super::win16_ole1_server_dde::Ole1ServerInitiateContinuation,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostClassicDdeResume, RuntimeError> {
        let started = host.win16_classic_dde_begin(call)?;
        let operation = match started {
            Win16HostClassicDdeStep::Started(operation) => operation,
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OleUnblockServer DDE route did not start an independent host operation",
                ));
            }
        };
        let mut reply = None;
        loop {
            let step = host.win16_classic_dde_resume(Win16HostClassicDdeResume {
                operation,
                reply: reply.take(),
            })?;
            match step {
                Win16HostClassicDdeStep::Started(actual) if actual == operation => continue,
                Win16HostClassicDdeStep::Callback(callback) => {
                    let disposition =
                        self.route_classic_dde_callback(&callback, cpu, dos, memory, host)?;
                    let resume = self.finish_deferred_server_initiate_disposition(
                        disposition,
                        cpu,
                        dos,
                        memory,
                        host,
                    )?;
                    if resume.operation != operation {
                        return Err(RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "nested OLE1 document INITIATE changed its exact host operation",
                        ));
                    }
                    reply = resume.reply;
                    if reply.is_none() {
                        return Err(RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "nested OLE1 INITIATE route produced no callback reply",
                        ));
                    }
                }
                Win16HostClassicDdeStep::Complete { .. } => {
                    return self.finish_server_initiate_host_call(&continuation, operation, &step);
                }
                _ => {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OleUnblockServer nested DDE call lost its exact terminal receipt",
                    ));
                }
            }
        }
    }

    fn read_server_api_string(
        &self,
        far: u32,
        maximum: usize,
        memory: &mut Memory,
    ) -> Result<Vec<u8>, Ole1ServerWireError> {
        let length = self.ole1_checked_string_len(far, maximum, memory)?;
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|error| selector_error(error, OLE_ERROR_ADDRESS))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            Ole1ServerWireError::GuestStatus(
                super::super::win16_ole1_server_state::OLE_ERROR_MEMORY,
            )
        })?;
        bytes.resize(length, 0);
        self.selectors
            .read(memory, pointer, &mut bytes)
            .map_err(|error| selector_error(error, OLE_ERROR_ADDRESS))?;
        if bytes.contains(&0) {
            return Err(Ole1ServerWireError::GuestStatus(OLE_ERROR_NAME));
        }
        Ok(bytes)
    }

    fn checked_server_input_pointer(
        &self,
        far: u32,
        bytes: usize,
        memory: &mut Memory,
    ) -> Result<SegmentedPointer, Ole1ServerWireError> {
        if far == 0 {
            return Err(Ole1ServerWireError::GuestStatus(OLE_ERROR_ADDRESS));
        }
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(|error| selector_error(error, OLE_ERROR_ADDRESS))?;
        self.selectors
            .translate(pointer, Access::Read, bytes, memory)
            .map_err(|error| selector_error(error, OLE_ERROR_ADDRESS))?;
        Ok(pointer)
    }
}
