use super::*;

impl Win16State {
    /// Finish the guest callback, acknowledge the exact host callback frame,
    /// release callback-scoped guest memory, and preserve its origin.
    pub(in crate::win16_runtime) fn finish_dde_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16DdeCallbackFinish, RuntimeError> {
        self.require_callback_top(CallbackKind::Dde)?;
        if let Some((callback_id, host_frame, origin, reply)) = self.dde_callbacks.last().and_then(|frame| {
            (frame.pending_resumed_step.is_none()
                && frame.pending_callback_reply.is_some()
                && frame.active_call.is_none())
            .then(|| {
                Some((
                    frame.callback_id,
                    frame.host_frame,
                    frame.origin,
                    frame.pending_callback_reply.clone()?,
                ))
            })
            .flatten()
        }) {
            let retried = super::clone_dde_callback_reply(&reply).and_then(|reply| {
                host.win16_dde_callback_reply(Win16HostDdeResume {
                    frame: host_frame,
                    reply,
                })
            });
            match retried {
                Ok(step) => {
                    if let Some(frame) = self.dde_callbacks.last_mut()
                        && frame.callback_id == callback_id
                        && frame.host_frame == host_frame
                    {
                        frame.pending_resumed_step = Some(step);
                        frame.native_reply_source = Some(
                            crate::Win16DdeCancellationSource::GuestReply,
                        );
                    } else {
                        let error = invariant(
                            "DDE callback reply retry changed its exact frame owner",
                        );
                        return Err(self.retain_dde_callback_entry_error(callback_id, error));
                    }
                    return self.finish_dde_callback(cpu, dos, memory, host);
                }
                Err(error) => {
                    let reported = self.retain_dde_callback_reply_failure(
                        callback_id,
                        origin,
                        error,
                    );
                    return Err(reported);
                }
            }
        }
        if let Some((origin, step, callback_error)) = self.dde_callbacks.last().and_then(|frame| {
            frame.pending_resumed_step.as_ref().map(|step| {
                (frame.origin, step.clone(), frame.pending_callback_error.clone())
            })
        }) {
            let host_frame = self.dde_callbacks.last().map(|frame| frame.host_frame)
                .ok_or_else(|| invariant("DDE callback retry lost its exact native frame"))?;
            if let Err(error) = validate_resumed_step(origin, host_frame, step.clone()) {
                let callback_id = self.dde_callbacks.last().map(|frame| frame.callback_id)
                    .ok_or_else(|| invariant("DDE callback retry lost its frame"))?;
                return Err(self.retain_dde_callback_entry_error(callback_id, error));
            }
            if let Win16DdeCallbackOrigin::CallbackFollowUp {
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
            } = origin
            {
                if let Err(error) = self.cache_callback_follow_up_returned_step(
                    callback_id,
                    host_frame,
                    operation,
                    owner,
                    worker_generation,
                    &step,
                ) {
                    let error = self.retain_dde_callback_entry_error(
                        self.dde_callbacks.last().map(|frame| frame.callback_id)
                            .ok_or_else(|| invariant("DDE callback retry lost its frame"))?,
                        error,
                    );
                    return Err(error);
                }
            }
            if let Err(cleanup) = self.finish_dde_callback_frame(None, host) {
                let reported = match callback_error.as_ref() {
                    Some(error) => super::dde_callback_failure(
                        Some(super::super::callback_lifo::shared_runtime_error(
                            std::sync::Arc::clone(error),
                        )),
                        cleanup,
                    ),
                    None => cleanup,
                };
                let callback_id = self.dde_callbacks.last().map(|frame| frame.callback_id)
                    .ok_or_else(|| invariant("DDE callback retry lost its frame"))?;
                return Err(self.retain_dde_callback_entry_error(callback_id, reported));
            }
            if let Some(error) = callback_error {
                return Err(super::super::callback_lifo::shared_runtime_error(error));
            }
            return Ok(Win16DdeCallbackFinish::Resume { origin, step });
        }
        let (host_frame, origin, callback_kind_active) = self
            .dde_callbacks
            .last()
            .map(|frame| (frame.host_frame, frame.origin, frame.callback_kind_active))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "DDE callback gate has no active callback frame",
                )
            })?;
        if !callback_kind_active {
            return Err(invariant(
                "DDE callback continuation has already left guest execution",
            ));
        }
        if let Win16DdeCallbackOrigin::GuestExecution { frame } = origin {
            if frame != host_frame {
                return Err(invariant(
                    "DDE guest callback frame changed before its CPU context preflight",
                ));
            }
            self.preflight_dde_guest_context(cpu, frame)?;
        }
        let observed_control_transfer = cpu.control_transfer();
        if matches!(
            origin,
            Win16DdeCallbackOrigin::Foreground(_)
                | Win16DdeCallbackOrigin::CallbackFollowUp { .. }
        )
            && !observed_control_transfer.is_some_and(x86_cpu::ControlTransfer::is_call_return)
        {
            return Err(invariant(
                "foreground DDE callback has no completed guest return event",
            ));
        }

        let (active, route, transaction_type, host_frame, origin, guest_instance) = {
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "DDE callback gate has no active callback frame",
                )
            })?;
            if !frame.callback_kind_active {
                return Err(invariant(
                    "DDE callback continuation has already left guest execution",
                ));
            }
            let active = frame.active_call.as_ref().cloned().ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "DDE callback gate has no active guest call",
                )
            })?;
            (
                active,
                frame.callback_route,
                frame.transaction_type,
                frame.host_frame,
                frame.origin,
                frame.guest_instance,
            )
        };
        let mut active = active;
        let (return_value, mut callback_error) =
            match self.finish_guest_far_callback_checked(cpu, dos, memory, &mut active) {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(std::sync::Arc::new(error))),
            };
        if return_value.is_some() {
            if let Some(transfer) = observed_control_transfer.filter(|transfer| transfer.is_call_return()) {
                match origin {
                    Win16DdeCallbackOrigin::Foreground(operation) => {
                        self.cache_dde_guest_return_transfer(operation, host_frame, transfer)?;
                    }
                    Win16DdeCallbackOrigin::CallbackFollowUp {
                        callback_id,
                        host_frame: owner_frame,
                        operation,
                        owner,
                        worker_generation,
                    } => self.cache_callback_owned_dde_return_transfer(
                        callback_id,
                        owner_frame,
                        operation,
                        owner,
                        worker_generation,
                        host_frame,
                        transfer,
                    )?,
                    Win16DdeCallbackOrigin::WindowWait { .. }
                    | Win16DdeCallbackOrigin::GuestExecution { .. } => {}
                }
            }
            if let Some(frame) = self.dde_callbacks.last_mut() {
                frame.active_call = Some(active.clone());
            }
            if let Err(error) = self.release_guest_far_callback_owner(&mut active, dos, memory) {
                let callback_id = self.dde_callbacks.last().map(|frame| frame.callback_id)
                    .ok_or_else(|| invariant("DDE callback lost its exact return owner"))?;
                self.dde_callbacks.last_mut().expect("frame checked").active_call = Some(active);
                let error = self.retain_dde_callback_entry_error(callback_id, error);
                return Err(error);
            }
            if let Some(frame) = self.dde_callbacks.last_mut() {
                frame.active_call = None;
            }
        }
        let mut reply =
            return_value.and_then(|value| self.dde.callback_reply(route, transaction_type, value));
        let mut returned_data = None;

        if let (Some(value), Some(Win16DdeCallbackReply::Data(host_data))) =
            (return_value, reply.as_ref())
        {
            if self.dde.host_data(value) != Some(*host_data)
                || self.dde.instance_for_data(value) != Some(guest_instance)
            {
                return Err(invariant(
                    "DDE callback data reply lost its guest-to-host identity",
                ));
            }
            let writable_snapshot = self
                .dde
                .access_block(value)
                .filter(|block| block.writable && self.dde.data_is_writable(value) == Some(true));
            let is_wildconnect = transaction_type::base(transaction_type)
                == transaction_type::base(transaction_type::WILDCONNECT);
            if writable_snapshot.is_some() {
                // The guest can still edit this mirror, but the host's native
                // callback reply owns the HDDEDATA lifetime and cannot safely
                // import a mirror without releasing a guest-visible lease.
                // WILDCONNECT additionally requires rebuilding native-width
                // HSZPAIR data while preserving that source lease. Leave the
                // object mapped for UnaccessData and use the empty callback
                // result until the host protocol can preserve both contracts.
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    if is_wildconnect {
                        "Win16 WILDCONNECT callback returned data with a writable DdeAccessData lease; replied with no data"
                    } else {
                        "Win16 DDE callback returned a writable access snapshot before UnaccessData; replied with no data"
                    }));
                reply = Some(Win16DdeCallbackReply::NoData);
            } else if is_wildconnect {
                let continuation = Win16DdeContinuation::wildconnect_readback(
                    Some(guest_instance),
                    Win16DdeCallbackReadback {
                        origin,
                        frame: host_frame,
                        source_data: value,
                        source_host: *host_data,
                        expected_size: None,
                    },
                )?;
                let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                    invariant("WILDCONNECT callback frame disappeared before readback ownership")
                })?;
                if frame.pending_returned_data.is_some() {
                    return Err(invariant(
                        "WILDCONNECT callback already owns a different pending result token",
                    ));
                }
                frame.pending_returned_data = Some(value);
                let follow_up_owner =
                    super::runtime_dde::Win16DdeFollowUpOwner::Callback {
                        callback_id: frame.callback_id,
                        host_frame: frame.host_frame,
                        parent: frame.source_step.parent,
                        owner: frame.source_step.owner,
                        worker_generation: frame.source_step.worker_generation,
                        origin: frame.origin,
                    };
                if frame.pending_follow_up.is_some() {
                    return Err(invariant(
                        "WILDCONNECT callback already owns a readback follow-up",
                    ));
                }
                let callback_id = frame.callback_id;
                frame.pending_follow_up = Some(Win16DdeCallbackFollowUp {
                    owner: follow_up_owner,
                    call: crate::Win16HostDdeCall::GetData {
                        data: *host_data,
                        capacity: None,
                        offset: 0,
                    },
                    continuation: Some(Box::new(continuation)),
                    phase: super::runtime_dde::Win16DdeFollowUpPhase::Prepared(
                        follow_up_owner,
                    ),
                    completed_step: None,
                    callback_reply: None,
                    callback_reply_step: None,
                    pending_child_callback: None,
                });
                self.leave_dde_callback_guest_frame()?;
                return Ok(Win16DdeCallbackFinish::FollowUp {
                    callback_id,
                });
            } else {
                self.with_dde_completion_access(|access| {
                    access.mark_callback_returned_data(value)
                })?;
                returned_data = Some(value);
            }
        }

        if reply.is_none() {
            let Some(fallback) = callback_projection_fallback_for_type(transaction_type) else {
                if let Some(error) = callback_error.take() {
                    return Err(super::super::callback_lifo::shared_runtime_error(error));
                }
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "Win16 DDE callback return class has no documented empty fallback",
                ));
            };
            if return_value.is_some() {
                self.dde
                    .set_last_error(guest_instance, dde_error::NOTPROCESSED);
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 DDE callback return value did not identify a valid result; replied with its documented empty value"));
            } else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "Win16 DDE guest callback failed; acknowledged its native frame with the documented empty value"));
            }
            reply = Some(fallback);
        }
        let Some(reply) = reply else {
            return Err(dde_callback_failure(
                callback_error
                    .take()
                    .map(super::super::callback_lifo::shared_runtime_error),
                invariant(
                    "DDE callback lost both its projected result and its documented fallback",
                ),
            ));
        };
        let callback_id = self.dde_callbacks.last().map(|frame| frame.callback_id)
            .ok_or_else(|| invariant("DDE callback lost its reply owner"))?;
        {
            let frame = self.dde_callbacks.last_mut().ok_or_else(|| {
                invariant("DDE callback disappeared before its reply was cached")
            })?;
            if frame.callback_id != callback_id || frame.host_frame != host_frame {
                return Err(invariant(
                    "DDE callback reply cache changed its exact frame owner",
                ));
            }
            match frame.pending_callback_reply.as_ref() {
                Some(existing) if existing == &reply => {}
                Some(_) => {
                    let error = invariant(
                        "DDE callback retry changed its exact guest response",
                    );
                    if frame.pending_callback_error.is_none() {
                        let error = std::sync::Arc::new(error);
                        frame.pending_callback_error = Some(std::sync::Arc::clone(&error));
                        return Err(super::super::callback_lifo::shared_runtime_error(error));
                    }
                    return Err(error);
                }
                None => frame.pending_callback_reply = Some(reply),
            }
            if frame.pending_returned_data.is_none() {
                frame.pending_returned_data = returned_data;
            }
            if let Some(error) = callback_error.as_ref()
                && frame.pending_callback_error.is_none()
            {
                frame.pending_callback_error = Some(std::sync::Arc::clone(error));
            }
        }
        let copied_reply = {
            let frame = self.dde_callbacks.last().ok_or_else(|| {
                invariant("DDE callback reply owner disappeared before submission")
            })?;
            let cached = frame.pending_callback_reply.as_ref().ok_or_else(|| {
                invariant("DDE callback response was not retained before submission")
            })?;
            super::clone_dde_callback_reply(cached)
        };
        let retry_reply = match copied_reply {
            Ok(reply) => reply,
            Err(error) => {
                let reported = self.retain_dde_callback_reply_failure(
                    callback_id,
                    origin,
                    error,
                );
                return Err(reported);
            }
        };
        let next = match host.win16_dde_callback_reply(Win16HostDdeResume {
            frame: host_frame,
            reply: retry_reply,
        }) {
            Ok(next) => next,
            Err(error) => {
                let reported = self.retain_dde_callback_reply_failure(
                    callback_id,
                    origin,
                    error,
                );
                return Err(reported);
            }
        };
        if let Some(frame) = self.dde_callbacks.last_mut() {
            frame.pending_resumed_step = Some(next.clone());
            if frame.pending_callback_error.is_none() {
                frame.pending_callback_error = callback_error.clone();
            }
        }
        let cache_result = match (origin, &next) {
            (Win16DdeCallbackOrigin::Foreground(operation), Win16HostDdeStep::Complete(result)) => {
                self.cache_foreground_dde_completion(operation, result.clone())
            }
            (
                Win16DdeCallbackOrigin::Foreground(operation),
                Win16HostDdeStep::SourceRetired { proof, result },
            ) => self.cache_foreground_dde_source_retirement(
                operation,
                std::sync::Arc::clone(proof),
                result.clone(),
            ),
            (
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    operation,
                    owner,
                    worker_generation,
                },
                _,
            ) => self.cache_callback_follow_up_returned_step(
                callback_id,
                host_frame,
                operation,
                owner,
                worker_generation,
                &next,
            ),
            _ => Ok(()),
        };
        if let Err(error) = cache_result {
            let callback_id = self.dde_callbacks.last().map(|frame| frame.callback_id)
                .ok_or_else(|| invariant("DDE callback lost its exact frame owner"))?;
            return Err(self.retain_dde_callback_entry_error(callback_id, error));
        }
        if let Err(cleanup) = validate_resumed_step(origin, host_frame, next.clone()) {
            let primary = callback_error
                .as_ref()
                .map(|error| super::super::callback_lifo::shared_runtime_error(std::sync::Arc::clone(error)));
            let combined = dde_callback_failure(primary, cleanup);
            match origin {
                Win16DdeCallbackOrigin::Foreground(operation) => {
                    return Err(self.retain_foreground_dde_completion_failure(operation, combined)
                        .unwrap_or_else(|error| error));
                }
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    operation,
                    ..
                } => return Err(self.retain_callback_follow_up_failure(
                    callback_id, host_frame, operation, combined,
                ).unwrap_or_else(|error| error)),
                _ => {}
            }
            return Err(combined);
        }
        self.dde_callbacks.last_mut().ok_or_else(|| {
            invariant("DDE callback frame disappeared after native acknowledgement")
        })?.native_reply_source = Some(crate::Win16DdeCancellationSource::GuestReply);
        if let Err(cleanup) = self.finish_dde_callback_frame(returned_data, host) {
            let primary = callback_error
                .as_ref()
                .map(|error| super::super::callback_lifo::shared_runtime_error(std::sync::Arc::clone(error)));
            let combined = dde_callback_failure(primary, cleanup);
            match origin {
                Win16DdeCallbackOrigin::Foreground(operation) => {
                    return Err(self.retain_foreground_dde_completion_failure(operation, combined)
                        .unwrap_or_else(|error| error));
                }
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    operation,
                    ..
                } => return Err(self.retain_callback_follow_up_failure(
                    callback_id, host_frame, operation, combined,
                ).unwrap_or_else(|error| error)),
                _ => {}
            }
            return Err(combined);
        }
        if let Some(error) = callback_error {
            let error = super::super::callback_lifo::shared_runtime_error(error);
            match origin {
                Win16DdeCallbackOrigin::Foreground(operation) => {
                    return Err(self.retain_foreground_dde_completion_failure(operation, error)
                        .unwrap_or_else(|error| error));
                }
                Win16DdeCallbackOrigin::CallbackFollowUp {
                    callback_id,
                    host_frame,
                    operation,
                    ..
                } => return Err(self.retain_callback_follow_up_failure(
                    callback_id, host_frame, operation, error,
                ).unwrap_or_else(|error| error)),
                _ => {}
            }
            return Err(error);
        }
        Ok(Win16DdeCallbackFinish::Resume { origin, step: next })
    }

    fn retain_dde_callback_reply_failure(
        &mut self,
        callback_id: super::CallbackFrameId,
        origin: Win16DdeCallbackOrigin,
        error: RuntimeError,
    ) -> RuntimeError {
        let retained = match origin {
            Win16DdeCallbackOrigin::Foreground(operation) => self
                .retain_foreground_dde_completion_failure(operation, error)
                .unwrap_or_else(|retained| retained),
            Win16DdeCallbackOrigin::CallbackFollowUp {
                callback_id: parent_id,
                host_frame,
                operation,
                ..
            } => self
                .retain_callback_follow_up_failure(
                    parent_id,
                    host_frame,
                    operation,
                    error,
                )
                .unwrap_or_else(|retained| retained),
            Win16DdeCallbackOrigin::WindowWait { .. }
            | Win16DdeCallbackOrigin::GuestExecution { .. } => error,
        };
        self.retain_dde_callback_entry_error(callback_id, retained)
    }

    fn leave_dde_callback_guest_frame(&mut self) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Dde)?;
        let frame = self.dde_callbacks.last().ok_or_else(|| {
            invariant("DDE callback frame disappeared before its readback follow-up")
        })?;
        if !frame.callback_kind_active || frame.active_call.is_some() {
            return Err(invariant(
                "DDE callback guest frame is still active during readback follow-up",
            ));
        }
        super::super::retire_callback_binding_from_stacks(
            &mut self.callback_kinds,
            &mut self.callback_frame_ids,
            CallbackKind::Dde,
            callback_id,
        )?;
        self.dde_callbacks.last_mut().expect("frame checked").callback_kind_active = false;
        Ok(())
    }

}
