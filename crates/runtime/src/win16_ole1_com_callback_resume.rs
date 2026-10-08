//! Exact COM callback-frame routing and acknowledgement for OLE1 client calls.

use super::*;

impl Win16State {
    /// Enter the application callback for one exact native COM AdviseSink
    /// frame. SaveObject is handled as a typed compatibility failure because
    /// it has no verified OLE1 callback equivalent; no OLE1 notification is
    /// synthesized for it.
    pub(in crate::win16_runtime) fn begin_ole1_com_advise_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        step: &crate::Win16ComHostCallbackStep,
    ) -> Result<(), RuntimeError> {
        let (call, callback) = self.prepare_ole1_com_advise_callback(step, memory)?;
        if !self.ole1_client_proxy_call_is_current(call, memory)? {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "OLE1 COM callback client selector generation is stale",
            ));
        }
        let procedure = match self.ole1_client_callback_address(call.client_far, memory) {
            Ok(procedure) => procedure,
            Err(error) => match error.status_or_runtime() {
                Ok(status) => {
                    return Err(RuntimeError::new(
                        Kind::GuestFault,
                        format!("OLE1 COM callback target is not callable (status {status})"),
                    ));
                }
                Err(error) => return Err(error),
            },
        };
        self.ole1_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve OLE1 COM callback continuation",
                error,
            )
        })?;
        self.ole1_com_callback_resumes
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve OLE1 COM callback resume record",
                    error,
                )
            })?;
        let callback_id = self.reserve_callback_frame_id()?;
        self.ole1_callbacks.push(Win16Ole1CallbackFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to: None,
            return_kind: None,
            stage: Win16Ole1CallbackStage::ClientComAdviseNotification { call, callback },
            object_effect: None,
            pending_proxy_retirement: None,
            active_call: None,
        });
        if let Err(primary) = self.push_callback_kind(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.pop();
            return Err(primary);
        }

        let arguments = [
            Win16FarCallbackArgument::GuestPointer {
                far: call.client_far,
                access: Access::Read,
                bytes: 4,
            },
            Win16FarCallbackArgument::Word(call.notification),
            Win16FarCallbackArgument::GuestPointer {
                far: call.object_far,
                access: Access::Read,
                bytes: OLEOBJECT_BYTES as u32,
            },
        ];
        if self.enter_ole1_client_proxy_guest_call(
            cpu,
            dos,
            memory,
            callback_id,
            Win16Ole1CallbackStage::ClientComAdviseNotification { call, callback },
            procedure,
            &arguments,
        )? {
            return Ok(());
        }

        self.ole1_callbacks.pop();
        if let Err(cleanup) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "checked OLE1 COM callback entry failed and its callback binding could not be retired",
            )
            .with_cleanup("retire unentered OLE1 COM callback binding", cleanup));
        }
        Err(RuntimeError::new(
            Kind::GuestFault,
            "checked OLE1 COM callback could not enter its guest callback",
        ))
    }

    /// Retain one exact callback outcome before submitting it to the STA.
    /// The queue remains authoritative if the transport returns an ambiguous
    /// error after the callback may already have consumed the outcome.
    pub(in crate::win16_runtime) fn queue_ole1_com_callback_resume(
        &mut self,
        resume: crate::Win16ComHostResume,
    ) -> Result<(), RuntimeError> {
        if let Some(existing) = self
            .ole1_com_callback_resumes
            .iter()
            .find(|existing| existing.owner == resume.owner && existing.frame == resume.frame)
        {
            return if existing == &resume {
                Ok(())
            } else {
                Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "COM callback frame already has a different retained outcome",
                ))
            };
        }
        self.ole1_com_callback_resumes.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact OLE1 COM callback outcome",
                error,
            )
        })?;
        self.ole1_com_callback_resumes.push(resume);
        Ok(())
    }

    /// Borrow the oldest prepared COM callback resume. The dispatcher must
    /// leave it queued until the exact host frame reports CallbackFrameComplete.
    pub(in crate::win16_runtime) fn pending_ole1_com_callback_resume(
        &self,
    ) -> Option<&crate::Win16ComHostResume> {
        self.ole1_com_callback_resumes.first()
    }

    /// Commit only the exact callback-frame completion. A transport error is
    /// retained as an uncertain, non-retryable reply because the STA may have
    /// consumed the outcome before the transport reported failure.
    pub(in crate::win16_runtime) fn complete_ole1_com_callback_resume(
        &mut self,
        resume: &crate::Win16ComHostResume,
        step: &crate::Win16ComHostStep,
    ) -> Result<(), RuntimeError> {
        let Some(expected) = self.ole1_com_callback_resumes.first() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM callback resume completion has no queued guest reply",
            ));
        };
        if expected != resume {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM callback resume completion names a different queued reply",
            ));
        }
        let expected_route = self.ole1_com_callback_route(resume)?;
        match (&resume.outcome, step) {
            (
                crate::Win16ComHostCallbackOutcome::Reply(_),
                crate::Win16ComHostStep::CallbackFrameComplete { frame, owner },
            ) if *frame == resume.frame && *owner == resume.owner => {}
            (
                crate::Win16ComHostCallbackOutcome::Failed(expected_failure),
                crate::Win16ComHostStep::CallbackFailed {
                    frame: Some(frame),
                    parent,
                    owner,
                    route,
                    failure,
                },
            ) if *frame == resume.frame
                && *parent == resume.parent
                && *owner == resume.owner
                && *route == expected_route
                && *failure == *expected_failure
                => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "COM callback resume did not receive its exact typed host acknowledgement",
                ));
            }
        }
        self.ole1_com_callback_resumes.remove(0);
        self.ole1_com_callback_resume_failures
            .retain(|(owner, failed_frame)| *owner != resume.owner || *failed_frame != resume.frame);
        Ok(())
    }

    /// Send the oldest checked guest callback result once to the exact host
    /// frame. On transport failure the reply stays queued and is marked
    /// uncertain; sending it again could deliver the same outcome twice.
    pub(in crate::win16_runtime) fn resume_pending_ole1_com_callback(
        &mut self,
        host: &mut impl crate::RuntimeHost,
    ) -> Result<Option<crate::Win16ComHostStep>, RuntimeError> {
        let Some(resume) = self.ole1_com_callback_resumes.first().cloned() else {
            return Ok(None);
        };
        if self
            .ole1_com_callback_resume_failures
            .contains(&(resume.owner, resume.frame))
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "OLE1 COM callback reply has uncertain delivery and is retained without retry",
            ));
        }
        self.ole1_com_callback_resume_failures
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve non-retryable COM callback delivery marker",
                    error,
                )
            })?;
        let step = if let Some(parent) = resume.parent {
            let operation = self
                .com_guest_operation_for_host(parent)?
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::CompatibilityGap,
                        "OLE1 COM callback parent has no registered guest continuation",
                    )
                })?;
            let disposition = match self.resume_com_guest_callback(operation, resume.clone(), host) {
                Ok(disposition) => disposition,
                Err(primary) => {
                    self.ole1_com_callback_resume_failures
                        .push((resume.owner, resume.frame));
                    return Err(primary);
                }
            };
            match (&resume.outcome, disposition) {
                (
                    crate::Win16ComHostCallbackOutcome::Reply(_),
                    super::super::super::com_operations::StepDisposition::CallbackFrameComplete,
                ) => crate::Win16ComHostStep::CallbackFrameComplete {
                    frame: resume.frame,
                    owner: resume.owner,
                },
                (
                    crate::Win16ComHostCallbackOutcome::Failed(failure),
                    super::super::super::com_operations::StepDisposition::CallbackFailed,
                ) => crate::Win16ComHostStep::CallbackFailed {
                    frame: Some(resume.frame),
                    parent: resume.parent,
                    owner: resume.owner,
                    route: self.com_operations.callback_route(operation)?,
                    failure: failure.clone(),
                },
                _ => {
                    self.ole1_com_callback_resume_failures
                        .push((resume.owner, resume.frame));
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "OLE1 COM callback outcome returned an unexpected host acknowledgement; outcome is retained without retry",
                    ));
                }
            }
        } else {
            match host.win16_com_continue(
                resume.owner,
                crate::Win16ComHostContinue {
                    operation: None,
                    resume: Some(resume.clone()),
                },
            ) {
                Ok(step) => step,
                Err(primary) => {
                    self.ole1_com_callback_resume_failures
                        .push((resume.owner, resume.frame));
                    return Err(primary);
                }
            }
        };
        if let Err(primary) = self.complete_ole1_com_callback_resume(&resume, &step) {
            self.ole1_com_callback_resume_failures
                .push((resume.owner, resume.frame));
            return Err(primary);
        }
        Ok(Some(step))
    }

    fn ole1_com_callback_route(
        &self,
        resume: &crate::Win16ComHostResume,
    ) -> Result<crate::Win16ComHostCallbackRoute, RuntimeError> {
        let mut routes = self.ole1_callbacks.iter().filter_map(|frame| match frame.stage {
            super::Win16Ole1CallbackStage::ClientComAdviseNotification { callback, .. }
                if callback.frame == resume.frame
                    && callback.parent == resume.parent
                    && callback.owner == resume.owner => Some(callback.route),
            _ => None,
        });
        let route = routes.next().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 COM callback resume has no matching live guest callback route",
            )
        })?;
        if routes.next().is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 COM callback route is duplicated for its exact frame identity",
            ));
        }
        Ok(route)
    }

}
