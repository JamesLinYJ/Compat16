//! Resource effects are staged once before the checked API return. A later
//! owner-release failure reuses that result, never a LoadResource/lock effect.
use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_resource_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Resource)?;
        let frame = self
            .resource_callbacks
            .last()
            .filter(|frame| frame.callback_id == id && !frame.terminal)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource return has no exact live source",
                )
            })?;
        if frame.phase == ResourceCallPhase::AwaitHandler {
            let mut call = frame.callback.clone().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource handler has no retained CPU owner",
                )
            })?;
            let result = self
                .finish_guest_far_callback_checked(cpu, dos, memory, &mut call)
                .and_then(|value| {
                    self.release_guest_far_callback_owner(&mut call, dos, memory)
                        .map(|()| value as u16)
                });
            self.resource_callbacks
                .last_mut()
                .expect("resource source survives checked return")
                .callback = Some(call);
            let data = result?;
            let frame = self
                .resource_callbacks
                .last_mut()
                .expect("returned resource handler");
            frame.callback = None;
            frame.completion = Some(ResourceCompletion::Commit {
                data,
                operation: "resource-callback-complete",
            });
            frame.phase = ResourceCallPhase::Complete;
        }
        self.complete_resource_call(cpu, dos, memory, host)
    }

    pub(super) fn complete_resource_call(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Resource)?;
        let frame = self
            .resource_callbacks
            .last()
            .filter(|frame| frame.callback_id == id && !frame.terminal)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource completion lost its exact source",
                )
            })?;
        if frame.phase == ResourceCallPhase::Returned {
            return self.retire_resource_call(dos, memory);
        }
        if frame.phase != ResourceCallPhase::Complete || frame.callback.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "resource API completion precedes its checked handler return",
            ));
        }
        let mut completion = self
            .resource_callbacks
            .last_mut()
            .expect("resource completion source")
            .completion
            .take()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource completion has no retained result phase",
                )
            })?;
        let result = self.apply_resource_completion(cpu, dos, memory, host, &mut completion);
        self.resource_callbacks
            .last_mut()
            .expect("resource source retained through CPU commit")
            .completion = Some(completion);
        result?;
        self.retire_resource_call(dos, memory)
    }

    fn apply_resource_completion(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        completion: &mut ResourceCompletion,
    ) -> Result<(), RuntimeError> {
        loop {
            match *completion {
                ResourceCompletion::Commit { data, operation } => {
                    let frame = self
                        .resource_callbacks
                        .last()
                        .expect("resource result owner");
                    let key = frame.key.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "resource result has no module-local resource identity",
                        )
                    })?;
                    *completion = match frame.result {
                        ResourceReturn::Load => {
                            let data = self.commit_loaded_resource(key, data)?;
                            ResourceCompletion::Ready {
                                value: u32::from(data),
                                kind: Win16ReturnKind::Word,
                                operation: Some(operation),
                                reported: false,
                            }
                        }
                        ResourceReturn::Lock => {
                            let data = self.commit_reloaded_resource(key, data)?;
                            ResourceCompletion::Lock { data, operation }
                        }
                    };
                }
                ResourceCompletion::Lock { data, operation } => {
                    let value = if data == 0 {
                        0
                    } else {
                        self.global_lock(data, memory)?
                    };
                    *completion = ResourceCompletion::Ready {
                        value,
                        kind: Win16ReturnKind::FarPointer,
                        operation: Some(operation),
                        reported: false,
                    };
                }
                ResourceCompletion::Ready {
                    value,
                    kind,
                    operation,
                    reported,
                } => {
                    if !reported {
                        if let (Some(key), Some(operation)) = (
                            self.resource_callbacks
                                .last()
                                .expect("resource observer source")
                                .key,
                            operation,
                        ) {
                            host.observe_win16_io(&crate::Win16IoEvent::ResourceResult {
                                operation,
                                module: key.module,
                                resource: key.info,
                                value,
                            });
                        }
                        *completion = ResourceCompletion::Ready {
                            value,
                            kind,
                            operation,
                            reported: true,
                        };
                    }
                    self.return_resource_caller(cpu, dos, memory, value, kind)?;
                    // CPU commit is followed only by an infallible phase write.
                    // Root release below can be retried without repeating effects.
                    self.resource_callbacks
                        .last_mut()
                        .expect("returned resource source")
                        .phase = ResourceCallPhase::Returned;
                    return Ok(());
                }
            }
        }
    }
}
