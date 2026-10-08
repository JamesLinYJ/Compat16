impl Win16State {

    pub(in crate::win16_runtime) fn cancel_ole1_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Ole1)?;
        let family_callback_id = self
            .ole1_callbacks
            .last()
            .map(|frame| frame.callback_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 teardown has no family continuation for its shared callback frame",
                )
            })?;
        if family_callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 teardown callback identity differs from its family continuation",
            ));
        }
        if let Some(pending) = self
            .ole1_server_state
            .pending_item_release_completion(callback_id.0)
        {
            let identity = self
                .ole1_callbacks
                .last()
                .and_then(|frame| match frame.stage {
                    Win16Ole1CallbackStage::ServerRevokeObject(identity) => Some(identity),
                    _ => None,
                })
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 teardown found a Release journal on another callback stage",
                    )
                })?;
            if pending.callback_id != callback_id.0 || pending.identity != identity {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 teardown Release journal no longer matches its exact callback identity",
                ));
            }
            // Retire the already-returned guest Release before dropping the
            // family/shared callback frames. A host error leaves the exact
            // journal and frame live, so a later teardown retry does not
            // execute OLEOBJECT::Release a second time.
            self.finish_server_item_release_completion(callback_id.0, identity, host)?;
        }
        if let Some(pending) = self
            .ole1_server_state
            .pending_release_completion(callback_id.0)
        {
            let target = self
                .ole1_callbacks
                .last()
                .and_then(|frame| match frame.stage {
                    Win16Ole1CallbackStage::ServerRelease(target) => Some(target),
                    _ => None,
                })
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 teardown found a server Release journal on another callback stage",
                    )
                })?;
            if pending.callback_id != callback_id.0 || pending.target != target {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 teardown server Release journal lost its exact callback identity",
                ));
            }
            // If atom deletion or endpoint retirement failed after Release
            // returned, teardown retries that journal before dropping the
            // callback owner; it never calls guest Release twice.
            super::server_api::finish_server_release_completion(
                &mut self.ole1_server_state,
                callback_id.0,
                target,
                host,
            )?;
        }
        let frame = self.ole1_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top OLE1 callback has no family continuation during teardown",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top OLE1 callback identity differs during teardown",
            ));
        }
        if let Some(mut active_call) = frame.active_call.take() {
            if let Err(error) = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::Ole1,
                callback_id,
                cpu,
                dos,
                memory,
                &mut active_call,
            ) {
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .active_call = Some(active_call);
                return Err(error);
            }
            self.ole1_callbacks
                .last_mut()
                .expect("OLE1 frame checked")
                .active_call = Some(active_call);
        }
        if let Some(proxy_id) = self
            .ole1_callbacks
            .last()
            .and_then(|frame| frame.pending_proxy_retirement)
        {
            self.ole1_callbacks
                .last_mut()
                .expect("OLE1 frame checked")
                .stage = Win16Ole1CallbackStage::ObjectMethod;
            self.queue_ole1_client_operation_proxy_for_teardown(proxy_id)?;
            self.ole1_callbacks
                .last_mut()
                .expect("OLE1 frame checked")
                .pending_proxy_retirement = None;
        }
        let (stage, effect) = self
            .ole1_callbacks
            .last()
            .map(|frame| (frame.stage, frame.object_effect.clone()))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 callback continuation disappeared during teardown",
                )
            })?;
        if let Win16Ole1CallbackStage::ClientComAdviseNotification { callback, .. } = stage {
            // Seal already delivered one precise typed failure to the native
            // callback. Consume its retained post-dispatch receipt here, at
            // the exact shared LIFO owner, without submitting a second reply.
            self.consume_sealed_com_callback_for_teardown(callback, host)?;
        }
        // If task execution ended while an OLESVR Release callback was still
        // in flight, retain a cancellation-phase journal before retiring the
        // callback frame. A subsequent teardown pass continues only the host
        // cleanup; it must never enter the same guest Release again.
        match stage {
            Win16Ole1CallbackStage::ServerRevokeObject(identity)
                if self
                    .ole1_server_state
                    .pending_item_release_completion(callback_id.0)
                    .is_none() =>
            {
                self.ole1_server_state
                    .begin_cancelled_item_release_completion(callback_id.0, identity)
                    .map_err(|status| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            format!("cannot journal cancelled OLE1 item Release ({status})"),
                        )
                    })?;
                self.finish_server_item_release_completion(callback_id.0, identity, host)?;
            }
            Win16Ole1CallbackStage::ServerRelease(target)
                if self
                    .ole1_server_state
                    .pending_release_completion(callback_id.0)
                    .is_none() =>
            {
                let owner = self
                    .ole1_server_state
                    .owner_of_release_target(target)
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "cancelled OLE1 server Release lost its exact owner",
                        )
                    })?;
                self.ole1_server_state
                    .begin_cancelled_release_completion(callback_id.0, owner, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            format!("cannot journal cancelled OLE1 server Release ({status})"),
                        )
                    })?;
                super::server_api::finish_server_release_completion(
                    &mut self.ole1_server_state,
                    callback_id.0,
                    target,
                    host,
                )?;
            }
            _ => {}
        }
        match (stage, effect) {
            (
                Win16Ole1CallbackStage::ObjectMethod,
                Some(Win16Ole1ObjectEffect::Add { operation_id, .. }),
            ) => {
                self.ole1_client_documents.finish_operation(operation_id);
                let proxy_id = self.ole1_client_documents.proxy_for_operation(operation_id);
                if let Some(proxy_id) = proxy_id {
                    if self
                        .ole1_client_proxy(proxy_id)
                        .is_some_and(|binding| binding.object.is_none())
                    {
                        self.ole1_callbacks
                            .last_mut()
                            .expect("OLE1 frame checked")
                            .pending_proxy_retirement = Some(proxy_id);
                        self.queue_ole1_client_operation_proxy_for_teardown(proxy_id)?;
                        self.ole1_callbacks
                            .last_mut()
                            .expect("OLE1 frame checked")
                            .pending_proxy_retirement = None;
                    }
                }
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .object_effect = None;
            }
            (
                Win16Ole1CallbackStage::ObjectMethod,
                Some(Win16Ole1ObjectEffect::Remove { operation_id, .. }),
            ) => {
                self.ole1_client_documents.finish_operation(operation_id);
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .object_effect = None;
            }
            _ => {}
        }
        let cancelled_proxy_call = match stage {
            Win16Ole1CallbackStage::ClientProxyQueryStatus(call)
            | Win16Ole1CallbackStage::ClientProxyQueryError(call)
            | Win16Ole1CallbackStage::ClientProxyQueryMethod(call)
            | Win16Ole1CallbackStage::ClientProxyNotification {
                call,
                completion: None,
            } => Some(call),
            _ => None,
        };
        if let Some(call) = cancelled_proxy_call {
            let Some(binding) = self.ole1_client_proxy(call.proxy_id) else {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client proxy binding disappeared while cancelling its callback",
                ));
            };
            if binding.proxy_far != call.proxy_far
                || binding.operation_id != call.proxy_operation_id
                || binding.client_far != call.client_far
                || binding.client_pointer != call.client_pointer
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client proxy identity changed before callback cancellation",
                ));
            }

            let captured_operation_id = call
                .pending_operation
                .map(|(operation_id, _initiating_callback_id)| operation_id);
            if let Some(operation_id) = captured_operation_id {
                // Finish only the generation captured when this proxy callback
                // began. Operation ids are never reused, so a stale callback
                // cannot cancel a later operation on the same object.
                self.ole1_client_documents.finish_operation(operation_id);
            } else if binding.object.is_none() {
                if let Some(operation_id) = call.proxy_operation_id {
                    self.ole1_client_documents.finish_operation(operation_id);
                }
            }

            let retire_unassociated_operation_proxy = binding.operation_id.is_some()
                && binding.operation_id == call.proxy_operation_id
                && binding.object.is_none();
            // Remove the callback's proxy reference before retirement. If the
            // exact handle cannot be freed, the binding/retirement queue keeps
            // the retry owner and this frame remains on the teardown stack.
            self.ole1_callbacks
                .last_mut()
                .expect("OLE1 frame checked")
                .stage = Win16Ole1CallbackStage::ObjectMethod;
            if retire_unassociated_operation_proxy {
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .pending_proxy_retirement = Some(call.proxy_id);
                self.queue_ole1_client_operation_proxy_for_teardown(call.proxy_id)?;
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .pending_proxy_retirement = None;
            }
        }
        let cancelled_completion = match stage {
            Win16Ole1CallbackStage::ClientProxyNotification {
                completion: Some(evidence),
                ..
            } => Some(evidence),
            _ => None,
        };
        if let Some(evidence) = cancelled_completion {
            let proxy_id = self
                .ole1_client_documents
                .complete_release_notification(evidence)
                .map_err(|status| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        format!(
                            "cancelled OLE1 release delivery no longer matches operation {} (status {status})",
                            evidence.operation_id.0
                        ),
                    )
                })?;
            // The guest task is gone, so commit this exact delivery as
            // cancelled. Keep the callback frame but clear the one-shot
            // evidence before any fallible proxy retirement attempt.
            self.ole1_callbacks
                .last_mut()
                .expect("OLE1 frame checked")
                .stage = Win16Ole1CallbackStage::ObjectMethod;
            if let Some(proxy_id) = proxy_id {
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .pending_proxy_retirement = Some(proxy_id);
                self.queue_ole1_client_operation_proxy_for_teardown(proxy_id)?;
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .pending_proxy_retirement = None;
            }
        }
        // Proxy handles are owned by the retirement queue before the callback
        // frame is retired. Process teardown frees them after selector-backed
        // aliases and callback buffers have released their pins.
        let frame = self.ole1_callbacks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 callback continuation disappeared during teardown",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.push(frame);
            return Err(error);
        }
        if let Win16Ole1CallbackStage::ServerRelease(target) = frame.stage {
            if self
                .ole1_server_state
                .pending_release_completion(callback_id.0)
                .is_some_and(|entry| {
                    entry.target == target
                        && entry.phase
                            == super::super::win16_ole1_server_state::Ole1ReleasePhase::Committed
                })
            {
                self.ole1_server_state
                    .finalize_release_completion(callback_id.0, target)
                    .map_err(|status| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            format!("teardown OLE1 server Release journal could not be finalized ({status})"),
                        )
                    })?;
            }
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn ole1_callback_code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        for frame in &self.ole1_callbacks {
            references.push((u32::from(frame.saved.cs) << 16) | u32::from(frame.saved.ip()));
            if let Some((cs, ip, _)) = frame.return_to {
                references.push((u32::from(cs) << 16) | u32::from(ip));
            }
            if let Some(active_call) = &frame.active_call {
                references.extend(active_call.code_references());
            }
        }
        references
    }
}
