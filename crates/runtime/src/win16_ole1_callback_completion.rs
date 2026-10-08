impl Win16State {

    pub(in crate::win16_runtime) fn finish_ole1_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Ole1)?;
        let frame = self.ole1_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "top OLE1 callback has no family continuation",
            )
        })?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "top OLE1 callback identity differs from its family continuation",
            ));
        }
        let stage = frame.stage;
        let pending_release = self
            .ole1_server_state
            .pending_item_release_completion(callback_id.0);
        let pending_server_release = self
            .ole1_server_state
            .pending_release_completion(callback_id.0);
        if pending_release.is_some()
            && !matches!(stage, Win16Ole1CallbackStage::ServerRevokeObject(_))
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 callback completion journal belongs to another callback stage",
            ));
        }
        if pending_server_release.is_some()
            && !matches!(stage, Win16Ole1CallbackStage::ServerRelease(_))
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 server Release journal belongs to another callback stage",
            ));
        }
        let mut active_call = if pending_release.is_some() || pending_server_release.is_some() {
            None
        } else {
            Some(frame.active_call.take().ok_or_else(|| {
                RuntimeError::new(Kind::GuestFault, "OLE1 callback gate has no active call")
            })?)
        };
        let callback_status = if let Some(pending) = pending_release {
            if pending.callback_id != callback_id.0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 callback completion journal changed its callback identity",
                ));
            }
            u32::from(OLE1_OK)
        } else if let Some(pending) = pending_server_release {
            if pending.callback_id != callback_id.0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 server Release journal changed its callback identity",
                ));
            }
            match pending.callback_result {
                super::super::win16_ole1_server_state::Ole1ReleaseCallbackResult::Returned(
                    status,
                ) => u32::from(status),
                _ => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "server Release callback frame has no returned OLESTATUS",
                    ));
                }
            }
        } else {
            let active = active_call.as_mut().expect("new callback owns active call");
            let status = match self.finish_guest_far_callback_checked(cpu, dos, memory, active) {
                Ok(status) => status,
                Err(error) => {
                    self.ole1_callbacks
                        .last_mut()
                        .expect("OLE1 frame checked")
                        .active_call = active_call.take();
                    return Err(error);
                }
            };
            if let Err(error) = self.release_guest_far_callback_owner(
                active_call.as_mut().expect("active callback retained"),
                dos,
                memory,
            ) {
                self.ole1_callbacks
                    .last_mut()
                    .expect("OLE1 frame checked")
                    .active_call = active_call.take();
                return Err(error);
            }

            let object_effect = self
                .ole1_callbacks
                .last_mut()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 continuation disappeared before effect completion",
                    )
                })?
                .object_effect
                .take();
            self.finish_ole1_object_effect(object_effect, status, memory)?
        };

        let mut next_server_release = None;
        let mut server_release_owner = None;
        let callback_status = match stage {
            Win16Ole1CallbackStage::ObjectMethod => callback_status,
            Win16Ole1CallbackStage::ServerRevokeObject(identity) => {
                if pending_release.is_none() {
                    self.ole1_server_state
                        .begin_item_release_completion(
                            callback_id.0,
                            identity,
                            callback_status as u16,
                        )
                        .map_err(|status| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                format!(
                                    "OLE1 Release completion lost its journal identity ({status})"
                                ),
                            )
                        })?;
                }
                self.finish_server_item_release_completion(callback_id.0, identity, host)?;
                // The XP server helper ignores the object Release method's
                // status after invoking it and reports OLE_OK.
                u32::from(OLE1_OK)
            }
            Win16Ole1CallbackStage::ServerRelease(target) => {
                if pending_server_release.is_none() {
                    let owner = self
                        .ole1_server_state
                        .owner_of_release_target(target)
                        .ok_or_else(|| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "OLE1 Release callback target lost its exact owner",
                            )
                        })?;
                    self.ole1_server_state
                        .begin_release_completion(
                            callback_id.0,
                            owner,
                            target,
                            callback_status as u16,
                        )
                        .map_err(|status| {
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                format!("OLE1 server Release completion lost readiness ({status})"),
                            )
                        })?;
                }
                super::server_api::finish_server_release_completion(
                    &mut self.ole1_server_state,
                    callback_id.0,
                    target,
                    host,
                )?;
                // XP's OleRevokeServer walks each document Release and then
                // the root server Release before the public import returns.
                // Keep the original caller continuation while another exact
                // generation-bound target is ready; return WAIT only after
                // the parent still has outstanding DDE/conversation work.
                let owner = self
                    .ole1_server_state
                    .pending_release_completion(callback_id.0)
                    .filter(|entry| entry.target == target)
                    .map(|entry| entry.owner)
                    .or_else(|| self.ole1_server_state.owner_of_release_target(target))
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "OLE1 Release completion lost its owner identity",
                        )
                    })?;
                server_release_owner = Some(owner);
                let parent_revoking = match target {
                    super::super::win16_ole1_server_state::Ole1ReleaseTarget::Document {
                        server, ..
                    } => self
                        .ole1_server_state
                        .server(owner, server)
                        .is_some_and(|record| {
                            record.state
                                == super::super::win16_ole1_server_state::Ole1RegistrationState::Revoking
                        }),
                    super::super::win16_ole1_server_state::Ole1ReleaseTarget::Server { .. } => {
                        false
                    }
                };
                if parent_revoking {
                    next_server_release = super::server_api::next_server_revoke_release_target(
                        self, owner, target, host,
                    )?;
                }
                if next_server_release.is_some() {
                    u32::from(OLE1_OK)
                } else if parent_revoking {
                    u32::from(super::super::win16_ole1_server_state::OLE_WAIT_FOR_RELEASE)
                } else {
                    u32::from(OLE1_OK)
                }
            }
            proxy_stage => {
                self.finish_ole1_proxy_callback_stage(
                    cpu,
                    dos,
                    memory,
                    callback_id,
                    proxy_stage,
                    callback_status,
                )?;
                return Ok(());
            }
        };

        if let Some(next_target) = next_server_release {
            let (completed_target, return_to, return_kind, saved) = self
                .ole1_callbacks
                .last()
                .filter(|frame| frame.callback_id == callback_id)
                .and_then(|frame| match frame.stage {
                    Win16Ole1CallbackStage::ServerRelease(target) => Some((
                        target,
                        frame.return_to,
                        frame.return_kind,
                        frame.saved.clone(),
                    )),
                    _ => None,
                })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 child Release lost its exact target or return contract",
                )
            })?;
            let owner = server_release_owner.ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 child Release cascade lost its exact owner",
                )
            })?;
            if let (Some(return_to), Some(return_kind)) = (return_to, return_kind) {
                if self
                    .ole1_server_release_cascades
                    .iter()
                    .any(|pending| pending.callback_id == callback_id)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 public Release cascade already has a continuation for this callback",
                    ));
                }
                self.ole1_server_release_cascades.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "retain OLE1 public Release cascade continuation",
                        error,
                    )
                })?;
                self.ole1_server_release_cascades
                    .push(super::super::Ole1ServerReleaseCascadeContinuation {
                        callback_id,
                        owner,
                        completed_target,
                        target: next_target,
                        return_to,
                        return_kind,
                        saved: saved.clone(),
                    });
            }
            let frame = self.ole1_callbacks.pop().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 child Release continuation disappeared before parent Release",
                )
            })?;
            if frame.callback_id != callback_id {
                self.ole1_callbacks.push(frame);
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 child Release continuation changed identity before parent Release",
                ));
            }
            if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
                self.ole1_callbacks.push(frame);
                self.ole1_server_release_cascades
                    .retain(|pending| pending.callback_id != callback_id);
                return Err(error);
            }
            if let Err(status) = self
                .ole1_server_state
                .finalize_release_completion(callback_id.0, completed_target)
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!(
                        "completed OLE1 child Release journal could not be finalized ({status})"
                    ),
                ));
            }
            cpu.regs = saved;
            return match (return_to, return_kind) {
                (Some(return_to), Some(_)) => {
                    let start = self.begin_server_release_callback(
                        owner,
                        next_target,
                        cpu,
                        dos,
                        memory,
                        return_to,
                    );
                    if start.is_ok() {
                        self.ole1_server_release_cascades
                            .retain(|pending| pending.callback_id != callback_id);
                    }
                    start.map(|_| ())
                }
                (None, None) => self
                    .begin_ole1_server_shutdown_release_callback(
                        owner,
                        next_target,
                        cpu,
                        dos,
                        memory,
                    )
                    .map(|_| ()),
                _ => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 child Release has a partial return continuation",
                )),
            };
        }

        let frame = self.ole1_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 continuation disappeared after callback return",
            )
        })?;
        frame.active_call = active_call;
        let saved = frame.saved.clone();
        let return_to = frame.return_to;
        let return_kind = frame.return_kind;
        cpu.regs = saved;
        match (return_to, return_kind) {
            (Some(return_to), Some(return_kind)) => {
                if let Err(error) = self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    callback_status,
                    return_kind,
                ) {
                    return Err(error);
                }
            }
            (None, None) => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 callback continuation has a partial guest-resume target",
                ));
            }
        }

        let frame = self.ole1_callbacks.pop().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 callback continuation disappeared before retirement",
            )
        })?;
        if let Err(error) = self.retire_callback_binding(CallbackKind::Ole1, callback_id) {
            self.ole1_callbacks.push(frame);
            return Err(error);
        }
        if let Win16Ole1CallbackStage::ServerRelease(target) = stage {
            self.ole1_server_state
                .finalize_release_completion(callback_id.0, target)
                .map_err(|status| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("completed OLE1 server Release journal could not be finalized ({status})"),
                    )
                })?;
        }
        self.retry_pending_ole1_proxy_retirements()?;
        Ok(())
    }

    /// Retry the exact next Release callback after a preceding child Release
    /// completed but checked guest entry could not begin. The original public
    /// API return address/register image stays in this journal until entry
    /// succeeds or the API path completes an explicit inline OLE status.
    pub(in crate::win16_runtime) fn retry_pending_ole1_server_release_cascade(
        &mut self,
        owner: guest_core::OwnerId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let Some(pending) = self
            .ole1_server_release_cascades
            .iter()
            .find(|pending| pending.owner == owner)
            .cloned()
        else {
            return Ok(false);
        };
        if pending.return_kind != Win16ReturnKind::Word {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 public Release cascade has a non-WORD return contract",
            ));
        }
        if let Some(journal) = self
            .ole1_server_state
            .pending_release_completion(pending.callback_id.0)
        {
            if journal.target != pending.completed_target
                || journal.phase
                    != super::super::win16_ole1_server_state::Ole1ReleasePhase::Committed
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 Release cascade retry lost the completed child resource journal",
                ));
            }
            self.ole1_server_state
                .finalize_release_completion(pending.callback_id.0, pending.completed_target)
                .map_err(|status| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("cannot finalize retried OLE1 child Release ({status})"),
                    )
                })?;
        }
        cpu.regs = pending.saved.clone();
        match self.begin_server_release_callback(
            pending.owner,
            pending.target,
            cpu,
            dos,
            memory,
            pending.return_to,
        ) {
            Ok(_) => {
                self.ole1_server_release_cascades
                    .retain(|entry| entry.callback_id != pending.callback_id);
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn finish_server_item_release_completion(
        &mut self,
        callback_id: u64,
        identity: super::super::win16_ole1_server_state::Ole1ItemCallbackIdentity,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let pending_atom = self
            .ole1_server_state
            .item_atom_delete_pending(callback_id, identity)
            .map_err(|status| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("OLE1 Release completion journal changed identity ({status})"),
                )
            })?;
        if let Some(atom) = pending_atom {
            // The host adapter must surface GlobalDeleteAtom's GetLastError
            // check as Result<()>; its native ATOM return is always zero and
            // is not a receipt containing the deleted atom.
            let _ = host.win16_global_delete_atom(atom)?;
            self.ole1_server_state
                .mark_item_atom_deleted(callback_id, identity)
                .map_err(|status| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        format!("OLE1 Release atom deletion lost its journal ({status})"),
                    )
                })?;
        }
        self.ole1_server_state
            .finish_revoke_item(callback_id, identity)
            .map_err(|status| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("OLE1 RevokeObject Release lost its exact item ({status})"),
                )
            })
    }

    fn finish_ole1_object_effect(
        &mut self,
        effect: Option<Win16Ole1ObjectEffect>,
        callback_status: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        match effect {
            Some(Win16Ole1ObjectEffect::Add {
                document,
                output_far,
                client_far,
                operation_id,
            }) => {
                let Some(proxy_id) = self
                    .ole1_client_documents
                    .proxy_for_operation(operation_id)
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 creation lost its operation-specific client proxy",
                    ));
                };
                if callback_status != u32::from(OLE1_OK)
                    && callback_status != u32::from(OLE1_WAIT_FOR_RELEASE)
                {
                    self.ole1_client_documents.finish_operation(operation_id);
                    self.retire_ole1_client_operation_proxy(proxy_id)?;
                    return Ok(callback_status);
                }
                let output = match self.checked_ole1_pointer(
                    output_far,
                    Access::Read,
                    4,
                    OLE1_ERROR_ADDRESS,
                    memory,
                ) {
                    Ok(output) => output,
                    Err(status) => {
                        self.ole1_client_documents.finish_operation(operation_id);
                        self.retire_ole1_client_operation_proxy(proxy_id)?;
                        return Ok(u32::from(status));
                    }
                };
                let mut object_bytes = [0_u8; 4];
                if self
                    .selectors
                    .read(memory, output, &mut object_bytes)
                    .is_err()
                {
                    self.ole1_client_documents.finish_operation(operation_id);
                    self.retire_ole1_client_operation_proxy(proxy_id)?;
                    return Ok(u32::from(OLE1_ERROR_ADDRESS));
                }
                let object_far = u32::from_le_bytes(object_bytes);
                if object_far == 0 {
                    if callback_status == u32::from(OLE1_OK) {
                        self.ole1_client_documents.finish_operation(operation_id);
                        self.retire_ole1_client_operation_proxy(proxy_id)?;
                        return Ok(u32::from(OLE1_ERROR_OBJECT));
                    }
                    self.ole1_client_documents.await_operation(operation_id);
                    return Ok(callback_status);
                }
                if self.ole1_object_vtable(object_far, memory).is_err() {
                    self.ole1_client_documents.finish_operation(operation_id);
                    self.retire_ole1_client_operation_proxy(proxy_id)?;
                    return Ok(u32::from(OLE1_ERROR_OBJECT));
                }
                if callback_status == u32::from(OLE1_WAIT_FOR_RELEASE) {
                    if let Err(status) = self
                        .ole1_client_documents
                        .record_pending_creation_object(operation_id, Some(object_far))
                    {
                        self.ole1_client_documents.finish_operation(operation_id);
                        self.retire_ole1_client_operation_proxy(proxy_id)?;
                        return Ok(u32::from(status));
                    }
                }
                if let Err(status) = self
                    .ole1_client_documents
                    .add_object_with_proxy(
                        document,
                        object_far,
                        client_far,
                        Some(proxy_id),
                        Some(operation_id),
                    )
                {
                    self.ole1_client_documents.finish_operation(operation_id);
                    self.retire_ole1_client_operation_proxy(proxy_id)?;
                    return Ok(u32::from(status));
                }
                if callback_status == u32::from(OLE1_WAIT_FOR_RELEASE) {
                    self.ole1_client_documents.await_operation(operation_id);
                } else {
                    self.ole1_client_documents.finish_operation(operation_id);
                }
                Ok(callback_status)
            }
            Some(Win16Ole1ObjectEffect::Remove {
                object_far,
                operation_id,
                pending_document,
            }) => {
                if callback_status == u32::from(OLE1_OK) {
                    let proxy_id = self.ole1_client_documents.remove_object(object_far);
                    self.ole1_client_documents.finish_operation(operation_id);
                    if let Some(proxy_id) = proxy_id {
                        self.retire_ole1_client_operation_proxy(proxy_id)?;
                    }
                    return Ok(callback_status);
                }
                if callback_status == u32::from(OLE1_WAIT_FOR_RELEASE) && pending_document.is_some()
                {
                    self.ole1_client_documents.await_operation(operation_id);
                } else {
                    self.ole1_client_documents.finish_operation(operation_id);
                }
                Ok(callback_status)
            }
            Some(Win16Ole1ObjectEffect::ProtocolAlias { owner, protocol }) => {
                if callback_status == 0 {
                    return Ok(0);
                }
                let alias_far = callback_status;
                if self
                    .checked_ole1_pointer(alias_far, Access::Read, 1, OLE1_ERROR_ADDRESS, memory)
                    .is_err()
                {
                    return Ok(0);
                }
                if is_known_oleobject_protocol(&protocol)
                    && self.ole1_object_vtable_wire(alias_far, memory).is_err()
                {
                    return Ok(0);
                }
                if let Some(owner) = owner {
                    if self
                        .ole1_client_documents
                        .add_protocol_alias(owner, alias_far, protocol)
                        .is_err()
                    {
                        return Ok(0);
                    }
                }
                Ok(callback_status)
            }
            None => Ok(callback_status),
        }
    }
}
