impl Win16State {
    pub(super) fn begin_ole1_server_request(
        &mut self,
        request: Win16Ole1Request,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let owner = self.current_task_owner()?;
        if let Win16Ole1Request::SavedServerDoc { document } = &request {
            return self.begin_saved_server_document_api(owner, *document, cpu, return_to);
        }
        if let Win16Ole1Request::RevokeObject { client_far } = &request {
            return self.begin_revoke_server_object_api(
                owner,
                *client_far,
                cpu,
                dos,
                memory,
                return_to,
            );
        }
        if let Win16Ole1Request::RevokeServer { server } = &request {
            return self.begin_revoke_server_api(owner, *server, cpu, dos, memory, host, return_to);
        }
        if let Win16Ole1Request::RevokeServerDoc { document } = &request {
            return self.begin_revoke_server_document_api(
                owner, *document, cpu, dos, memory, host, return_to,
            );
        }
        let status = match request {
            Win16Ole1Request::RegisterServer {
                class_name_far,
                server_far,
                output_far,
                instance,
                use_mode,
            } => self.register_server_api(
                owner,
                class_name_far,
                server_far,
                output_far,
                instance,
                use_mode,
                memory,
                host,
            )?,
            Win16Ole1Request::BlockServer { server } => {
                self.ole1_server_state
                    .set_blocked(owner, Ole1ServerHandle::from_guest_long(server as u32))
                    .map_or_else(u32::from, |_| u32::from(OLE_OK))
            }
            Win16Ole1Request::UnblockServer {
                server,
                blocked_output_far,
            } => self.unblock_server_api(
                owner,
                server,
                blocked_output_far,
                cpu,
                dos,
                memory,
                host,
            )?,
            Win16Ole1Request::RegisterServerDoc {
                server,
                document_name_far,
                server_document_far,
                output_far,
            } => self.register_server_document_api(
                owner,
                server,
                document_name_far,
                server_document_far,
                output_far,
                memory,
                host,
            )?,
            Win16Ole1Request::RenameServerDoc {
                document,
                document_name_far,
            } => self.rename_server_document_api(
                owner,
                document,
                document_name_far,
                memory,
                host,
            )?,
            Win16Ole1Request::RevertServerDoc { document } => {
                self.ole1_server_state
                    .document(
                        owner,
                        super::super::win16_ole1_server_state::Ole1ServerDocumentHandle::from_guest_long(
                            document as u32,
                        ),
                    )
                    .map_or_else(|| u32::from(OLE_ERROR_HANDLE), |_| u32::from(OLE_OK))
            }
            Win16Ole1Request::RevokeServer { .. }
            | Win16Ole1Request::RevokeServerDoc { .. } => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "revoke API bypassed its resumable OLESVR path",
                ));
            }
            _ => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "non-server OLE1 request reached the OLESVR API executor",
                ));
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            status,
            return_kind,
        )
    }

    fn begin_saved_server_document_api(
        &mut self,
        owner: guest_core::OwnerId,
        document_long: i32,
        cpu: &mut Cpu,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use super::super::win16_ole1_server_state::{
            OLE_ERROR_COMMAND, OLE_ERROR_HANDLE, OLE_ERROR_TERMINATE, OLE_OK, Ole1DocumentState,
            Ole1ServerDocumentHandle,
        };
        let document = Ole1ServerDocumentHandle::from_guest_long(document_long as u32);
        let status = match self.ole1_server_state.document(owner, document) {
            None => OLE_ERROR_HANDLE,
            Some(record) if record.state != Ole1DocumentState::Active => OLE_ERROR_TERMINATE,
            // XP dispatches OLE_SAVED through the per-item DDE advise table.
            // This candidate does not yet implement that table or its DATA
            // transfer/ACK lifecycle, so it must not report success for live
            // object items it has not notified.
            Some(record) if !record.items.is_empty() => OLE_ERROR_COMMAND,
            Some(_) => OLE_OK,
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            u32::from(status),
            Win16ReturnKind::Word,
        )
    }

    fn begin_revoke_server_object_api(
        &mut self,
        owner: guest_core::OwnerId,
        client_far: u32,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use super::super::far_callback::Win16FarCallbackArgument;
        let identity = match self.ole1_server_state.begin_revoke_item(owner, client_far) {
            Ok(identity) => identity,
            Err(status) => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(status),
                    Win16ReturnKind::Word,
                );
            }
        };
        // OLEOBJECTVTBL's Release is slot 1; the server-required object table
        // is ten FARPROC entries through SetColorScheme.
        let release = self.ole1_interface_method_address(identity.object_far, 1, 10, memory);
        let release = match release {
            Ok(address) => address,
            Err(error) => {
                self.ole1_server_state
                    .cancel_revoke_item(identity)
                    .map_err(|rollback| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            format!(
                                "failed to restore OLE1 item after Release validation ({rollback})"
                            ),
                        )
                    })?;
                return match error {
                    Ole1ServerWireError::GuestStatus(status) => self.complete_return(
                        &mut cpu.regs,
                        return_to.0,
                        return_to.1,
                        return_to.2,
                        u32::from(status),
                        Win16ReturnKind::Word,
                    ),
                    Ole1ServerWireError::Runtime(error) => Err(error),
                };
            }
        };
        let args = vec![Win16FarCallbackArgument::GuestPointer {
            far: identity.object_far,
            access: Access::Read,
            bytes: 4,
        }];
        let entered = self.enter_server_api_callback(
            cpu,
            dos,
            memory,
            return_to,
            release,
            args,
            super::Win16Ole1CallbackStage::ServerRevokeObject(identity),
        );
        match entered {
            Ok(result) => Ok(result),
            Err(primary) => {
                if let Err(rollback) = self.ole1_server_state.cancel_revoke_item(identity) {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!(
                            "failed Release callback entry ({primary}); item rollback also failed ({rollback})"
                        ),
                    ));
                }
                Err(primary)
            }
        }
    }

    fn register_server_api(
        &mut self,
        owner: guest_core::OwnerId,
        class_name_far: u32,
        server_far: u32,
        output_far: u32,
        instance: u16,
        use_mode: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let use_mode = match Ole1ServerUse::from_guest_word(use_mode) {
            Ok(use_mode) => use_mode,
            Err(status) => return Ok(u32::from(status)),
        };
        let class_name = match self.read_server_api_string(class_name_far, 123, memory) {
            Ok(name) if !name.is_empty() => name,
            Ok(_) => return Ok(u32::from(OLE_ERROR_CLASS)),
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        let _server_interface = match self.checked_server_input_pointer(server_far, 4, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        // SDK SRVRDEMO initializes method tables as part of server setup;
        // registration only probes the interface FAR. Validate a method slot
        // immediately before its checked callback is entered.
        let output = match self.ole1_checked_output_pointer(output_far, 4, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        let registration = match validate_server_registration(host, &class_name)? {
            Ok(registration) => registration,
            Err(status) => return Ok(u32::from(status)),
        };
        let class_atom =
            host.win16_global_add_atom(crate::Win16HostAtomName::String(&class_name))?;
        if class_atom == 0 {
            return Ok(u32::from(OLE_ERROR_MEMORY));
        }
        let executable_atom = match host.win16_global_add_atom(crate::Win16HostAtomName::String(
            &registration.executable_name,
        )) {
            Ok(atom) => atom,
            Err(primary) => {
                journal_unpublished_cleanup(self, owner, None, None, vec![class_atom])?;
                return Err(primary.with_context(
                    "retained OLE1 class atom for background cleanup after executable atom allocation failed",
                ));
            }
        };
        if executable_atom == 0 {
            journal_unpublished_cleanup(self, owner, None, None, vec![class_atom])?;
            return Ok(u32::from(OLE_ERROR_MEMORY));
        }

        let endpoint_result = create_endpoint_checked(owner, None, host);
        let endpoint_result = match endpoint_result {
            Ok(result) => result,
            Err(primary) => {
                journal_unpublished_cleanup(
                    self,
                    owner,
                    None,
                    None,
                    vec![executable_atom, class_atom],
                )?;
                return Err(primary.with_context(
                    "retained OLE1 registration atoms for background cleanup after endpoint creation failed",
                ));
            }
        };
        let (endpoint, endpoint_worker_generation) = match endpoint_result {
            Ok(endpoint) => endpoint,
            Err(status) => {
                journal_unpublished_cleanup(
                    self,
                    owner,
                    None,
                    None,
                    vec![executable_atom, class_atom],
                )?;
                return Ok(u32::from(status));
            }
        };
        let handle = match self.ole1_server_state.register_server(
            owner,
            class_name,
            class_atom,
            executable_atom,
            server_far,
            instance,
            use_mode,
            endpoint,
            endpoint_worker_generation,
            registration.registry_value,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                journal_unpublished_cleanup(
                    self,
                    owner,
                    Some(endpoint),
                    Some(endpoint_worker_generation),
                    vec![executable_atom, class_atom],
                )?;
                return Ok(u32::from(status));
            }
        };
        if let Err(error) =
            self.selectors
                .write(memory, output, &handle.to_guest_long().to_le_bytes())
        {
            self.ole1_server_state
                .mark_server_handle_unpublished(owner, handle)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("failed to quarantine unpublished OLE1 server ({status})"),
                    )
                })?;
            let target = self
                .ole1_server_state
                .server_release_target(owner, handle)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("unpublished OLE1 server is not cleanup-ready ({status})"),
                    )
                })?;
            // The guest never received this registration token. Start native
            // cleanup now; a pending EventId/host failure remains in the exact
            // release journal for the shared safe-point dispatcher.
            let _ = finish_release_without_guest_callback(self, owner, target, host)?;
            return match selector_error(error, OLE_ERROR_ADDRESS) {
                Ole1ServerWireError::GuestStatus(status) => Ok(u32::from(status)),
                Ole1ServerWireError::Runtime(error) => Err(error),
            };
        }
        Ok(u32::from(OLE_OK))
    }

    fn register_server_document_api(
        &mut self,
        owner: guest_core::OwnerId,
        server_long: i32,
        document_name_far: u32,
        server_document_far: u32,
        output_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let server_handle = Ole1ServerHandle::from_guest_long(server_long as u32);
        let Some(server) = self.ole1_server_state.server(owner, server_handle) else {
            return Ok(u32::from(OLE_ERROR_HANDLE));
        };
        if server.state != super::super::win16_ole1_server_state::Ole1RegistrationState::Active {
            return Ok(u32::from(OLE_ERROR_TERMINATE));
        }
        let server_endpoint = server.endpoint;
        let name = match self.read_server_api_string(document_name_far, 123, memory) {
            Ok(name) if !name.is_empty() => name,
            Ok(_) => return Ok(u32::from(OLE_ERROR_NAME)),
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        if server_document_far != 0 {
            if let Err(error) = self.checked_server_input_pointer(server_document_far, 4, memory) {
                return Ok(u32::from(wire_status_or_runtime(error)?));
            }
        }
        // OLESERVERDOC is often zero-initialized when registered and receives
        // its vtable afterward. Check only the interface storage here; the
        // callback gate validates each actual slot at use time.
        let output = match self.ole1_checked_output_pointer(output_far, 4, memory) {
            Ok(pointer) => pointer,
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        let atom = match host.win16_global_add_atom(crate::Win16HostAtomName::String(&name)) {
            Ok(atom) => atom,
            Err(error) => return Err(error),
        };
        if atom == 0 {
            return Ok(u32::from(OLE_ERROR_MEMORY));
        }
        let server_worker_generation = server.endpoint_worker_generation;
        let endpoint_result = create_endpoint_checked(owner, Some(server_endpoint), host);
        let endpoint_result = match endpoint_result {
            Ok(result) => result,
            Err(primary) => {
                journal_unpublished_cleanup(self, owner, None, None, vec![atom])?;
                return Err(primary.with_context(
                    "retained OLE1 document atom for background cleanup after endpoint creation failed",
                ));
            }
        };
        let (endpoint, endpoint_worker_generation) = match endpoint_result {
            Ok((endpoint, worker_generation)) if worker_generation == server_worker_generation => {
                (endpoint, worker_generation)
            }
            Ok((endpoint, worker_generation)) => {
                journal_unpublished_cleanup(
                    self,
                    owner,
                    Some(endpoint),
                    Some(worker_generation),
                    vec![atom],
                )?;
                return Ok(u32::from(OLE_ERROR_HANDLE));
            }
            Err(status) => {
                journal_unpublished_cleanup(self, owner, None, None, vec![atom])?;
                return Ok(u32::from(status));
            }
        };
        let document = match self.ole1_server_state.register_document(
            owner,
            server_handle,
            endpoint,
            endpoint_worker_generation,
            name,
            atom,
            (server_document_far != 0).then_some(server_document_far),
        ) {
            Ok(document) => document,
            Err(status) => {
                journal_unpublished_cleanup(
                    self,
                    owner,
                    Some(endpoint),
                    Some(endpoint_worker_generation),
                    vec![atom],
                )?;
                return Ok(u32::from(status));
            }
        };
        if let Err(error) =
            self.selectors
                .write(memory, output, &document.to_guest_long().to_le_bytes())
        {
            self.ole1_server_state
                .mark_document_handle_unpublished(owner, document)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("failed to quarantine unpublished OLE1 document ({status})"),
                    )
                })?;
            let target = self
                .ole1_server_state
                .document_release_target(owner, document)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("unpublished OLE1 document is not cleanup-ready ({status})"),
                    )
                })?;
            let _ = finish_release_without_guest_callback(self, owner, target, host)?;
            return match selector_error(error, OLE_ERROR_ADDRESS) {
                Ole1ServerWireError::GuestStatus(status) => Ok(u32::from(status)),
                Ole1ServerWireError::Runtime(error) => Err(error),
            };
        }
        Ok(u32::from(OLE_OK))
    }

    fn rename_server_document_api(
        &mut self,
        owner: guest_core::OwnerId,
        document_long: i32,
        document_name_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        use super::super::win16_ole1_server_state::{
            OLE_ERROR_COMMAND, OLE_ERROR_HANDLE, OLE_ERROR_MEMORY, OLE_ERROR_NAME, OLE_OK,
            Ole1ServerDocumentHandle,
        };
        let handle = Ole1ServerDocumentHandle::from_guest_long(document_long as u32);
        let Some(document) = self.ole1_server_state.document(owner, handle) else {
            return Ok(u32::from(OLE_ERROR_HANDLE));
        };
        if document.state != super::super::win16_ole1_server_state::Ole1DocumentState::Active {
            return Ok(u32::from(OLE_ERROR_HANDLE));
        }
        // A connected document needs StdDocName DATA and peer TERMINATE
        // transactions. Leave the published atom unchanged until that typed
        // transaction continuation exists.
        if !document.conversations.is_empty() || !document.items.is_empty() {
            return Ok(u32::from(OLE_ERROR_COMMAND));
        }
        let name = match self.read_server_api_string(document_name_far, 123, memory) {
            Ok(name) if !name.is_empty() => name,
            Ok(_) => return Ok(u32::from(OLE_ERROR_NAME)),
            Err(error) => return Ok(u32::from(wire_status_or_runtime(error)?)),
        };
        let atom = host.win16_global_add_atom(crate::Win16HostAtomName::String(&name))?;
        if atom == 0 {
            return Ok(u32::from(OLE_ERROR_MEMORY));
        }
        let previous = match self
            .ole1_server_state
            .set_document_name_and_atom(owner, handle, name, atom)
        {
            Ok(previous) => previous,
            Err(status) => {
                journal_unpublished_cleanup(self, owner, None, None, vec![atom])?;
                return Ok(u32::from(status));
            }
        };
        if previous != 0 {
            // The document now owns the replacement atom. Preserve the exact
            // old reference separately if its retirement fails so a later
            // safe-point retry cannot delete or lose the new document atom.
            if let Err(error) = host.win16_global_delete_atom(previous) {
                journal_unpublished_cleanup(self, owner, None, None, vec![previous])?;
                return Err(error
                    .with_context("retained replaced OLE1 document atom for background cleanup"));
            }
        }
        Ok(u32::from(OLE_OK))
    }
}
