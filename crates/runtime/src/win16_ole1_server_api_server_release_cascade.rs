impl Win16State {
    fn begin_revoke_server_api(
        &mut self,
        owner: guest_core::OwnerId,
        server_long: i32,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use super::super::win16_ole1_server_state::{
            OLE_ERROR_SERVER_BLOCKED, Ole1RegistrationState,
        };
        let handle = Ole1ServerHandle::from_guest_long(server_long as u32);
        let Some(server) = self.ole1_server_state.server(owner, handle) else {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_HANDLE);
        };
        if server.blocked {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_SERVER_BLOCKED);
        }
        if server.documents.iter().any(|document| {
            self.ole1_server_state
                .document(owner, *document)
                .is_some_and(|doc| doc.prepared_callback_scratch.is_some())
        }) {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_PROTOCOL);
        }
        // XP's DeleteAllItems runs before it starts the TERMINATE fan-out.
        // This candidate has not yet connected that item callback sequence;
        // leave the live registry untouched rather than strand items in a
        // half-revoking server.
        if server.documents.iter().any(|document| {
            self.ole1_server_state
                .document(owner, *document)
                .is_some_and(|doc| !doc.items.is_empty())
        }) {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_COMMAND);
        }
        if server.state == Ole1RegistrationState::Active {
            self.ole1_server_state
                .mark_server_revoking(owner, handle)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("cannot begin exact OLE1 server revocation ({status})"),
                    )
                })?;
        }

        loop {
            let posts = self
                .ole1_server_state
                .pending_termination_posts(owner, handle)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("OLE1 server lost its termination journal ({status})"),
                    )
                })?;
            for post in posts {
                post_termination_exact(&mut self.ole1_server_state, owner, post, host)?;
            }

            let document_to_release = self
                .ole1_server_state
                .server(owner, handle)
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "OLE1 server disappeared during revocation",
                    )
                })?
                .documents
                .iter()
                .find_map(|document| {
                    self.ole1_server_state
                        .document_release_target(owner, *document)
                        .ok()
                });
            if let Some(target) = document_to_release {
                let (document_handle, document_far) = match target {
                    Ole1ReleaseTarget::Document { handle, .. } => (
                        handle,
                        self.ole1_server_state
                            .document(owner, handle)
                            .and_then(|record| record.server_document_far),
                    ),
                    Ole1ReleaseTarget::Server { .. } => {
                        return Err(RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "document release selection returned a server target",
                        ));
                    }
                };
                let _ = document_handle;
                if document_far.is_some() {
                    return self
                        .begin_server_release_callback(owner, target, cpu, dos, memory, return_to);
                }
                match finish_release_without_guest_callback(self, owner, target, host)? {
                    Ole1ReleaseEndpointOutcome::Complete => {}
                    Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                        return complete_ole1_api_status(
                            self,
                            cpu,
                            return_to,
                            OLE_WAIT_FOR_RELEASE,
                        );
                    }
                }
                continue;
            }

            match self.ole1_server_state.server_release_target(owner, handle) {
                Ok(target) => {
                    return self
                        .begin_server_release_callback(owner, target, cpu, dos, memory, return_to);
                }
                Err(OLE_WAIT_FOR_RELEASE) => {
                    return complete_ole1_api_status(self, cpu, return_to, OLE_WAIT_FOR_RELEASE);
                }
                Err(status) => {
                    return complete_ole1_api_status(self, cpu, return_to, status);
                }
            }
        }
    }

    fn begin_revoke_server_document_api(
        &mut self,
        owner: guest_core::OwnerId,
        document_long: i32,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use super::super::win16_ole1_server_state::{Ole1DocumentState, Ole1ServerDocumentHandle};
        let handle = Ole1ServerDocumentHandle::from_guest_long(document_long as u32);
        let Some(document) = self.ole1_server_state.document(owner, handle) else {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_HANDLE);
        };
        if document.prepared_callback_scratch.is_some() {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_PROTOCOL);
        }
        // `DeleteAllItems` is a distinct guest OLEOBJECT::Release sequence;
        // do not begin document termination until that sequence is available.
        if !document.items.is_empty() {
            return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_COMMAND);
        }
        if document.state == Ole1DocumentState::Active {
            self.ole1_server_state
                .mark_document_revoking(owner, handle)
                .map_err(|status| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        format!("cannot begin exact OLE1 document revocation ({status})"),
                    )
                })?;
        }
        let posts = self
            .ole1_server_state
            .pending_document_termination_posts(owner, handle)
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("OLE1 document lost its termination journal ({status})"),
                )
            })?;
        for post in posts {
            post_termination_exact(&mut self.ole1_server_state, owner, post, host)?;
        }
        let target = match self
            .ole1_server_state
            .document_release_target(owner, handle)
        {
            Ok(target) => target,
            Err(OLE_WAIT_FOR_RELEASE) => {
                return complete_ole1_api_status(self, cpu, return_to, OLE_WAIT_FOR_RELEASE);
            }
            Err(status) => return complete_ole1_api_status(self, cpu, return_to, status),
        };
        if self
            .ole1_server_state
            .document(owner, handle)
            .is_some_and(|record| record.server_document_far.is_some())
        {
            self.begin_server_release_callback(owner, target, cpu, dos, memory, return_to)
        } else {
            match finish_release_without_guest_callback(self, owner, target, host)? {
                Ole1ReleaseEndpointOutcome::Complete => {
                    complete_ole1_api_status(self, cpu, return_to, OLE_OK)
                }
                Ole1ReleaseEndpointOutcome::PendingEvents(_) => {
                    complete_ole1_api_status(self, cpu, return_to, OLE_WAIT_FOR_RELEASE)
                }
            }
        }
    }

    pub(in crate::win16_runtime) fn begin_server_release_callback(
        &mut self,
        owner: guest_core::OwnerId,
        target: Ole1ReleaseTarget,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        use super::super::win16_ole1_server_callbacks::{
            ServerCallbackArguments, ServerCallbackMethod, ServerDocumentCallbackArguments,
            ServerDocumentCallbackMethod,
        };
        use super::super::win16_ole1_server_state::Ole1ReleaseTarget;
        let (procedure, arguments) = match target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => {
                let Some(document) = self
                    .ole1_server_state
                    .document(owner, handle)
                    .filter(|doc| {
                        doc.generation == generation
                            && doc.server == server
                            && doc.endpoint == endpoint
                            && doc.endpoint_worker_generation == endpoint_worker_generation
                            && doc.document_atom == document_atom
                    })
                else {
                    return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_HANDLE);
                };
                let Some(server_record) = self
                    .ole1_server_state
                    .server(owner, server)
                    .filter(|record| record.generation == server_generation)
                else {
                    return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_HANDLE);
                };
                let Some(document_far) = document.server_document_far else {
                    return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_OBJECT);
                };
                let _ = server_record;
                self.release_server_document_callback_scratch(owner, handle, generation)?;
                let procedure = match self.ole1_server_document_method_address(
                    document_far,
                    ServerDocumentCallbackMethod::Release.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => return complete_wire_failure(self, cpu, return_to, error),
                };
                let arguments = ServerDocumentCallbackArguments::Release {
                    server_document_far: document_far,
                }
                .encode();
                (procedure, arguments)
            }
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => {
                let Some(server) = self
                    .ole1_server_state
                    .server(owner, handle)
                    .filter(|server| {
                        server.generation == generation
                            && server.endpoint == endpoint
                            && server.endpoint_worker_generation == endpoint_worker_generation
                            && server.class_atom == class_atom
                            && server.executable_atom == executable_atom
                    })
                else {
                    return complete_ole1_api_status(self, cpu, return_to, OLE_ERROR_HANDLE);
                };
                let procedure = match self.ole1_server_method_address(
                    server.server_far,
                    ServerCallbackMethod::Release.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => return complete_wire_failure(self, cpu, return_to, error),
                };
                let arguments = ServerCallbackArguments::Release {
                    server_far: server.server_far,
                }
                .encode();
                (procedure, arguments)
            }
        };
        self.enter_server_api_callback(
            cpu,
            dos,
            memory,
            return_to,
            procedure,
            arguments,
            super::Win16Ole1CallbackStage::ServerRelease(target),
        )
    }
}
