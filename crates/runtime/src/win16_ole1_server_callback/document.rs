use super::*;

#[path = "document_completion.rs"]
mod completion;

impl super::super::Win16State {
    pub(super) fn prepare_server_document_callback(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        server_handle: Ole1ServerHandle,
        server_generation: u64,
        server_far: u32,
        server_endpoint: Win16HostClassicDdeEndpoint,
        server_worker_generation: u64,
        method: ServerCallbackMethod,
        class_name: Option<&[u8]>,
        document_name: &[u8],
        template_name: Option<&[u8]>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<
        Result<
            (
                Ole1ServerCallbackTarget,
                u32,
                Win16FarCallbackReturn,
                Vec<Win16FarCallbackArgument>,
                Ole1ServerPreparedDocumentCallback,
            ),
            u16,
        >,
        RuntimeError,
    > {
        if document_name.is_empty() || document_name.len() > 123 || document_name.contains(&0) {
            return Ok(Err(OLE_ERROR_NAME));
        }
        let mut document_name_owned = Vec::new();
        document_name_owned
            .try_reserve_exact(document_name.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "copy OLE1 server document name for registration",
                    error,
                )
            })?;
        document_name_owned.extend_from_slice(document_name);
        if matches!(
            method,
            ServerCallbackMethod::Create | ServerCallbackMethod::CreateFromTemplate
        ) && class_name
            .is_none_or(|name| name.is_empty() || name.len() > 123 || name.contains(&0))
        {
            return Ok(Err(super::super::win16_ole1_server_state::OLE_ERROR_CLASS));
        }
        if template_name
            .is_some_and(|name| name.is_empty() || name.len() > 123 || name.contains(&0))
        {
            return Ok(Err(OLE_ERROR_NAME));
        }

        let procedure =
            match self.ole1_server_method_address(server_far, method.vtable_slot(), memory) {
                Ok(procedure) => procedure,
                Err(error) => {
                    return match super::super::win16_ole1_server_wire::status_or_runtime(error) {
                        Ok(status) => Ok(Err(status)),
                        Err(error) => Err(error),
                    };
                }
            };

        let atom = host.win16_global_add_atom(Win16HostAtomName::String(document_name))?;
        if atom == 0 {
            return Ok(Err(OLE_ERROR_MEMORY));
        }
        let endpoint_and_generation =
            self.create_server_document_endpoint_checked(event.owner, Some(server_endpoint), host);
        let (endpoint, worker_generation) = match endpoint_and_generation {
            Ok(Ok(identity)) => identity,
            Ok(Err(status)) => {
                self.journal_server_callback_unpublished_resources(
                    event.owner,
                    None,
                    None,
                    vec![atom],
                )?;
                return Ok(Err(status));
            }
            Err(primary) => {
                if let Err(cleanup) = self.journal_server_callback_unpublished_resources(
                    event.owner,
                    None,
                    None,
                    vec![atom],
                ) {
                    return Err(primary.with_cleanup(
                        "retain OLE1 document atom after endpoint creation failed",
                        cleanup,
                    ));
                }
                return Err(primary
                    .with_context("retained OLE1 document atom after endpoint creation failed"));
            }
        };
        if worker_generation != server_worker_generation {
            self.journal_server_callback_unpublished_resources(
                event.owner,
                Some(endpoint),
                Some(worker_generation),
                vec![atom],
            )?;
            return Ok(Err(OLE_ERROR_HANDLE));
        }
        if self
            .ole1_server_state
            .server(event.owner, server_handle)
            .is_none_or(|server| {
                server.generation != server_generation
                    || server.state
                        != super::super::win16_ole1_server_state::Ole1RegistrationState::Active
                    || server.endpoint != server_endpoint
                    || server.endpoint_worker_generation != server_worker_generation
            })
        {
            self.journal_server_callback_unpublished_resources(
                event.owner,
                Some(endpoint),
                Some(worker_generation),
                vec![atom],
            )?;
            return Ok(Err(OLE_ERROR_HANDLE));
        }
        let document = match self.ole1_server_state.register_document(
            event.owner,
            server_handle,
            endpoint,
            worker_generation,
            document_name_owned,
            atom,
            None,
        ) {
            Ok(document) => document,
            Err(status) => {
                self.journal_server_callback_unpublished_resources(
                    event.owner,
                    Some(endpoint),
                    Some(worker_generation),
                    vec![atom],
                )?;
                return Ok(Err(status));
            }
        };
        let document_generation = self
            .ole1_server_state
            .document(event.owner, document)
            .map(|record| record.generation)
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "new OLE1 server document disappeared before callback preparation",
                )
            })?;
        let scratch = match self.allocate_prepared_server_document_scratch(
            event.owner,
            document,
            document_generation,
            class_name,
            document_name,
            template_name,
            memory,
        ) {
            Ok(scratch) => scratch,
            Err(primary) => {
                let proof = Ole1ServerPreparedDocumentCallback {
                    owner: event.owner,
                    server: server_handle,
                    server_generation,
                    document,
                    document_generation,
                    endpoint,
                    worker_generation,
                    method,
                    output_far: 0,
                };
                return match self.cancel_prepared_server_document_callback(proof, memory, host) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(primary.with_cleanup(
                        "cancel provisional OLE1 document after callback scratch allocation failed",
                        cleanup,
                    )),
                };
            }
        };
        let callback_result = (|| -> Result<ServerCallbackArguments, RuntimeError> {
            let callback = match method {
                ServerCallbackMethod::Open => ServerCallbackArguments::Open {
                    server_far,
                    document_handle: document.to_guest_long(),
                    document_name_far: scratch.document_name_far,
                    document_output_far: scratch.output_far,
                },
                ServerCallbackMethod::Create => ServerCallbackArguments::Create {
                    server_far,
                    document_handle: document.to_guest_long(),
                    class_name_far: scratch.class_name_far.ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 Create callback scratch lost its class name",
                        )
                    })?,
                    document_name_far: scratch.document_name_far,
                    document_output_far: scratch.output_far,
                },
                ServerCallbackMethod::CreateFromTemplate => {
                    ServerCallbackArguments::CreateFromTemplate {
                        server_far,
                        document_handle: document.to_guest_long(),
                        class_name_far: scratch.class_name_far.ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 CreateFromTemplate scratch lost its class name",
                            )
                        })?,
                        document_name_far: scratch.document_name_far,
                        template_name_far: scratch.template_name_far.ok_or_else(|| {
                            RuntimeError::new(
                                crate::DiagnosticKind::InternalInvariant,
                                "OLE1 CreateFromTemplate scratch lost its template name",
                            )
                        })?,
                        document_output_far: scratch.output_far,
                    }
                }
                ServerCallbackMethod::Edit => ServerCallbackArguments::Edit {
                    server_far,
                    document_handle: document.to_guest_long(),
                    class_name_far: scratch.class_name_far.ok_or_else(|| {
                        RuntimeError::new(
                            crate::DiagnosticKind::InternalInvariant,
                            "OLE1 Edit callback scratch lost its class name",
                        )
                    })?,
                    document_name_far: scratch.document_name_far,
                    document_output_far: scratch.output_far,
                },
                _ => {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "non-document OLESERVER slot selected a provisional document callback",
                    ));
                }
            };
            Ok(callback)
        })();
        let proof = Ole1ServerPreparedDocumentCallback {
            owner: event.owner,
            server: server_handle,
            server_generation,
            document,
            document_generation,
            endpoint,
            worker_generation,
            method,
            output_far: scratch.output_far,
        };
        let callback = match callback_result {
            Ok(callback) if callback.method() == method => callback,
            Ok(_) => {
                let error = RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 prepared callback arguments changed their selected vtable method",
                );
                return match self.cancel_prepared_server_document_callback(proof, memory, host) {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(error
                            .with_cleanup("cancel mismatched provisional OLE1 callback", cleanup))
                    }
                };
            }
            Err(primary) => {
                return match self.cancel_prepared_server_document_callback(proof, memory, host) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(primary.with_cleanup(
                        "cancel provisional OLE1 callback after argument preparation failed",
                        cleanup,
                    )),
                };
            }
        };
        let target = Ole1ServerCallbackTarget::Document {
            handle: document,
            generation: document_generation,
        };
        Ok(Ok((
            target,
            procedure,
            method.callback_return(),
            callback.encode(),
            proof,
        )))
    }

    fn allocate_prepared_server_document_scratch(
        &mut self,
        owner: guest_core::OwnerId,
        document: Ole1ServerDocumentHandle,
        generation: u64,
        class_name: Option<&[u8]>,
        document_name: &[u8],
        template_name: Option<&[u8]>,
        memory: &mut Memory,
    ) -> Result<ServerDocumentScratchPointers, RuntimeError> {
        let mut scratch_bytes = Vec::new();
        let total = [class_name, Some(document_name), template_name]
            .into_iter()
            .flatten()
            .try_fold(4usize, |size, value| size.checked_add(value.len() + 1))
            .ok_or_else(|| {
                RuntimeError::new(
                    crate::DiagnosticKind::ResourceExhausted,
                    "OLE1 server callback scratch length overflowed",
                )
            })?;
        scratch_bytes.try_reserve_exact(total).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve OLE1 server callback scratch bytes",
                error,
            )
        })?;
        let class_offset =
            class_name.map(|value| append_callback_string(&mut scratch_bytes, value));
        let document_offset = append_callback_string(&mut scratch_bytes, document_name);
        let template_offset =
            template_name.map(|value| append_callback_string(&mut scratch_bytes, value));
        let output_offset = scratch_bytes.len();
        scratch_bytes.extend_from_slice(&[0; 4]);
        let size = u32::try_from(scratch_bytes.len()).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "OLE1 server callback scratch exceeds Win16 GlobalHeap size",
                error,
            )
        })?;
        let allocation = self
            .heap
            .alloc(
                memory,
                owner,
                size,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(|error| match error {
                win16_abi::Win16Error::OutOfMemory | win16_abi::Win16Error::HandleTableFull => {
                    RuntimeError::new(
                        crate::DiagnosticKind::ResourceExhausted,
                        "Win16 GlobalHeap cannot allocate OLE1 server callback scratch",
                    )
                }
                error => crate::runtime_error(error),
            })?;
        self.ole1_server_state
            .set_prepared_callback_scratch(
                owner,
                document,
                generation,
                Some(Ole1ServerPreparedCallbackScratch {
                    allocation,
                    locked: false,
                }),
            )
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot retain exact OLE1 callback scratch handle ({status})"),
                )
            })?;
        let pointer = self
            .heap
            .lock(allocation, &mut self.selectors, memory)
            .map_err(crate::runtime_error)?;
        self.ole1_server_state
            .set_prepared_callback_scratch(
                owner,
                document,
                generation,
                Some(Ole1ServerPreparedCallbackScratch {
                    allocation,
                    locked: true,
                }),
            )
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot record OLE1 callback scratch lock ({status})"),
                )
            })?;
        self.selectors
            .write(memory, pointer, &scratch_bytes)
            .map_err(crate::runtime_error)?;
        let far_at = |offset: usize, selectors: &win16_abi::SelectorTable| {
            let offset = u32::try_from(offset).map_err(|error| {
                RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "OLE1 callback scratch offset exceeds Win16 selector range",
                    error,
                )
            })?;
            selectors
                .add_bytes(pointer, offset)
                .map(|pointer| pointer.far_value())
                .map_err(crate::runtime_error)
        };
        Ok(ServerDocumentScratchPointers {
            class_name_far: class_offset
                .map(|offset| far_at(offset, &self.selectors))
                .transpose()?,
            document_name_far: far_at(document_offset, &self.selectors)?,
            template_name_far: template_offset
                .map(|offset| far_at(offset, &self.selectors))
                .transpose()?,
            output_far: far_at(output_offset, &self.selectors)?,
        })
    }

    fn journal_server_callback_unpublished_resources(
        &mut self,
        owner: guest_core::OwnerId,
        endpoint: Option<Win16HostClassicDdeEndpoint>,
        worker_generation: Option<u64>,
        atoms: Vec<u16>,
    ) -> Result<(), RuntimeError> {
        self.ole1_server_state
            .begin_unpublished_cleanup(owner, endpoint, worker_generation, atoms)
            .map(|_| ())
            .map_err(|status| {
                RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    format!("cannot journal unpublished OLE1 callback resources ({status})"),
                )
            })
    }
}

struct ServerDocumentScratchPointers {
    class_name_far: Option<u32>,
    document_name_far: u32,
    template_name_far: Option<u32>,
    output_far: u32,
}

fn append_callback_string(bytes: &mut Vec<u8>, value: &[u8]) -> usize {
    let offset = bytes.len();
    bytes.extend_from_slice(value);
    bytes.push(0);
    offset
}
