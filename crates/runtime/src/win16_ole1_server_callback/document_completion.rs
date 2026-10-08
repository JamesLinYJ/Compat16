//! Resumable completion of provisional OLESERVER document callbacks.

use super::super::super::win16_ole1_server_state::{
    Ole1DocumentState, Ole1PendingReleaseEvents, Ole1RegistrationState,
    Ole1ServerPreparedCallbackCompletion, Ole1ServerPreparedCallbackPhase as Phase,
    Ole1ServerPreparedCallbackResult as CallbackResult,
};
use super::*;

impl super::super::super::Win16State {
    pub(in crate::win16_runtime) fn cancel_prepared_server_document_callback(
        &mut self,
        proof: Ole1ServerPreparedDocumentCallback,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.begin_prepared_server_document_completion(proof, CallbackResult::Cancelled)?;
        require_prepared_document_completion(self.advance_prepared_server_document_completion(
            proof.owner,
            proof.document,
            proof.document_generation,
            memory,
            host,
        )?)?;
        Ok(())
    }

    pub(in crate::win16_runtime) fn finish_prepared_server_document_callback(
        &mut self,
        proof: Ole1ServerPreparedDocumentCallback,
        callback_result: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.begin_prepared_server_document_completion(
            proof,
            CallbackResult::Returned(callback_result),
        )?;
        require_prepared_document_completion(self.advance_prepared_server_document_completion(
            proof.owner,
            proof.document,
            proof.document_generation,
            memory,
            host,
        )?)?
        .ok_or_else(|| completion_invariant("returned OLE1 document callback lost its status"))
    }

    fn begin_prepared_server_document_completion(
        &mut self,
        proof: Ole1ServerPreparedDocumentCallback,
        result: CallbackResult,
    ) -> Result<(), RuntimeError> {
        self.validate_prepared_server_document_callback(proof)?;
        let embedded = matches!(
            proof.method,
            ServerCallbackMethod::Create
                | ServerCallbackMethod::CreateFromTemplate
                | ServerCallbackMethod::Edit
        );
        if let Some(existing) = self.prepared_server_document_completion(
            proof.owner,
            proof.document,
            proof.document_generation,
        )? {
            if existing.result != result
                || existing.output_far != proof.output_far
                || existing.embedded != embedded
            {
                return Err(completion_invariant(
                    "OLE1 document completion changed its checked callback result",
                ));
            }
            return Ok(());
        }
        let (status, phase) = match result {
            CallbackResult::Returned(OLE_OK) => {
                if self
                    .ole1_server_state
                    .prepared_callback_scratch(
                        proof.owner,
                        proof.document,
                        proof.document_generation,
                    )
                    .is_none()
                {
                    return Err(completion_invariant(
                        "OLE1 document callback returned without its exact scratch buffer",
                    ));
                }
                (None, Phase::ReadOutput)
            }
            CallbackResult::Returned(status) => (Some(status), Phase::Quarantine),
            CallbackResult::Cancelled => (None, Phase::Quarantine),
        };
        self.retain_prepared_server_document_completion(
            proof.owner,
            proof.document,
            proof.document_generation,
            Ole1ServerPreparedCallbackCompletion {
                result,
                output_far: proof.output_far,
                embedded,
                document_far: None,
                status,
                phase,
            },
        )
    }

    /// Advance only the local and host finish phases. A durable returned or
    /// cancelled result is required; this routine never enters guest code.
    pub(in crate::win16_runtime) fn advance_prepared_server_document_completion(
        &mut self,
        owner: guest_core::OwnerId,
        document: Ole1ServerDocumentHandle,
        generation: u64,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<Option<u16>, Ole1PendingReleaseEvents>, RuntimeError> {
        loop {
            let mut completion = self
                .prepared_server_document_completion(owner, document, generation)?
                .ok_or_else(|| {
                    completion_invariant(
                        "OLE1 document cleanup has no returned or cancelled callback proof",
                    )
                })?;
            match completion.phase {
                Phase::ReadOutput => {
                    if self
                        .ole1_server_state
                        .prepared_callback_scratch(owner, document, generation)
                        .is_none()
                    {
                        return Err(completion_invariant(
                            "OLE1 document output read lost its callback scratch",
                        ));
                    }
                    let output = self
                        .selectors
                        .pointer_from_far(completion.output_far)
                        .map_err(crate::runtime_error)?;
                    self.selectors
                        .translate(output, Access::Read, 4, memory)
                        .map_err(crate::runtime_error)?;
                    let mut bytes = [0_u8; 4];
                    self.selectors
                        .read(memory, output, &mut bytes)
                        .map_err(crate::runtime_error)?;
                    // Retain this value before validation or publication can
                    // fail. Later scratch-release retries never read it again.
                    completion.document_far = Some(u32::from_le_bytes(bytes));
                    completion.phase = Phase::ValidateInterface;
                }
                Phase::ValidateInterface => {
                    let document_far = completion.document_far.ok_or_else(|| {
                        completion_invariant("OLE1 interface validation lost its read output FAR")
                    })?;
                    let status = if document_far == 0 {
                        OLE_ERROR_OBJECT
                    } else {
                        match self.ole1_server_document_method_address(
                            document_far,
                            ServerDocumentCallbackMethod::Release.vtable_slot(),
                            memory,
                        ) {
                            Ok(_) => OLE_OK,
                            Err(error) => {
                                match super::super::super::win16_ole1_server_wire::status_or_runtime(
                                    error,
                                ) {
                                    Ok(status) => status,
                                    Err(error) => return Err(error),
                                }
                            }
                        }
                    };
                    completion.status = Some(status);
                    completion.phase = if status == OLE_OK {
                        Phase::PublishInterface
                    } else {
                        Phase::Quarantine
                    };
                }
                Phase::PublishInterface => {
                    let document_far = completion.document_far.ok_or_else(|| {
                        completion_invariant(
                            "OLE1 document publication lost its validated output FAR",
                        )
                    })?;
                    self.ole1_server_state
                        .publish_server_document_interface(owner, document, document_far)
                        .map_err(|status| {
                            completion_status("publish exact OLE1 document interface", status)
                        })?;
                    completion.phase = Phase::SetEmbedded;
                }
                Phase::SetEmbedded => {
                    if completion.embedded {
                        self.ole1_server_state
                            .set_embedded(owner, document)
                            .map_err(|status| {
                                completion_status("publish OLE1 embedded-document mode", status)
                            })?;
                    }
                    completion.phase = Phase::ReleaseScratch;
                }
                Phase::Quarantine => {
                    let record = self
                        .ole1_server_state
                        .document(owner, document)
                        .filter(|record| record.generation == generation)
                        .ok_or_else(|| {
                            completion_invariant("OLE1 quarantine lost its exact document")
                        })?;
                    if record.state != Ole1DocumentState::Revoking || record.guest_handle_published
                    {
                        self.ole1_server_state
                            .mark_document_handle_unpublished(owner, document)
                            .map_err(|status| {
                                completion_status(
                                    "quarantine failed OLE1 document callback",
                                    status,
                                )
                            })?;
                    }
                    completion.phase = Phase::ReleaseScratch;
                }
                Phase::ReleaseScratch => {
                    self.release_server_document_callback_scratch(owner, document, generation)?;
                    completion.phase = if completion.status == Some(OLE_OK) {
                        Phase::Complete
                    } else {
                        Phase::CleanupDocument
                    };
                }
                Phase::CleanupDocument => {
                    let target = self
                        .ole1_server_state
                        .document_release_target(owner, document)
                        .map_err(|status| {
                            completion_status("select failed OLE1 document cleanup", status)
                        })?;
                    return match super::super::super::ole1::finish_release_without_guest_callback_for_dde(
                        self, owner, target, host,
                    )? {
                        super::super::super::ole1::Ole1ReleaseEndpointOutcome::Complete => Ok(Ok(completion.status)),
                        super::super::super::ole1::Ole1ReleaseEndpointOutcome::PendingEvents(events) => {
                            let Ole1ReleaseTarget::Document { endpoint, .. } = target else {
                                return Err(completion_invariant("OLE1 document cleanup selected a server target"));
                            };
                            let pending = self.pending_ole1_release_for_endpoint(owner, endpoint)?
                                .filter(|pending| pending.target == target && pending.pending_events == events)
                                .ok_or_else(|| completion_invariant("OLE1 document cleanup lost its exact pending EventId receipt"))?;
                            Ok(Err(pending))
                        }
                    };
                }
                Phase::Complete => return Ok(Ok(completion.status)),
            }
            self.retain_prepared_server_document_completion(
                owner, document, generation, completion,
            )?;
        }
    }

    fn prepared_server_document_completion(
        &self,
        owner: guest_core::OwnerId,
        document: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<Option<Ole1ServerPreparedCallbackCompletion>, RuntimeError> {
        self.ole1_server_state
            .document(owner, document)
            .filter(|record| record.generation == generation)
            .map(|record| record.prepared_callback_completion)
            .ok_or_else(|| {
                completion_invariant("OLE1 document finish lost its exact owner or generation")
            })
    }

    fn retain_prepared_server_document_completion(
        &mut self,
        owner: guest_core::OwnerId,
        document: Ole1ServerDocumentHandle,
        generation: u64,
        completion: Ole1ServerPreparedCallbackCompletion,
    ) -> Result<(), RuntimeError> {
        let record = self
            .ole1_server_state
            .document_mut(owner, document)
            .filter(|record| record.generation == generation)
            .ok_or_else(|| {
                completion_invariant("OLE1 document finish journal lost its exact generation")
            })?;
        record.prepared_callback_completion = Some(completion);
        Ok(())
    }

    fn validate_prepared_server_document_callback(
        &self,
        proof: Ole1ServerPreparedDocumentCallback,
    ) -> Result<(), RuntimeError> {
        let server = self
            .ole1_server_state
            .server(proof.owner, proof.server)
            .filter(|server| {
                server.generation == proof.server_generation
                    && matches!(
                        server.state,
                        Ole1RegistrationState::Active | Ole1RegistrationState::Revoking
                    )
            });
        let document = self
            .ole1_server_state
            .document(proof.owner, proof.document)
            .filter(|document| {
                document.generation == proof.document_generation
                    && document.server == proof.server
                    && document.endpoint == proof.endpoint
                    && document.endpoint_worker_generation == proof.worker_generation
                    && (document.state == Ole1DocumentState::Active
                        || (document.state == Ole1DocumentState::Revoking
                            && document.prepared_callback_completion.is_some()))
            });
        if server.is_none() || document.is_none() {
            return Err(completion_invariant(
                "OLE1 prepared document callback lost its exact owner or generation",
            ));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn release_server_document_callback_scratch(
        &mut self,
        owner: guest_core::OwnerId,
        document: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<(), RuntimeError> {
        let Some(mut scratch) = self
            .ole1_server_state
            .prepared_callback_scratch(owner, document, generation)
        else {
            return Ok(());
        };
        let completion = self.prepared_server_document_completion(owner, document, generation)?;
        if !completion.is_some_and(|completion| {
            matches!(
                completion.phase,
                Phase::ReleaseScratch | Phase::CleanupDocument | Phase::Complete
            )
        }) {
            return Err(completion_invariant(
                "OLE1 callback scratch is still owned by an unfinished checked callback",
            ));
        }
        if scratch.locked {
            self.heap
                .unlock(scratch.allocation, &mut self.selectors)
                .map_err(crate::runtime_error)?;
            scratch.locked = false;
            self.ole1_server_state
                .set_prepared_callback_scratch(owner, document, generation, Some(scratch))
                .map_err(|status| {
                    completion_status("retain unlocked OLE1 callback scratch", status)
                })?;
        }
        self.heap
            .free(scratch.allocation, &mut self.selectors)
            .map_err(crate::runtime_error)?;
        self.ole1_server_state
            .set_prepared_callback_scratch(owner, document, generation, None)
            .map_err(|status| completion_status("clear retired OLE1 callback scratch", status))
    }
}

fn completion_invariant(message: &str) -> RuntimeError {
    RuntimeError::new(crate::DiagnosticKind::InternalInvariant, message)
}

fn completion_status(action: &str, status: u16) -> RuntimeError {
    completion_invariant(&format!("cannot {action} ({status})"))
}

fn require_prepared_document_completion(
    outcome: Result<Option<u16>, Ole1PendingReleaseEvents>,
) -> Result<Option<u16>, RuntimeError> {
    outcome.map_err(|pending| {
        RuntimeError::new(
            crate::DiagnosticKind::HostFailure,
            format!(
                "failed OLE1 document callback cleanup retains exact EventIds {:?}",
                pending.pending_events
            ),
        )
    })
}
