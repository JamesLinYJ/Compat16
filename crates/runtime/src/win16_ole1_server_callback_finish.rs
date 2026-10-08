impl super::Win16State {
    /// Translate a checked OLESERVER Execute return into the protocol action
    /// XP performs: PostMessage WM_DDE_ACK with status bits and the exact
    /// correlated execute transfer. Transport acceptance does not complete
    /// the guest callback; the caller must then resume its exact suspended
    /// WndProc or acknowledge the already-published queued event.
    pub(in crate::win16_runtime) fn finish_ole1_server_guest_callback(
        &mut self,
        continuation: &Ole1ServerDdeContinuation,
        callback_result: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Ole1ServerGuestCallbackFinish, RuntimeError> {
        if self
            .ole1_server_state
            .server(continuation.owner, continuation.server)
            .is_none_or(|server| server.generation != continuation.server_generation)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 server generation retired during a checked guest callback",
            ));
        }
        let (
            event,
            target,
            transfer,
            global_handle,
            global_generation,
            allow_self_retirement,
            prepared_document,
        ) = match &continuation.completion {
            Ole1ServerCallbackCompletion::DdeExecute {
                event,
                target,
                transfer,
                global_handle,
                global_generation,
                allow_document_self_retirement,
                prepared_document,
            } => (
                event,
                target,
                transfer,
                global_handle,
                global_generation,
                *allow_document_self_retirement,
                *prepared_document,
            ),
            Ole1ServerCallbackCompletion::DdeRelease { .. } => {
                return Err(RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant,
                    "OLE1 Release callback must use its exact server-release continuation",
                ));
            }
        };
        if event.owner != continuation.owner
            || event.endpoint != continuation.endpoint
            || event.event_id != continuation.event_id
            || event.peer != continuation.peer
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 DDE callback continuation changed its event identity",
            ));
        }
        let Some(conversation) = event.conversation else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Execute completion lost its checked DDE conversation",
            ));
        };
        let close_document_proof = continuation.close_document_proof;
        if allow_self_retirement != close_document_proof.is_some()
            || close_document_proof.is_some_and(|proof| {
                proof.0 != continuation.owner
                    || Some(proof.1) != continuation.document
                    || Some(proof.2) != continuation.document_generation
            })
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "StdCloseDocument proof changed its exact owner or document generation",
            ));
        }
        let target_matches = match *target {
            Ole1ServerCallbackTarget::Server { handle, generation } => {
                handle == continuation.server
                    && generation == continuation.server_generation
                    && continuation.document.is_none()
            }
            Ole1ServerCallbackTarget::Document { handle, generation } => {
                if Some(handle) != continuation.document
                    || Some(generation) != continuation.document_generation
                {
                    false
                } else if let Some(document) =
                    self.ole1_server_state.document(continuation.owner, handle)
                {
                    generation == document.generation && document.server == continuation.server
                } else if allow_self_retirement
                    && self.ole1_server_state.document_generation_was_retired(
                        continuation.owner,
                        handle,
                        generation,
                    )
                {
                    true
                } else {
                    false
                }
            }
        };
        if !target_matches {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Execute completion changed its server/document target",
            ));
        }
        let Win16ClassicDdeMessage::Execute { global } = &event.message else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Execute continuation no longer owns an Execute event",
            ));
        };
        let Some(global_identity) = global.guest_global else {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Execute event lost its checked guest HGLOBAL identity",
            ));
        };
        if global_identity.owner != continuation.owner
            || global_identity.handle != *global_handle
            || global_identity.generation != *global_generation
            || global.transfer != Some(*transfer)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "OLE1 Execute HGLOBAL/transfer lease changed during guest callback",
            ));
        }
        let after = match event.delivery {
            crate::Win16ClassicDdeDeliveryKind::Synchronous {
                operation_id,
                callback,
                frame,
            } => {
                let Some(step) = &continuation.callback_step else {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "synchronous OLE1 Execute callback lost its exact classic-DDE callback step",
                    ));
                };
                let expected_operation = continuation.operation.ok_or_else(|| {
                    RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "synchronous OLE1 Execute callback lost its classic-DDE operation identity",
                    )
                })?;
                if step.owner != continuation.owner
                    || step.endpoint != continuation.endpoint
                    || expected_operation.owner != continuation.owner
                    || step.event.event_id != continuation.event_id
                    || step.event.peer != continuation.peer
                    || step.operation_id != operation_id
                    || expected_operation.id != operation_id
                    || step.callback != callback
                    || step.frame != frame
                    || expected_operation.worker_generation != step.worker_generation
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "synchronous OLE1 Execute callback step no longer matches its exact DDE identity",
                    ));
                }
                Ole1ServerDdeAfterPost::ResumeSynchronousWindow {
                    reply: Win16HostClassicDdeCallbackReply {
                        owner: step.owner,
                        endpoint: step.endpoint,
                        operation_id: step.operation_id,
                        worker_generation: step.worker_generation,
                        callback: step.callback,
                        frame: step.frame,
                        event_id: step.event.event_id,
                        peer: step.event.peer,
                        causal_parents: step.causal_parents.clone(),
                        result: Win16HostClassicDdeCallbackResult::WindowProcedure(0),
                    },
                    expected_conversation: conversation,
                    expected_transaction: event.transaction,
                    expected_transfer: *transfer,
                    close_document_proof,
                }
            }
            crate::Win16ClassicDdeDeliveryKind::Queued => {
                Ole1ServerDdeAfterPost::AcknowledgeQueuedEvent {
                    event: event.clone(),
                    owner: continuation.owner,
                    endpoint: continuation.endpoint,
                    event_id: continuation.event_id,
                    worker_generation: event.worker_generation,
                    peer: continuation.peer,
                    conversation: Some(conversation),
                    transaction: event.transaction,
                    transfer: *transfer,
                    close_document_proof,
                }
            }
        };
        // Validate every fallible ACK continuation field before document
        // completion can retire its record. The DDE frame retains this
        // helper's returned action immediately after it succeeds.
        let ole_status = if let Some(prepared) = prepared_document {
            self.finish_prepared_server_document_callback(
                prepared,
                callback_result as u16,
                memory,
                host,
            )?
        } else {
            callback_result as u16
        };
        // XP's SET_MSG_STATUS macro sets ACK on OLE_OK and BUSY on OLE_BUSY;
        // all other OLESTATUS values produce a negative DDEACK. The high word
        // is the transfer lease, not a raw native HGLOBAL or guest handle.
        let raw = match ole_status {
            0 => 0x8000,
            OLE_BUSY => 0x4000,
            _ => 0,
        };
        let message = Win16ClassicDdeMessage::Ack {
            status: Win16ClassicDdeAckStatus {
                raw,
                application_return_code: 0,
                reserved: 0,
                busy: raw & 0x4000 != 0,
                acknowledged: raw & 0x8000 != 0,
            },
            value: Win16ClassicDdeAckValue::ExecuteTransfer(Some(*transfer)),
        };
        let call = Win16HostClassicDdeCall::Post {
            owner: continuation.owner,
            endpoint: continuation.endpoint,
            target: continuation.peer,
            conversation,
            transaction: event.transaction,
            message,
        };
        Ok(Ole1ServerGuestCallbackFinish::BeginHostCall {
            call,
            continuation: Ole1ServerDdeHostContinuation::ExecuteAcknowledgement(after),
        })
    }
}
