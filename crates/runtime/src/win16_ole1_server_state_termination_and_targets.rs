impl Ole1ServerState {
    pub(crate) fn mark_server_revoking(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<(), Ole1Status> {
        let record = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if record.blocked {
            return Err(OLE_ERROR_SERVER_BLOCKED);
        }
        let document_handles = record.documents.clone();
        let document_conversations = document_handles
            .iter()
            .filter_map(|document| self.document(owner, *document))
            .flat_map(|document| document.conversations.keys().copied())
            .collect::<std::collections::BTreeSet<_>>();

        let record = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        record.state = Ole1RegistrationState::Revoking;
        for binding in record.conversations.values() {
            // bind_server_document_conversation intentionally mirrors a doc
            // channel into the parent server map. The child endpoint owns its
            // TERMINATE count, so only root server conversations are seeded
            // here.
            if !document_conversations.contains(&binding.id) {
                record
                    .pending_terminations
                    .entry(binding.id)
                    .or_insert(Ole1PendingTermination {
                        binding: *binding,
                        phase: Ole1TerminationPhase::PostPending,
                    });
            }
        }
        for document_handle in document_handles {
            let document = self
                .document_mut(owner, document_handle)
                .ok_or(OLE_ERROR_HANDLE)?;
            document.state = Ole1DocumentState::Revoking;
            seed_pending_terminations(&document.conversations, &mut document.pending_terminations);
        }
        Ok(())
    }

    pub(crate) fn mark_document_revoking(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<(), Ole1Status> {
        let record = self.document_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        record.state = Ole1DocumentState::Revoking;
        seed_pending_terminations(&record.conversations, &mut record.pending_terminations);
        Ok(())
    }

    /// Return the exact conversations whose TERMINATE post has not yet
    /// received a host queued receipt. A failed/started host operation leaves
    /// these entries in PostPending for an explicit retry.
    pub(crate) fn pending_termination_posts(
        &self,
        owner: OwnerId,
        server: Ole1ServerHandle,
    ) -> Result<Vec<Ole1TerminationPost>, Ole1Status> {
        let server_record = self.server(owner, server).ok_or(OLE_ERROR_HANDLE)?;
        let mut posts = Vec::new();
        for pending in server_record.pending_terminations.values() {
            if pending.phase == Ole1TerminationPhase::PostPending {
                posts.try_reserve(1).map_err(|_| OLE_ERROR_MEMORY)?;
                posts.push(Ole1TerminationPost {
                    target: Ole1TerminationTarget::Server {
                        handle: server,
                        generation: server_record.generation,
                        endpoint: server_record.endpoint,
                        worker_generation: server_record.endpoint_worker_generation,
                    },
                    binding: pending.binding,
                });
            }
        }
        for document_handle in &server_record.documents {
            let document = self
                .document(owner, *document_handle)
                .ok_or(OLE_ERROR_HANDLE)?;
            for pending in document.pending_terminations.values() {
                if pending.phase == Ole1TerminationPhase::PostPending {
                    posts.try_reserve(1).map_err(|_| OLE_ERROR_MEMORY)?;
                    posts.push(Ole1TerminationPost {
                        target: Ole1TerminationTarget::Document {
                            handle: *document_handle,
                            generation: document.generation,
                            endpoint: document.endpoint,
                            worker_generation: document.endpoint_worker_generation,
                        },
                        binding: pending.binding,
                    });
                }
            }
        }
        Ok(posts)
    }

    pub(crate) fn pending_document_termination_posts(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<Vec<Ole1TerminationPost>, Ole1Status> {
        let document = self.document(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        let mut posts = Vec::new();
        for pending in document.pending_terminations.values() {
            if pending.phase == Ole1TerminationPhase::PostPending {
                posts.try_reserve(1).map_err(|_| OLE_ERROR_MEMORY)?;
                posts.push(Ole1TerminationPost {
                    target: Ole1TerminationTarget::Document {
                        handle,
                        generation: document.generation,
                        endpoint: document.endpoint,
                        worker_generation: document.endpoint_worker_generation,
                    },
                    binding: pending.binding,
                });
            }
        }
        Ok(posts)
    }

    /// Commit a TERMINATE post only from its exact successful host receipt.
    /// This is idempotent for a duplicate matching receipt, but cannot advance
    /// a later conversation generation or a different peer incarnation.
    pub(crate) fn mark_termination_posted(
        &mut self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        binding: Ole1ConversationBinding,
    ) -> Result<(), Ole1Status> {
        let pending = self.termination_pending(owner, target, binding.id)?;
        if pending.binding != binding {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let phase = pending.phase;
        match phase {
            Ole1TerminationPhase::PostInFlight => {
                self.termination_pending_mut(owner, target, binding.id)?
                    .phase = Ole1TerminationPhase::AwaitingPeer;
                Ok(())
            }
            Ole1TerminationPhase::AwaitingPeer => Ok(()),
            Ole1TerminationPhase::PostPending => Err(OLE_ERROR_PROTOCOL),
        }
    }

    /// Mark one exact pending TERMINATE as owned by a host operation before
    /// dispatch. This prevents a reentrant retry from posting it twice.
    pub(crate) fn begin_termination_post(
        &mut self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        binding: Ole1ConversationBinding,
    ) -> Result<(), Ole1Status> {
        let pending = self.termination_pending_mut(owner, target, binding.id)?;
        if pending.binding != binding || pending.phase != Ole1TerminationPhase::PostPending {
            return Err(OLE_ERROR_PROTOCOL);
        }
        pending.phase = Ole1TerminationPhase::PostInFlight;
        Ok(())
    }

    /// Roll back a failed exact Post operation. If its queued event already
    /// proved that the peer terminated, leave the conversation live so that
    /// the retained event can take the reciprocal-Terminate path.
    pub(crate) fn fail_termination_post(
        &mut self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        binding: Ole1ConversationBinding,
    ) -> Result<(), Ole1Status> {
        let pending = self.termination_pending(owner, target, binding.id)?;
        if pending.binding != binding {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let phase = pending.phase;
        match phase {
            Ole1TerminationPhase::PostInFlight => {
                self.termination_pending_mut(owner, target, binding.id)?
                    .phase = Ole1TerminationPhase::PostPending;
                Ok(())
            }
            Ole1TerminationPhase::PostPending | Ole1TerminationPhase::AwaitingPeer => {
                Err(OLE_ERROR_PROTOCOL)
            }
        }
    }

    /// Classify an inbound WM_DDE_TERMINATE by the complete endpoint,
    /// conversation and peer identity. During revocation it is an ACK only
    /// after the exact outgoing Post receipt was committed.
    pub(crate) fn classify_terminate(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
    ) -> Ole1TerminateDisposition {
        if let Some((handle, server)) = self.server_for_endpoint(owner, endpoint) {
            let Some(binding) = server.conversations.get(&conversation).copied() else {
                return Ole1TerminateDisposition::Stale;
            };
            if binding.peer != peer {
                return Ole1TerminateDisposition::Stale;
            }
            let target = Ole1TerminationTarget::Server {
                handle,
                generation: server.generation,
                endpoint: server.endpoint,
                worker_generation: server.endpoint_worker_generation,
            };
            return if server.state == Ole1RegistrationState::Revoking {
                match server.pending_terminations.get(&conversation) {
                    Some(pending)
                        if pending.binding == binding
                            && pending.phase == Ole1TerminationPhase::AwaitingPeer =>
                    {
                        Ole1TerminateDisposition::RevocationAck(target)
                    }
                    Some(pending)
                        if pending.binding == binding
                            && matches!(pending.phase, Ole1TerminationPhase::PostInFlight) =>
                    {
                        Ole1TerminateDisposition::RevocationPostInFlight(target)
                    }
                    Some(pending)
                        if pending.binding == binding
                            && pending.phase == Ole1TerminationPhase::PostPending =>
                    {
                        // A prior revocation Post failed after this exact
                        // peer had already sent TERMINATE. Retry the required
                        // reciprocal Post before retiring the conversation.
                        Ole1TerminateDisposition::PeerInitiated(target)
                    }
                    _ => Ole1TerminateDisposition::Stale,
                }
            } else {
                Ole1TerminateDisposition::PeerInitiated(target)
            };
        }
        let Some((handle, document)) = self.document_for_endpoint(owner, endpoint) else {
            return Ole1TerminateDisposition::Stale;
        };
        let Some(binding) = document.conversations.get(&conversation).copied() else {
            return Ole1TerminateDisposition::Stale;
        };
        if binding.peer != peer {
            return Ole1TerminateDisposition::Stale;
        }
        let target = Ole1TerminationTarget::Document {
            handle,
            generation: document.generation,
            endpoint: document.endpoint,
            worker_generation: document.endpoint_worker_generation,
        };
        if document.state == Ole1DocumentState::Revoking {
            match document.pending_terminations.get(&conversation) {
                Some(pending)
                    if pending.binding == binding
                        && pending.phase == Ole1TerminationPhase::AwaitingPeer =>
                {
                    Ole1TerminateDisposition::RevocationAck(target)
                }
                Some(pending)
                    if pending.binding == binding
                        && matches!(pending.phase, Ole1TerminationPhase::PostInFlight) =>
                {
                    Ole1TerminateDisposition::RevocationPostInFlight(target)
                }
                Some(pending)
                    if pending.binding == binding
                        && pending.phase == Ole1TerminationPhase::PostPending =>
                {
                    Ole1TerminateDisposition::PeerInitiated(target)
                }
                _ => Ole1TerminateDisposition::Stale,
            }
        } else {
            Ole1TerminateDisposition::PeerInitiated(target)
        }
    }

    /// Retire the exact conversation only after its Terminate classification
    /// or matching response Post receipt has been consumed.
    pub(crate) fn retire_terminated_conversation(
        &mut self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
        expected_revocation_ack: bool,
    ) -> Result<bool, Ole1Status> {
        let binding = match target {
            Ole1TerminationTarget::Server {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => {
                let record = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
                if record.generation != generation
                    || record.endpoint != endpoint
                    || record.endpoint_worker_generation != worker_generation
                {
                    return Err(OLE_ERROR_HANDLE);
                }
                let binding = record
                    .conversations
                    .get(&conversation)
                    .copied()
                    .ok_or(OLE_ERROR_HANDLE)?;
                if binding.peer != peer {
                    return Err(OLE_ERROR_PROTOCOL);
                }
                let pending = record.pending_terminations.get(&conversation);
                if expected_revocation_ack
                    && !pending.is_some_and(|pending| {
                        pending.binding == binding
                            && pending.phase == Ole1TerminationPhase::AwaitingPeer
                    })
                {
                    return Err(OLE_ERROR_PROTOCOL);
                }
                binding
            }
            Ole1TerminationTarget::Document {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => {
                let record = self.document(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
                if record.generation != generation
                    || record.endpoint != endpoint
                    || record.endpoint_worker_generation != worker_generation
                {
                    return Err(OLE_ERROR_HANDLE);
                }
                let binding = record
                    .conversations
                    .get(&conversation)
                    .copied()
                    .ok_or(OLE_ERROR_HANDLE)?;
                if binding.peer != peer {
                    return Err(OLE_ERROR_PROTOCOL);
                }
                let pending = record.pending_terminations.get(&conversation);
                if expected_revocation_ack
                    && !pending.is_some_and(|pending| {
                        pending.binding == binding
                            && pending.phase == Ole1TerminationPhase::AwaitingPeer
                    })
                {
                    return Err(OLE_ERROR_PROTOCOL);
                }
                binding
            }
        };
        let _ = binding;
        self.retire_conversation(owner, conversation)
    }

    pub(crate) fn document_release_ready(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> bool {
        self.document(owner, handle).is_some_and(|document| {
            document.generation == generation
                && document.state == Ole1DocumentState::Revoking
                && document.conversations.is_empty()
                && document.pending_terminations.is_empty()
                && document.items.is_empty()
        })
    }

    pub(crate) fn server_release_ready(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
        generation: u64,
    ) -> bool {
        self.server(owner, handle).is_some_and(|server| {
            server.generation == generation
                && server.state == Ole1RegistrationState::Revoking
                && server.conversations.is_empty()
                && server.pending_terminations.is_empty()
                && server.documents.is_empty()
                && !server.blocked
                && server.deferred_events.is_empty()
                && server.in_flight_deferred.is_none()
                && !server.processing_deferred_message
        })
    }

    pub(crate) fn document_release_target(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<Ole1ReleaseTarget, Ole1Status> {
        let document = self.document(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        let server = self
            .server(owner, document.server)
            .ok_or(OLE_ERROR_HANDLE)?;
        if !self.document_release_ready(owner, handle, document.generation) {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        Ok(Ole1ReleaseTarget::Document {
            handle,
            generation: document.generation,
            server: document.server,
            server_generation: server.generation,
            endpoint: document.endpoint,
            endpoint_worker_generation: document.endpoint_worker_generation,
            document_atom: document.document_atom,
        })
    }

    pub(crate) fn server_release_target(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<Ole1ReleaseTarget, Ole1Status> {
        let server = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !self.server_release_ready(owner, handle, server.generation) {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        Ok(Ole1ReleaseTarget::Server {
            handle,
            generation: server.generation,
            endpoint: server.endpoint,
            endpoint_worker_generation: server.endpoint_worker_generation,
            class_atom: server.class_atom,
            executable_atom: server.executable_atom,
        })
    }

    /// Return the next generation-checked Release target in XP's server
    /// cascade after one document cleanup. Documents are released before the
    /// parent server; a server target is ready only after all documents and
    /// root conversations have retired.
    pub(crate) fn release_target_after_completion(
        &self,
        owner: OwnerId,
        completed: Ole1ReleaseTarget,
    ) -> Option<Ole1ReleaseTarget> {
        let Ole1ReleaseTarget::Document {
            server,
            server_generation,
            ..
        } = completed
        else {
            return None;
        };
        let parent = self.server(owner, server)?;
        if parent.generation != server_generation || parent.state != Ole1RegistrationState::Revoking
        {
            return None;
        }
        for document in &parent.documents {
            if let Ok(target) = self.document_release_target(owner, *document) {
                return Some(target);
            }
        }
        self.server_release_target(owner, server).ok()
    }

    pub(crate) fn set_document_name_and_atom(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        new_name: Vec<u8>,
        new_atom: u16,
    ) -> Result<u16, Ole1Status> {
        if new_name.is_empty() || new_name.contains(&0) || new_atom == 0 {
            return Err(OLE_ERROR_NAME);
        }
        let document = self.document_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if document.state != Ole1DocumentState::Active {
            return Err(OLE_ERROR_TERMINATE);
        }
        let previous_atom = document.document_atom;
        document.name = new_name;
        document.document_atom = new_atom;
        document.embedded = false;
        Ok(previous_atom)
    }
}
