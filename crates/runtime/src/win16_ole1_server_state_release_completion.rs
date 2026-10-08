impl Ole1ServerState {

    /// Begin the resource phase after an exact checked server/document
    /// Release callback has returned. A duplicate finish for the same
    /// callback is accepted only when every generation-bound field matches.
    pub(crate) fn begin_release_completion(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        callback_status: Ole1Status,
    ) -> Result<Ole1ReleaseCompletionJournalEntry, Ole1Status> {
        if callback_id == 0 {
            return Err(OLE_ERROR_HANDLE);
        }
        self.begin_release_completion_with_result(
            callback_id,
            owner,
            target,
            Ole1ReleaseCallbackResult::Returned(callback_status),
        )
    }

    pub(crate) fn begin_release_completion_without_guest_callback(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
    ) -> Result<Ole1ReleaseCompletionJournalEntry, Ole1Status> {
        self.begin_release_completion_with_result(
            callback_id,
            owner,
            target,
            Ole1ReleaseCallbackResult::NotRegistered,
        )
    }

    fn begin_release_completion_with_result(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        callback_result: Ole1ReleaseCallbackResult,
    ) -> Result<Ole1ReleaseCompletionJournalEntry, Ole1Status> {
        if callback_id == 0 {
            return Err(OLE_ERROR_HANDLE);
        }
        if let Some(existing) = self.release_completion_journal.get(&callback_id).copied() {
            return (existing.owner == owner
                && existing.target == target
                && existing.callback_result == callback_result)
                .then_some(existing)
                .ok_or(OLE_ERROR_HANDLE);
        }
        if self
            .release_completion_journal
            .values()
            .any(|existing| existing.owner == owner && existing.target == target)
        {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        let ready = match target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => {
                self.document_release_ready(owner, handle, generation)
                    && self.document(owner, handle).is_some_and(|document| {
                        document.server == server
                            && document.endpoint == endpoint
                            && document.endpoint_worker_generation == endpoint_worker_generation
                            && document.document_atom == document_atom
                    })
                    && self.server(owner, server).is_some_and(|parent| {
                        parent.generation == server_generation
                            && parent.endpoint_worker_generation == endpoint_worker_generation
                    })
            }
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => {
                self.server_release_ready(owner, handle, generation)
                    && self.server(owner, handle).is_some_and(|server| {
                        server.endpoint == endpoint
                            && server.endpoint_worker_generation == endpoint_worker_generation
                            && server.class_atom == class_atom
                            && server.executable_atom == executable_atom
                    })
            }
        };
        if !ready {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        let entry = Ole1ReleaseCompletionJournalEntry {
            callback_id,
            owner,
            target,
            callback_result,
            phase: Ole1ReleasePhase::DeleteFirstAtom,
        };
        self.release_completion_journal.insert(callback_id, entry);
        self.release_pending_events.insert(
            callback_id,
            Ole1PendingReleaseEvents {
                callback_id,
                owner,
                target,
                worker_generation: 0,
                pending_events: Vec::new(),
                receipt_revision: 0,
                acknowledged_events: BTreeSet::new(),
            },
        );
        Ok(entry)
    }

    /// Preserve a Release callback aborted during owner teardown. The
    /// callback has no OLESTATUS result, but its exact target remains owned so
    /// endpoint/atom retirement can proceed without calling guest code again.
    pub(crate) fn begin_cancelled_release_completion(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
    ) -> Result<Ole1ReleaseCompletionJournalEntry, Ole1Status> {
        let entry = self.begin_release_completion_with_result(
            callback_id,
            owner,
            target,
            Ole1ReleaseCallbackResult::CancelledByOwnerExit,
        )?;
        Ok(entry)
    }

    /// Record the exact pending EventIds returned by a non-retired host
    /// endpoint. Every previously observed unacknowledged ID must remain in
    /// the next host snapshot; the host may remove one only after its exact
    /// EventAcknowledged terminal receipt.
    pub(crate) fn record_release_pending_events(
        &mut self,
        callback_id: u64,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
        worker_generation: u64,
        pending_events: Vec<Win16ClassicDdeEventId>,
    ) -> Result<(), Ole1Status> {
        let journal = self
            .release_completion_journal
            .get(&callback_id)
            .filter(|entry| entry.owner == owner && entry.target == target)
            .ok_or(OLE_ERROR_HANDLE)?;
        let _ = journal;
        if worker_generation == 0 || worker_generation != release_target_worker_generation(target) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if !self
            .release_completion_journal
            .get(&callback_id)
            .is_some_and(|entry| {
                entry.owner == owner
                    && entry.target == target
                    && entry.phase == Ole1ReleasePhase::RetireEndpoint
            })
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let wait = self
            .release_pending_events
            .get_mut(&callback_id)
            .filter(|entry| entry.owner == owner && entry.target == target)
            .ok_or(OLE_ERROR_HANDLE)?;
        if wait.worker_generation != 0 && wait.worker_generation != worker_generation {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let mut unique = BTreeSet::new();
        if pending_events.iter().any(|event| {
            event.0 == 0 || !unique.insert(*event) || wait.acknowledged_events.contains(event)
        }) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if wait.pending_events.iter().any(|previous| {
            !pending_events.contains(previous) && !wait.acknowledged_events.contains(previous)
        }) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        wait.receipt_revision = wait
            .receipt_revision
            .checked_add(1)
            .ok_or(OLE_ERROR_MEMORY)?;
        wait.pending_events = pending_events;
        wait.worker_generation = worker_generation;
        Ok(())
    }

    /// Mark an EventId as delivered only after the host's exact ACK receipt.
    /// The call is idempotent for replayed terminal handling but never matches
    /// a different owner or endpoint generation.
    pub(crate) fn acknowledge_release_event(
        &mut self,
        callback_id: u64,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<Option<u64>, Ole1Status> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let Some(journal) = self
            .release_completion_journal
            .get(&callback_id)
            .filter(|journal| {
                journal.owner == event.owner
                    && release_target_endpoint(journal.target) == event.endpoint
                    && release_target_worker_generation(journal.target) == event.worker_generation
            })
        else {
            return Ok(None);
        };
        let wait = self
            .release_pending_events
            .get_mut(&callback_id)
            .filter(|wait| {
                wait.owner == journal.owner
                    && wait.target == journal.target
                    && wait.worker_generation == event.worker_generation
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if wait.acknowledged_events.contains(&event.event_id) {
            return Ok(Some(callback_id));
        }
        if !wait.pending_events.contains(&event.event_id) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        wait.acknowledged_events.insert(event.event_id);
        wait.pending_events
            .retain(|pending| *pending != event.event_id);
        Ok(Some(callback_id))
    }

    pub(crate) fn release_pending_events_for_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<Option<Ole1PendingReleaseEvents>, Ole1Status> {
        let mut matching = self.release_pending_events.values().filter(|wait| {
            wait.owner == owner
                && release_target_endpoint(wait.target) == endpoint
                && wait.receipt_revision > 0
                && wait.worker_generation != 0
                && wait.worker_generation == release_target_worker_generation(wait.target)
                && self
                    .release_completion_journal
                    .get(&wait.callback_id)
                    .is_some_and(|journal| {
                        journal.owner == owner
                            && journal.target == wait.target
                            && journal.phase == Ole1ReleasePhase::RetireEndpoint
                    })
        });
        let Some(wait) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(Some(wait.clone()))
    }

    pub(crate) fn pending_release_completion(
        &self,
        callback_id: u64,
    ) -> Option<Ole1ReleaseCompletionJournalEntry> {
        self.release_completion_journal.get(&callback_id).copied()
    }

    pub(crate) fn release_completion_for_target(
        &self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
    ) -> Option<Ole1ReleaseCompletionJournalEntry> {
        self.release_completion_journal
            .values()
            .find(|entry| entry.owner == owner && entry.target == target)
            .copied()
    }

    /// Resolve the owner of one exact live release target. Callback completion
    /// must not infer ownership from whichever task happens to be current when
    /// a checked guest callback returns.
    pub(crate) fn owner_of_release_target(&self, target: Ole1ReleaseTarget) -> Option<OwnerId> {
        match target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => self
                .document_for_release_identity(
                    handle,
                    generation,
                    server,
                    server_generation,
                    endpoint,
                    endpoint_worker_generation,
                    document_atom,
                )
                .map(|document| document.owner),
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => self
                .servers
                .get(&handle)
                .filter(|server| {
                    server.generation == generation
                        && server.endpoint == endpoint
                        && server.endpoint_worker_generation == endpoint_worker_generation
                        && server.class_atom == class_atom
                        && server.executable_atom == executable_atom
                })
                .map(|server| server.owner),
        }
    }

    fn document_for_release_identity(
        &self,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
        server: Ole1ServerHandle,
        server_generation: u64,
        endpoint: Win16HostClassicDdeEndpoint,
        endpoint_worker_generation: u64,
        document_atom: u16,
    ) -> Option<&Ole1ServerDocumentRecord> {
        let document = self.documents.get(&handle)?;
        let parent = self.servers.get(&server)?;
        (document.generation == generation
            && document.server == server
            && document.endpoint == endpoint
            && document.endpoint_worker_generation == endpoint_worker_generation
            && document.document_atom == document_atom
            && parent.owner == document.owner
            && parent.generation == server_generation
            && parent.endpoint_worker_generation == endpoint_worker_generation)
            .then_some(document)
    }

    pub(crate) fn owner_item_release_journals(
        &self,
        owner: OwnerId,
    ) -> Vec<Ole1ServerCompletionJournalEntry> {
        self.completion_journal
            .values()
            .filter(|entry| entry.identity.owner == owner)
            .copied()
            .collect()
    }

    pub(crate) fn owner_release_journals(
        &self,
        owner: OwnerId,
    ) -> Vec<Ole1ReleaseCompletionJournalEntry> {
        self.release_completion_journal
            .values()
            .filter(|entry| entry.owner == owner)
            .copied()
            .collect()
    }

    pub(crate) fn owner_dde_release_chains(
        &self,
        owner: OwnerId,
    ) -> Vec<Ole1ServerDdeReleaseChain> {
        self.dde_release_chains
            .iter()
            .filter(|entry| entry.event.owner == owner)
            .cloned()
            .collect()
    }

    pub(crate) fn owner_has_lifecycle_work(&self, owner: OwnerId) -> bool {
        self.servers.values().any(|record| record.owner == owner)
            || self.documents.values().any(|record| record.owner == owner)
            || self
                .completion_journal
                .values()
                .any(|entry| entry.identity.owner == owner)
            || self
                .release_completion_journal
                .values()
                .any(|entry| entry.owner == owner)
            || self
                .unpublished_cleanups
                .values()
                .any(|entry| entry.owner == owner)
            || self
                .dde_release_chains
                .iter()
                .any(|entry| entry.event.owner == owner)
            || self
                .close_callback_documents
                .iter()
                .any(|(entry_owner, _, _)| *entry_owner == owner)
            || self
                .retired_documents
                .keys()
                .any(|(entry_owner, _)| *entry_owner == owner)
    }

    pub(crate) fn release_atom_delete_pending(
        &self,
        callback_id: u64,
        target: Ole1ReleaseTarget,
    ) -> Result<Option<u16>, Ole1Status> {
        let entry = self
            .release_completion_journal
            .get(&callback_id)
            .filter(|entry| entry.target == target)
            .ok_or(OLE_ERROR_HANDLE)?;
        Ok(match (entry.phase, target) {
            (
                Ole1ReleasePhase::DeleteFirstAtom,
                Ole1ReleaseTarget::Document { document_atom, .. },
            ) => Some(document_atom),
            (Ole1ReleasePhase::DeleteFirstAtom, Ole1ReleaseTarget::Server { class_atom, .. }) => {
                Some(class_atom)
            }
            (
                Ole1ReleasePhase::DeleteSecondAtom,
                Ole1ReleaseTarget::Server {
                    executable_atom, ..
                },
            ) => Some(executable_atom),
            _ => None,
        })
    }

    pub(crate) fn mark_release_atom_deleted(
        &mut self,
        callback_id: u64,
        target: Ole1ReleaseTarget,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .release_completion_journal
            .get_mut(&callback_id)
            .filter(|entry| entry.target == target)
            .ok_or(OLE_ERROR_HANDLE)?;
        entry.phase = match (entry.phase, target) {
            (Ole1ReleasePhase::DeleteFirstAtom, Ole1ReleaseTarget::Document { .. }) => {
                Ole1ReleasePhase::RetireEndpoint
            }
            (Ole1ReleasePhase::DeleteFirstAtom, Ole1ReleaseTarget::Server { .. }) => {
                Ole1ReleasePhase::DeleteSecondAtom
            }
            (Ole1ReleasePhase::DeleteSecondAtom, Ole1ReleaseTarget::Server { .. }) => {
                Ole1ReleasePhase::RetireEndpoint
            }
            _ => return Err(OLE_ERROR_PROTOCOL),
        };
        Ok(())
    }

    pub(crate) fn mark_release_endpoint_retired(
        &mut self,
        callback_id: u64,
        target: Ole1ReleaseTarget,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .release_completion_journal
            .get_mut(&callback_id)
            .filter(|entry| entry.target == target)
            .ok_or(OLE_ERROR_HANDLE)?;
        if entry.phase != Ole1ReleasePhase::RetireEndpoint {
            return Err(OLE_ERROR_PROTOCOL);
        }
        entry.phase = Ole1ReleasePhase::CommitRegistry;
        Ok(())
    }

    pub(crate) fn finish_release_completion(
        &mut self,
        callback_id: u64,
        target: Ole1ReleaseTarget,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .release_completion_journal
            .get(&callback_id)
            .filter(|entry| {
                entry.callback_id == callback_id
                    && entry.target == target
                    && entry.phase == Ole1ReleasePhase::CommitRegistry
            })
            .copied()
            .ok_or(OLE_ERROR_HANDLE)?;
        let owner = entry.owner;
        match target {
            Ole1ReleaseTarget::Document {
                handle,
                generation,
                server,
                server_generation,
                endpoint,
                endpoint_worker_generation,
                document_atom,
            } => {
                let parent = self.server(entry.owner, server).ok_or(OLE_ERROR_HANDLE)?;
                if parent.generation != server_generation
                    || parent.endpoint_worker_generation != endpoint_worker_generation
                {
                    return Err(OLE_ERROR_HANDLE);
                }
                let document = self
                    .document(entry.owner, handle)
                    .filter(|document| {
                        document.generation == generation
                            && document.server == server
                            && document.endpoint == endpoint
                            && document.endpoint_worker_generation == endpoint_worker_generation
                            && document.document_atom == document_atom
                    })
                    .ok_or(OLE_ERROR_HANDLE)?;
                if !document.conversations.is_empty()
                    || !document.pending_terminations.is_empty()
                    || !document.items.is_empty()
                    || document.state != Ole1DocumentState::Revoking
                {
                    return Err(OLE_WAIT_FOR_RELEASE);
                }
                let _ = document;
                self.remove_document(entry.owner, handle)?;
            }
            Ole1ReleaseTarget::Server {
                handle,
                generation,
                endpoint,
                endpoint_worker_generation,
                class_atom,
                executable_atom,
            } => {
                let server = self
                    .server(entry.owner, handle)
                    .filter(|server| {
                        server.generation == generation
                            && server.endpoint == endpoint
                            && server.endpoint_worker_generation == endpoint_worker_generation
                            && server.class_atom == class_atom
                            && server.executable_atom == executable_atom
                    })
                    .ok_or(OLE_ERROR_HANDLE)?;
                if server.state != Ole1RegistrationState::Revoking
                    || !server.conversations.is_empty()
                    || !server.pending_terminations.is_empty()
                    || !server.documents.is_empty()
                    || server.blocked
                {
                    return Err(OLE_WAIT_FOR_RELEASE);
                }
                let _ = server;
                self.remove_server(entry.owner, handle)?;
            }
        }
        let journal = self
            .release_completion_journal
            .get_mut(&callback_id)
            .filter(|entry| {
                entry.callback_id == callback_id && entry.owner == owner && entry.target == target
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if journal.phase != Ole1ReleasePhase::CommitRegistry {
            return Err(OLE_ERROR_PROTOCOL);
        }
        journal.phase = Ole1ReleasePhase::Committed;
        self.release_pending_events.remove(&callback_id);
        Ok(())
    }

    pub(crate) fn finalize_release_completion(
        &mut self,
        callback_id: u64,
        target: Ole1ReleaseTarget,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .release_completion_journal
            .get(&callback_id)
            .filter(|entry| {
                entry.callback_id == callback_id
                    && entry.target == target
                    && entry.phase == Ole1ReleasePhase::Committed
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        let _ = entry;
        self.release_completion_journal.remove(&callback_id);
        self.release_pending_events.remove(&callback_id);
        Ok(())
    }
}
