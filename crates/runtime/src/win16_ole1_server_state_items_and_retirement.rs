impl Ole1ServerState {
    pub(crate) fn prepared_callback_scratch(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Option<Ole1ServerPreparedCallbackScratch> {
        self.document(owner, handle)
            .filter(|document| document.generation == generation)
            .and_then(|document| document.prepared_callback_scratch)
    }

    pub(crate) fn set_prepared_callback_scratch(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
        scratch: Option<Ole1ServerPreparedCallbackScratch>,
    ) -> Result<(), Ole1Status> {
        let document = self
            .document_mut(owner, handle)
            .filter(|document| document.generation == generation)
            .ok_or(OLE_ERROR_HANDLE)?;
        document.prepared_callback_scratch = scratch;
        Ok(())
    }

    pub(crate) fn publish_server_document_interface(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        server_document_far: u32,
    ) -> Result<(), Ole1Status> {
        if server_document_far == 0 {
            return Err(OLE_ERROR_OBJECT);
        }
        let document = self.document_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if document.state != Ole1DocumentState::Active {
            return Err(OLE_ERROR_HANDLE);
        }
        document.server_document_far = Some(server_document_far);
        Ok(())
    }

    pub(crate) fn set_embedded(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<(), Ole1Status> {
        self.document_mut(owner, handle)
            .ok_or(OLE_ERROR_HANDLE)?
            .embedded = true;
        Ok(())
    }

    pub(crate) fn item_callback_identity(
        &self,
        owner: OwnerId,
        client_far: u32,
        object_far: u32,
    ) -> Option<Ole1ItemCallbackIdentity> {
        self.documents.iter().find_map(|(handle, document)| {
            if document.owner != owner || document.state != Ole1DocumentState::Active {
                return None;
            }
            let item = document.items.iter().find(|item| {
                item.client_far == client_far
                    && item.object_far == object_far
                    && !item.revoking
                    && document.conversations.contains_key(&item.conversation)
            })?;
            Some(Ole1ItemCallbackIdentity {
                owner,
                document: *handle,
                document_generation: document.generation,
                item_generation: item.generation,
                client_far,
                object_far,
            })
        })
    }

    pub(crate) fn validate_item_callback_identity(
        &self,
        identity: Ole1ItemCallbackIdentity,
    ) -> bool {
        let Some(document) = self.document(identity.owner, identity.document) else {
            return false;
        };
        document.generation == identity.document_generation
            && document.state == Ole1DocumentState::Active
            && document.items.iter().any(|item| {
                item.generation == identity.item_generation
                    && item.client_far == identity.client_far
                    && item.object_far == identity.object_far
                    && !item.revoking
                    && document.conversations.contains_key(&item.conversation)
            })
    }

    pub(crate) fn begin_revoke_item(
        &mut self,
        owner: OwnerId,
        client_far: u32,
    ) -> Result<Ole1ItemCallbackIdentity, Ole1Status> {
        let Some((document_handle, document)) = self.documents.iter().find(|(_, document)| {
            document.owner == owner
                && document.state == Ole1DocumentState::Active
                && document
                    .items
                    .iter()
                    .any(|item| item.client_far == client_far)
        }) else {
            return Err(OLE_ERROR_HANDLE);
        };
        let document_handle = *document_handle;
        let document_generation = document.generation;
        let Some(item) = document
            .items
            .iter()
            .find(|item| item.client_far == client_far)
        else {
            return Err(OLE_ERROR_HANDLE);
        };
        if item.revoking {
            return Err(OLE_ERROR_HANDLE);
        }
        let identity = Ole1ItemCallbackIdentity {
            owner,
            document: document_handle,
            document_generation,
            item_generation: item.generation,
            client_far: item.client_far,
            object_far: item.object_far,
        };
        let item = self
            .document_mut(owner, document_handle)
            .and_then(|document| {
                document.items.iter_mut().find(|item| {
                    item.generation == identity.item_generation
                        && item.client_far == identity.client_far
                        && item.object_far == identity.object_far
                })
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        item.revoking = true;
        Ok(identity)
    }

    pub(crate) fn cancel_revoke_item(
        &mut self,
        identity: Ole1ItemCallbackIdentity,
    ) -> Result<(), Ole1Status> {
        if self
            .completion_journal
            .values()
            .any(|entry| entry.identity == identity)
        {
            return Err(OLE_ERROR_HANDLE);
        }
        let item = self
            .document_mut(identity.owner, identity.document)
            .filter(|document| document.generation == identity.document_generation)
            .and_then(|document| {
                document.items.iter_mut().find(|item| {
                    item.generation == identity.item_generation
                        && item.client_far == identity.client_far
                        && item.object_far == identity.object_far
                        && item.revoking
                })
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        item.revoking = false;
        Ok(())
    }

    /// Begin journaling the post-Release side effects exactly once. If the
    /// host operation fails, the callback frame remains live with no active
    /// guest call and this record lets the dispatcher retry only retirement.
    pub(crate) fn begin_item_release_completion(
        &mut self,
        callback_id: u64,
        identity: Ole1ItemCallbackIdentity,
        callback_status: Ole1Status,
    ) -> Result<Ole1ServerCompletionJournalEntry, Ole1Status> {
        if callback_id == 0 {
            return Err(OLE_ERROR_HANDLE);
        }
        if let Some(existing) = self.completion_journal.get(&callback_id).copied() {
            return (existing.identity == identity
                && existing.callback_result
                    == Ole1ItemReleaseCallbackResult::Returned(callback_status))
            .then_some(existing)
            .ok_or(OLE_ERROR_HANDLE);
        }
        let item = self
            .document(identity.owner, identity.document)
            .filter(|document| document.generation == identity.document_generation)
            .and_then(|document| {
                document.items.iter().find(|item| {
                    item.generation == identity.item_generation
                        && item.client_far == identity.client_far
                        && item.object_far == identity.object_far
                        && item.revoking
                })
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if item.item_atom == 0 {
            return Err(OLE_ERROR_NAME);
        }
        let entry = Ole1ServerCompletionJournalEntry {
            callback_id,
            identity,
            item_atom: item.item_atom,
            callback_result: Ole1ItemReleaseCallbackResult::Returned(callback_status),
            phase: Ole1ItemRetirementPhase::AtomDeletePending,
        };
        self.completion_journal.insert(callback_id, entry);
        Ok(entry)
    }

    /// Task-exit counterpart to a returned OLEOBJECT::Release. This records
    /// cancellation explicitly, so subsequent cleanup can retire the exact
    /// item atom without re-entering guest code or claiming its return value.
    pub(crate) fn begin_cancelled_item_release_completion(
        &mut self,
        callback_id: u64,
        identity: Ole1ItemCallbackIdentity,
    ) -> Result<Ole1ServerCompletionJournalEntry, Ole1Status> {
        let mut entry =
            self.begin_item_release_completion(callback_id, identity, OLE_WAIT_FOR_RELEASE)?;
        entry.callback_result = Ole1ItemReleaseCallbackResult::CancelledByOwnerExit;
        self.completion_journal.insert(callback_id, entry);
        Ok(entry)
    }

    pub(crate) fn pending_item_release_completion(
        &self,
        callback_id: u64,
    ) -> Option<Ole1ServerCompletionJournalEntry> {
        self.completion_journal.get(&callback_id).copied()
    }

    pub(crate) fn item_atom_delete_pending(
        &self,
        callback_id: u64,
        identity: Ole1ItemCallbackIdentity,
    ) -> Result<Option<u16>, Ole1Status> {
        let entry = self
            .completion_journal
            .get(&callback_id)
            .filter(|entry| entry.callback_id == callback_id && entry.identity == identity)
            .ok_or(OLE_ERROR_HANDLE)?;
        Ok(match entry.phase {
            Ole1ItemRetirementPhase::AtomDeletePending => Some(entry.item_atom),
            Ole1ItemRetirementPhase::AtomDeleted => None,
        })
    }

    pub(crate) fn mark_item_atom_deleted(
        &mut self,
        callback_id: u64,
        identity: Ole1ItemCallbackIdentity,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .completion_journal
            .get_mut(&callback_id)
            .filter(|entry| entry.callback_id == callback_id && entry.identity == identity)
            .ok_or(OLE_ERROR_HANDLE)?;
        entry.phase = Ole1ItemRetirementPhase::AtomDeleted;
        Ok(())
    }

    pub(crate) fn finish_revoke_item(
        &mut self,
        callback_id: u64,
        identity: Ole1ItemCallbackIdentity,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .completion_journal
            .get(&callback_id)
            .filter(|entry| {
                entry.callback_id == callback_id
                    && entry.identity == identity
                    && entry.phase == Ole1ItemRetirementPhase::AtomDeleted
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if entry.item_atom == 0 {
            return Err(OLE_ERROR_NAME);
        }
        let document = self
            .document_mut(identity.owner, identity.document)
            .filter(|document| document.generation == identity.document_generation)
            .ok_or(OLE_ERROR_HANDLE)?;
        let index = document
            .items
            .iter()
            .position(|item| {
                item.generation == identity.item_generation
                    && item.client_far == identity.client_far
                    && item.object_far == identity.object_far
                    && item.revoking
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        document.items.remove(index);
        self.completion_journal.remove(&callback_id);
        Ok(())
    }

    pub(crate) fn remove_document(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<Ole1ServerDocumentRecord, Ole1Status> {
        let record = self.document(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !record.conversations.is_empty()
            || !record.pending_terminations.is_empty()
            || !record.items.is_empty()
        {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        let server = record.server;
        let generation = record.generation;
        let removed = self.documents.remove(&handle).ok_or(OLE_ERROR_HANDLE)?;
        if self
            .close_callback_documents
            .remove(&(owner, handle, generation))
        {
            self.retired_documents.insert((owner, handle), generation);
        }
        if let Some(server_record) = self.server_mut(owner, server) {
            server_record
                .documents
                .retain(|existing| *existing != handle);
        }
        Ok(removed)
    }

    pub(crate) fn document_generation_was_retired(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> bool {
        self.retired_documents.get(&(owner, handle)) == Some(&generation)
    }

    pub(crate) fn begin_close_document_callback(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<(), Ole1Status> {
        let document = self.document(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if document.generation != generation || document.state != Ole1DocumentState::Active {
            return Err(OLE_ERROR_HANDLE);
        }
        if !self
            .close_callback_documents
            .insert((owner, handle, generation))
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(())
    }

    pub(crate) fn finish_close_document_callback_post(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<(), Ole1Status> {
        if let Some(document) = self.document(owner, handle) {
            if document.generation != generation {
                return Err(OLE_ERROR_HANDLE);
            }
            return self
                .close_callback_documents
                .remove(&(owner, handle, generation))
                .then_some(())
                .ok_or(OLE_ERROR_PROTOCOL);
        }
        self.consume_retired_document_generation(owner, handle, generation)
    }

    pub(crate) fn cancel_close_document_callback(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<(), Ole1Status> {
        if self
            .document(owner, handle)
            .is_some_and(|document| document.generation == generation)
        {
            return self
                .close_callback_documents
                .remove(&(owner, handle, generation))
                .then_some(())
                .ok_or(OLE_ERROR_PROTOCOL);
        }
        self.consume_retired_document_generation(owner, handle, generation)
    }

    pub(crate) fn owner_pending_close_document_proofs(
        &self,
        owner: OwnerId,
    ) -> Vec<(Ole1ServerDocumentHandle, u64)> {
        let mut pending = self
            .close_callback_documents
            .iter()
            .filter_map(|(entry_owner, handle, generation)| {
                (*entry_owner == owner).then_some((*handle, *generation))
            })
            .collect::<Vec<_>>();
        pending.extend(self.retired_documents.iter().filter_map(
            |((entry_owner, handle), generation)| {
                (*entry_owner == owner).then_some((*handle, *generation))
            },
        ));
        pending.sort_unstable_by_key(|(handle, generation)| (handle.to_guest_long(), *generation));
        pending.dedup();
        pending
    }

    pub(crate) fn consume_retired_document_generation(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
        generation: u64,
    ) -> Result<(), Ole1Status> {
        if !self.document_generation_was_retired(owner, handle, generation) {
            return Err(OLE_ERROR_HANDLE);
        }
        self.retired_documents.remove(&(owner, handle));
        Ok(())
    }

    pub(crate) fn remove_server(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<Ole1ServerRecord, Ole1Status> {
        let record = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !record.conversations.is_empty()
            || !record.pending_terminations.is_empty()
            || !record.documents.is_empty()
            || !record.deferred_events.is_empty()
            || record.in_flight_deferred.is_some()
            || record.processing_deferred_message
            || record.blocked
        {
            return Err(OLE_WAIT_FOR_RELEASE);
        }
        self.servers.remove(&handle).ok_or(OLE_ERROR_HANDLE)
    }

    pub(crate) fn owner_servers(
        &self,
        owner: OwnerId,
    ) -> impl Iterator<Item = (Ole1ServerHandle, &Ole1ServerRecord)> {
        self.servers.iter().filter_map(move |(handle, record)| {
            (record.owner == owner).then_some((*handle, record))
        })
    }

    pub(crate) fn owner_documents(
        &self,
        owner: OwnerId,
    ) -> impl Iterator<Item = (Ole1ServerDocumentHandle, &Ole1ServerDocumentRecord)> {
        self.documents.iter().filter_map(move |(handle, record)| {
            (record.owner == owner).then_some((*handle, record))
        })
    }

    fn reserve_handle(&mut self) -> Result<Ole1ServerHandle, Ole1Status> {
        let value = self.next_handle.ok_or(OLE_ERROR_MEMORY)?;
        let handle = Ole1ServerHandle(value);
        self.next_handle = value.checked_add(1).filter(|next| *next > 0);
        Ok(handle)
    }

    fn reserve_generation(&mut self) -> Result<u64, Ole1Status> {
        let value = self.next_generation.ok_or(OLE_ERROR_MEMORY)?;
        self.next_generation = value.checked_add(1);
        Ok(value)
    }
}
