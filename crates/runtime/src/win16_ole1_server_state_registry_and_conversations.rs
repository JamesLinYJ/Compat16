impl Ole1ServerState {
    pub(crate) fn register_server(
        &mut self,
        owner: OwnerId,
        class_name: Vec<u8>,
        class_atom: u16,
        executable_atom: u16,
        server_far: u32,
        instance: u16,
        use_mode: Ole1ServerUse,
        endpoint: Win16HostClassicDdeEndpoint,
        endpoint_worker_generation: u64,
        registered_server_value: Vec<u8>,
    ) -> Result<Ole1ServerHandle, Ole1Status> {
        if self
            .servers
            .values()
            .any(|record| record.owner == owner && record.class_atom == class_atom)
        {
            return Err(OLE_ERROR_ALREADY_REGISTERED);
        }
        if class_name.is_empty() || class_name.contains(&0) || class_atom == 0 {
            return Err(OLE_ERROR_CLASS);
        }
        if server_far == 0 || executable_atom == 0 {
            return Err(OLE_ERROR_OBJECT);
        }
        if endpoint.0 == 0 || endpoint_worker_generation == 0 {
            return Err(OLE_ERROR_HANDLE);
        }
        if registered_server_value.is_empty() {
            return Err(OLE_ERROR_REGISTRATION);
        }
        let handle = self.reserve_handle()?;
        let generation = self.reserve_generation()?;
        self.servers.insert(
            handle,
            Ole1ServerRecord {
                owner,
                generation,
                class_name,
                class_atom,
                executable_atom,
                server_far,
                guest_handle_published: true,
                instance,
                use_mode,
                endpoint,
                endpoint_worker_generation,
                state: Ole1RegistrationState::Active,
                blocked: false,
                documents: Vec::new(),
                conversations: BTreeMap::new(),
                pending_terminations: BTreeMap::new(),
                deferred_events: VecDeque::new(),
                in_flight_deferred: None,
                processing_deferred_message: false,
                registered_server_value,
            },
        );
        Ok(handle)
    }

    pub(crate) fn register_document(
        &mut self,
        owner: OwnerId,
        server: Ole1ServerHandle,
        endpoint: Win16HostClassicDdeEndpoint,
        endpoint_worker_generation: u64,
        name: Vec<u8>,
        document_atom: u16,
        server_document_far: Option<u32>,
    ) -> Result<Ole1ServerDocumentHandle, Ole1Status> {
        let server_record = self
            .servers
            .get(&server)
            .filter(|record| record.owner == owner)
            .ok_or(OLE_ERROR_HANDLE)?;
        if server_record.state != Ole1RegistrationState::Active {
            return Err(OLE_ERROR_HANDLE);
        }
        if endpoint.0 == 0
            || endpoint_worker_generation == 0
            || server_record.endpoint_worker_generation != endpoint_worker_generation
        {
            return Err(OLE_ERROR_HANDLE);
        }
        if name.is_empty() || name.contains(&0) || document_atom == 0 {
            return Err(OLE_ERROR_NAME);
        }
        self.servers
            .get_mut(&server)
            .expect("server was validated above")
            .documents
            .try_reserve(1)
            .map_err(|_| OLE_ERROR_MEMORY)?;
        // XP NTVDM allocates a fresh DOC record for each call and does not
        // reject a repeated document name here. Preserve that observed ABI.
        let handle = Ole1ServerDocumentHandle(self.reserve_handle()?.0);
        let generation = self.reserve_generation()?;
        self.documents.insert(
            handle,
            Ole1ServerDocumentRecord {
                owner,
                generation,
                server,
                endpoint,
                endpoint_worker_generation,
                name,
                document_atom,
                server_document_far,
                guest_handle_published: true,
                state: Ole1DocumentState::Active,
                conversations: BTreeMap::new(),
                pending_terminations: BTreeMap::new(),
                items: Vec::new(),
                embedded: false,
                prepared_callback_scratch: None,
                prepared_callback_completion: None,
            },
        );
        let server_record = self.servers.get_mut(&server).ok_or(OLE_ERROR_HANDLE)?;
        server_record.documents.push(handle);
        Ok(handle)
    }

    /// Retain a newly registered server when the caller's output handle could
    /// not be committed. No guest can address this handle, so make it
    /// ineligible for DDE immediately and let task shutdown retire its exact
    /// atoms/endpoint without invoking an unobservable Release callback.
    pub(crate) fn mark_server_handle_unpublished(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<(), Ole1Status> {
        let record = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if record.state != Ole1RegistrationState::Active
            || !record.conversations.is_empty()
            || !record.documents.is_empty()
            || record.blocked
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        record.guest_handle_published = false;
        record.state = Ole1RegistrationState::Revoking;
        Ok(())
    }

    /// Retain a newly registered document whose output handle was not
    /// published. It is kept in its exact parent and is retired by the
    /// owner-scoped cleanup path, without calling guest code through a
    /// registration-time vtable that may not yet have been initialized.
    pub(crate) fn mark_document_handle_unpublished(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Result<(), Ole1Status> {
        let record = self.document_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if record.state != Ole1DocumentState::Active
            || !record.conversations.is_empty()
            || !record.items.is_empty()
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        record.guest_handle_published = false;
        record.state = Ole1DocumentState::Revoking;
        Ok(())
    }

    pub(crate) fn server(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Option<&Ole1ServerRecord> {
        self.servers
            .get(&handle)
            .filter(|record| record.owner == owner)
    }

    pub(crate) fn server_mut(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Option<&mut Ole1ServerRecord> {
        self.servers
            .get_mut(&handle)
            .filter(|record| record.owner == owner)
    }

    pub(crate) fn document(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Option<&Ole1ServerDocumentRecord> {
        self.documents
            .get(&handle)
            .filter(|record| record.owner == owner)
    }

    pub(crate) fn document_mut(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Option<&mut Ole1ServerDocumentRecord> {
        self.documents
            .get_mut(&handle)
            .filter(|record| record.owner == owner)
    }

    pub(crate) fn server_for_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Option<(Ole1ServerHandle, &Ole1ServerRecord)> {
        self.servers
            .iter()
            .find(|(_, record)| record.owner == owner && record.endpoint == endpoint)
            .map(|(handle, record)| (*handle, record))
    }

    pub(crate) fn server_for_any_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Option<(Ole1ServerHandle, &Ole1ServerRecord)> {
        self.server_for_endpoint(owner, endpoint).or_else(|| {
            let (_, document) = self.document_for_endpoint(owner, endpoint)?;
            self.server(owner, document.server)
                .map(|server| (document.server, server))
        })
    }

    pub(crate) fn server_for_document(
        &self,
        owner: OwnerId,
        handle: Ole1ServerDocumentHandle,
    ) -> Option<(
        Ole1ServerHandle,
        &Ole1ServerRecord,
        &Ole1ServerDocumentRecord,
    )> {
        let document = self.document(owner, handle)?;
        let server = self.server(owner, document.server)?;
        Some((document.server, server, document))
    }

    /// Resolve a protocol conversation only when owner, endpoint incarnation,
    /// conversation ID and peer HWND incarnation all match the registration.
    /// A numeric guest HWND or conversation ID by itself is never membership.
    pub(crate) fn conversation_target(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
    ) -> Option<Ole1ConversationTarget> {
        if let Some((server_handle, server)) = self.server_for_endpoint(owner, endpoint) {
            let binding = server.conversations.get(&conversation)?;
            if binding.peer != peer || server.state != Ole1RegistrationState::Active {
                return None;
            }
            return Some(Ole1ConversationTarget {
                server: server_handle,
                server_generation: server.generation,
                document: None,
                document_generation: None,
            });
        }
        let (document_handle, document) = self.document_for_endpoint(owner, endpoint)?;
        let binding = document.conversations.get(&conversation)?;
        if binding.peer != peer || document.state != Ole1DocumentState::Active {
            return None;
        }
        let server = self.server(owner, document.server)?;
        if server.state != Ole1RegistrationState::Active {
            return None;
        }
        Some(Ole1ConversationTarget {
            server: document.server,
            server_generation: server.generation,
            document: Some(document_handle),
            document_generation: Some(document.generation),
        })
    }

    /// Resolve a host child endpoint through the exact owner-bound document
    /// record. Endpoint tokens and document handles each carry independent
    /// monotonic generations at their respective boundaries; neither is
    /// reconstructed from guest numeric values.
    pub(crate) fn document_for_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Option<(Ole1ServerDocumentHandle, &Ole1ServerDocumentRecord)> {
        self.documents
            .iter()
            .find(|(_, document)| document.owner == owner && document.endpoint == endpoint)
            .map(|(handle, document)| (*handle, document))
    }

    /// Find a document by the guest-encoded OLE topic name. This lookup is
    /// scoped to one server and does not infer a document from an HWND or
    /// server class atom.
    pub(crate) fn document_by_name(
        &self,
        owner: OwnerId,
        server: Ole1ServerHandle,
        name: &[u8],
    ) -> Option<(Ole1ServerDocumentHandle, &Ole1ServerDocumentRecord)> {
        self.documents.iter().find_map(|(handle, document)| {
            (document.owner == owner
                && document.server == server
                && document.state == Ole1DocumentState::Active
                && document.name.eq_ignore_ascii_case(name))
            .then_some((*handle, document))
        })
    }

    /// Return only owner-matched endpoint identities for task teardown. The
    /// caller must retire each endpoint with the host and verify receipts
    /// before dropping retained DDE callbacks/transfers.
    pub(crate) fn owner_endpoints(
        &self,
        owner: OwnerId,
    ) -> impl Iterator<Item = Win16HostClassicDdeEndpoint> + '_ {
        self.servers
            .values()
            .filter(move |record| record.owner == owner)
            .map(|record| record.endpoint)
            .chain(
                self.documents
                    .values()
                    .filter(move |record| record.owner == owner)
                    .map(|record| record.endpoint),
            )
    }

    /// Publish a server and optional document conversation as one checked
    /// transition after the host's exact INITIATE reply receipt. The second
    /// insertion cannot leave only a server-side record if its handle is stale
    /// or the conversation was already bound.
    pub(crate) fn bind_server_document_conversation(
        &mut self,
        owner: OwnerId,
        server: Ole1ServerHandle,
        document: Option<Ole1ServerDocumentHandle>,
        binding: Ole1ConversationBinding,
    ) -> Result<(), Ole1Status> {
        let server_record = self.server(owner, server).ok_or(OLE_ERROR_HANDLE)?;
        if server_record.state != Ole1RegistrationState::Active
            || server_record.conversations.contains_key(&binding.id)
        {
            return Err(OLE_ERROR_HANDLE);
        }
        if let Some(document) = document {
            let document_record = self.document(owner, document).ok_or(OLE_ERROR_HANDLE)?;
            if document_record.server != server
                || document_record.state != Ole1DocumentState::Active
                || document_record.conversations.contains_key(&binding.id)
            {
                return Err(OLE_ERROR_HANDLE);
            }
        }
        self.servers
            .get_mut(&server)
            .ok_or(OLE_ERROR_HANDLE)?
            .conversations
            .insert(binding.id, binding);
        if let Some(document) = document {
            self.documents
                .get_mut(&document)
                .ok_or(OLE_ERROR_HANDLE)?
                .conversations
                .insert(binding.id, binding);
        }
        Ok(())
    }

    pub(crate) fn retire_conversation(
        &mut self,
        owner: OwnerId,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<bool, Ole1Status> {
        let mut found = false;
        for record in self
            .servers
            .values_mut()
            .filter(|record| record.owner == owner)
        {
            found |= record.conversations.remove(&conversation).is_some();
            record.pending_terminations.remove(&conversation);
        }
        for record in self
            .documents
            .values_mut()
            .filter(|record| record.owner == owner)
        {
            found |= record.conversations.remove(&conversation).is_some();
            record.pending_terminations.remove(&conversation);
            // Item bindings own separate OLEOBJECT callback identity and
            // global-atom references. Ending a DDE conversation retires only
            // its transport binding; the application must still revoke each
            // item through OleRevokeObject (or owner-exit cleanup).
        }
        Ok(found)
    }
}
