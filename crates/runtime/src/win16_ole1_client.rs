//! OLE1 client-document object membership and enumeration.
//!
//! The document table owns guest OLE object and client FAR tokens. It never
//! interprets them as native interface pointers.

use guest_core::memory::Memory;
use win16_abi::Access;

use super::methods::is_known_oleobject_protocol;
use super::{
    OLE1_BUSY, OLE1_ERROR_ADDRESS, OLE1_ERROR_HANDLE, OLE1_ERROR_MEMORY, OLE1_ERROR_OBJECT,
    OLE1_OK, Win16Ole1AsyncBusyOwner, Win16Ole1AsyncCommand, Win16Ole1ClientDocHandle,
    Win16Ole1ClientDocuments, Win16Ole1PendingOperation, Win16Ole1ProtocolAliasOwner,
    Win16Ole1ReleaseMethodExpectation, Win16Ole1SourceProbePolicy, Win16Ole1Status, Win16State,
};

impl Win16Ole1ClientDocuments {
    pub(super) fn reserve_operation(
        &mut self,
    ) -> Result<super::Win16Ole1OperationId, Win16Ole1Status> {
        let Some(value) = self.next_operation_id else {
            return Err(OLE1_ERROR_MEMORY);
        };
        if value == 0 {
            return Err(OLE1_ERROR_MEMORY);
        }
        self.next_operation_id = value.checked_add(1).filter(|next| *next != 0);
        Ok(super::Win16Ole1OperationId(value))
    }

    pub(super) fn add_object_with_proxy(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
        object_far: u32,
        client_far: u32,
        proxy_id: Option<super::Win16Ole1ClientProxyId>,
        operation_id: Option<super::Win16Ole1OperationId>,
    ) -> Result<(), Win16Ole1Status> {
        if object_far == 0 || client_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }
        if !self.documents.contains_key(&handle) {
            return Err(OLE1_ERROR_HANDLE);
        }
        let canonical = self.canonical_object(object_far);
        if let Some(proxy_id) = proxy_id {
            let Some(operation_id) = operation_id else {
                return Err(OLE1_ERROR_OBJECT);
            };
            let Some(binding) = self
                .client_proxies
                .iter()
                .find(|binding| binding.id == proxy_id)
            else {
                return Err(OLE1_ERROR_OBJECT);
            };
            if binding.operation_id != Some(operation_id)
                || binding.client_far != client_far
                || binding
                    .object
                    .is_some_and(|object| object != (handle, canonical))
            {
                return Err(OLE1_ERROR_OBJECT);
            }
        } else if operation_id.is_some() {
            return Err(OLE1_ERROR_OBJECT);
        }
        if let Some((owner, _canonical)) = self.owner_of(object_far) {
            if owner != handle {
                return Err(OLE1_ERROR_OBJECT);
            }
            let existing_proxy = self.proxy_for_object(object_far);
            return match (self.client_for_object(object_far), existing_proxy, proxy_id) {
                (Some(existing), Some(existing_proxy), Some(proxy_id))
                    if existing == client_far && existing_proxy == proxy_id => Ok(()),
                (Some(existing), None, None) if existing == client_far => Ok(()),
                _ => Err(OLE1_ERROR_OBJECT),
            };
        }
        let document = self.documents.get_mut(&handle).ok_or(OLE1_ERROR_HANDLE)?;
        document
            .objects
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        document
            .object_clients
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        if proxy_id.is_some() {
            document
                .object_proxy_bindings
                .try_reserve(1)
                .map_err(|_| OLE1_ERROR_MEMORY)?;
        }
        document.objects.push(canonical);
        document.object_clients.push((canonical, client_far));
        if let Some(proxy_id) = proxy_id {
            document.object_proxy_bindings.push((canonical, proxy_id));
            let binding = self
                .client_proxies
                .iter_mut()
                .find(|binding| binding.id == proxy_id)
                .ok_or(OLE1_ERROR_OBJECT)?;
            binding.object = Some((handle, canonical));
        }
        Ok(())
    }

    pub(super) fn reserve_object_slot(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
    ) -> Result<(), Win16Ole1Status> {
        let Some(document) = self.documents.get_mut(&handle) else {
            return Err(OLE1_ERROR_HANDLE);
        };
        document
            .objects
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        document
            .object_clients
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        document
            .object_proxy_bindings
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)
    }

    pub(super) fn reserve_pending_operation(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
    ) -> Result<(), Win16Ole1Status> {
        let Some(document) = self.documents.get_mut(&handle) else {
            return Err(OLE1_ERROR_HANDLE);
        };
        document
            .pending_operations
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)
    }

    pub(super) fn reserve_pending_release(
        &mut self,
        object_far: u32,
    ) -> Result<Option<Win16Ole1ClientDocHandle>, Win16Ole1Status> {
        let Some((handle, _canonical)) = self.owner_of(object_far) else {
            return Ok(None);
        };
        self.reserve_pending_operation(handle)?;
        Ok(Some(handle))
    }

    pub(super) fn begin_pending_creation(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
        operation_id: super::Win16Ole1OperationId,
        initiating_callback_id: Option<u64>,
        source_object: Option<u32>,
        source_probe_policy: Win16Ole1SourceProbePolicy,
        proxy_id: Option<super::Win16Ole1ClientProxyId>,
        async_busy_command_on_return: Option<Win16Ole1AsyncCommand>,
        client_far: u32,
        expected_release_method: Win16Ole1ReleaseMethodExpectation,
    ) -> Result<(), Win16Ole1Status> {
        self.push_pending(
            handle,
            Win16Ole1PendingOperation::Creation {
                operation_id,
                initiating_callback_id,
                source_object,
                source_probe_policy,
                proxy_id,
                async_busy_command_on_return,
                release_object: None,
                async_busy: None,
                client_far,
                expected_release_method,
                awaiting_release: false,
            },
        )
    }

    pub(super) fn set_pending_creation_proxy(
        &mut self,
        operation_id: super::Win16Ole1OperationId,
        proxy_id: super::Win16Ole1ClientProxyId,
    ) -> Result<(), Win16Ole1Status> {
        let Some(binding) = self
            .client_proxies
            .iter()
            .find(|binding| binding.id == proxy_id)
        else {
            return Err(OLE1_ERROR_OBJECT);
        };
        if binding.operation_id != Some(operation_id) {
            return Err(OLE1_ERROR_OBJECT);
        }
        for document in self.documents.values_mut() {
            if let Some(Win16Ole1PendingOperation::Creation {
                proxy_id: pending_proxy,
                client_far,
                ..
            }) = document.pending_operations.iter_mut().find(|operation| {
                matches!(operation, Win16Ole1PendingOperation::Creation { operation_id: id, .. } if *id == operation_id)
            }) {
                if *client_far != binding.client_far
                    || pending_proxy.is_some_and(|existing| existing != proxy_id)
                {
                    return Err(OLE1_ERROR_OBJECT);
                }
                *pending_proxy = Some(proxy_id);
                return Ok(());
            }
        }
        Err(OLE1_ERROR_OBJECT)
    }

    pub(super) fn begin_pending_release(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
        operation_id: super::Win16Ole1OperationId,
        initiating_callback_id: Option<u64>,
        object_far: u32,
    ) -> Result<(), Win16Ole1Status> {
        self.push_pending(
            handle,
            Win16Ole1PendingOperation::Release {
                operation_id,
                initiating_callback_id,
                object_far,
                async_busy: None,
                // Both public OleDelete and OleRelease use the OLE_DELETE
                // asynchronous method for the standard file-editing object.
                expected_release_method: 1,
                awaiting_release: false,
            },
        )
    }

    fn push_pending(
        &mut self,
        handle: Win16Ole1ClientDocHandle,
        operation: Win16Ole1PendingOperation,
    ) -> Result<(), Win16Ole1Status> {
        // Probe the concrete input object's current command state using the
        // method-specific PROBE_ASYNC or PROBE_CREATE_ASYNC contract. The
        // source does not become busy merely because this operation began.
        let (object, probe_policy) = pending_source_probe(operation);
        let aliases = &self.protocol_aliases;
        let canonical = object.map(|object| canonical_in(aliases, object));
        if !self.documents.contains_key(&handle) {
            return Err(OLE1_ERROR_HANDLE);
        }
        if canonical.is_some_and(|canonical| {
            self.documents.values().any(|document| {
                document.pending_operations.iter().any(|pending| {
                    pending_async_busy_owner(*pending).is_some_and(|owner| {
                        canonical_in(aliases, owner.object_far) == canonical
                            && source_probe_matches(probe_policy, owner.command)
                    })
                })
            })
        }) {
            return Err(OLE1_BUSY);
        }
        let document = self.documents.get_mut(&handle).ok_or(OLE1_ERROR_HANDLE)?;
        document.pending_operations.push(operation);
        Ok(())
    }

    pub(super) fn finish_operation(&mut self, operation_id: super::Win16Ole1OperationId) {
        for document in self.documents.values_mut() {
            document.pending_operations.retain(|operation| {
                pending_operation_id(*operation) != operation_id
            });
        }
    }

    pub(super) fn await_operation(&mut self, operation_id: super::Win16Ole1OperationId) {
        for document in self.documents.values_mut() {
            for operation in &mut document.pending_operations {
                if pending_operation_id(*operation) == operation_id {
                    match operation {
                        Win16Ole1PendingOperation::Creation {
                            awaiting_release,
                            release_object,
                            async_busy_command_on_return,
                            async_busy,
                            ..
                        } => {
                            *awaiting_release = true;
                            *async_busy = match (*async_busy_command_on_return, *release_object) {
                                (Some(command), Some(object_far)) => Some(Win16Ole1AsyncBusyOwner {
                                    object_far,
                                    command,
                                }),
                                _ => None,
                            };
                        }
                        Win16Ole1PendingOperation::Release {
                            awaiting_release,
                            object_far,
                            async_busy,
                            ..
                        } => {
                            *awaiting_release = true;
                            *async_busy = Some(Win16Ole1AsyncBusyOwner {
                                object_far: *object_far,
                                command: Win16Ole1AsyncCommand::Delete,
                            });
                        }
                    }
                }
            }
        }
    }

    pub(super) fn record_pending_creation_object(
        &mut self,
        operation_id: super::Win16Ole1OperationId,
        object_far: Option<u32>,
    ) -> Result<(), Win16Ole1Status> {
        let object_far = object_far.filter(|object| *object != 0);
        let aliases = &self.protocol_aliases;
        let canonical = object_far.map(|object| canonical_in(aliases, object));
        let exists = self.documents.values().any(|document| {
            document.pending_operations.iter().any(|operation| {
                pending_operation_id(*operation) == operation_id
            })
        });
        if !exists {
            return Err(OLE1_ERROR_OBJECT);
        }
        if let Some(canonical) = canonical {
            if self.documents.values().any(|document| {
                document.pending_operations.iter().any(|pending| {
                    pending_operation_id(*pending) != operation_id
                        && (pending_conflict_object(*pending)
                            .is_some_and(|object| canonical_in(aliases, object) == canonical)
                            || matches!(pending, Win16Ole1PendingOperation::Creation { release_object: Some(object), .. } if canonical_in(aliases, *object) == canonical))
                })
            }) {
                return Err(OLE1_BUSY);
            }
        }
        for document in self.documents.values_mut() {
            if let Some(target_index) = document.pending_operations.iter().position(|operation| {
                matches!(operation, Win16Ole1PendingOperation::Creation { operation_id: id, .. } if *id == operation_id)
            }) {
                if let Win16Ole1PendingOperation::Creation { release_object, .. } =
                    &mut document.pending_operations[target_index]
                {
                    *release_object = object_far;
                    return Ok(());
                }
            }
        }
        Err(OLE1_ERROR_OBJECT)
    }

    pub(super) fn reserve_protocol_alias(
        &mut self,
        object_far: u32,
    ) -> Result<Win16Ole1ProtocolAliasOwner, Win16Ole1Status> {
        let owner = self.owner_of(object_far);
        let canonical_object = owner
            .map(|(_, canonical)| canonical)
            .unwrap_or_else(|| self.canonical_object(object_far));
        self.protocol_aliases
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        Ok(Win16Ole1ProtocolAliasOwner {
            document: owner.map(|(handle, _)| handle),
            canonical_object,
        })
    }

    pub(super) fn client_for_object(&self, object_far: u32) -> Option<u32> {
        let (handle, canonical) = self.owner_of(object_far)?;
        self.documents
            .get(&handle)?
            .object_clients
            .iter()
            .find_map(|(object, client)| (*object == canonical).then_some(*client))
    }

    pub(super) fn proxy_for_object(
        &self,
        object_far: u32,
    ) -> Option<super::Win16Ole1ClientProxyId> {
        let (handle, canonical) = self.owner_of(object_far)?;
        self.documents
            .get(&handle)?
            .object_proxy_bindings
            .iter()
            .find_map(|(object, proxy)| (*object == canonical).then_some(*proxy))
    }

    pub(super) fn set_proxy_object(
        &mut self,
        proxy_id: super::Win16Ole1ClientProxyId,
        object: Option<(Win16Ole1ClientDocHandle, u32)>,
    ) -> Result<(), Win16Ole1Status> {
        let Some(binding) = self
            .client_proxies
            .iter_mut()
            .find(|binding| binding.id == proxy_id)
        else {
            return Err(OLE1_ERROR_OBJECT);
        };
        binding.object = object;
        Ok(())
    }

    pub(super) fn proxy_for_operation(
        &self,
        operation_id: super::Win16Ole1OperationId,
    ) -> Option<super::Win16Ole1ClientProxyId> {
        let mut matches = self
            .client_proxies
            .iter()
            .filter(|binding| binding.operation_id == Some(operation_id));
        let binding = matches.next()?;
        matches.next().is_none().then_some(binding.id)
    }

    pub(super) fn add_protocol_alias(
        &mut self,
        owner: Win16Ole1ProtocolAliasOwner,
        alias_far: u32,
        protocol: Vec<u8>,
    ) -> Result<(), Win16Ole1Status> {
        if alias_far == 0 {
            return Err(OLE1_ERROR_OBJECT);
        }
        if alias_far == owner.canonical_object {
            return Ok(());
        }
        if let Some(document_handle) = owner.document {
            let Some(document) = self.documents.get(&document_handle) else {
                return Err(OLE1_ERROR_HANDLE);
            };
            if !document.objects.contains(&owner.canonical_object) {
                return Err(OLE1_ERROR_OBJECT);
            }
        }
        if self
            .documents
            .values()
            .any(|document| document.objects.contains(&alias_far))
            || self.protocol_aliases.iter().any(|alias| {
                alias.far == alias_far && alias.canonical_object != owner.canonical_object
            })
        {
            return Err(OLE1_ERROR_OBJECT);
        }
        if self.protocol_aliases.iter().any(|alias| {
            alias.far == alias_far
                && alias.canonical_object == owner.canonical_object
                && alias.protocol == protocol
                && alias.document == owner.document
        }) {
            return Ok(());
        }
        let Some(generation) = self.next_protocol_alias_generation else {
            return Err(OLE1_ERROR_MEMORY);
        };
        let next_generation = generation.checked_add(1);
        // A guest callback can reenter OLE and consume capacity reserved
        // before QueryProtocol was entered, so reserve again at commit time.
        self.protocol_aliases
            .try_reserve(1)
            .map_err(|_| OLE1_ERROR_MEMORY)?;
        self.protocol_aliases.push(super::Win16Ole1ProtocolAlias {
            far: alias_far,
            canonical_object: owner.canonical_object,
            protocol,
            document: owner.document,
            generation,
        });
        self.next_protocol_alias_generation = next_generation;
        Ok(())
    }

    pub(super) fn is_opaque_protocol_alias(&self, object_far: u32) -> bool {
        let mut found = false;
        for alias in self
            .protocol_aliases
            .iter()
            .filter(|alias| alias.far == object_far)
        {
            found = true;
            if is_known_oleobject_protocol(&alias.protocol) {
                return false;
            }
        }
        found
    }

    pub(super) fn remove_object(
        &mut self,
        object_far: u32,
    ) -> Option<super::Win16Ole1ClientProxyId> {
        let canonical_object = self.canonical_object(object_far);
        let mut removed_proxy = None;
        if let Some((owner, _)) = self.owner_of(object_far) {
            if let Some(document) = self.documents.get_mut(&owner) {
                let aliases = &self.protocol_aliases;
                document
                    .pending_operations
                    .retain(|operation| match *operation {
                        Win16Ole1PendingOperation::Release {
                            object_far: pending_far,
                            awaiting_release,
                            ..
                        } => {
                            !awaiting_release
                                || canonical_in(aliases, pending_far) != canonical_object
                        }
                        Win16Ole1PendingOperation::Creation { .. } => true,
                    });
                document
                    .objects
                    .retain(|candidate| *candidate != canonical_object);
                document
                    .object_clients
                    .retain(|(candidate, _)| *candidate != canonical_object);
                removed_proxy = document
                    .object_proxy_bindings
                    .iter()
                    .find_map(|(candidate, proxy)| {
                        (*candidate == canonical_object).then_some(*proxy)
                    });
                document
                    .object_proxy_bindings
                    .retain(|(candidate, _)| *candidate != canonical_object);
            }
        }
        if let Some(proxy_id) = removed_proxy {
            if let Some(binding) = self
                .client_proxies
                .iter_mut()
                .find(|binding| binding.id == proxy_id)
            {
                binding.object = None;
            }
        }
        self.protocol_aliases
            .retain(|alias| alias.canonical_object != canonical_object);
        removed_proxy
    }

    pub(super) fn next_object(
        &self,
        handle: Win16Ole1ClientDocHandle,
        current_far: u32,
    ) -> Result<Option<u32>, Win16Ole1Status> {
        let Some(document) = self.documents.get(&handle) else {
            return Err(OLE1_ERROR_HANDLE);
        };
        if current_far == 0 {
            return Ok(document.objects.first().copied());
        }
        let canonical = self.canonical_object(current_far);
        let Some(index) = document
            .objects
            .iter()
            .position(|candidate| *candidate == canonical)
        else {
            return Err(OLE1_ERROR_OBJECT);
        };
        Ok(document.objects.get(index + 1).copied())
    }

    pub(super) fn canonical_object(&self, object_far: u32) -> u32 {
        self.protocol_aliases
            .iter()
            .find(|alias| alias.far == object_far && is_known_oleobject_protocol(&alias.protocol))
            .map(|alias| alias.canonical_object)
            .unwrap_or(object_far)
    }

    pub(super) fn owner_of(&self, object_far: u32) -> Option<(Win16Ole1ClientDocHandle, u32)> {
        let canonical = self.canonical_object(object_far);
        self.documents
            .iter()
            .find(|(_, document)| document.objects.contains(&canonical))
            .map(|(handle, _)| (*handle, canonical))
    }
}

fn pending_operation_id(operation: Win16Ole1PendingOperation) -> super::Win16Ole1OperationId {
    match operation {
        Win16Ole1PendingOperation::Creation { operation_id, .. }
        | Win16Ole1PendingOperation::Release { operation_id, .. } => operation_id,
    }
}

fn pending_async_busy_owner(
    operation: Win16Ole1PendingOperation,
) -> Option<Win16Ole1AsyncBusyOwner> {
    match operation {
        Win16Ole1PendingOperation::Creation { async_busy, .. }
        | Win16Ole1PendingOperation::Release { async_busy, .. } => async_busy,
    }
}

fn pending_conflict_object(operation: Win16Ole1PendingOperation) -> Option<u32> {
    pending_async_busy_owner(operation).map(|owner| owner.object_far)
}

fn pending_source_probe(
    operation: Win16Ole1PendingOperation,
) -> (Option<u32>, Win16Ole1SourceProbePolicy) {
    match operation {
        Win16Ole1PendingOperation::Creation {
            source_object,
            source_probe_policy,
            ..
        } => (source_object, source_probe_policy),
        Win16Ole1PendingOperation::Release { object_far, .. } => {
            (Some(object_far), Win16Ole1SourceProbePolicy::ProbeAsync)
        }
    }
}

fn source_probe_matches(
    probe: Win16Ole1SourceProbePolicy,
    command: Win16Ole1AsyncCommand,
) -> bool {
    match probe {
        Win16Ole1SourceProbePolicy::ProbeAsync => true,
        Win16Ole1SourceProbePolicy::ProbeCreateAsync => {
            (16..=21).contains(&command.wire_value())
        }
    }
}

pub(super) fn canonical_in(aliases: &[super::Win16Ole1ProtocolAlias], object_far: u32) -> u32 {
    aliases
        .iter()
        .find(|alias| alias.far == object_far && is_known_oleobject_protocol(&alias.protocol))
        .map(|alias| alias.canonical_object)
        .unwrap_or(object_far)
}

impl Win16State {
    pub(super) fn ole1_enum_objects(
        &self,
        document_value: i32,
        object_slot_far: u32,
        memory: &mut Memory,
    ) -> Win16Ole1Status {
        let document = Win16Ole1ClientDocHandle::from_guest_long(document_value as u32);
        if !self.ole1_client_documents.documents.contains_key(&document) {
            return OLE1_ERROR_HANDLE;
        }

        let pointer = match self.checked_ole1_pointer(
            object_slot_far,
            Access::Read,
            4,
            OLE1_ERROR_ADDRESS,
            memory,
        ) {
            Ok(pointer) => pointer,
            Err(status) => return status,
        };
        if let Err(status) = self.checked_ole1_pointer(
            object_slot_far,
            Access::Write,
            4,
            OLE1_ERROR_ADDRESS,
            memory,
        ) {
            return status;
        }

        let mut current_bytes = [0_u8; 4];
        if self
            .selectors
            .read(memory, pointer, &mut current_bytes)
            .is_err()
        {
            return OLE1_ERROR_ADDRESS;
        }
        let current_far = u32::from_le_bytes(current_bytes);
        if current_far != 0 && self.ole1_object_vtable(current_far, memory).is_err() {
            return OLE1_ERROR_OBJECT;
        }
        let next_far = match self
            .ole1_client_documents
            .next_object(document, current_far)
        {
            Ok(next) => next.unwrap_or(0),
            Err(status) => return status,
        };
        if self
            .selectors
            .write(memory, pointer, &next_far.to_le_bytes())
            .is_err()
        {
            return OLE1_ERROR_ADDRESS;
        }
        OLE1_OK
    }
}
