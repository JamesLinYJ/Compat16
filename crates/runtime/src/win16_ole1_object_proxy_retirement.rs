//! Native-owner-proven membership and exact guest allocation retirement.

use super::*;

impl Win16State {
    /// After the STA's exact owner receipt, detach every native-backed OLE1
    /// guest object and transfer its guest allocations to an owner-tagged
    /// retry queue. Native references were released by the host's single
    /// owner-table shutdown; this method never issues another COM Release.
    pub(in crate::win16_runtime) fn retire_native_com_owner_proxy_state(
        &mut self,
        receipt: crate::Win16ComHostShutdownReceipt,
    ) -> Result<(), RuntimeError> {
        let owner = receipt.owner;
        if !owner.is_valid() || !receipt.callback_ingress_closed || !receipt.native_objects_shutdown {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 proxy retirement lacks an exact complete COM-owner receipt",
            ));
        }
        let mut records = Vec::new();
        let record_count = self.ole1_client_documents.native_object_proxies.len();
        records.try_reserve_exact(record_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact native OLE1 proxy shutdown snapshot",
                error,
            )
        })?;
        records.extend(
            self.ole1_client_documents
                .native_object_proxies
                .iter()
                .filter(|record| record.object.owner == owner)
                .copied(),
        );
        // Only the live proxy registry owns a native guest allocation. A
        // retained method record may describe a proxy already queued or freed
        // by Release or by an earlier successful owner-retirement iteration.
        for record in records {
            validate_native_object_record_owner(record, owner)?;
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .try_reserve(2)
                .map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve both exact COM object/client allocation retirements before detaching membership",
                    error,
                ))?;
            self.ole1_client_documents.finish_operation(record.operation_id);
            self.ole1_client_documents.remove_native_object_membership(
                record.document,
                record.object_far,
                record.client_far,
                record.client_proxy_id,
            )?;
            self.queue_com_client_proxy_allocation(
                owner,
                record.client_proxy_id,
                record.client_proxy_allocation,
                record.operation_id,
            )?;
            self.queue_owner_proxy_allocation(
                owner,
                record.allocation,
                Some(record.id),
                None,
                0,
            )?;
            self.ole1_client_documents
                .native_object_proxies
                .retain(|candidate| candidate.id != record.id);
        }

        let pending_client_count = self
            .ole1_client_documents
            .pending_creations
            .iter()
            .filter(|sequence| sequence.owner == owner)
            .count()
            + self
                .ole1_client_documents
                .pending_object_methods
                .iter()
                .filter(|sequence| sequence.owner == owner)
                .count();
        let mut pending_clients = Vec::new();
        pending_clients
            .try_reserve_exact(pending_client_count)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact pending OLE1 client-proxy retirement snapshot",
                    error,
                )
            })?;
        pending_clients.extend(
            self.ole1_client_documents
                .pending_creations
                .iter()
                .filter(|sequence| sequence.owner == owner)
                .map(|sequence| {
                    (
                        sequence.operation_id,
                        sequence.client_proxy_id,
                        sequence.client_proxy_allocation,
                    )
                }),
        );
        // Release may have retired the native allocation before client-proxy
        // retirement failed. Keep its exact client identity for retry without
        // reconstructing ownership of the former native allocation.
        pending_clients.extend(
            self.ole1_client_documents
                .pending_object_methods
                .iter()
                .filter(|sequence| sequence.owner == owner)
                .map(|sequence| {
                    (
                        sequence.record.operation_id,
                        sequence.record.client_proxy_id,
                        sequence.record.client_proxy_allocation,
                    )
                }),
        );
        for (operation_id, proxy_id, allocation) in pending_clients {
            self.ole1_client_documents.finish_operation(operation_id);
            self.queue_com_client_proxy_allocation(owner, proxy_id, allocation, operation_id)?;
        }
        self.ole1_client_documents
            .pending_creations
            .retain(|sequence| sequence.owner != owner);
        self.ole1_client_documents
            .pending_object_methods
            .retain(|sequence| sequence.owner != owner);
        Ok(())
    }

    fn queue_com_client_proxy_allocation(
        &mut self,
        owner: crate::Win16ComHostOwnerIdentity,
        proxy_id: Win16Ole1ClientProxyId,
        allocation: GlobalHandle,
        operation_id: Win16Ole1OperationId,
    ) -> Result<(), RuntimeError> {
        if let Some(retirement) = self
            .ole1_client_documents
            .pending_native_object_proxy_retirements
            .iter()
            .find(|retirement| retirement.client_proxy_id == Some(proxy_id))
        {
            if retirement.owner == owner && retirement.allocation == allocation {
                return Ok(());
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM client-proxy retirement identity was reused by another allocation",
            ));
        }
        if let Some(index) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .position(|binding| binding.id == proxy_id)
        {
            let binding = self.ole1_client_documents.client_proxies[index];
            if binding.operation_id != Some(operation_id)
                || binding.allocation != allocation
                || binding.object.is_some()
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "COM client proxy is not the exact detached operation-specific binding",
                ));
            }
            if self.ole1_client_documents.release_deliveries.iter().any(|delivery| {
                delivery.removed_object_proxy == Some(proxy_id)
            }) || self.ole1_client_documents.documents.values().any(|document| {
                document.object_proxy_bindings.iter().any(|(_, id)| *id == proxy_id)
                    || document.pending_operations.iter().any(|operation| {
                        matches!(operation,
                            super::super::Win16Ole1PendingOperation::Creation { proxy_id: Some(id), .. }
                                if *id == proxy_id)
                    })
            }) {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "COM client proxy remains owned by a document operation or release delivery",
                ));
            }
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve exact COM client-proxy allocation retirement",
                        error,
                    )
                })?;
            self.ole1_client_documents.client_proxies.remove(index);
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner,
                    allocation,
                    native_proxy_id: None,
                    client_proxy_id: Some(proxy_id),
                    unlocks_pending: 0,
                });
            return Ok(());
        }

        // A callback teardown may already have moved this exact handle to the
        // generic OLE1 proxy queue. Transfer that single owner rather than
        // duplicating or losing the allocation receipt.
        if let Some(index) = self
            .ole1_client_documents
            .pending_proxy_retirements
            .iter()
            .position(|retirement| retirement.allocation == allocation)
        {
            let retirement = self.ole1_client_documents.pending_proxy_retirements[index];
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve transfer of exact COM client-proxy allocation ownership",
                        error,
                    )
                })?;
            self.ole1_client_documents
                .pending_proxy_retirements
                .remove(index);
            self.ole1_client_documents
                .pending_native_object_proxy_retirements
                .push(Win16Ole1PendingObjectProxyRetirement {
                    owner,
                    allocation,
                    native_proxy_id: None,
                    client_proxy_id: Some(proxy_id),
                    unlocks_pending: u16::from(retirement.unlock_pending),
                });
            return Ok(());
        }

        // No binding or retirement remains for this never-reused proxy ID;
        // its exact allocation was already freed by the existing OLE1 path.
        Ok(())
    }

    fn queue_owner_proxy_allocation(
        &mut self,
        owner: crate::Win16ComHostOwnerIdentity,
        allocation: GlobalHandle,
        native_proxy_id: Option<u64>,
        client_proxy_id: Option<Win16Ole1ClientProxyId>,
        unlocks_pending: u16,
    ) -> Result<(), RuntimeError> {
        if native_proxy_id.is_none() && client_proxy_id.is_none() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM proxy retirement lacks a stable guest allocation identity",
            ));
        }
        if let Some(existing) = self
            .ole1_client_documents
            .pending_native_object_proxy_retirements
            .iter()
            .find(|retirement| {
                retirement.native_proxy_id == native_proxy_id
                    && retirement.client_proxy_id == client_proxy_id
            })
        {
            if existing.owner == owner && existing.allocation == allocation {
                return Ok(());
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM proxy retirement identity was reused by another allocation",
            ));
        }
        self.ole1_client_documents
            .pending_native_object_proxy_retirements
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact COM proxy allocation retirement",
                    error,
                )
            })?;
        self.ole1_client_documents
            .pending_native_object_proxy_retirements
            .push(Win16Ole1PendingObjectProxyRetirement {
                owner,
                allocation,
                native_proxy_id,
                client_proxy_id,
                unlocks_pending,
            });
        Ok(())
    }


}

impl Win16Ole1ClientDocuments {
    pub(in crate::win16_runtime::ole1) fn remove_native_object_membership(
        &mut self,
        document: Win16Ole1ClientDocHandle,
        object_far: u32,
        client_far: u32,
        proxy_id: Win16Ole1ClientProxyId,
    ) -> Result<(), RuntimeError> {
        let canonical = self.canonical_object(object_far);
        if canonical != object_far {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 object identity unexpectedly resolves through a protocol alias",
            ));
        }
        let binding_index = self
            .client_proxies
            .iter()
            .position(|binding| binding.id == proxy_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "native OLE1 object lost its exact client proxy binding",
                )
            })?;
        let Some(document_state) = self.documents.get(&document) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 object lost its exact client document before owner retirement",
            ));
        };
        let object_count = document_state.objects.iter().filter(|object| **object == object_far).count();
        let client_identity = (object_far, client_far);
        let client_count = document_state
            .object_clients
            .iter()
            .filter(|entry| **entry == client_identity)
            .count();
        let proxy_identity = (object_far, proxy_id);
        let proxy_count = document_state
            .object_proxy_bindings
            .iter()
            .filter(|entry| **entry == proxy_identity)
            .count();
        let expected_object = Some((document, object_far));
        let binding_object = self.client_proxies[binding_index].object;
        let absent = object_count == 0 && client_count == 0 && proxy_count == 0;
        if absent && binding_object.is_none() {
            return Ok(());
        }
        if self.owner_of(object_far) != Some((document, object_far)) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 object is owned by another document during exact retirement",
            ));
        }
        if object_count != 1
            || client_count != 1
            || proxy_count != 1
            || binding_object != expected_object
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native OLE1 object membership differs from its exact document/client/proxy identities",
            ));
        }
        // This helper owns only native COM membership. All labels above were
        // checked before mutation; allocation ownership is transferred by the
        // caller to its exact owner queue after the native shutdown receipt.
        let document_state = self.documents.get_mut(&document).expect("native document checked");
        document_state.objects.retain(|object| *object != object_far);
        document_state.object_clients.retain(|entry| *entry != client_identity);
        document_state.object_proxy_bindings.retain(|entry| *entry != proxy_identity);
        self.client_proxies[binding_index].object = None;
        self.protocol_aliases.retain(|alias| {
            alias.document != Some(document) || alias.canonical_object != object_far
        });
        Ok(())
    }
}

fn validate_native_object_record_owner(
    record: Win16Ole1NativeObjectProxyRecord,
    owner: crate::Win16ComHostOwnerIdentity,
) -> Result<(), RuntimeError> {
    let interfaces = [
        Some(record.object),
        record.storage,
        Some(record.client_site),
        Some(record.advise_sink),
    ];
    if interfaces.into_iter().flatten().all(|interface| {
        interface.owner == owner && interface.object.0 != 0
    }) {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native OLE1 proxy contains an interface from another COM owner",
        ))
    }
}
