use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn retry_ole1_dde_object_proxy_retirements(
        &mut self,
        owner: OwnerId,
    ) -> Result<(), RuntimeError> {
        if owner.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "DDE object-proxy retirement requires a valid task owner",
            ));
        }
        let mut index = 0;
        while index
            < self
                .ole1_client_documents
                .pending_dde_object_proxy_retirements
                .len()
        {
            let pending = self
                .ole1_client_documents
                .pending_dde_object_proxy_retirements[index];
            if pending.owner != owner {
                index += 1;
                continue;
            }
            if pending.owner.0 == 0 {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "pending DDE object-proxy retirement lost its exact owner",
                ));
            }
            let mut unlocks = pending.unlocks_pending;
            while unlocks != 0 {
                let previous = unlocks;
                unlocks = self
                    .heap
                    .unlock(pending.allocation, &mut self.selectors)
                    .map_err(crate::runtime_error)
                    .map_err(|error| error.with_context("retry DDE object-proxy unlock"))?;
                if unlocks >= previous {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retrying DDE object-proxy unlock made no progress",
                    ));
                }
                self.ole1_client_documents
                    .pending_dde_object_proxy_retirements[index]
                    .unlocks_pending = unlocks;
            }
            self.heap
                .free(pending.allocation, &mut self.selectors)
                .map_err(crate::runtime_error)
                .map_err(|error| error.with_context("retry DDE object-proxy allocation free"))?;
            self.ole1_client_documents
                .pending_dde_object_proxy_retirements
                .remove(index);
        }
        if self
            .ole1_client_documents
            .dde_object_proxies
            .iter()
            .any(|record| {
                record.owner == owner
                    && record.client_proxy_retire_requested
                    && !record.client_proxy_retired
            })
            || self
                .ole1_client_documents
                .pending_dde_client_proxy_retirements
                .iter()
                .any(|pending| pending.owner == owner)
        {
            // The shared proxy retirement queue is keyed by its exact GlobalHandle.
            // The DDE object record retains the owner/proxy/allocation tuple until
            // this retry and the later exact terminal consume can prove it freed.
            self.retry_pending_ole1_proxy_retirements()?;
        }
        let mut index = 0;
        while index
            < self
                .ole1_client_documents
                .pending_dde_client_proxy_retirements
                .len()
        {
            let pending = self
                .ole1_client_documents
                .pending_dde_client_proxy_retirements[index];
            if pending.owner != owner {
                index += 1;
                continue;
            }
            if self.try_retire_ole1_dde_client_proxy(pending.client_proxy_id, pending.allocation)? {
                self.ole1_client_documents
                    .pending_dde_client_proxy_retirements
                    .remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    /// Ask the shared client-proxy journal to retire this exact binding, then
    /// prove that neither its binding nor exact allocation lease remains.
    /// `false` means a callback still pins it or its free is awaiting retry.
    pub(in crate::win16_runtime) fn try_retire_ole1_dde_client_proxy(
        &mut self,
        client_proxy_id: Win16Ole1ClientProxyId,
        allocation: GlobalHandle,
    ) -> Result<bool, RuntimeError> {
        if let Some(binding) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == client_proxy_id)
        {
            if binding.allocation != allocation {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE client-proxy retirement changed its exact allocation",
                ));
            }
            if !binding.retire_requested {
                self.retire_ole1_client_operation_proxy(client_proxy_id)?;
            }
        }
        if self
            .ole1_client_documents
            .pending_proxy_retirements
            .iter()
            .any(|pending| pending.allocation == allocation)
            || self
                .ole1_client_documents
                .pending_native_object_proxy_retirements
                .iter()
                .any(|pending| pending.client_proxy_id == Some(client_proxy_id))
        {
            return Ok(false);
        }
        if let Some(binding) = self
            .ole1_client_documents
            .client_proxies
            .iter()
            .find(|binding| binding.id == client_proxy_id)
        {
            if binding.allocation != allocation || !binding.retire_requested {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE client-proxy retirement no longer matches its requested binding",
                ));
            }
            return Ok(false);
        }
        match self.heap.info(allocation) {
            Ok(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE client-proxy binding disappeared while its exact allocation remains live",
            )),
            Err(win16_abi::Win16Error::InvalidHandle | win16_abi::Win16Error::StaleHandle) => Ok(true),
            Err(error) => Err(crate::runtime_error(error)
                .with_context("query exact DDE client-proxy allocation retirement")),
        }
    }

    pub(in crate::win16_runtime) fn track_ole1_dde_client_proxy_retirement(
        &mut self,
        owner: OwnerId,
        client_proxy_id: Win16Ole1ClientProxyId,
        allocation: GlobalHandle,
    ) -> Result<(), RuntimeError> {
        if owner.0 == 0 || client_proxy_id.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE client-proxy retirement lost its exact owner or identity",
            ));
        }
        if self
            .ole1_client_documents
            .pending_dde_client_proxy_retirements
            .iter()
            .any(|entry| entry.client_proxy_id == client_proxy_id)
        {
            let existing = self
                .ole1_client_documents
                .pending_dde_client_proxy_retirements
                .iter()
                .find(|entry| entry.client_proxy_id == client_proxy_id)
                .copied()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE client-proxy retirement disappeared during duplicate check",
                    )
                })?;
            if existing.owner == owner && existing.allocation == allocation {
                return Ok(());
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE client-proxy retirement identity was reused for another owner or allocation",
            ));
        }
        self.ole1_client_documents
            .pending_dde_client_proxy_retirements
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact DDE client-proxy retirement lease",
                    error,
                )
            })?;
        self.ole1_client_documents
            .pending_dde_client_proxy_retirements
            .push(Win16Ole1PendingDdeClientProxyRetirement {
                owner,
                client_proxy_id,
                allocation,
            });
        Ok(())
    }

    /// Retire the checked guest OLEOBJECT only after its DDE endpoint and both
    /// conversations have exact host receipts. Each local step is journaled
    /// so an allocation/proxy cleanup failure cannot make Release look done.
    pub(in crate::win16_runtime) fn retire_ole1_dde_object_proxy(
        &mut self,
        owner: OwnerId,
        id: u64,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self
            .ole1_client_documents
            .dde_object_proxies
            .iter()
            .position(|record| record.id == id && record.owner == owner)
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "exact DDE OLE1 object proxy disappeared before Release retirement",
            ));
        };
        let record = self.ole1_client_documents.dde_object_proxies[index].clone();
        if !record.membership_retired {
            let binding = self
                .ole1_client_documents
                .proxy_for_object(record.object_far);
            if binding != Some(record.client_proxy_id) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE OLE1 object membership changed before Release retirement",
                ));
            }
            let removed = self.ole1_client_documents.remove_object(record.object_far);
            if removed != Some(record.client_proxy_id) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE OLE1 Release removed a different client proxy association",
                ));
            }
            self.ole1_client_documents.dde_object_proxies[index].membership_retired = true;
        }
        if !record.allocation_retired {
            self.heap
                .free(record.allocation, &mut self.selectors)
                .map_err(crate::runtime_error)
                .map_err(|error| error.with_context("free released DDE OLE1 object allocation"))?;
            self.ole1_client_documents.dde_object_proxies[index].allocation_retired = true;
        }
        if !record.client_proxy_retire_requested {
            self.ole1_client_documents.dde_object_proxies[index].client_proxy_retire_requested =
                true;
        }
        let retired = self.try_retire_ole1_dde_client_proxy(
            record.client_proxy_id,
            record.client_proxy_allocation,
        )?;
        if !retired {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DDE OLE1 client callback proxy retirement is pinned or awaiting exact allocation cleanup",
            ));
        }
        self.ole1_client_documents.dde_object_proxies[index].client_proxy_retired = true;
        self.ole1_client_documents.dde_object_proxies.remove(index);
        Ok(())
    }
}
