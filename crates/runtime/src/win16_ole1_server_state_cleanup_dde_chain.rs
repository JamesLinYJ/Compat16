impl Ole1ServerState {
    /// Retain all resources acquired by a registration attempt that failed
    /// before its server/document record became guest-visible. Cleanup is
    /// driven by the classic-DDE dispatcher; this function never attempts a
    /// best-effort host operation and then drops the only retry owner.
    pub(crate) fn begin_unpublished_cleanup(
        &mut self,
        owner: OwnerId,
        endpoint: Option<Win16HostClassicDdeEndpoint>,
        worker_generation: Option<u64>,
        atoms: Vec<u16>,
    ) -> Result<Ole1UnpublishedCleanupId, Ole1Status> {
        if atoms.is_empty()
            || atoms.iter().any(|atom| *atom == 0)
            || endpoint.is_some() != worker_generation.is_some()
            || endpoint.is_some_and(|endpoint| endpoint.0 == 0)
            || worker_generation.is_some_and(|generation| generation == 0)
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let id_value = self.next_unpublished_cleanup_id.ok_or(OLE_ERROR_MEMORY)?;
        self.next_unpublished_cleanup_id = id_value.checked_add(1);
        let id = Ole1UnpublishedCleanupId(id_value);
        let phase = if endpoint.is_some() {
            Ole1UnpublishedCleanupPhase::RetireEndpoint
        } else {
            Ole1UnpublishedCleanupPhase::DeleteAtom { index: 0 }
        };
        let entry = Ole1UnpublishedCleanup {
            id,
            owner,
            endpoint,
            worker_generation,
            atoms,
            phase,
            pending_events: Vec::new(),
            receipt_revision: 0,
            acknowledged_events: BTreeSet::new(),
        };
        if self.unpublished_cleanups.contains_key(&id) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        self.unpublished_cleanups.insert(id, entry);
        Ok(id)
    }

    pub(crate) fn pending_unpublished_cleanups(
        &self,
        owner: OwnerId,
    ) -> Vec<Ole1UnpublishedCleanup> {
        self.unpublished_cleanups
            .values()
            .filter(|entry| entry.owner == owner)
            .cloned()
            .collect()
    }

    pub(crate) fn unpublished_cleanup_for_endpoint(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<Option<Ole1UnpublishedCleanup>, Ole1Status> {
        let mut matching = self.unpublished_cleanups.values().filter(|entry| {
            entry.owner == owner
                && entry.endpoint == Some(endpoint)
                && entry.phase == Ole1UnpublishedCleanupPhase::RetireEndpoint
        });
        let Some(entry) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(Some(entry.clone()))
    }

    pub(crate) fn unpublished_cleanup_owns_event(
        &self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<bool, Ole1Status> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let mut matching = self.unpublished_cleanups.values().filter(|entry| {
            entry.owner == event.owner
                && entry.endpoint == Some(event.endpoint)
                && entry.worker_generation == Some(event.worker_generation)
                && entry.phase == Ole1UnpublishedCleanupPhase::RetireEndpoint
                && entry.pending_events.contains(&event.event_id)
        });
        if matching.next().is_some() && matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(self.unpublished_cleanups.values().any(|entry| {
            entry.owner == event.owner
                && entry.endpoint == Some(event.endpoint)
                && entry.worker_generation == Some(event.worker_generation)
                && entry.phase == Ole1UnpublishedCleanupPhase::RetireEndpoint
                && entry.pending_events.contains(&event.event_id)
        }))
    }

    pub(crate) fn next_unpublished_cleanup_action(
        &self,
        id: Ole1UnpublishedCleanupId,
    ) -> Result<Option<Ole1UnpublishedCleanupAction>, Ole1Status> {
        let Some(entry) = self.unpublished_cleanups.get(&id) else {
            return Ok(None);
        };
        let action = match entry.phase {
            Ole1UnpublishedCleanupPhase::RetireEndpoint => {
                if !entry.pending_events.is_empty() {
                    return Ok(None);
                }
                let endpoint = entry.endpoint.ok_or(OLE_ERROR_PROTOCOL)?;
                let worker_generation = entry.worker_generation.ok_or(OLE_ERROR_PROTOCOL)?;
                Some(Ole1UnpublishedCleanupAction::RetireEndpoint {
                    id,
                    owner: entry.owner,
                    endpoint,
                    worker_generation,
                    receipt_revision: entry.receipt_revision,
                })
            }
            Ole1UnpublishedCleanupPhase::DeleteAtom { index } => {
                entry.atoms.get(index).copied().map(|atom| {
                    Ole1UnpublishedCleanupAction::DeleteAtom {
                        id,
                        owner: entry.owner,
                        worker_generation: entry.worker_generation,
                        atom,
                        receipt_revision: entry.receipt_revision,
                    }
                })
            }
        };
        Ok(action)
    }

    /// Consume the exact RetireEndpoint terminal receipt. Pending IDs remain
    /// owned here until the dispatcher records their individual exact event
    /// acknowledgements. A non-retired receipt is never treated as success.
    pub(crate) fn record_unpublished_cleanup_retirement(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        expected_revision: u64,
        receipt: &Win16HostClassicDdeRetirementReceipt,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .unpublished_cleanups
            .get_mut(&id)
            .filter(|entry| {
                entry.owner == owner
                    && entry.endpoint == Some(receipt.endpoint)
                    && entry.worker_generation == Some(receipt.worker_generation)
                    && entry.phase == Ole1UnpublishedCleanupPhase::RetireEndpoint
                    && entry.receipt_revision == expected_revision
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if receipt.owner != owner
            || receipt.endpoint.0 == 0
            || receipt.worker_generation == 0
            || !receipt.retained_callbacks.is_empty()
            || !receipt.retained_transfers.is_empty()
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let mut unique = BTreeSet::new();
        if receipt.pending_events.iter().any(|event| {
            event.0 == 0 || !unique.insert(*event) || entry.acknowledged_events.contains(event)
        }) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if entry.pending_events.iter().any(|previous| {
            !receipt.pending_events.contains(previous)
                && !entry.acknowledged_events.contains(previous)
        }) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if receipt.retired {
            if !receipt.pending_events.is_empty() {
                return Err(OLE_ERROR_PROTOCOL);
            }
            entry.pending_events.clear();
            entry.phase = Ole1UnpublishedCleanupPhase::DeleteAtom { index: 0 };
        } else if receipt.pending_events.is_empty() {
            return Err(OLE_ERROR_PROTOCOL);
        } else {
            entry.pending_events.clone_from(&receipt.pending_events);
        }
        entry.receipt_revision = entry
            .receipt_revision
            .checked_add(1)
            .ok_or(OLE_ERROR_MEMORY)?;
        Ok(())
    }

    /// Mark only the exact queued event acknowledged by the host. Event ACK
    /// changes mailbox delivery state, not the endpoint/atom retirement phase.
    pub(crate) fn acknowledge_unpublished_cleanup_event(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<bool, Ole1Status> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let Some(entry) = self.unpublished_cleanups.get_mut(&id) else {
            return Ok(false);
        };
        if entry.owner != event.owner
            || entry.endpoint != Some(event.endpoint)
            || entry.worker_generation != Some(event.worker_generation)
            || entry.phase != Ole1UnpublishedCleanupPhase::RetireEndpoint
        {
            return Ok(false);
        }
        if entry.acknowledged_events.contains(&event.event_id) {
            return Ok(true);
        }
        if !entry.pending_events.contains(&event.event_id) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        entry.pending_events.retain(|id| *id != event.event_id);
        entry.acknowledged_events.insert(event.event_id);
        entry.receipt_revision = entry
            .receipt_revision
            .checked_add(1)
            .ok_or(OLE_ERROR_MEMORY)?;
        Ok(true)
    }

    /// Advance atom retirement only after the matching host delete call has
    /// returned its exact success result.
    pub(crate) fn record_unpublished_cleanup_atom_deleted(
        &mut self,
        id: Ole1UnpublishedCleanupId,
        owner: OwnerId,
        worker_generation: Option<u64>,
        expected_revision: u64,
        atom: u16,
    ) -> Result<bool, Ole1Status> {
        let entry = self
            .unpublished_cleanups
            .get_mut(&id)
            .filter(|entry| {
                entry.owner == owner
                    && entry.worker_generation == worker_generation
                    && entry.receipt_revision == expected_revision
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        let Ole1UnpublishedCleanupPhase::DeleteAtom { index } = entry.phase else {
            return Err(OLE_ERROR_PROTOCOL);
        };
        if entry.atoms.get(index).copied() != Some(atom) || atom == 0 {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let next_index = index.checked_add(1).ok_or(OLE_ERROR_MEMORY)?;
        entry.receipt_revision = entry
            .receipt_revision
            .checked_add(1)
            .ok_or(OLE_ERROR_MEMORY)?;
        if next_index == entry.atoms.len() {
            self.unpublished_cleanups.remove(&id);
            Ok(true)
        } else {
            entry.phase = Ole1UnpublishedCleanupPhase::DeleteAtom { index: next_index };
            Ok(false)
        }
    }

    pub(crate) fn begin_dde_release_chain(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        first_target: Ole1ReleaseTarget,
    ) -> Result<(), Ole1Status> {
        if event.conversation.is_none() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if let Some(existing) = self.dde_release_chains.iter().find(|entry| {
            entry.event.owner == event.owner
                && entry.event.endpoint == event.endpoint
                && entry.event.event_id == event.event_id
        }) {
            return (existing.event == *event && existing.next_target == Some(first_target))
                .then_some(())
                .ok_or(OLE_ERROR_PROTOCOL);
        }
        self.dde_release_chains
            .try_reserve(1)
            .map_err(|_| OLE_ERROR_MEMORY)?;
        self.dde_release_chains.push(Ole1ServerDdeReleaseChain {
            event: event.clone(),
            next_target: Some(first_target),
            pending_events: Vec::new(),
            event_acknowledged: false,
        });
        Ok(())
    }

    pub(crate) fn dde_release_chain_for_event(
        &self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<Option<Ole1ServerDdeReleaseChain>, Ole1Status> {
        let Some(entry) = self.dde_release_chains.iter().find(|entry| {
            entry.event.owner == event.owner
                && entry.event.endpoint == event.endpoint
                && entry.event.event_id == event.event_id
        }) else {
            return Ok(None);
        };
        if entry.event != *event {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(Some(entry.clone()))
    }

    pub(crate) fn dde_release_chain_for_pending_event(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<Option<Ole1ServerDdeReleaseChain>, Ole1Status> {
        let mut matching = self.dde_release_chains.iter().filter(|entry| {
            entry.event.owner == owner
                && entry.next_target.is_some_and(|target| {
                    release_target_endpoint(target) == endpoint
                        && release_target_worker_generation(target) == entry.event.worker_generation
                })
                && entry.pending_events.contains(&event_id)
        });
        let Some(entry) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(Some(entry.clone()))
    }

    pub(crate) fn dde_release_chain_owns_target(
        &self,
        owner: OwnerId,
        target: Ole1ReleaseTarget,
    ) -> Result<bool, Ole1Status> {
        let mut matching = self
            .dde_release_chains
            .iter()
            .filter(|entry| entry.event.owner == owner && entry.next_target == Some(target));
        if matching.next().is_some() && matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        Ok(self
            .dde_release_chains
            .iter()
            .any(|entry| entry.event.owner == owner && entry.next_target == Some(target)))
    }

    pub(crate) fn advance_dde_release_chain(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        completed_target: Ole1ReleaseTarget,
        next_target: Option<Ole1ReleaseTarget>,
    ) -> Result<(), Ole1Status> {
        let entry = self
            .dde_release_chains
            .iter_mut()
            .find(|entry| {
                entry.event.owner == event.owner
                    && entry.event.endpoint == event.endpoint
                    && entry.event.event_id == event.event_id
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if entry.event != *event || entry.next_target != Some(completed_target) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        entry.next_target = next_target;
        entry.pending_events.clear();
        Ok(())
    }

    pub(crate) fn record_dde_release_pending_events(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        target: Ole1ReleaseTarget,
        pending_events: Vec<Win16ClassicDdeEventId>,
    ) -> Result<(), Ole1Status> {
        let journal = self
            .release_completion_for_target(event.owner, target)
            .ok_or(OLE_ERROR_HANDLE)?;
        let wait = self
            .release_pending_events
            .get(&journal.callback_id)
            .filter(|wait| {
                wait.owner == event.owner
                    && wait.target == target
                    && wait.worker_generation == event.worker_generation
                    && wait.pending_events == pending_events
            })
            .ok_or(OLE_ERROR_PROTOCOL)?;
        let _ = wait;
        let entry = self
            .dde_release_chains
            .iter_mut()
            .find(|entry| {
                entry.event.owner == event.owner
                    && entry.event.endpoint == event.endpoint
                    && entry.event.event_id == event.event_id
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        if entry.event != *event || entry.next_target != Some(target) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        entry.pending_events = pending_events;
        Ok(())
    }

    pub(crate) fn acknowledge_dde_release_pending_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<Option<Ole1ServerDdeReleaseChain>, Ole1Status> {
        if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let mut matching = self
            .dde_release_chains
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.event.owner == event.owner
                    && entry.next_target.is_some_and(|target| {
                        release_target_endpoint(target) == event.endpoint
                            && release_target_worker_generation(target) == event.worker_generation
                    })
                    && entry.pending_events.contains(&event.event_id)
            });
        let Some((index, original)) = matching.next() else {
            return Ok(None);
        };
        let original = original.clone();
        if matching.next().is_some() {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let target = original.next_target.ok_or(OLE_ERROR_PROTOCOL)?;
        let journal = self
            .release_completion_for_target(event.owner, target)
            .ok_or(OLE_ERROR_HANDLE)?;
        if self.acknowledge_release_event(journal.callback_id, event)? != Some(journal.callback_id)
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let entry = self
            .dde_release_chains
            .get_mut(index)
            .ok_or(OLE_ERROR_HANDLE)?;
        if entry.event != original.event || entry.next_target != Some(target) {
            return Err(OLE_ERROR_PROTOCOL);
        }
        entry
            .pending_events
            .retain(|event_id| *event_id != event.event_id);
        if entry.event.event_id == event.event_id && entry.event.endpoint == event.endpoint {
            entry.event_acknowledged = true;
        }
        Ok(Some(entry.clone()))
    }

    pub(crate) fn finish_dde_release_chain(
        &mut self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<bool, Ole1Status> {
        let Some(index) = self.dde_release_chains.iter().position(|entry| {
            entry.event.owner == event.owner
                && entry.event.endpoint == event.endpoint
                && entry.event.event_id == event.event_id
        }) else {
            return Ok(false);
        };
        let entry = &self.dde_release_chains[index];
        if entry.event != *event
            || entry.next_target.is_some()
            || !entry.event_acknowledged
            || !entry.pending_events.is_empty()
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        self.dde_release_chains.remove(index);
        Ok(true)
    }
}
