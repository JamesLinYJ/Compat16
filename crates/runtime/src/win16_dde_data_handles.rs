//! DDEML guest data tokens, transfer guards, and AccessData leases.

use super::*;

impl Win16DdeState {
    /// Pending transfer guard count used by the terminal owner-retirement
    /// barrier. A DDE operation source cannot retire while any exact guard
    /// remains attached to its runtime owner.
    pub fn pending_data_transfer_guard_count(&self) -> usize {
        self.data_transfer_guards.len()
    }

    pub fn add_data(
        &mut self,
        instance: u32,
        host: Win16HostDdeData,
        origin: Win16DdeDataOrigin,
    ) -> Option<u32> {
        if !self.instances.contains_key(&instance) {
            return None;
        }
        if let Some((guest, value)) = self
            .data
            .iter_mut()
            .find(|(_, value)| value.instance == instance && value.host == host && value.available)
        {
            value.origin = merge_data_origin(value.origin, origin);
            return Some(*guest);
        }
        let token = self.allocate_token()?;
        self.data.insert(
            token,
            DdeDataRecord {
                instance,
                host,
                origin,
                available: true,
                transferred: false,
                callback_references: 0,
                guest_freed: false,
            },
        );
        Some(token)
    }
    pub fn add_created_data(
        &mut self,
        instance: u32,
        host: Win16HostDdeData,
        retain_after_transfer: bool,
    ) -> Option<u32> {
        self.add_data(
            instance,
            host,
            Win16DdeDataOrigin::Created {
                retain_after_transfer,
            },
        )
    }
    pub fn add_callback_data(&mut self, instance: u32, host: Win16HostDdeData) -> Option<u32> {
        self.add_data(instance, host, Win16DdeDataOrigin::CallbackBorrowed)
    }
    pub fn add_client_result_data(&mut self, instance: u32, host: Win16HostDdeData) -> Option<u32> {
        self.add_data(instance, host, Win16DdeDataOrigin::ClientResult)
    }
    pub fn host_data(&self, guest: u32) -> Option<Win16HostDdeData> {
        self.data
            .get(&guest)
            .filter(|value| value.available)
            .map(|value| value.host)
    }
    /// Resolve only to balance an AccessData lease that predates a consumed
    /// transaction. A consumed token is not usable by any new data operation.
    pub fn host_data_for_unaccess(&self, guest: u32) -> Option<Win16HostDdeData> {
        let record = self.data.get(&guest)?;
        let access = self.access_blocks.get(&guest)?;
        (access.references != 0).then_some(record.host)
    }
    pub fn instance_for_data(&self, guest: u32) -> Option<u32> {
        self.data.get(&guest).map(|value| value.instance)
    }
    pub fn data_origin(&self, guest: u32) -> Option<Win16DdeDataOrigin> {
        self.data.get(&guest).map(|value| value.origin)
    }
    pub fn can_free_data(&self, guest: u32) -> Option<bool> {
        self.data
            .get(&guest)
            .filter(|value| value.available)
            .map(|value| match value.origin {
                Win16DdeDataOrigin::Created {
                    retain_after_transfer,
                } => !value.transferred || retain_after_transfer,
                Win16DdeDataOrigin::ClientResult => !value.transferred,
                Win16DdeDataOrigin::CallbackBorrowed => false,
            })
    }
    pub fn data_is_writable(&self, guest: u32) -> Option<bool> {
        self.data
            .get(&guest)
            .filter(|value| value.available)
            .map(|value| {
                matches!(value.origin, Win16DdeDataOrigin::Created { .. }) && !value.transferred
            })
    }
    pub fn mark_data_transferred(&mut self, guest: u32) -> Option<()> {
        let record = self.data.get_mut(&guest)?;
        if let Win16DdeDataOrigin::Created {
            retain_after_transfer,
        } = record.origin
        {
            record.transferred = true;
            if !retain_after_transfer {
                record.available = false;
            }
        }
        Some(())
    }
    pub fn data_transfer_state(&self, guest: u32) -> Option<bool> {
        self.data.get(&guest).map(|record| record.transferred)
    }
    /// Allocate an operation-local nonce for a potentially reentrant
    /// ClientTransaction. The guard is removed exactly once at completion.
    pub fn allocate_data_transfer_guard(&mut self) -> Option<u64> {
        let start = self.next_data_transfer_guard.max(1);
        let mut guard = start;
        loop {
            if !self.data_transfer_guards.contains_key(&guard) {
                self.next_data_transfer_guard = guard.wrapping_add(1).max(1);
                return Some(guard);
            }
            guard = guard.wrapping_add(1).max(1);
            if guard == start {
                return None;
            }
        }
    }

    pub fn register_data_transfer_guard(
        &mut self,
        guest: u32,
        guard_id: u64,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
        previously_transferred: bool,
    ) -> Option<()> {
        let record = self.data.get(&guest).filter(|record| {
            record.available
                && record.host == host
                && record.instance == owner
                && record.origin == origin
                && record.transferred == previously_transferred
        })?;
        let _ = record;
        if guard_id == 0 || self.data_transfer_guards.contains_key(&guard_id) {
            return None;
        }
        self.data_transfer_guards.insert(
            guard_id,
            PendingDdeDataTransferGuard {
                guest_data: guest,
                host_data: host,
                owner,
                origin,
                previously_available: true,
                previously_transferred,
                guest_free_seen: false,
                instance_uninitialized: false,
                begun: false,
            },
        );
        Some(())
    }

    /// Begin the actual native transfer after all preflight work has passed.
    /// Non-APPOWNED Created handles stop resolving for new guest data calls
    /// immediately, while the exact record remains for the operation receipt.
    /// Copy-source origins are never mutated by a copied-input transaction.
    pub fn begin_data_transfer(
        &mut self,
        guest: u32,
        guard_id: u64,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<()> {
        let guard = self.data_transfer_guards.get(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
            || guard.begun
        {
            return None;
        }
        let record = self.data.get_mut(&guest)?;
        if !record.available
            || record.host != host
            || record.instance != owner
            || record.origin != origin
            || record.transferred != guard.previously_transferred
        {
            return None;
        }
        if let Win16DdeDataOrigin::Created {
            retain_after_transfer,
        } = origin
        {
            record.transferred = true;
            if !retain_after_transfer {
                record.available = false;
            }
        }
        self.data_transfer_guards.get_mut(&guard_id)?.begun = true;
        Some(())
    }

    /// Restore a NotPassed input's exact pre-call view. A successful nested
    /// guest FreeData is stronger evidence and deliberately prevents alias
    /// resurrection, even when the native operation later reports NotPassed.
    pub fn restore_data_transfer(
        &mut self,
        guard_id: u64,
        guest: u32,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<()> {
        let guard = *self.data_transfer_guards.get(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
        {
            return None;
        }
        if guard.guest_free_seen || guard.instance_uninitialized {
            // A nested FreeData or successful owner Uninitialize retired the
            // captured identity. A NotPassed receipt must not recreate it.
            return Some(());
        }
        let record = self.data.get_mut(&guest)?;
        if record.host != host || record.instance != owner || record.origin != origin {
            return None;
        }
        record.available = guard.previously_available;
        record.transferred = guard.previously_transferred;
        Some(())
    }

    /// Cancel a guard when preparation/native entry is abandoned before any
    /// transfer receipt can be produced.
    pub fn cancel_data_transfer_guard(&mut self, guard_id: u64) -> Option<()> {
        self.data_transfer_guards.remove(&guard_id).map(|_| ())
    }

    /// Bind global native-owner shutdown evidence to this exact guest-side
    /// operation before consuming its transfer guard. This does not remove
    /// the data record or its AccessData allocation; final DDE teardown owns
    /// those resources.
    pub fn mark_transfer_guard_instance_uninitialized(
        &mut self,
        guard_id: u64,
        guest: u32,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<()> {
        let guard = self.data_transfer_guards.get_mut(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
            || !guard.begun
        {
            return None;
        }
        guard.instance_uninitialized = true;
        Some(())
    }

    /// Check that an operation still owns the exact hidden token identity.
    /// This does not make the token available to guest Get/Access/Transaction.
    pub fn data_transfer_guard_matches(
        &self,
        guard_id: u64,
        guest: u32,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<bool> {
        let guard = self.data_transfer_guards.get(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
        {
            return Some(false);
        }
        let record_matches = self.data.get(&guest).is_some_and(|record| {
            record.host == host && record.instance == owner && record.origin == origin
        });
        Some(record_matches || guard.guest_free_seen || guard.instance_uninitialized)
    }

    pub fn data_transfer_guard_retirement_state(
        &self,
        guard_id: u64,
        guest: u32,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<(bool, bool, bool, bool)> {
        let guard = self.data_transfer_guards.get(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
        {
            return None;
        }
        Some((
            guard.previously_transferred,
            guard.guest_free_seen,
            guard.instance_uninitialized,
            guard.begun,
        ))
    }

    /// Record retirement only after the native guest FreeData operation
    /// succeeded. Every suspended transfer of the exact same identity gets
    /// its own evidence bit; unrelated cleanup never writes this evidence.
    pub fn remove_data_after_guest_free(
        &mut self,
        guest: u32,
    ) -> Result<Option<Win16DdeRemovedData>, Win16DdeCallbackEventError> {
        let captured = self
            .data
            .get(&guest)
            .copied()
            .ok_or(Win16DdeCallbackEventError::InvalidState)?;
        for guard in self.data_transfer_guards.values_mut().filter(|guard| {
            guard.guest_data == guest
                && guard.host_data == captured.host
                && guard.owner == captured.instance
                && guard.origin == captured.origin
        }) {
            guard.guest_free_seen = true;
        }
        let record = self
            .data
            .get_mut(&guest)
            .ok_or(Win16DdeCallbackEventError::InvalidState)?;
        record.available = false;
        record.guest_freed = true;
        Ok(self.release_unowned_data(guest))
    }

    /// Close exactly one completion's retirement evidence and return its
    /// captured pre-call transfer state and exact retirement causes.
    pub fn take_guest_free_evidence(
        &mut self,
        guard_id: u64,
        guest: u32,
        host: Win16HostDdeData,
        owner: u32,
        origin: Win16DdeDataOrigin,
    ) -> Option<(bool, bool, bool)> {
        let guard = *self.data_transfer_guards.get(&guard_id)?;
        if guard.guest_data != guest
            || guard.host_data != host
            || guard.owner != owner
            || guard.origin != origin
        {
            return None;
        }
        self.data_transfer_guards.remove(&guard_id);
        Some((
            guard.previously_transferred,
            guard.guest_free_seen,
            guard.instance_uninitialized,
        ))
    }
    /// Resolve a transaction's guest data token only when both the data handle
    /// and conversation belong to the same DDEML instance.
    pub fn host_data_for_conversation(
        &self,
        guest_conversation: u32,
        guest_data: u32,
    ) -> Option<Win16HostDdeData> {
        let conversation = self.conversations.get(&guest_conversation)?;
        let data = self.data.get(&guest_data).filter(|data| data.available)?;
        (conversation.instance == data.instance).then_some(data.host)
    }
    pub fn remove_data(&mut self, guest: u32) -> Option<Win16DdeRemovedData> {
        self.callback_data.remove(&guest);
        let host = self.data.remove(&guest)?.host;
        let access_block = self.access_blocks.remove(&guest).map(access_view);
        Some(Win16DdeRemovedData { host, access_block })
    }

    /// Retire a DDEML-owned handle after DDEML has consumed it or a callback
    /// frame that borrowed it has completed. Application-owned handles remain
    /// valid until the guest explicitly frees them.
    pub fn release_unowned_data(&mut self, guest: u32) -> Option<Win16DdeRemovedData> {
        let record = self.data.get(&guest)?;
        let owned_after_callback = match record.origin {
            Win16DdeDataOrigin::CallbackBorrowed => false,
            Win16DdeDataOrigin::Created {
                retain_after_transfer,
            } => !record.transferred || retain_after_transfer,
            Win16DdeDataOrigin::ClientResult => !record.transferred,
        };
        if (!record.guest_freed && owned_after_callback)
            || record.callback_references != 0
            || self
                .access_blocks
                .get(&guest)
                .is_some_and(|block| block.references != 0)
        {
            return None;
        }
        self.remove_data(guest)
    }

    /// Apply an exact Consumed receipt: invalidate the handle for all new
    /// guest operations now, retaining only frame/lease metadata until those
    /// references are balanced.
    pub fn consume_data_transfer(
        &mut self,
        guest: u32,
    ) -> Result<Option<Win16DdeRemovedData>, Win16DdeCallbackEventError> {
        let record = self
            .data
            .get_mut(&guest)
            .ok_or(Win16DdeCallbackEventError::InvalidState)?;
        if !record.transferred
            || matches!(
                record.origin,
                Win16DdeDataOrigin::Created {
                    retain_after_transfer: true
                }
            )
        {
            return Err(Win16DdeCallbackEventError::InvalidState);
        }
        record.available = false;
        Ok(self.release_unowned_data(guest))
    }

    pub fn access_block(&self, data_guest: u32) -> Option<Win16DdeAccessBlock> {
        self.access_blocks
            .get(&data_guest)
            .copied()
            .map(access_view)
    }

    pub fn retain_access_block(
        &mut self,
        data_guest: u32,
        guest_block: u16,
        identity: win16_abi::GlobalHandle,
        far_pointer: u32,
        byte_length: u32,
        writable: bool,
    ) -> Option<u32> {
        if let Some(record) = self.access_blocks.get_mut(&data_guest) {
            if record.identity != identity
                || record.byte_length != byte_length
                || writable && !record.writable
            {
                return None;
            }
            record.references = record.references.checked_add(1)?;
            return Some(record.far_pointer);
        }
        self.access_blocks.insert(
            data_guest,
            GuestAccessBlock {
                block: guest_block,
                identity,
                far_pointer,
                byte_length,
                writable,
                references: 1,
            },
        );
        Some(far_pointer)
    }

    pub fn take_access_block(&mut self, data_guest: u32) -> Option<Win16DdeAccessBlock> {
        let record = self.access_blocks.get_mut(&data_guest)?;
        if record.references > 1 {
            record.references -= 1;
            return None;
        }
        let record = self.access_blocks.remove(&data_guest)?;
        Some(access_view(record))
    }
}

fn merge_data_origin(
    current: Win16DdeDataOrigin,
    incoming: Win16DdeDataOrigin,
) -> Win16DdeDataOrigin {
    use Win16DdeDataOrigin as Origin;
    match (current, incoming) {
        (
            Origin::Created {
                retain_after_transfer: current,
            },
            Origin::Created {
                retain_after_transfer: incoming,
            },
        ) => Origin::Created {
            retain_after_transfer: current || incoming,
        },
        (Origin::Created { .. }, _) | (Origin::ClientResult, Origin::CallbackBorrowed) => current,
        (Origin::CallbackBorrowed, Origin::Created { .. } | Origin::ClientResult) => incoming,
        (Origin::ClientResult, Origin::Created { .. }) => current,
        (Origin::ClientResult, Origin::ClientResult) => current,
        (Origin::CallbackBorrowed, Origin::CallbackBorrowed) => current,
    }
}

pub(super) fn access_view(record: GuestAccessBlock) -> Win16DdeAccessBlock {
    Win16DdeAccessBlock {
        block: record.block,
        identity: record.identity,
        far_pointer: record.far_pointer,
        byte_length: record.byte_length,
        writable: record.writable,
    }
}
