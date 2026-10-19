//! Native DDEML calls, handle tables, and callback argument projection.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::{size_of, zeroed};
use std::ptr;

use compat_services::win16_dde::{callback_class, transaction_type};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeCallbackReply, Win16HostDdeCall,
    Win16HostDdeCallbackData, Win16HostDdeContext, Win16HostDdeConversation,
    Win16HostDdeConversationInfo, Win16HostDdeConversationList, Win16HostDdeData,
    Win16HostDdeDataTransfer, Win16HostDdeDataTransferOutcome, Win16HostDdeInstance,
    Win16HostDdeOperation, Win16HostDdeResult, Win16HostDdeString, Win16HostDdeTransactionData,
    Win16HostDdeValue,
};
use windows_sys::Win32::System::DataExchange::*;

use super::worker::{self, WorkerContext};

#[path = "win16_dde_native_api.rs"]
mod api;
pub(super) use api::execute_call;
#[path = "win16_dde_native_callback.rs"]
pub(super) mod callback;
#[path = "win16_dde_native_data.rs"]
pub(super) mod data;
#[path = "win16_dde_native_handles.rs"]
mod handles;
#[path = "win16_dde_native_support.rs"]
mod support;
#[path = "win16_dde_native_transaction.rs"]
mod transaction;
#[path = "win16_dde_native_transfer_state.rs"]
mod transfer_state;
use support::*;
pub(super) use support::{cancel_active_conversations, uninitialize_all};

#[derive(Clone, Copy)]
struct InstanceRecord {
    native: u32,
    callback_route: u64,
    callback_slot: u16,
}

#[derive(Clone, Copy)]
struct CallbackRegistration {
    instance: Win16HostDdeInstance,
    route: u64,
}

#[derive(Clone, Copy)]
struct OwnedHandle<T> {
    instance: Win16HostDdeInstance,
    native: T,
}

#[derive(Clone, Copy)]
struct OwnedStringHandle {
    instance: Win16HostDdeInstance,
    native: HSZ,
    references: u32,
    callback_references: u32,
    data_references: u32,
    retired: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DataOrigin {
    Created { retain_after_transfer: bool },
    CallbackBorrowed,
    ClientResult,
}

#[derive(Clone, Copy)]
struct OwnedDataHandle {
    instance: Win16HostDdeInstance,
    native: HDDEDATA,
    format: u16,
    item: Option<Win16HostDdeString>,
    origin: DataOrigin,
    /// True only for adapter-created callback projections or converted
    /// XTYP_EXECUTE inputs whose lifetime is owned by this handle table.
    native_owned: bool,
    /// Consumed aliases remain only as non-usable metadata until callback and
    /// AccessData release receipts arrive.
    available: bool,
    guest_freed: bool,
    transferred: bool,
    callback_references: u32,
    retired: bool,
}

#[derive(Clone, Copy)]
struct PendingDataTransferGuard {
    token: Win16HostDdeData,
    instance: Win16HostDdeInstance,
    native: usize,
    format: u16,
    origin: DataOrigin,
    guest_free_seen: bool,
    instance_retired: bool,
    begun: bool,
}

#[derive(Clone, Copy)]
struct NativeAccessLease {
    pointer: *mut u8,
    byte_length: u32,
}

/// Native values exist only in this Windows-thread-local table. The numeric
/// runtime tokens do not encode or expose native handle bits.
pub(super) struct NativeState {
    next_token: u64,
    instances: BTreeMap<Win16HostDdeInstance, InstanceRecord>,
    instances_by_native: BTreeMap<u32, Win16HostDdeInstance>,
    callbacks_by_slot: BTreeMap<u16, CallbackRegistration>,
    strings: BTreeMap<Win16HostDdeString, OwnedStringHandle>,
    strings_by_native: BTreeMap<(Win16HostDdeInstance, usize), Win16HostDdeString>,
    conversations: BTreeMap<Win16HostDdeConversation, OwnedHandle<HCONV>>,
    conversations_by_native: BTreeMap<usize, Win16HostDdeConversation>,
    /// Query-only HCONV views are not owners of the native handle and must
    /// not reserve its raw identity. A later callback from the real partner
    /// instance may establish the owned conversation independently.
    query_only_conversations: BTreeMap<Win16HostDdeConversation, OwnedHandle<HCONV>>,
    query_only_by_native: BTreeMap<(Win16HostDdeInstance, usize), Win16HostDdeConversation>,
    conversation_strings: BTreeMap<Win16HostDdeConversation, BTreeSet<Win16HostDdeString>>,
    conversation_lists: BTreeMap<Win16HostDdeConversationList, OwnedHandle<HCONVLIST>>,
    lists_by_native: BTreeMap<usize, Win16HostDdeConversationList>,
    list_members: BTreeMap<Win16HostDdeConversationList, BTreeSet<Win16HostDdeConversation>>,
    data: BTreeMap<Win16HostDdeData, OwnedDataHandle>,
    data_by_native: BTreeMap<usize, Win16HostDdeData>,
    data_transfer_guards:
        BTreeMap<(Win16HostDdeOperation, Win16HostDdeData), PendingDataTransferGuard>,
    /// Native pointers stay private to the owner thread and live exactly as
    /// long as their successful DdeAccessData leases.
    access_pointers: BTreeMap<Win16HostDdeData, Vec<NativeAccessLease>>,
}

impl NativeState {
    pub(super) fn new() -> Self {
        Self {
            next_token: 1,
            instances: BTreeMap::new(),
            instances_by_native: BTreeMap::new(),
            callbacks_by_slot: BTreeMap::new(),
            strings: BTreeMap::new(),
            strings_by_native: BTreeMap::new(),
            conversations: BTreeMap::new(),
            conversations_by_native: BTreeMap::new(),
            query_only_conversations: BTreeMap::new(),
            query_only_by_native: BTreeMap::new(),
            conversation_strings: BTreeMap::new(),
            conversation_lists: BTreeMap::new(),
            lists_by_native: BTreeMap::new(),
            list_members: BTreeMap::new(),
            data: BTreeMap::new(),
            data_by_native: BTreeMap::new(),
            data_transfer_guards: BTreeMap::new(),
            access_pointers: BTreeMap::new(),
        }
    }

    fn token(&mut self) -> Result<u64, RuntimeError> {
        let token = self.next_token;
        self.next_token = token.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDEML host token space is exhausted",
            )
        })?;
        if token == 0 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "DDEML host token space is exhausted",
            ));
        }
        Ok(token)
    }

    fn native_instance(&self, token: Win16HostDdeInstance) -> Result<u32, RuntimeError> {
        self.instances
            .get(&token)
            .map(|record| record.native)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host instance token")
            })
    }

    fn allocate_callback_slot(&self) -> Result<u16, RuntimeError> {
        (0..callback::CALLBACKS.len())
            .find(|slot| !self.callbacks_by_slot.contains_key(&(*slot as u16)))
            .map(|slot| slot as u16)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "DDE callback registration slots are exhausted",
                )
            })
    }

    fn owner_for_conversation(
        &self,
        token: Win16HostDdeConversation,
    ) -> Result<Win16HostDdeInstance, RuntimeError> {
        self.conversations
            .get(&token)
            .filter(|_| !self.query_only_conversations.contains_key(&token))
            .map(|record| record.instance)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host conversation token")
            })
    }

    fn native_conversation(&self, token: Win16HostDdeConversation) -> Result<HCONV, RuntimeError> {
        self.conversations
            .get(&token)
            .filter(|_| !self.query_only_conversations.contains_key(&token))
            .map(|record| record.native)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host conversation token")
            })
    }

    fn conversation_for_info(
        &self,
        token: Win16HostDdeConversation,
    ) -> Result<(Win16HostDdeInstance, HCONV), RuntimeError> {
        self.conversations
            .get(&token)
            .map(|record| (record.instance, record.native))
            .or_else(|| {
                self.query_only_conversations
                    .get(&token)
                    .map(|record| (record.instance, record.native))
            })
            .ok_or_else(|| protocol_error("DDE conversation info references an unknown host token"))
    }

    fn native_string(
        &self,
        instance: Win16HostDdeInstance,
        token: Win16HostDdeString,
    ) -> Result<HSZ, RuntimeError> {
        self.strings
            .get(&token)
            .filter(|record| record.instance == instance && !record.retired)
            .map(|record| record.native)
            .ok_or_else(|| {
                protocol_error("DDEML operation references a foreign or unknown string token")
            })
    }

    fn native_optional_string(
        &self,
        instance: Win16HostDdeInstance,
        token: Option<Win16HostDdeString>,
    ) -> Result<HSZ, RuntimeError> {
        token.map_or(Ok(ptr::null_mut()), |token| {
            self.native_string(instance, token)
        })
    }

    fn native_list(&self, token: Win16HostDdeConversationList) -> Result<HCONVLIST, RuntimeError> {
        self.conversation_lists
            .get(&token)
            .map(|record| record.native)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host conversation-list token")
            })
    }

    fn native_data(&self, token: Win16HostDdeData) -> Result<HDDEDATA, RuntimeError> {
        self.data
            .get(&token)
            .filter(|record| record.available)
            .map(|record| record.native)
            .ok_or_else(|| protocol_error("DDEML operation references an unknown host data token"))
    }

    fn native_data_for_unaccess(&self, token: Win16HostDdeData) -> Result<HDDEDATA, RuntimeError> {
        let record = self
            .data
            .get(&token)
            .filter(|_| {
                self.access_pointers
                    .get(&token)
                    .is_some_and(|pointers| !pointers.is_empty())
            })
            .ok_or_else(|| {
                protocol_error("DDE UnaccessData has no retained native access lease")
            })?;
        Ok(record.native)
    }

    fn latest_access_lease(
        &self,
        token: Win16HostDdeData,
    ) -> Result<NativeAccessLease, RuntimeError> {
        self.access_pointers
            .get(&token)
            .and_then(|pointers| pointers.last())
            .copied()
            .ok_or_else(|| protocol_error("DDE UnaccessData has no retained data pointer"))
    }

    fn data_origin(&self, token: Win16HostDdeData) -> Result<DataOrigin, RuntimeError> {
        self.data
            .get(&token)
            .filter(|record| record.available)
            .map(|record| record.origin)
            .ok_or_else(|| protocol_error("DDEML operation references an unknown host data token"))
    }

    fn data_writable(&self, token: Win16HostDdeData) -> Result<bool, RuntimeError> {
        let record = self
            .data
            .get(&token)
            .filter(|record| record.available)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host data token")
            })?;
        Ok(matches!(record.origin, DataOrigin::Created { .. }) && !record.transferred)
    }

    fn data_freeable(&self, token: Win16HostDdeData) -> Result<bool, RuntimeError> {
        let record = self
            .data
            .get(&token)
            .filter(|record| record.available)
            .ok_or_else(|| {
                protocol_error("DDEML operation references an unknown host data token")
            })?;
        Ok(match record.origin {
            DataOrigin::Created {
                retain_after_transfer,
            } => !record.transferred || retain_after_transfer,
            DataOrigin::CallbackBorrowed => false,
            DataOrigin::ClientResult => !record.transferred,
        })
    }

    fn intern_data(
        &mut self,
        instance: Win16HostDdeInstance,
        native: HDDEDATA,
        format: u16,
        origin: DataOrigin,
        item: Option<Win16HostDdeString>,
    ) -> Result<Option<Win16HostDdeData>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let key = native as usize;
        if let Some(token) = self.data_by_native.get(&key).copied() {
            let record = self
                .data
                .get(&token)
                .filter(|record| record.instance == instance && record.available)
                .ok_or_else(|| {
                    protocol_error(
                        "native DDE data handle belongs to another instance or is unavailable",
                    )
                })?;
            if record.format != format {
                return Err(protocol_error(
                    "native DDE data handle was observed with a different format",
                ));
            }
            if let (Some(existing), Some(incoming)) = (record.item, item) {
                let existing = self.native_string(instance, existing)?;
                let incoming = self.native_string(instance, incoming)?;
                // SAFETY: `DdeCmpStringHandles` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                if unsafe { DdeCmpStringHandles(existing, incoming) } != 0 {
                    return Err(protocol_error(
                        "native DDE data handle was observed with a different item name",
                    ));
                }
            }
            let current_item = record.item;
            if current_item.is_none() && item.is_some() {
                self.retain_data_item(instance, item)?;
            }
            let record = self.data.get_mut(&token).ok_or_else(|| {
                protocol_error("native DDE data handle disappeared while updating its metadata")
            })?;
            if record.item.is_none() {
                record.item = item;
            }
            record.origin = merge_data_origin(record.origin, origin);
            return Ok(Some(token));
        }
        let token = Win16HostDdeData(self.token()?);
        self.retain_data_item(instance, item)?;
        self.data.insert(
            token,
            OwnedDataHandle {
                instance,
                native,
                format,
                item,
                origin,
                native_owned: false,
                available: true,
                guest_freed: false,
                transferred: false,
                callback_references: 0,
                retired: false,
            },
        );
        self.data_by_native.insert(key, token);
        Ok(Some(token))
    }

    fn retain_data_item(
        &mut self,
        instance: Win16HostDdeInstance,
        item: Option<Win16HostDdeString>,
    ) -> Result<(), RuntimeError> {
        let Some(item) = item else {
            return Ok(());
        };
        let string = self
            .strings
            .get(&item)
            .filter(|record| record.instance == instance)
            .ok_or_else(|| protocol_error("DDE data item string belongs to another instance"))?;
        let next_references = string.data_references.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE data-item reference count is exhausted",
            )
        })?;
        let native_instance = self.native_instance(instance)?;
        // SAFETY: `DdeKeepStringHandle` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe { DdeKeepStringHandle(native_instance, string.native) } == 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DDEML could not retain a data object's item-name HSZ",
            ));
        }
        self.strings
            .get_mut(&item)
            .ok_or_else(|| protocol_error("DDE data item string disappeared after native retain"))?
            .data_references = next_references;
        Ok(())
    }

    fn unpin_callback_data(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let (origin, native, references) = {
            let record = self.data.get_mut(&token).ok_or_else(|| {
                protocol_error("DDE callback data pin references an unknown token")
            })?;
            if record.callback_references == 0 {
                return Err(protocol_error("DDE callback data pin count underflow"));
            }
            record.callback_references -= 1;
            (record.origin, record.native, record.callback_references)
        };
        if origin == DataOrigin::CallbackBorrowed && references == 0 {
            if let Some(record) = self.data.get_mut(&token) {
                record.available = false;
            }
            if self.data_by_native.get(&(native as usize)) == Some(&token) {
                self.data_by_native.remove(&(native as usize));
            }
        }
        self.collect_consumed_data(token)
    }

    fn remove_instance(&mut self, token: Win16HostDdeInstance) {
        let Some(record) = self.instances.remove(&token) else {
            return;
        };
        self.instances_by_native.remove(&record.native);
        self.callbacks_by_slot.remove(&record.callback_slot);
        for guard in self
            .data_transfer_guards
            .values_mut()
            .filter(|guard| guard.instance == token)
        {
            guard.instance_retired = true;
        }
        let strings: Vec<_> = self
            .strings
            .iter()
            .filter_map(|(key, value)| (value.instance == token).then_some(*key))
            .collect();
        for key in strings {
            if let Some(value) = self.strings.get(&key).copied() {
                self.strings_by_native
                    .remove(&(token, value.native as usize));
                if value.callback_references != 0 {
                    if let Some(record) = self.strings.get_mut(&key) {
                        record.retired = true;
                    }
                } else {
                    self.strings.remove(&key);
                }
            }
        }
        let conversations: Vec<_> = self
            .conversations
            .iter()
            .filter_map(|(key, value)| (value.instance == token).then_some(*key))
            .collect();
        for key in conversations {
            self.remove_conversation(key);
        }
        let query_aliases: Vec<_> = self
            .query_only_conversations
            .iter()
            .filter_map(|(key, value)| (value.instance == token).then_some(*key))
            .collect();
        for key in query_aliases {
            self.remove_conversation(key);
        }
        let lists: Vec<_> = self
            .conversation_lists
            .iter()
            .filter_map(|(key, value)| (value.instance == token).then_some(*key))
            .collect();
        for key in lists {
            self.remove_list(key);
        }
        let data: Vec<_> = self
            .data
            .iter()
            .filter_map(|(key, value)| (value.instance == token).then_some(*key))
            .collect();
        for key in data {
            if let Some(value) = self.data.get(&key).copied() {
                if self.data_by_native.get(&(value.native as usize)) == Some(&key) {
                    self.data_by_native.remove(&(value.native as usize));
                }
                if value.callback_references != 0 {
                    if let Some(record) = self.data.get_mut(&key) {
                        record.available = false;
                        record.retired = true;
                    }
                } else {
                    self.data.remove(&key);
                }
            }
            self.access_pointers.remove(&key);
        }
    }

    fn remove_conversation(&mut self, token: Win16HostDdeConversation) {
        if let Some(record) = self.query_only_conversations.remove(&token) {
            self.query_only_by_native
                .remove(&(record.instance, record.native as usize));
            let strings = self.conversation_strings.remove(&token).unwrap_or_default();
            for string in strings {
                self.forget_unretained_string(string);
            }
            return;
        }
        if let Some(record) = self.conversations.remove(&token) {
            self.conversations_by_native
                .remove(&(record.native as usize));
            for members in self.list_members.values_mut() {
                members.remove(&token);
            }
            let strings = self.conversation_strings.remove(&token).unwrap_or_default();
            for string in strings {
                self.forget_unretained_string(string);
            }
        }
    }

    fn remove_list(&mut self, token: Win16HostDdeConversationList) {
        if let Some(record) = self.conversation_lists.remove(&token) {
            self.lists_by_native.remove(&(record.native as usize));
            if let Some(members) = self.list_members.remove(&token) {
                for conversation in members {
                    self.remove_conversation(conversation);
                }
            }
        }
    }

    fn remove_data(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let Some(record) = self.data.get(&token).copied() else {
            return Ok(());
        };
        if record.retired {
            self.data.remove(&token);
            if self.data_by_native.get(&(record.native as usize)) == Some(&token) {
                self.data_by_native.remove(&(record.native as usize));
            }
            self.access_pointers.remove(&token);
            return Ok(());
        }
        if record.native_owned {
            // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
            if unsafe { DdeFreeDataHandle(record.native) } == 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "DDEML could not release an adapter-owned translated data handle",
                ));
            }
            self.data
                .get_mut(&token)
                .ok_or_else(|| {
                    protocol_error("translated DDE data handle disappeared during release")
                })?
                .native_owned = false;
        }
        if let Some(item) = record.item {
            let string = self
                .strings
                .get(&item)
                .filter(|string| string.instance == record.instance && string.data_references != 0)
                .ok_or_else(|| {
                    protocol_error("DDE data item HSZ reference accounting is inconsistent")
                })?;
            let native_instance = self.native_instance(record.instance)?;
            // SAFETY: DdeFreeStringHandle releases a string handle this instance created.
            if unsafe { DdeFreeStringHandle(native_instance, string.native) } == 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "DDEML could not release a retained data object's item-name HSZ",
                ));
            }
            let string = self.strings.get_mut(&item).ok_or_else(|| {
                protocol_error("DDE data item string disappeared after native release")
            })?;
            string.data_references -= 1;
            self.forget_unretained_string(item);
        }
        let record = self
            .data
            .remove(&token)
            .ok_or_else(|| protocol_error("DDE data record disappeared during retirement"))?;
        if self.data_by_native.get(&(record.native as usize)) == Some(&token) {
            self.data_by_native.remove(&(record.native as usize));
        }
        self.access_pointers.remove(&token);
        Ok(())
    }

    fn mark_native_data_owned(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let record = self.data.get_mut(&token).ok_or_else(|| {
            protocol_error("DDE translated data ownership references an unknown token")
        })?;
        if !record.available || record.native_owned {
            return Err(protocol_error(
                "DDE translated data ownership does not name a fresh available handle",
            ));
        }
        record.native_owned = true;
        Ok(())
    }

    fn consume_data_transfer(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let record = self
            .data
            .get_mut(&token)
            .ok_or_else(|| protocol_error("DDE transaction consumed an unknown host data token"))?;
        if !record.transferred
            || matches!(
                record.origin,
                DataOrigin::Created {
                    retain_after_transfer: true
                }
            )
        {
            return Err(protocol_error(
                "DDE transaction consumed a non-consumable data token",
            ));
        }
        record.available = false;
        record.transferred = true;
        if self.data_by_native.get(&(record.native as usize)) == Some(&token) {
            self.data_by_native.remove(&(record.native as usize));
        }
        self.collect_consumed_data(token)?;
        Ok(())
    }

    fn collect_consumed_data(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let record = self.data.get(&token).copied();
        let ready = record.is_some_and(|record| {
            !record.available
                && record.callback_references == 0
                && self.access_pointers.get(&token).is_none_or(Vec::is_empty)
        });
        if ready {
            self.remove_data(token)?;
        }
        Ok(())
    }

    fn reserve_access_slot(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        if self.data.get(&token).is_none_or(|record| !record.available) {
            return Err(protocol_error(
                "DDE AccessData references an unavailable token",
            ));
        }
        self.access_pointers
            .entry(token)
            .or_default()
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve DDE access lease record",
                    error,
                )
            })
    }

    fn cancel_access_slot(&mut self, token: Win16HostDdeData) {
        if self.access_pointers.get(&token).is_some_and(Vec::is_empty) {
            self.access_pointers.remove(&token);
        }
    }

    fn note_access(
        &mut self,
        token: Win16HostDdeData,
        pointer: *mut u8,
        byte_length: u32,
    ) -> Result<(), RuntimeError> {
        let pointers = self.access_pointers.get_mut(&token).ok_or_else(|| {
            protocol_error("DDE access slot was not reserved before the native acquisition")
        })?;
        if pointers.len() == pointers.capacity() {
            return Err(protocol_error(
                "DDE access slot capacity changed during acquisition",
            ));
        }
        pointers.push(NativeAccessLease {
            pointer,
            byte_length,
        });
        Ok(())
    }

    fn access_count(&self, token: Win16HostDdeData) -> usize {
        self.access_pointers.get(&token).map_or(0, Vec::len)
    }

    fn note_unaccess(&mut self, token: Win16HostDdeData) -> Result<(), RuntimeError> {
        let pointers = self
            .access_pointers
            .get_mut(&token)
            .ok_or_else(|| protocol_error("DDE native access lease disappeared before release"))?;
        pointers
            .pop()
            .ok_or_else(|| protocol_error("DDE native access lease count underflowed"))?;
        self.cancel_access_slot(token);
        Ok(())
    }
}
