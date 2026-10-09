//! Private Win16 DDEML guest-token and callback ownership state.

use std::collections::{BTreeMap, BTreeSet};
use win16_abi::GlobalHandle;

#[path = "win16_dde_callbacks.rs"]
mod callbacks;
#[path = "win16_dde_data_handles.rs"]
mod data_handles;
#[path = "win16_dde_handles.rs"]
mod handles;
#[path = "win16_dde_guest_block_retirement.rs"]
mod guest_block_retirement;
pub(crate) use guest_block_retirement::{
    Win16DdeGuestBlockRetirementPhase, Win16DdeRetiredGuestBlock,
};
use crate::win16_host_dde::{
    Win16DdeCallbackCall, Win16DdeCallbackReply, Win16HostDdeCallbackData,
    Win16HostDdeConversation, Win16HostDdeConversationList, Win16HostDdeData, Win16HostDdeInstance,
    Win16HostDdeString,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DdeInstanceRecord {
    host: Win16HostDdeInstance,
    guest_callback: u32,
    callback_token: u64,
    callback_route: u64,
    last_error: u16,
    provisional: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingDdeInitialization {
    guest_instance: u32,
    guest_callback: u32,
    callback_token: u64,
    callback_route: u64,
    host_instance: Option<Win16HostDdeInstance>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedDdeHandle<T> {
    instance: u32,
    host: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16DdeDataOrigin {
    /// Created by the guest. Ownership transfers on the first DDEML use
    /// unless APPOWNED requested that the handle remain with the guest.
    Created { retain_after_transfer: bool },
    /// Borrowed from DDEML for the duration of a callback frame.
    CallbackBorrowed,
    /// Returned by a synchronous client transaction and owned by the guest.
    ClientResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DdeDataRecord {
    instance: u32,
    host: Win16HostDdeData,
    origin: Win16DdeDataOrigin,
    /// Consumed transfer aliases stop resolving immediately while callback
    /// and access reference metadata drains through its matching completion.
    available: bool,
    transferred: bool,
    callback_references: u32,
    guest_freed: bool,
}

#[derive(Clone, Copy, Debug)]
struct PendingDdeDataTransferGuard {
    guest_data: u32,
    host_data: Win16HostDdeData,
    owner: u32,
    origin: Win16DdeDataOrigin,
    previously_available: bool,
    previously_transferred: bool,
    guest_free_seen: bool,
    instance_uninitialized: bool,
    begun: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DdeCallbackRegistration {
    guest_instance: u32,
    guest_callback: u32,
    callback_token: u64,
    active: bool,
    in_flight: u32,
    /// A replaced route remains valid until its instance is successfully
    /// uninitialized. This covers native callbacks already queued but not yet
    /// delivered to the guest safe point.
    retire_on_idle: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestAccessBlock {
    block: u16,
    /// Exact heap allocation identity captured when this AccessData snapshot
    /// was created. The raw guest word can be reused after retirement.
    identity: GlobalHandle,
    far_pointer: u32,
    byte_length: u32,
    writable: bool,
    references: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win16DdeRemovedData {
    pub host: Win16HostDdeData,
    pub access_block: Option<Win16DdeAccessBlock>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win16DdeAccessBlock {
    pub block: u16,
    pub identity: GlobalHandle,
    pub far_pointer: u32,
    pub byte_length: u32,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16DdeCallbackArgument {
    Word(u16),
    Dword(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16DdeCallbackEventError {
    /// Native DDEML delivered a callback after its route was retired.
    StaleRoute,
    /// A known route was paired with a different host DDE instance.
    InstanceMismatch,
    /// A native value has no safe Win16 callback projection.
    InvalidProjection,
    /// A callback route, handle token, or in-flight count could not be allocated.
    ResourceExhausted,
    /// The callback state tables contradict a route that was previously staged.
    InvalidState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16DdeGuestCallback {
    pub guest_instance: u32,
    pub callback_route: u64,
    pub callback_token: u64,
    pub arguments: [Win16DdeCallbackArgument; 8],
    pub data_guest: u32,
    /// String tokens first exposed by this callback. They remain available
    /// through the callback frame and retire afterward unless the guest kept
    /// an explicit DDEML reference.
    pub borrowed_strings: Vec<u32>,
    /// Unique string tokens pinned for this callback, including tokens that
    /// already had application references before this frame began.
    pub callback_strings: Vec<u32>,
    pub data_snapshot: Option<Vec<u8>>,
    /// A copied callback CONVCONTEXT to allocate as a temporary guest block
    /// when `transaction_type` is XTYP_CONNECT or XTYP_WILDCONNECT.
    pub conversation_context: Option<crate::Win16HostDdeContext>,
}

#[derive(Debug, Default)]
pub struct Win16DdeState {
    instances: BTreeMap<u32, DdeInstanceRecord>,
    pending_initializations: BTreeMap<u64, PendingDdeInitialization>,
    reserved_instance_tokens: BTreeSet<u32>,
    strings: BTreeMap<u32, OwnedDdeHandle<Win16HostDdeString>>,
    string_references: BTreeMap<u32, u32>,
    callback_string_references: BTreeMap<u32, u32>,
    conversations: BTreeMap<u32, OwnedDdeHandle<Win16HostDdeConversation>>,
    query_only_conversations: BTreeSet<u32>,
    conversation_strings: BTreeMap<u32, BTreeSet<u32>>,
    conversation_lists: BTreeMap<u32, OwnedDdeHandle<Win16HostDdeConversationList>>,
    list_members: BTreeMap<u32, BTreeSet<u32>>,
    data: BTreeMap<u32, DdeDataRecord>,
    next_token: u32,
    /// Each route retains the guest callback identity captured when native
    /// DDEML began that callback. Prior routes remain resolvable for callbacks
    /// already in flight after a successful re-registration.
    callback_routes: BTreeMap<u64, DdeCallbackRegistration>,
    next_callback_route: u64,
    retired_callback_tokens: Vec<u64>,
    next_data_transfer_guard: u64,
    data_transfer_guards: BTreeMap<u64, PendingDdeDataTransferGuard>,
    /// DdeAccessData output snapshots are guest allocations owned by runtime.
    access_blocks: BTreeMap<u32, GuestAccessBlock>,
    /// Host data is copied and retained only for an active typed callback.
    callback_data: BTreeMap<u32, Vec<Vec<u8>>>,
}

impl Win16DdeState {
    pub fn new() -> Self {
        Self {
            next_token: 1,
            next_callback_route: 1,
            ..Self::default()
        }
    }

    pub(crate) fn needs_scheduler_progress(&self) -> bool {
        self.has_callback_owners()
            || !self.retired_callback_tokens.is_empty()
            || !self.data_transfer_guards.is_empty()
            || self.callback_data.values().any(|snapshots| !snapshots.is_empty())
            || !self.callback_string_references.is_empty()
    }

    /// Routes and instances are callback-producing owners until the host
    /// supplies an exact abort/quiescence receipt. A unit abort result cannot
    /// prove that no native callback is still in flight.
    pub(crate) fn has_callback_owners(&self) -> bool {
        !self.instances.is_empty()
            || !self.pending_initializations.is_empty()
            || !self.callback_routes.is_empty()
    }

    /// Reserve a guest callback route and an internal guest instance token
    /// before the first native DdeInitialize. The token is available only to
    /// callbacks/nested DDE calls; runtime must not write it to the guest's
    /// output parameter until `commit_initialization` succeeds.
    pub fn stage_initialization(
        &mut self,
        callback: u32,
        callback_token: u64,
    ) -> Option<(u32, u64)> {
        let guest_instance = self.allocate_token()?;
        let callback_route = self.allocate_callback_route()?;
        self.reserved_instance_tokens.insert(guest_instance);
        self.pending_initializations.insert(
            callback_route,
            PendingDdeInitialization {
                guest_instance,
                guest_callback: callback,
                callback_token,
                callback_route,
                host_instance: None,
            },
        );
        self.callback_routes.insert(
            callback_route,
            DdeCallbackRegistration {
                guest_instance,
                guest_callback: callback,
                callback_token,
                active: true,
                in_flight: 0,
                retire_on_idle: false,
            },
        );
        Some((guest_instance, callback_route))
    }

    /// Publish a candidate route before native reinitialization while leaving
    /// the old route available until the API result is known.
    pub fn stage_callback_registration(
        &mut self,
        guest_instance: u32,
        callback: u32,
        callback_token: u64,
    ) -> Option<u64> {
        self.instances.get(&guest_instance)?;
        let callback_route = self.allocate_callback_route()?;
        self.callback_routes.insert(
            callback_route,
            DdeCallbackRegistration {
                guest_instance,
                guest_callback: callback,
                callback_token,
                active: true,
                in_flight: 0,
                retire_on_idle: false,
            },
        );
        Some(callback_route)
    }

    /// Commit the staged first initialization after the native DDEML call
    /// succeeds. A callback may have bound the provisional token earlier.
    pub fn commit_initialization(
        &mut self,
        guest_instance: u32,
        host_instance: Win16HostDdeInstance,
        callback_route: u64,
    ) -> Option<()> {
        let pending = *self.pending_initializations.get(&callback_route)?;
        if pending.guest_instance != guest_instance
            || pending
                .host_instance
                .is_some_and(|host| host != host_instance)
            || self
                .callback_routes
                .get(&callback_route)
                .is_none_or(|route| !route.active || route.guest_instance != guest_instance)
        {
            return None;
        }
        if let Some(record) = self.instances.get_mut(&guest_instance) {
            if !record.provisional
                || record.host != host_instance
                || record.callback_route != callback_route
            {
                return None;
            }
            record.provisional = false;
        } else {
            self.instances.insert(
                guest_instance,
                DdeInstanceRecord {
                    host: host_instance,
                    guest_callback: pending.guest_callback,
                    callback_token: pending.callback_token,
                    callback_route,
                    last_error: 0,
                    provisional: false,
                },
            );
        }
        self.pending_initializations.remove(&callback_route);
        self.reserved_instance_tokens.remove(&guest_instance);
        Some(())
    }

    /// Commit a staged reinitialization and retire the old route only after
    /// any callback frames that captured it have drained.
    pub fn commit_callback_registration(
        &mut self,
        guest_instance: u32,
        callback: u32,
        callback_token: u64,
        callback_route: u64,
    ) -> Option<Win16HostDdeInstance> {
        let candidate = self.callback_routes.get(&callback_route)?;
        if candidate.guest_instance != guest_instance
            || candidate.guest_callback != callback
            || candidate.callback_token != callback_token
            || !candidate.active
            || self.pending_initializations.contains_key(&callback_route)
        {
            return None;
        }
        let old_route = self.instances.get(&guest_instance)?.callback_route;
        let host = self.instances.get(&guest_instance)?.host;
        if let Some(old) = self.callback_routes.get_mut(&old_route) {
            old.active = false;
        }
        let record = self.instances.get_mut(&guest_instance)?;
        record.guest_callback = callback;
        record.callback_token = callback_token;
        record.callback_route = callback_route;
        Some(host)
    }

    /// Abandon a staged route after native DDEML rejects it. First-time
    /// initialization additionally retires provisional guest state and
    /// returns any guest access snapshots that runtime must free.
    pub fn rollback_callback_registration(
        &mut self,
        callback_route: u64,
    ) -> Option<(u32, Vec<Win16DdeAccessBlock>)> {
        let registration = *self.callback_routes.get(&callback_route)?;
        let guest_instance = registration.guest_instance;
        if self
            .pending_initializations
            .remove(&callback_route)
            .is_some()
        {
            self.reserved_instance_tokens.remove(&guest_instance);
            if self
                .instances
                .get(&guest_instance)
                .is_some_and(|record| record.provisional && record.callback_route == callback_route)
            {
                let (_, blocks) = self.remove_instance(guest_instance)?;
                return Some((guest_instance, blocks));
            }
        }
        if let Some(route) = self.callback_routes.get_mut(&callback_route) {
            route.active = false;
            route.retire_on_idle = true;
        }
        self.collect_retired_route(callback_route);
        Some((guest_instance, Vec::new()))
    }

    /// Return the native host instance only for an existing guest token.
    pub fn existing_host_instance(&self, guest_instance: u32) -> Option<Win16HostDdeInstance> {
        self.instances
            .get(&guest_instance)
            .map(|record| record.host)
    }

    /// Reserve a fresh opaque callback route for a re-registration attempt.
    /// The active callback mapping remains installed until native DDEML
    /// accepts the new registration.
    pub fn allocate_callback_route(&mut self) -> Option<u64> {
        let route = self.next_free_callback_route()?;
        self.next_callback_route = route.wrapping_add(1).max(1);
        Some(route)
    }

    pub fn host_instance(&self, instance: u32) -> Option<Win16HostDdeInstance> {
        self.instances.get(&instance).map(|record| record.host)
    }

    pub fn instance_for_route(&self, route: u64) -> Option<u32> {
        self.callback_routes
            .get(&route)
            .map(|registration| registration.guest_instance)
    }

    pub fn callback_for_route(&self, route: u64) -> Option<u32> {
        self.callback_routes
            .get(&route)
            .map(|registration| registration.guest_callback)
    }

    pub fn guest_instance_for_host(&self, host: Win16HostDdeInstance) -> Option<u32> {
        self.instances
            .iter()
            .find_map(|(guest, record)| (record.host == host).then_some(*guest))
    }

    /// Convert the host callback's opaque handles into instance-scoped guest
    /// tokens. The host never supplies a guest address or FARPROC here.
    pub fn release_callback_route(&mut self, route: u64) {
        if let Some(registration) = self.callback_routes.get_mut(&route) {
            registration.in_flight = registration.in_flight.saturating_sub(1);
        }
        self.collect_retired_route(route);
    }

    pub fn take_retired_callback_tokens(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.retired_callback_tokens)
    }

    pub fn retired_callback_token_count(&self) -> usize {
        self.retired_callback_tokens.len()
    }

    pub fn callback_retirement_count_bound(&self) -> usize {
        self.callback_routes.len().saturating_add(self.retired_callback_tokens.len())
    }

    pub fn access_block_count(&self) -> usize {
        self.access_blocks.len()
    }

    /// Drain every remaining callback route after the native DDE owner has
    /// stopped. No native callback can still reference these identities.
    pub fn drain_callback_routes(&mut self) -> Vec<u64> {
        let mut tokens = BTreeSet::new();
        tokens.extend(
            self.callback_routes
                .values()
                .map(|route| route.callback_token),
        );
        tokens.extend(std::mem::take(&mut self.retired_callback_tokens));
        self.callback_routes.clear();
        self.pending_initializations.clear();
        self.reserved_instance_tokens.clear();
        tokens.into_iter().collect()
    }

    pub fn remove_instance(
        &mut self,
        instance: u32,
    ) -> Option<(Win16HostDdeInstance, Vec<Win16DdeAccessBlock>)> {
        let record = self.instances.remove(&instance)?;
        self.pending_initializations.retain(|route, pending| {
            if pending.guest_instance == instance {
                self.reserved_instance_tokens.remove(&instance);
                self.callback_routes
                    .get_mut(route)
                    .map(|route| route.active = false);
                false
            } else {
                true
            }
        });
        let routes: Vec<u64> = self
            .callback_routes
            .iter()
            .filter_map(|(route, registration)| {
                (registration.guest_instance == instance).then_some(*route)
            })
            .collect();
        for route in routes {
            if let Some(registration) = self.callback_routes.get_mut(&route) {
                registration.active = false;
                registration.retire_on_idle = true;
            }
            self.collect_retired_route(route);
        }
        // In-flight callbacks keep their exact pin counters so end_callback
        // can retire the frame, but a successful Uninitialize makes every
        // guest HSZ stale immediately. Drop the host mapping and app-owned
        // reference counts while leaving only those callback counters.
        self.strings.retain(|_, value| value.instance != instance);
        self.string_references
            .retain(|guest, _| self.strings.contains_key(guest));
        self.callback_string_references
            .retain(|_, references| *references != 0);
        let conversations: Vec<u32> = self
            .conversations
            .iter()
            .filter_map(|(guest, value)| (value.instance == instance).then_some(*guest))
            .collect();
        for conversation in conversations {
            self.remove_conversation(conversation);
        }
        self.query_only_conversations
            .retain(|guest| self.conversations.contains_key(guest));
        self.conversation_lists
            .retain(|_, value| value.instance != instance);
        self.list_members
            .retain(|list, _| self.conversation_lists.contains_key(list));
        for members in self.list_members.values_mut() {
            members.retain(|guest| self.conversations.contains_key(guest));
        }
        self.data.retain(|_, value| value.instance != instance);
        let removed_data_tokens: Vec<u32> = self
            .access_blocks
            .keys()
            .copied()
            .filter(|guest| !self.data.contains_key(guest))
            .collect();
        let blocks = removed_data_tokens
            .into_iter()
            .filter_map(|guest| self.access_blocks.remove(&guest))
            .map(data_handles::access_view)
            .collect();
        self.callback_data
            .retain(|guest, _| self.data.contains_key(guest));
        // A successful guest DdeUninitialize is explicit retirement evidence
        // for every active transfer guard owned by this instance. Keep each
        // guard until its own foreground continuation consumes the evidence.
        for guard in self
            .data_transfer_guards
            .values_mut()
            .filter(|guard| guard.owner == instance)
        {
            guard.instance_uninitialized = true;
        }
        Some((record.host, blocks))
    }

    /// Guest instance identities used by ordered DDE shutdown cleanup.
    pub fn guest_instances(&self) -> Vec<u32> {
        self.instances.keys().copied().collect()
    }

    /// Cancel staged initializations that never reached the provisional host
    /// callback binding. Their callback routes retire through the same queue
    /// as active registrations and are unregistered by runtime afterward.
    pub fn cancel_pending_initializations(&mut self) {
        let pending: Vec<(u64, u32)> = self
            .pending_initializations
            .iter()
            .map(|(route, pending)| (*route, pending.guest_instance))
            .collect();
        for (route, instance) in pending {
            self.pending_initializations.remove(&route);
            self.reserved_instance_tokens.remove(&instance);
            if let Some(registration) = self.callback_routes.get_mut(&route) {
                registration.active = false;
                registration.retire_on_idle = true;
            }
            self.collect_retired_route(route);
        }
    }

    pub fn last_error(&self, instance: u32) -> u16 {
        self.instances
            .get(&instance)
            .map(|record| record.last_error)
            .unwrap_or(0)
    }

    pub fn set_last_error(&mut self, instance: u32, error: u16) {
        if let Some(record) = self.instances.get_mut(&instance) {
            record.last_error = error;
        }
    }

    fn next_free_callback_route(&self) -> Option<u64> {
        let start = self.next_callback_route.max(1);
        let mut route = start;
        loop {
            if !self.callback_routes.contains_key(&route) {
                return Some(route);
            }
            route = route.wrapping_add(1).max(1);
            if route == start {
                return None;
            }
        }
    }

    fn collect_retired_route(&mut self, route: u64) {
        let Some(registration) = self.callback_routes.get(&route).copied() else {
            return;
        };
        if registration.active || !registration.retire_on_idle || registration.in_flight != 0 {
            return;
        }
        self.callback_routes.remove(&route);
        self.retired_callback_tokens
            .push(registration.callback_token);
    }

    fn rollback_callback_event(
        &mut self,
        instance: u32,
        route: u64,
        provisional_created: bool,
        conversation: Option<u32>,
        strings: &BTreeSet<u32>,
        data: Option<u32>,
    ) {
        self.rollback_callback_tokens(instance, conversation, strings, data);
        if provisional_created {
            self.instances.remove(&instance);
            if let Some(pending) = self.pending_initializations.get_mut(&route) {
                pending.host_instance = None;
            }
        }
    }

    fn rollback_callback_tokens(
        &mut self,
        instance: u32,
        conversation: Option<u32>,
        strings: &BTreeSet<u32>,
        data: Option<u32>,
    ) {
        if let Some(conversation) = conversation {
            if self
                .conversations
                .get(&conversation)
                .is_some_and(|record| record.instance == instance)
            {
                self.remove_conversation(conversation);
            }
        }
        for string in strings {
            if self
                .strings
                .get(string)
                .is_some_and(|record| record.instance == instance)
            {
                self.remove_string(*string);
            }
        }
        if let Some(data) = data {
            if self
                .data
                .get(&data)
                .is_some_and(|record| record.instance == instance)
            {
                self.remove_data(data);
            }
        }
    }

    fn allocate_token(&mut self) -> Option<u32> {
        let start = self.next_token.max(1);
        let mut token = start;
        loop {
            if token != 0
                && token != compat_services::win16_dde::callback_class::BLOCK
                && !self.instances.contains_key(&token)
                && !self.reserved_instance_tokens.contains(&token)
                && !self.strings.contains_key(&token)
                && !self.conversations.contains_key(&token)
                && !self.conversation_lists.contains_key(&token)
                && !self.data.contains_key(&token)
            {
                self.next_token = token.wrapping_add(1).max(1);
                return Some(token);
            }
            token = token.wrapping_add(1).max(1);
            if token == start {
                return None;
            }
        }
    }
}
