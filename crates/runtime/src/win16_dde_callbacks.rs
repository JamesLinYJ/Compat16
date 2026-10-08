//! Synchronous DDEML callback projection and frame ownership.

use super::*;

impl Win16DdeState {
    pub fn callback_event(
        &mut self,
        call: &Win16DdeCallbackCall,
    ) -> Result<Win16DdeGuestCallback, Win16DdeCallbackEventError> {
        let registration = self
            .callback_routes
            .get(&call.callback_route)
            .copied()
            .ok_or(Win16DdeCallbackEventError::StaleRoute)?;
        let transaction_type = u16::try_from(call.transaction_type)
            .map_err(|_| Win16DdeCallbackEventError::InvalidProjection)?;
        let data_1 = call
            .data_1
            .ok_or(Win16DdeCallbackEventError::InvalidProjection)?;
        let data_2 = call
            .data_2
            .ok_or(Win16DdeCallbackEventError::InvalidProjection)?;
        if call.host_conversation.is_some_and(|token| token.0 == 0)
            || call.host_string_1.is_some_and(|token| token.0 == 0)
            || call.host_string_2.is_some_and(|token| token.0 == 0)
            || matches!(&call.data, Win16HostDdeCallbackData::Borrowed { handle, .. } if handle.0 == 0)
        {
            return Err(Win16DdeCallbackEventError::InvalidProjection);
        }
        let host_data = match &call.data {
            Win16HostDdeCallbackData::Borrowed { handle, .. } => Some(*handle),
            Win16HostDdeCallbackData::Null | Win16HostDdeCallbackData::SuccessNoData => None,
        };
        let in_flight = registration
            .in_flight
            .checked_add(1)
            .ok_or(Win16DdeCallbackEventError::ResourceExhausted)?;
        let guest_instance = registration.guest_instance;
        let mut provisional_created = false;
        if let Some(instance) = self.instances.get(&guest_instance) {
            if instance.host != call.host_instance {
                return Err(Win16DdeCallbackEventError::InstanceMismatch);
            }
        } else {
            let Some(pending) = self
                .pending_initializations
                .get(&call.callback_route)
                .copied()
            else {
                return Err(Win16DdeCallbackEventError::StaleRoute);
            };
            if pending.guest_instance != guest_instance
                || pending
                    .host_instance
                    .is_some_and(|host| host != call.host_instance)
            {
                return Err(Win16DdeCallbackEventError::InstanceMismatch);
            }
            let Some(pending) = self.pending_initializations.get_mut(&call.callback_route) else {
                return Err(Win16DdeCallbackEventError::InvalidState);
            };
            pending.host_instance = Some(call.host_instance);
            self.instances.insert(
                guest_instance,
                DdeInstanceRecord {
                    host: call.host_instance,
                    guest_callback: pending.guest_callback,
                    callback_token: pending.callback_token,
                    callback_route: call.callback_route,
                    last_error: 0,
                    provisional: true,
                },
            );
            provisional_created = true;
        }
        let callback_token = registration.callback_token;
        let string_1_existed = self.has_string(guest_instance, call.host_string_1);
        let string_2_existed = self.has_string(guest_instance, call.host_string_2);
        let conversation_existed = call.host_conversation.is_some_and(|host| {
            self.conversations
                .values()
                .any(|record| record.instance == guest_instance && record.host == host)
        });
        let data_existed = host_data.is_some_and(|host| {
            self.data
                .values()
                .any(|record| record.instance == guest_instance && record.host == host)
        });
        let conversation = match self.ensure_conversation(guest_instance, call.host_conversation) {
            Some(value) => value,
            None => {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    None,
                    &BTreeSet::new(),
                    None,
                );
                return Err(Win16DdeCallbackEventError::ResourceExhausted);
            }
        };
        let new_conversation = (!conversation_existed).then_some(conversation).flatten();
        let mut borrowed_strings = BTreeSet::new();
        let string_1 = match self.ensure_string(guest_instance, call.host_string_1) {
            Some(string) => string,
            None => {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    None,
                );
                return Err(Win16DdeCallbackEventError::ResourceExhausted);
            }
        };
        if !string_1_existed {
            borrowed_strings.extend(string_1);
        }
        let string_2 = match self.ensure_string(guest_instance, call.host_string_2) {
            Some(string) => string,
            None => {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    None,
                );
                return Err(Win16DdeCallbackEventError::ResourceExhausted);
            }
        };
        if !string_2_existed {
            borrowed_strings.extend(string_2);
        }
        let callback_strings: BTreeSet<u32> = string_1.into_iter().chain(string_2).collect();
        let callback_string_references = callback_strings
            .iter()
            .map(|guest| {
                self.callback_string_references
                    .get(guest)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .map(|next| (*guest, next))
                    .ok_or(Win16DdeCallbackEventError::ResourceExhausted)
            })
            .collect::<Result<Vec<_>, _>>();
        let callback_string_references = match callback_string_references {
            Ok(references) => references,
            Err(error) => {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    None,
                );
                return Err(error);
            }
        };
        let data = match self.ensure_data(guest_instance, host_data) {
            Some(data) => data,
            None => {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    None,
                );
                return Err(Win16DdeCallbackEventError::ResourceExhausted);
            }
        };
        let new_data = (!data_existed).then_some(data).flatten();
        let callback_data_references = if let Some(guest_data) = data {
            let Some(record) = self.data.get(&guest_data) else {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    new_data,
                );
                return Err(Win16DdeCallbackEventError::InvalidState);
            };
            let Some(references) = record.callback_references.checked_add(1) else {
                self.rollback_callback_event(
                    guest_instance,
                    call.callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    new_data,
                );
                return Err(Win16DdeCallbackEventError::ResourceExhausted);
            };
            Some((guest_data, references))
        } else {
            None
        };
        let callback_route = call.callback_route;
        if let Some((guest_data, references)) = callback_data_references {
            let Some(record) = self.data.get_mut(&guest_data) else {
                self.rollback_callback_event(
                    guest_instance,
                    callback_route,
                    provisional_created,
                    new_conversation,
                    &borrowed_strings,
                    new_data,
                );
                return Err(Win16DdeCallbackEventError::InvalidState);
            };
            record.callback_references = references;
        }
        let Some(route) = self.callback_routes.get_mut(&callback_route) else {
            if let Some(guest_data) = data {
                if let Some(record) = self.data.get_mut(&guest_data) {
                    record.callback_references = record.callback_references.saturating_sub(1);
                }
            }
            self.rollback_callback_event(
                guest_instance,
                callback_route,
                provisional_created,
                new_conversation,
                &borrowed_strings,
                new_data,
            );
            return Err(Win16DdeCallbackEventError::InvalidState);
        };
        route.in_flight = in_flight;
        for (guest, references) in callback_string_references {
            self.callback_string_references.insert(guest, references);
        }
        if let (
            Some(guest_data),
            Win16HostDdeCallbackData::Borrowed {
                snapshot: Some(snapshot),
                ..
            },
        ) = (data, &call.data)
        {
            self.callback_data
                .entry(guest_data)
                .or_default()
                .push(snapshot.clone());
        }
        let (callback_data_argument, data_snapshot) = match &call.data {
            Win16HostDdeCallbackData::Null => (0, None),
            Win16HostDdeCallbackData::SuccessNoData => (1, None),
            Win16HostDdeCallbackData::Borrowed { snapshot, .. } => {
                (data.unwrap_or(0), snapshot.clone())
            }
        };
        Ok(Win16DdeGuestCallback {
            guest_instance,
            callback_route,
            callback_token,
            arguments: [
                Win16DdeCallbackArgument::Word(transaction_type),
                Win16DdeCallbackArgument::Word(call.format),
                Win16DdeCallbackArgument::Dword(conversation.unwrap_or(0)),
                Win16DdeCallbackArgument::Dword(string_1.unwrap_or(0)),
                Win16DdeCallbackArgument::Dword(string_2.unwrap_or(0)),
                Win16DdeCallbackArgument::Dword(callback_data_argument),
                Win16DdeCallbackArgument::Dword(data_1),
                Win16DdeCallbackArgument::Dword(data_2),
            ],
            data_guest: data.unwrap_or(0),
            borrowed_strings: borrowed_strings.into_iter().collect(),
            callback_strings: callback_strings.into_iter().collect(),
            data_snapshot,
            conversation_context: call.conversation_context,
        })
    }

    /// Convert a callback DWORD back to either an instance-owned data token or
    /// a DDEML status/scalar according to the transaction's documented return
    /// class. A guest token from another instance is rejected.
    pub fn callback_reply(
        &self,
        callback_route: u64,
        transaction_type: u32,
        value: u32,
    ) -> Option<Win16DdeCallbackReply> {
        let instance = self.callback_routes.get(&callback_route)?.guest_instance;
        let return_class =
            compat_services::win16_dde::callback_class::from_transaction_type(transaction_type)?;
        if return_class != compat_services::win16_dde::callback_class::DATA {
            return Some(Win16DdeCallbackReply::Scalar(value));
        }
        match value {
            0 | compat_services::win16_dde::callback_class::BLOCK => {
                Some(Win16DdeCallbackReply::Scalar(value))
            }
            token => self
                .data
                .get(&token)
                .filter(|handle| handle.instance == instance && handle.available)
                .map(|handle| Win16DdeCallbackReply::Data(handle.host)),
        }
    }

    pub fn end_callback(
        &mut self,
        callback_route: u64,
        guest_data: u32,
        callback_strings: &[u32],
        borrowed_strings: &[u32],
    ) -> Result<Option<Win16DdeRemovedData>, Win16DdeCallbackEventError> {
        if self
            .callback_routes
            .get(&callback_route)
            .is_none_or(|route| route.in_flight == 0)
        {
            return Err(Win16DdeCallbackEventError::InvalidState);
        }
        let unique_strings: BTreeSet<u32> = callback_strings.iter().copied().collect();
        if unique_strings.len() != callback_strings.len()
            || borrowed_strings
                .iter()
                .any(|guest| !unique_strings.contains(guest))
            || unique_strings.iter().any(|guest| {
                self.callback_string_references
                    .get(guest)
                    .is_none_or(|references| *references == 0)
            })
        {
            return Err(Win16DdeCallbackEventError::InvalidState);
        }
        for guest in unique_strings {
            let Some(references) = self.callback_string_references.get_mut(&guest) else {
                return Err(Win16DdeCallbackEventError::InvalidState);
            };
            *references -= 1;
            if *references == 0 {
                self.callback_string_references.remove(&guest);
            }
            self.retire_unreferenced_string(guest);
        }
        if guest_data != 0 {
            if let Some(snapshots) = self.callback_data.get_mut(&guest_data) {
                snapshots.pop();
                if snapshots.is_empty() {
                    self.callback_data.remove(&guest_data);
                }
            }
        }
        let removed = if guest_data == 0 {
            None
        } else {
            if let Some(record) = self.data.get_mut(&guest_data) {
                record.callback_references = record.callback_references.saturating_sub(1);
                if record.origin == Win16DdeDataOrigin::CallbackBorrowed
                    && record.callback_references == 0
                {
                    record.available = false;
                }
            }
            self.release_unowned_data(guest_data)
        };
        self.release_callback_route(callback_route);
        Ok(removed)
    }
}
