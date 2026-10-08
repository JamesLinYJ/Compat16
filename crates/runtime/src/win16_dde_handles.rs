//! DDEML guest handle ledgers for strings, conversations, lists, and data.

use std::collections::BTreeSet;

use super::*;

impl Win16DdeState {
    pub fn add_string(&mut self, instance: u32, host: Win16HostDdeString) -> Option<u32> {
        if !self.instances.contains_key(&instance) {
            return None;
        }
        if let Some((guest, _)) = self
            .strings
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host)
        {
            return Some(*guest);
        }
        let token = self.allocate_token()?;
        self.strings
            .insert(token, OwnedDdeHandle { instance, host });
        self.string_references.insert(token, 0);
        Some(token)
    }
    pub fn host_string(&self, guest: u32) -> Option<Win16HostDdeString> {
        self.strings.get(&guest).map(|value| value.host)
    }
    pub fn instance_for_string(&self, guest: u32) -> Option<u32> {
        self.strings.get(&guest).map(|value| value.instance)
    }
    pub fn remove_string(&mut self, guest: u32) -> Option<Win16HostDdeString> {
        self.string_references.remove(&guest);
        self.callback_string_references.remove(&guest);
        self.strings.remove(&guest).map(|value| value.host)
    }

    /// Account for a successful DdeCreateStringHandle or DdeKeepStringHandle.
    pub fn retain_string_reference(&mut self, guest: u32) -> Option<()> {
        let references = self.string_references.get_mut(&guest)?;
        *references = references.checked_add(1)?;
        Some(())
    }

    pub fn string_reference_count(&self, guest: u32) -> Option<u32> {
        self.string_references.get(&guest).copied()
    }

    /// Release one successful native DdeFreeStringHandle reference. Returns
    /// true when the guest token no longer has a mapping and should be retired.
    pub fn release_string_reference(&mut self, guest: u32) -> Option<bool> {
        let references = self.string_references.get(&guest).copied()?;
        if references == 0 {
            return None;
        }
        if references > 1 {
            self.string_references.insert(guest, references - 1);
            return Some(false);
        }
        self.string_references.insert(guest, 0);
        Some(self.retire_unreferenced_string(guest))
    }

    pub fn add_conversation(
        &mut self,
        instance: u32,
        host: Win16HostDdeConversation,
    ) -> Option<u32> {
        if !self.instances.contains_key(&instance) {
            return None;
        }
        if let Some((guest, _)) = self
            .conversations
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host)
        {
            self.query_only_conversations.remove(guest);
            return Some(*guest);
        }
        let token = self.allocate_token()?;
        self.conversations
            .insert(token, OwnedDdeHandle { instance, host });
        Some(token)
    }
    pub fn host_conversation(&self, guest: u32) -> Option<Win16HostDdeConversation> {
        if self.query_only_conversations.contains(&guest) {
            return None;
        }
        self.conversations.get(&guest).map(|value| value.host)
    }
    pub fn host_conversation_for_info(&self, guest: u32) -> Option<Win16HostDdeConversation> {
        self.conversations.get(&guest).map(|value| value.host)
    }
    pub fn add_query_only_conversation(
        &mut self,
        instance: u32,
        host: Win16HostDdeConversation,
    ) -> Option<u32> {
        if !self.instances.contains_key(&instance) {
            return None;
        }
        if let Some((guest, _)) = self.conversations.iter().find(|(guest, value)| {
            value.host == host && !self.query_only_conversations.contains(*guest)
        }) {
            return Some(*guest);
        }
        if let Some((guest, _)) = self.conversations.iter().find(|(guest, value)| {
            value.instance == instance
                && value.host == host
                && self.query_only_conversations.contains(*guest)
        }) {
            return Some(*guest);
        }
        let guest = self.allocate_token()?;
        self.conversations
            .insert(guest, OwnedDdeHandle { instance, host });
        self.query_only_conversations.insert(guest);
        Some(guest)
    }
    pub fn ensure_conversation_info_partner(
        &mut self,
        current_guest_conversation: u32,
        host_partner: Option<Win16HostDdeConversation>,
        partner_guest_instance: Option<u32>,
        query_only: bool,
    ) -> Option<Option<u32>> {
        let Some(host_partner) = host_partner else {
            return (partner_guest_instance.is_none() && !query_only).then_some(None);
        };
        let current_instance = self
            .conversations
            .get(&current_guest_conversation)?
            .instance;
        if query_only {
            if partner_guest_instance.is_some() {
                return None;
            }
            self.add_query_only_conversation(current_instance, host_partner)
                .map(Some)
        } else {
            let partner_instance = partner_guest_instance?;
            if !self.instances.contains_key(&partner_instance) {
                return None;
            }
            if let Some((guest, _)) = self.conversations.iter().find(|(guest, record)| {
                record.instance == partner_instance
                    && record.host == host_partner
                    && !self.query_only_conversations.contains(*guest)
            }) {
                return Some(Some(*guest));
            }
            self.add_conversation(partner_instance, host_partner)
                .map(Some)
        }
    }
    pub fn instance_for_conversation(&self, guest: u32) -> Option<u32> {
        self.conversations.get(&guest).map(|value| value.instance)
    }
    pub fn remove_conversation(&mut self, guest: u32) -> Option<Win16HostDdeConversation> {
        let record = self.conversations.remove(&guest)?;
        self.query_only_conversations.remove(&guest);
        for members in self.list_members.values_mut() {
            members.remove(&guest);
        }
        let strings = self.conversation_strings.remove(&guest).unwrap_or_default();
        for string in strings {
            let still_owned = self
                .conversation_strings
                .values()
                .any(|members| members.contains(&string));
            let references = self.string_references.get(&string).copied().unwrap_or(0);
            if !still_owned && references == 0 {
                self.retire_unreferenced_string(string);
            }
        }
        Some(record.host)
    }

    pub fn note_conversation_string(&mut self, conversation: u32, string: u32) -> bool {
        let Some(owner) = self
            .conversations
            .get(&conversation)
            .map(|record| record.instance)
        else {
            return false;
        };
        if self
            .strings
            .get(&string)
            .is_none_or(|record| record.instance != owner)
        {
            return false;
        }
        self.conversation_strings
            .entry(conversation)
            .or_default()
            .insert(string);
        true
    }

    pub fn add_conversation_list(
        &mut self,
        instance: u32,
        host: Win16HostDdeConversationList,
    ) -> Option<u32> {
        if !self.instances.contains_key(&instance) {
            return None;
        }
        if let Some((guest, _)) = self
            .conversation_lists
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host)
        {
            return Some(*guest);
        }
        let token = self.allocate_token()?;
        self.conversation_lists
            .insert(token, OwnedDdeHandle { instance, host });
        self.list_members.insert(token, BTreeSet::new());
        Some(token)
    }
    pub fn host_conversation_list(&self, guest: u32) -> Option<Win16HostDdeConversationList> {
        self.conversation_lists.get(&guest).map(|value| value.host)
    }
    pub fn instance_for_conversation_list(&self, guest: u32) -> Option<u32> {
        self.conversation_lists
            .get(&guest)
            .map(|value| value.instance)
    }
    pub fn note_list_member(&mut self, guest_list: u32, guest_conversation: u32) -> bool {
        if !self.conversation_lists.contains_key(&guest_list)
            || !self.conversations.contains_key(&guest_conversation)
        {
            return false;
        }
        self.list_members
            .entry(guest_list)
            .or_default()
            .insert(guest_conversation);
        true
    }
    /// Retire all known member tokens returned by native DdeDisconnectList,
    /// including members the guest never obtained through QueryNextServer.
    pub fn remove_disconnected_list(
        &mut self,
        guest: u32,
        members: &[Win16HostDdeConversation],
    ) -> Option<Win16HostDdeConversationList> {
        let instance = self.conversation_lists.get(&guest)?.instance;
        let mut tokens: BTreeSet<u32> = self.list_members.remove(&guest).unwrap_or_default();
        for host in members {
            if let Some((token, _)) = self
                .conversations
                .iter()
                .find(|(_, value)| value.instance == instance && value.host == *host)
            {
                tokens.insert(*token);
            }
        }
        for token in tokens {
            self.remove_conversation(token);
        }
        self.conversation_lists
            .remove(&guest)
            .map(|record| record.host)
    }

    pub fn ensure_string(
        &mut self,
        instance: u32,
        host: Option<Win16HostDdeString>,
    ) -> Option<Option<u32>> {
        let Some(host) = host else {
            return Some(None);
        };
        if let Some((guest, _)) = self
            .strings
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host)
        {
            return Some(Some(*guest));
        }
        self.add_string(instance, host).map(Some)
    }

    pub(super) fn has_string(&self, instance: u32, host: Option<Win16HostDdeString>) -> bool {
        host.is_some_and(|host| {
            self.strings
                .values()
                .any(|record| record.instance == instance && record.host == host)
        })
    }

    pub fn ensure_conversation(
        &mut self,
        instance: u32,
        host: Option<Win16HostDdeConversation>,
    ) -> Option<Option<u32>> {
        let Some(host) = host else {
            return Some(None);
        };
        if let Some((guest, _)) = self
            .conversations
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host)
        {
            return Some(Some(*guest));
        }
        self.add_conversation(instance, host).map(Some)
    }

    pub fn ensure_data(
        &mut self,
        instance: u32,
        host: Option<Win16HostDdeData>,
    ) -> Option<Option<u32>> {
        let Some(host) = host else {
            return Some(None);
        };
        if let Some((guest, _)) = self
            .data
            .iter()
            .find(|(_, value)| value.instance == instance && value.host == host && value.available)
        {
            return Some(Some(*guest));
        }
        self.add_callback_data(instance, host).map(Some)
    }

    pub(super) fn retire_unreferenced_string(&mut self, guest: u32) -> bool {
        let references = self.string_references.get(&guest).copied().unwrap_or(0);
        let callback_references = self
            .callback_string_references
            .get(&guest)
            .copied()
            .unwrap_or(0);
        let anchored = self
            .conversation_strings
            .values()
            .any(|strings| strings.contains(&guest));
        if references == 0 && callback_references == 0 && !anchored {
            self.remove_string(guest);
            true
        } else {
            false
        }
    }
}
