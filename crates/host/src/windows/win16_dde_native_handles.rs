//! Native DDEML string, conversation, and list handle registry.

use super::*;

impl NativeState {
    pub(super) fn intern_string(
        &mut self,
        instance: Win16HostDdeInstance,
        native: HSZ,
    ) -> Result<Option<Win16HostDdeString>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let key = (instance, native as usize);
        if let Some(token) = self.strings_by_native.get(&key).copied() {
            if self
                .strings
                .get(&token)
                .is_some_and(|record| record.instance == instance)
            {
                return Ok(Some(token));
            }
            return Err(protocol_error(
                "native DDE string-token table is inconsistent",
            ));
        }
        let token = Win16HostDdeString(self.token()?);
        self.strings.insert(
            token,
            OwnedStringHandle {
                instance,
                native,
                references: 0,
                callback_references: 0,
                data_references: 0,
                retired: false,
            },
        );
        self.strings_by_native.insert(key, token);
        Ok(Some(token))
    }

    pub(super) fn retain_string(&mut self, token: Win16HostDdeString) -> Result<(), RuntimeError> {
        let record = self
            .strings
            .get_mut(&token)
            .ok_or_else(|| protocol_error("DDE string reference names an unknown host token"))?;
        record.references = record.references.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE string reference count is exhausted",
            )
        })?;
        Ok(())
    }

    pub(super) fn unpin_callback_string(
        &mut self,
        token: Win16HostDdeString,
    ) -> Result<(), RuntimeError> {
        let record = self
            .strings
            .get_mut(&token)
            .ok_or_else(|| protocol_error("DDE callback string pin references an unknown token"))?;
        if record.callback_references == 0 {
            return Err(protocol_error("DDE callback string pin count underflow"));
        }
        record.callback_references -= 1;
        if record.retired && record.callback_references == 0 {
            self.strings.remove(&token);
            return Ok(());
        }
        self.forget_unretained_string(token);
        Ok(())
    }

    pub(super) fn release_string(&mut self, token: Win16HostDdeString) {
        let retire = {
            let Some(record) = self.strings.get_mut(&token) else {
                return;
            };
            record.references = record.references.saturating_sub(1);
            record.references == 0
        };
        if retire {
            self.forget_unretained_string(token);
        }
    }

    pub(super) fn discard_unreferenced_string(&mut self, token: Win16HostDdeString) {
        let Some(record) = self.strings.get(&token).copied() else {
            return;
        };
        if record.references == 0 && record.callback_references == 0 && record.data_references == 0
        {
            self.strings.remove(&token);
            self.strings_by_native
                .remove(&(record.instance, record.native as usize));
        }
    }

    pub(super) fn forget_unretained_string(&mut self, token: Win16HostDdeString) {
        let Some(record) = self.strings.get(&token).copied() else {
            return;
        };
        let conversation_owned = self
            .conversation_strings
            .values()
            .any(|strings| strings.contains(&token));
        if record.references == 0
            && record.callback_references == 0
            && record.data_references == 0
            && !conversation_owned
        {
            self.strings.remove(&token);
            self.strings_by_native
                .remove(&(record.instance, record.native as usize));
        }
    }

    pub(super) fn note_conversation_string(
        &mut self,
        conversation: Win16HostDdeConversation,
        string: Win16HostDdeString,
    ) -> Result<(), RuntimeError> {
        let conversation_owner = self
            .conversations
            .get(&conversation)
            .or_else(|| self.query_only_conversations.get(&conversation))
            .map(|record| record.instance)
            .ok_or_else(|| {
                protocol_error("DDE conversation info references an unknown conversation token")
            })?;
        let string_owner = self
            .strings
            .get(&string)
            .ok_or_else(|| {
                protocol_error("DDE conversation info references an unknown string token")
            })?
            .instance;
        if conversation_owner != string_owner {
            return Err(protocol_error(
                "DDE conversation info string belongs to another instance",
            ));
        }
        self.conversation_strings
            .entry(conversation)
            .or_default()
            .insert(string);
        Ok(())
    }

    pub(super) fn intern_conversation(
        &mut self,
        instance: Win16HostDdeInstance,
        native: HCONV,
    ) -> Result<Option<Win16HostDdeConversation>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let key = native as usize;
        if let Some(token) = self.conversations_by_native.get(&key).copied() {
            if self
                .conversations
                .get(&token)
                .is_some_and(|record| record.instance == instance)
            {
                return Ok(Some(token));
            }
            return Err(protocol_error(
                "native DDE conversation belongs to another instance",
            ));
        }
        let token = Win16HostDdeConversation(self.token()?);
        self.conversations
            .insert(token, OwnedHandle { instance, native });
        self.conversations_by_native.insert(key, token);
        Ok(Some(token))
    }

    pub(super) fn intern_conversation_info_partner(
        &mut self,
        instance: Win16HostDdeInstance,
        native: HCONV,
    ) -> Result<(Option<Win16HostDdeConversation>, bool), RuntimeError> {
        if native.is_null() {
            return Ok((None, false));
        }
        let key = native as usize;
        if let Some(token) = self.conversations_by_native.get(&key).copied() {
            if self
                .conversations
                .get(&token)
                .is_some_and(|record| record.native == native)
            {
                return Ok((Some(token), false));
            }
            return Err(protocol_error(
                "native DDE conversation owner table is inconsistent",
            ));
        }
        let alias_key = (instance, key);
        if let Some(token) = self.query_only_by_native.get(&alias_key).copied() {
            if self
                .query_only_conversations
                .get(&token)
                .is_some_and(|record| record.instance == instance && record.native == native)
            {
                return Ok((Some(token), true));
            }
            return Err(protocol_error(
                "native DDE query-only conversation table is inconsistent",
            ));
        }
        let token = Win16HostDdeConversation(self.token()?);
        self.query_only_conversations
            .insert(token, OwnedHandle { instance, native });
        self.query_only_by_native.insert(alias_key, token);
        Ok((Some(token), true))
    }

    pub(super) fn intern_list(
        &mut self,
        instance: Win16HostDdeInstance,
        native: HCONVLIST,
    ) -> Result<Option<Win16HostDdeConversationList>, RuntimeError> {
        if native.is_null() {
            return Ok(None);
        }
        let key = native as usize;
        if let Some(token) = self.lists_by_native.get(&key).copied() {
            if self
                .conversation_lists
                .get(&token)
                .is_some_and(|record| record.instance == instance)
            {
                return Ok(Some(token));
            }
            return Err(protocol_error(
                "native DDE conversation list belongs to another instance",
            ));
        }
        let token = Win16HostDdeConversationList(self.token()?);
        self.conversation_lists
            .insert(token, OwnedHandle { instance, native });
        self.lists_by_native.insert(key, token);
        self.list_members.insert(token, BTreeSet::new());
        Ok(Some(token))
    }
}
