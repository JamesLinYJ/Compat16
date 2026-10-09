//! Exact guest global-atom references held by classic WM_DDE events.
//!
//! Native ATOM values never enter this table. Host ingress contains only
//! decoded name bytes; this sidecar materializes actual task-visible WORD
//! values with GlobalAddAtom and retains the corresponding reference until an
//! exact EventId acknowledgement or conversation retirement.

use guest_core::OwnerId;

use crate::{
    RuntimeError, RuntimeHost, Win16ClassicDdeAtom, Win16ClassicDdeConversationId,
    Win16ClassicDdeEventId, Win16HostClassicDdeEvent, Win16HostClassicDdeEndpoint,
    Win16HostClassicDdePeer, Win16HostClassicDdeResult,
};
use win16_abi::Win16AtomName;

use super::Win16State;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventKey {
    owner: OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    event_id: Win16ClassicDdeEventId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConversationKey {
    owner: OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    conversation: Win16ClassicDdeConversationId,
    peer: Win16HostClassicDdePeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomScope {
    Event(EventKey),
    Conversation(ConversationKey),
    ClientOperation {
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        operation: super::ole1::Win16Ole1OperationId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AtomReference {
    scope: AtomScope,
    slot: usize,
    word: u16,
    name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventAtomRecord {
    key: EventKey,
    original: Win16HostClassicDdeEvent,
    /// One entry per named-atom occurrence in stable message field order.
    /// `None` means GlobalAddAtom failed for this occurrence; earlier exact
    /// references remain journaled and are reused on the same EventId retry.
    words: Vec<Option<u16>>,
}

#[derive(Default)]
pub(super) struct ClassicDdeAtomLeases {
    events: Vec<EventAtomRecord>,
    references: Vec<AtomReference>,
}

impl ClassicDdeAtomLeases {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.events.is_empty() || !self.references.is_empty()
    }

    pub(super) fn owner_has_leases(&self, owner: OwnerId) -> bool {
        self.events.iter().any(|event| event.key.owner == owner)
            || self.references.iter().any(|reference| match reference.scope {
                AtomScope::Event(key) => key.owner == owner,
                AtomScope::Conversation(key) => key.owner == owner,
                AtomScope::ClientOperation { owner: candidate, .. } => candidate == owner,
            })
    }
}

impl Win16State {
    /// Materialize the two task-local atom words owned by one exact client
    /// INITIATE attempt. The caller must first reserve that attempt in the
    /// OLE1 client journal; this sidecar then acquires each reference with
    /// GlobalAddAtom and records it under the exact operation before any
    /// later operation can fail.
    pub(in crate::win16_runtime) fn create_classic_dde_client_initiate_atoms(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        operation: super::ole1::Win16Ole1OperationId,
        application_name: &[u8],
        topic_name: &[u8],
        host: &mut impl RuntimeHost,
    ) -> Result<(u16, u16), RuntimeError> {
        if application_name.is_empty()
            || topic_name.is_empty()
            || application_name.contains(&0)
            || topic_name.contains(&0)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InvalidInput,
                "client INITIATE atom names must be nonempty NUL-free byte strings",
            ));
        }

        let scope = AtomScope::ClientOperation {
            owner,
            endpoint,
            operation,
        };
        let mut names = Vec::new();
        names.try_reserve_exact(2).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve exact client INITIATE atom names",
                error,
            )
        })?;
        for source in [application_name, topic_name] {
            let mut name = Vec::new();
            name.try_reserve_exact(source.len()).map_err(|error| {
                RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "copy exact client INITIATE atom spelling",
                    error,
                )
            })?;
            name.extend_from_slice(source);
            names.push(name);
        }
        self.classic_dde.atoms.references.try_reserve(2).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve exact client INITIATE atom leases",
                error,
            )
        })?;

        let mut words = [0u16; 2];
        let mut present = [false; 2];
        for (slot, name) in names.iter().enumerate() {
            let mut existing = self.classic_dde.atoms.references.iter().filter(|reference| {
                reference.scope == scope && reference.slot == slot
            });
            if let Some(reference) = existing.next() {
                if existing.next().is_some()
                    || reference.name.as_slice() != name.as_slice()
                    || reference.word == 0
                {
                    return Err(RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "client INITIATE atom lease changed its exact operation slot",
                    ));
                }
                words[slot] = reference.word;
                present[slot] = true;
            }
        }

        for (slot, name) in names.into_iter().enumerate() {
            if present[slot] {
                continue;
            }
            let actual = match self.global_add_atom(Win16AtomName::String(name.clone()), host) {
                Ok(actual) if actual != 0 => actual,
                Ok(_) => {
                    let mut error = RuntimeError::new(
                        crate::DiagnosticKind::InternalInvariant,
                        "GlobalAddAtom returned the reserved zero client INITIATE WORD",
                    );
                    if let Err(cleanup) = self.retire_classic_dde_client_initiate_atoms(
                        owner, endpoint, operation, host,
                    ) {
                        error = error.with_cleanup(
                            "retire exact partial client INITIATE atom pair",
                            cleanup,
                        );
                    }
                    return Err(error);
                }
                Err(mut error) => {
                    if let Err(cleanup) = self.retire_classic_dde_client_initiate_atoms(
                        owner, endpoint, operation, host,
                    ) {
                        error = error.with_cleanup(
                            "retire exact partial client INITIATE atom pair",
                            cleanup,
                        );
                    }
                    return Err(error);
                }
            };
            self.classic_dde.atoms.references.push(AtomReference {
                scope,
                slot,
                word: actual,
                name,
            });
            words[slot] = actual;
        }

        Ok((words[0], words[1]))
    }

    /// Retain the task-local atom references used by one client INITIATE
    /// attempt. Host messages use only name bytes; the actual guest atom WORD
    /// is retained in this sidecar until bind or exact attempt retirement.
    pub(super) fn retain_classic_dde_initiate_atoms(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        operation: super::ole1::Win16Ole1OperationId,
        application: &Win16ClassicDdeAtom,
        topic: &Win16ClassicDdeAtom,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let scope = AtomScope::ClientOperation { owner, endpoint, operation };
        let mut requested = Vec::new();
        requested.try_reserve_exact(2).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve client INITIATE atom references", error)
        })?;
        requested.push(application);
        requested.push(topic);
        self.classic_dde.atoms.references.try_reserve(2).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve client INITIATE atom lease records", error)
        })?;
        for (slot, atom) in requested.into_iter().enumerate() {
            let (expected, name_bytes) = match atom {
                Win16ClassicDdeAtom::Name {
                    guest_value: Some(expected), name_bytes,
                } => (expected, name_bytes),
                Win16ClassicDdeAtom::Name { guest_value: None, .. } => {
                    return Err(classic_dde_invariant(
                        "outbound client INITIATE name has no guest atom identity"));
                }
                Win16ClassicDdeAtom::Integer(_) => continue,
            };
            if *expected == 0 {
                return Err(classic_dde_invariant(
                    "client INITIATE string atom has the reserved zero guest WORD"));
            }
            let mut existing = self.classic_dde.atoms.references.iter().filter(|reference| {
                reference.scope == scope && reference.slot == slot
            });
            if let Some(reference) = existing.next() {
                if existing.next().is_some()
                    || reference.word != *expected
                    || reference.name.as_slice() != name_bytes.as_slice()
                {
                    return Err(classic_dde_invariant(
                        "client INITIATE atom lease changed its exact operation slot",
                    ));
                }
                continue;
            }
            let mut name = Vec::new();
            name.try_reserve_exact(name_bytes.len()).map_err(|error| {
                RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                    "copy client INITIATE atom spelling", error)
            })?;
            name.extend_from_slice(name_bytes);
            let actual = self.global_add_atom(Win16AtomName::String(name.clone()), host)?;
            if actual == 0 {
                return Err(classic_dde_invariant(
                    "GlobalAddAtom returned zero for a client INITIATE name"));
            }
            // Keep the returned reference even on a mismatched WORD so the
            // caller can fail the attempt without losing ownership of the
            // incremented task-local atom reference.
            self.classic_dde.atoms.references.push(AtomReference {
                scope, slot, word: actual, name,
            });
            if actual != *expected {
                return Err(classic_dde_invariant(
                    "client INITIATE atom WORD did not resolve to its exact name"));
            }
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn retire_classic_dde_client_initiate_atoms(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        operation: super::ole1::Win16Ole1OperationId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let scope = AtomScope::ClientOperation { owner, endpoint, operation };
        let mut index = 0usize;
        while index < self.classic_dde.atoms.references.len() {
            if self.classic_dde.atoms.references[index].scope != scope {
                index += 1;
                continue;
            }
            let word = self.classic_dde.atoms.references[index].word;
            host.win16_global_delete_atom(word)?;
            self.classic_dde.atoms.references.remove(index);
        }
        Ok(())
    }

    /// Resolve every named atom in an inbound event to a real guest GlobalAtom
    /// WORD. Integer atoms remain their protocol value. A partial failure
    /// keeps acquired references attached to the exact EventId so retrying
    /// that event cannot lose or double-delete them.
    pub(super) fn materialize_classic_dde_event_atoms(
        &mut self,
        host_event: &Win16HostClassicDdeEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostClassicDdeEvent, RuntimeError> {
        let key = EventKey {
            owner: host_event.owner,
            endpoint: host_event.endpoint,
            worker_generation: host_event.worker_generation,
            event_id: host_event.event_id,
        };
        if key.event_id.0 == 0 || key.worker_generation == 0 {
            return Err(classic_dde_invariant(
                "classic DDE ingress omitted its event or worker generation",
            ));
        }
        if has_host_supplied_guest_atom(&host_event.message) {
            return Err(classic_dde_invariant(
                "native classic DDE ingress supplied a guest atom word",
            ));
        }
        let index = if let Some(index) = self.classic_dde.atoms.events.iter().position(|record|
            record.key == key)
        {
            let record = &self.classic_dde.atoms.events[index];
            if record.original != *host_event {
                return Err(classic_dde_invariant(
                    "classic DDE EventId was replayed with different atom/message contents"));
            }
            index
        } else {
            self.classic_dde.atoms.events.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                    "reserve classic DDE inbound atom-event owner", error)
            })?;
            let slots = named_atom_count(&host_event.message);
            self.classic_dde.atoms.references.try_reserve(slots).map_err(|error| {
                RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                    "reserve classic DDE inbound atom references", error)
            })?;
            let mut words = Vec::new();
            words.try_reserve_exact(slots).map_err(|error| {
                RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                    "reserve classic DDE atom occurrence map", error)
            })?;
            words.resize(slots, None);
            self.classic_dde.atoms.events.push(EventAtomRecord {
                key,
                original: host_event.clone(),
                words,
            });
            self.classic_dde.atoms.events.len() - 1
        };

        let unresolved = self.classic_dde.atoms.events[index]
            .words.iter().filter(|word| word.is_none()).count();
        self.classic_dde.atoms.references.try_reserve(unresolved).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve retryable classic DDE atom references", error)
        })?;
        let names = named_atom_names(&host_event.message)?;
        if names.len() != self.classic_dde.atoms.events[index].words.len() {
            return Err(classic_dde_invariant(
                "classic DDE atom field order changed during materialization"));
        }
        for (slot, name) in names.iter().enumerate() {
            if self.classic_dde.atoms.events[index].words[slot].is_some() {
                continue;
            }
            let word = self.global_add_atom(
                Win16AtomName::String(name.clone()), host,
            )?;
            if word == 0 {
                return Err(classic_dde_invariant(
                    "GlobalAddAtom did not materialize a guest atom word"));
            }
            self.classic_dde.atoms.events[index].words[slot] = Some(word);
            self.classic_dde.atoms.references.push(AtomReference {
                scope: AtomScope::Event(key),
                slot,
                word,
                name: name.clone(),
            });
        }

        let words = self.classic_dde.atoms.events[index].words.clone();
        let mut materialized = host_event.clone();
        let mut slot = 0usize;
        visit_atoms_mut(&mut materialized.message, &mut |atom| {
            if let Some(Win16ClassicDdeAtom::Name { guest_value, .. }) = atom.as_mut() {
                *guest_value = words.get(slot).copied().flatten();
                slot += 1;
            }
        });
        if slot != words.len() || words.iter().any(Option::is_none) {
            return Err(classic_dde_invariant(
                "classic DDE inbound atom materialization is incomplete"));
        }
        Ok(materialized)
    }

    /// Promote the exact INITIATE name references after an accepted native
    /// conversation receipt. Both synchronous server replies and client
    /// BindConversation receipts use their typed event/conversation identity.
    pub(super) fn bind_classic_dde_initiate_atoms(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        result: &Win16HostClassicDdeResult,
    ) -> Result<(), RuntimeError> {
        let (receipt_owner, receipt_endpoint, receipt_generation, receipt_event,
            receipt_peer, receipt_conversation, application, topic) = match result {
            Win16HostClassicDdeResult::InitiateReplied(receipt) if receipt.accepted => (
                receipt.owner, receipt.endpoint, worker_generation, receipt.event_id,
                receipt.peer, receipt.conversation.ok_or_else(|| classic_dde_invariant(
                    "accepted WM_DDE_INITIATE receipt omitted its conversation"))?,
                &receipt.application_atom, &receipt.topic_atom,
            ),
            Win16HostClassicDdeResult::ConversationBound(receipt) => (
                receipt.owner, receipt.endpoint, receipt.source_operation.worker_generation,
                receipt.initiate_event_id, receipt.peer, receipt.conversation,
                &receipt.application, &receipt.topic,
            ),
            _ => return Err(classic_dde_invariant(
                "nonaccepted or unrelated classic DDE result cannot bind INITIATE atoms")),
        };
        if receipt_owner != owner || receipt_endpoint != endpoint
            || receipt_generation != worker_generation || receipt_event != event_id
            || receipt_peer != peer || receipt_conversation != conversation
        {
            return Err(classic_dde_invariant(
                "classic DDE conversation receipt does not match its exact INITIATE event"));
        }
        let key = EventKey { owner, endpoint, worker_generation, event_id };
        let record = self.classic_dde.atoms.events.iter().find(|record| record.key == key)
            .ok_or_else(|| classic_dde_invariant(
                "classic DDE INITIATE receipt has no materialized event atom lease"))?;
        let (input_app, input_topic) = match &record.original.message {
            crate::Win16ClassicDdeMessage::Initiate { application, topic } =>
                (application, topic),
            crate::Win16ClassicDdeMessage::Ack {
                value: crate::Win16ClassicDdeAckValue::InitiateAtoms { application, topic }, ..
            } => (application, topic),
            _ => return Err(classic_dde_invariant(
                "classic DDE conversation receipt is not backed by an INITIATE event")),
        };
        validate_bound_atom(input_app.as_ref(), application.as_ref(), &record.words)?;
        validate_bound_atom(input_topic.as_ref(), topic.as_ref(), &record.words)?;
        let conversation_key = ConversationKey {
            owner, endpoint, worker_generation, conversation, peer,
        };
        for reference in &mut self.classic_dde.atoms.references {
            if reference.scope == AtomScope::Event(key) {
                reference.scope = AtomScope::Conversation(conversation_key);
            }
        }
        self.classic_dde.atoms.events.remove(
            self.classic_dde.atoms.events.iter().position(|record| record.key == key)
                .ok_or_else(|| classic_dde_invariant(
                    "classic DDE INITIATE atom owner disappeared during binding"))?,
        );
        Ok(())
    }

    /// Atomically transfer both sides of one client INITIATE binding: the
    /// exact incoming ACK EventId references and the outbound application /
    /// topic references retained by the OLE operation. All receipt and lease
    /// checks happen before either scope is changed, so a failed check cannot
    /// leave half of a conversation's atoms promoted.
    pub(super) fn bind_classic_dde_client_conversation_atoms(
        &mut self,
        operation: super::ole1::Win16Ole1OperationId,
        identity: crate::Win16ClassicDdeOperationIdentity,
        atoms: super::ole1::Win16Ole1ClientDdeConversationAtoms,
        result: &Win16HostClassicDdeResult,
    ) -> Result<(), RuntimeError> {
        let Win16HostClassicDdeResult::ConversationBound(receipt) = result else {
            return Err(classic_dde_invariant(
                "client atom promotion requires an exact ConversationBound receipt"));
        };
        if receipt.owner != atoms.owner
            || receipt.endpoint != atoms.endpoint
            || receipt.conversation != atoms.conversation
            || receipt.initiate_event_id != atoms.source_event_id
            || receipt.source_operation.owner != identity.owner
            || receipt.source_operation.worker_generation != identity.worker_generation
            || receipt.source_operation.id.0 == 0
            || identity.owner != atoms.owner
        {
            return Err(classic_dde_invariant(
                "client atom promotion receipt changed its operation or conversation identity"));
        }

        let event_key = EventKey {
            owner: atoms.owner,
            endpoint: atoms.endpoint,
            worker_generation: identity.worker_generation,
            event_id: atoms.source_event_id,
        };
        let event_record = self.classic_dde.atoms.events.iter()
            .find(|record| record.key == event_key)
            .ok_or_else(|| classic_dde_invariant(
                "client conversation receipt has no exact incoming atom event"))?;
        let (incoming_application, incoming_topic) = match &event_record.original.message {
            crate::Win16ClassicDdeMessage::Ack {
                value: crate::Win16ClassicDdeAckValue::InitiateAtoms {
                    application, topic,
                }, ..
            } => (application.as_ref(), topic.as_ref()),
            _ => return Err(classic_dde_invariant(
                "client ConversationBound source event is not an INITIATE ACK")),
        };
        let (application_name, application_word) = named_atom_identity(
            incoming_application, receipt.application.as_ref(),
        )?;
        let (topic_name, topic_word) = named_atom_identity(
            incoming_topic, receipt.topic.as_ref(),
        )?;
        if event_record.words.as_slice() != [Some(application_word), Some(topic_word)]
            || atoms.application_atom != application_word
            || atoms.topic_atom != topic_word
        {
            return Err(classic_dde_invariant(
                "client INITIATE atom WORDs do not match the exact event lease"));
        }

        let operation_scope = AtomScope::ClientOperation {
            owner: atoms.owner,
            endpoint: atoms.endpoint,
            operation,
        };
        let mut application_match = false;
        let mut application_count = 0usize;
        let mut topic_match = false;
        let mut topic_count = 0usize;
        for reference in &self.classic_dde.atoms.references {
            if reference.scope != operation_scope {
                continue;
            }
            match reference.slot {
                0 => {
                    application_count += 1;
                    application_match = reference.word == application_word
                        && reference.name.as_slice() == application_name;
                }
                1 => {
                    topic_count += 1;
                    topic_match = reference.word == topic_word
                        && reference.name.as_slice() == topic_name;
                }
                _ => return Err(classic_dde_invariant(
                    "client INITIATE operation owns an unexpected atom slot")),
            }
        }
        if application_count != 1 || topic_count != 1
            || !application_match || !topic_match
        {
            return Err(classic_dde_invariant(
                "client INITIATE conversation does not own its exact outbound atom references"));
        }

        let target_scope = AtomScope::Conversation(ConversationKey {
            owner: atoms.owner,
            endpoint: atoms.endpoint,
            worker_generation: identity.worker_generation,
            conversation: atoms.conversation,
            peer: receipt.peer,
        });
        for reference in &mut self.classic_dde.atoms.references {
            if reference.scope == AtomScope::Event(event_key)
                || reference.scope == operation_scope
            {
                reference.scope = target_scope;
            }
        }
        let event_index = self.classic_dde.atoms.events.iter()
            .position(|record| record.key == event_key)
            .ok_or_else(|| classic_dde_invariant(
                "client INITIATE event lease disappeared during atomic transfer"))?;
        self.classic_dde.atoms.events.remove(event_index);
        Ok(())
    }

    /// Release only atom references still owned by this exact queued event.
    /// References promoted to a conversation remain live until its exact
    /// RetireConversation terminal is consumed.
    pub(super) fn retire_classic_dde_event_atoms(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.retire_classic_dde_event_atoms_by_key(
            event.owner, event.endpoint, event.worker_generation, event.event_id, host,
        )
    }

    pub(super) fn retire_classic_dde_event_atoms_by_key(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let key = EventKey { owner, endpoint, worker_generation, event_id };
        let mut index = 0usize;
        while index < self.classic_dde.atoms.references.len() {
            if self.classic_dde.atoms.references[index].scope != AtomScope::Event(key) {
                index += 1;
                continue;
            }
            let word = self.classic_dde.atoms.references[index].word;
            host.win16_global_delete_atom(word)?;
            self.classic_dde.atoms.references.remove(index);
        }
        if let Some(event_index) = self.classic_dde.atoms.events.iter()
            .position(|record| record.key == key)
        {
            self.classic_dde.atoms.events.remove(event_index);
        }
        Ok(())
    }

    pub(super) fn retire_classic_dde_conversation_atoms(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        conversation: Win16ClassicDdeConversationId,
        peer: Win16HostClassicDdePeer,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let key = ConversationKey { owner, endpoint, worker_generation, conversation, peer };
        let mut index = 0usize;
        while index < self.classic_dde.atoms.references.len() {
            if self.classic_dde.atoms.references[index].scope != AtomScope::Conversation(key) {
                index += 1;
                continue;
            }
            host.win16_global_delete_atom(self.classic_dde.atoms.references[index].word)?;
            self.classic_dde.atoms.references.remove(index);
        }
        Ok(())
    }
}

fn validate_bound_atom(
    incoming: Option<&Win16ClassicDdeAtom>,
    receipt: Option<&Win16ClassicDdeAtom>,
    words: &[Option<u16>],
) -> Result<(), RuntimeError> {
    match (incoming, receipt) {
        (None, None) => Ok(()),
        (Some(Win16ClassicDdeAtom::Integer(left)), Some(Win16ClassicDdeAtom::Integer(right)))
            if left == right => Ok(()),
        (Some(Win16ClassicDdeAtom::Name { name_bytes: left, .. }),
            Some(Win16ClassicDdeAtom::Name { guest_value: Some(word), name_bytes: right }))
            if left == right && words.iter().any(|found| *found == Some(*word)) => Ok(()),
        _ => Err(classic_dde_invariant(
            "classic DDE conversation atom receipt does not echo the guest event atom")),
    }
}

fn named_atom_identity<'a>(
    incoming: Option<&'a Win16ClassicDdeAtom>,
    receipt: Option<&'a Win16ClassicDdeAtom>,
) -> Result<(&'a [u8], u16), RuntimeError> {
    match (incoming, receipt) {
        (
            Some(Win16ClassicDdeAtom::Name { name_bytes: incoming_name, .. }),
            Some(Win16ClassicDdeAtom::Name {
                guest_value: Some(word), name_bytes: receipt_name,
            }),
        ) if incoming_name == receipt_name && *word != 0 => Ok((receipt_name, *word)),
        _ => Err(classic_dde_invariant(
            "client INITIATE receipt lacks the exact named guest atom")),
    }
}

fn named_atom_count(message: &crate::Win16ClassicDdeMessage) -> usize {
    let mut count = 0usize;
    visit_atoms(message, &mut |atom| {
        if matches!(atom, Some(Win16ClassicDdeAtom::Name { .. })) {
            count = count.saturating_add(1);
        }
    });
    count
}

fn named_atom_names(message: &crate::Win16ClassicDdeMessage) -> Result<Vec<Vec<u8>>, RuntimeError> {
    let mut names = Vec::new();
    names.try_reserve_exact(named_atom_count(message)).map_err(|error| {
        RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
            "reserve classic DDE atom name references", error)
    })?;
    visit_atoms(message, &mut |atom| {
        if let Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) = atom {
            names.push(name_bytes.clone());
        }
    });
    Ok(names)
}

fn has_host_supplied_guest_atom(message: &crate::Win16ClassicDdeMessage) -> bool {
    let mut invalid = false;
    visit_atoms(message, &mut |atom| {
        invalid |= matches!(atom, Some(Win16ClassicDdeAtom::Name {
            guest_value: Some(_), ..
        }));
    });
    invalid
}

fn visit_atoms(
    message: &crate::Win16ClassicDdeMessage,
    visit: &mut impl FnMut(&Option<Win16ClassicDdeAtom>),
) {
    use crate::Win16ClassicDdeMessage as Message;
    match message {
        Message::Initiate { application, topic } => {
            visit(application); visit(topic);
        }
        Message::Ack { value, .. } => match value {
            crate::Win16ClassicDdeAckValue::InitiateAtoms { application, topic } => {
                visit(application); visit(topic);
            }
            crate::Win16ClassicDdeAckValue::ItemAtom(item) => visit(item),
            crate::Win16ClassicDdeAckValue::ExecuteTransfer(_) |
            crate::Win16ClassicDdeAckValue::Unmatched => {}
        },
        Message::Advise { item, .. } | Message::Unadvise { item, .. } |
        Message::Request { item, .. } | Message::Poke { item, .. } |
        Message::Data { item, .. } => visit(item),
        Message::Terminate | Message::Execute { .. } => {}
    }
}

fn visit_atoms_mut(
    message: &mut crate::Win16ClassicDdeMessage,
    visit: &mut impl FnMut(&mut Option<Win16ClassicDdeAtom>),
) {
    use crate::Win16ClassicDdeMessage as Message;
    match message {
        Message::Initiate { application, topic } => {
            visit(application); visit(topic);
        }
        Message::Ack { value, .. } => match value {
            crate::Win16ClassicDdeAckValue::InitiateAtoms { application, topic } => {
                visit(application); visit(topic);
            }
            crate::Win16ClassicDdeAckValue::ItemAtom(item) => visit(item),
            crate::Win16ClassicDdeAckValue::ExecuteTransfer(_) |
            crate::Win16ClassicDdeAckValue::Unmatched => {}
        },
        Message::Advise { item, .. } | Message::Unadvise { item, .. } |
        Message::Request { item, .. } | Message::Poke { item, .. } |
        Message::Data { item, .. } => visit(item),
        Message::Terminate | Message::Execute { .. } => {}
    }
}

fn classic_dde_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(crate::DiagnosticKind::InternalInvariant, message)
}
