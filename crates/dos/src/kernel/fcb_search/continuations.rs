//! Immutable host enumeration results; each guest FCB carries its own position.
use crate::{DosCallerId, DosErrorCode, DosHostError};

#[derive(Debug)]
pub(super) struct Snapshot {
    pub psp: u16,
    pub caller: DosCallerId,
    pub identity: u32,
    pub drive: u8,
    pub pattern: super::super::state::DosSearchPattern,
    pub records: Vec<[u8; 32]>,
}

#[derive(Debug, Default)]
pub(in super::super) struct Continuations {
    next_identity: u32,
    snapshots: Vec<Snapshot>,
}

impl Continuations {
    pub(super) fn reserve(&mut self) -> Result<u32, DosHostError> {
        if self.snapshots.len() >= u32::MAX as usize - 1 {
            return Err(DosHostError::new(DosErrorCode::InsufficientMemory));
        }
        self.snapshots
            .try_reserve(1)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InsufficientMemory, error))?;
        loop {
            self.next_identity = self.next_identity.wrapping_add(1);
            if self.next_identity != 0
                && !self
                    .snapshots
                    .iter()
                    .any(|s| s.identity == self.next_identity)
            {
                return Ok(self.next_identity);
            }
        }
    }

    pub(super) fn insert(&mut self, snapshot: Snapshot) -> u32 {
        // Repeated probes of an unchanged directory can share immutable data;
        // guest positions are independent and never live in this registry.
        if let Some(existing) = self.snapshots.iter().find(|existing| {
            existing.psp == snapshot.psp
                && existing.caller == snapshot.caller
                && existing.drive == snapshot.drive
                && existing.pattern.name == snapshot.pattern.name
                && existing.pattern.extension == snapshot.pattern.extension
                && existing.records == snapshot.records
        }) {
            return existing.identity;
        }
        // reserve() precedes native enumeration and guest publication.
        let identity = snapshot.identity;
        self.snapshots.push(snapshot);
        identity
    }

    pub(super) fn get(&self, psp: u16, caller: DosCallerId, identity: u32) -> Option<&Snapshot> {
        self.snapshots
            .iter()
            .find(|s| s.psp == psp && s.caller == caller && s.identity == identity)
    }

    pub(in super::super) fn release_psp(&mut self, psp: u16) {
        self.snapshots.retain(|s| s.psp != psp);
    }

    pub(in super::super) fn release_caller(&mut self, caller: DosCallerId) {
        self.snapshots.retain(|s| s.caller != caller);
    }

    pub(in super::super) fn clear(&mut self) {
        self.snapshots.clear();
    }
}
