//! Immutable host enumeration results; each guest FCB carries its own position.
use crate::{DosCallerId, DosErrorCode, DosHostError};
use std::mem::size_of;

// Copied guest FCBs can still refer to any retained snapshot, so quota pressure
// must fail new searches rather than evicting a live continuation. Bound both
// the owner and the shared DOS registry, including Vec spare record capacity.
const MAX_OWNER_SNAPSHOTS: usize = 256;
const MAX_TOTAL_SNAPSHOTS: usize = 1024;
const MAX_OWNER_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 4 * MAX_OWNER_BYTES;

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
    pub(super) fn insert(
        &mut self,
        psp: u16,
        caller: DosCallerId,
        drive: u8,
        pattern: super::super::state::DosSearchPattern,
        records: Vec<[u8; 32]>,
    ) -> Result<u32, DosHostError> {
        // Repeated probes of an unchanged directory can share immutable data,
        // even at the quota. Each guest FCB still carries its own position.
        if let Some(existing) = self.snapshots.iter().find(|existing| {
            existing.psp == psp
                && existing.caller == caller
                && existing.drive == drive
                && existing.pattern.name == pattern.name
                && existing.pattern.extension == pattern.extension
                && existing.records == records
        }) {
            return Ok(existing.identity);
        }
        let bytes = records
            .capacity()
            .checked_mul(size_of::<[u8; 32]>())
            .ok_or_else(|| DosHostError::new(DosErrorCode::InsufficientMemory))?;
        let mut owner_count = 0;
        let mut owner_bytes = 0;
        let mut total_bytes = 0;
        for snapshot in &self.snapshots {
            let retained = snapshot.records.capacity() * size_of::<[u8; 32]>();
            total_bytes += retained;
            if snapshot.psp == psp && snapshot.caller == caller {
                owner_count += 1;
                owner_bytes += retained;
            }
        }
        if self.snapshots.len() >= MAX_TOTAL_SNAPSHOTS
            || owner_count >= MAX_OWNER_SNAPSHOTS
            || bytes > MAX_OWNER_BYTES.saturating_sub(owner_bytes)
            || bytes > MAX_TOTAL_BYTES.saturating_sub(total_bytes)
        {
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
                break;
            }
        }
        let identity = self.next_identity;
        self.snapshots.push(Snapshot {
            psp,
            caller,
            identity,
            drive,
            pattern,
            records,
        });
        Ok(identity)
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

#[cfg(test)]
mod tests;
