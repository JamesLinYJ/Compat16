//! Checked guest GlobalHeap copies for native classic-DDE transfer blocks.
//!
//! The worker's HGLOBAL never crosses this module boundary. Each copied guest
//! handle is paired with the exact GlobalHeap generation and EventId that
//! caused its allocation; stale guest WORD reuse is never freed as cleanup.

use guest_core::{memory::Memory, OwnerId};
use win16_abi::global::{GMEM_MOVEABLE, GMEM_ZEROINIT};

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16ClassicDdeEventId,
    Win16ClassicDdeGlobalBlock, Win16ClassicDdeGuestGlobal, Win16ClassicDdeMessage,
    Win16HostClassicDdeEndpoint, Win16HostClassicDdeEvent,
};

use super::Win16State;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClassicDdeGuestGlobalLease {
    pub(super) owner: OwnerId,
    pub(super) endpoint: Win16HostClassicDdeEndpoint,
    pub(super) worker_generation: u64,
    pub(super) event_id: Win16ClassicDdeEventId,
    pub(super) transfer: Option<crate::Win16ClassicDdeTransferId>,
    pub(super) handle: u16,
    pub(super) generation: u64,
    pub(super) content: Vec<u8>,
    pub(super) materialized: bool,
}

impl ClassicDdeGuestGlobalLease {
    fn matches_event(&self, event: &Win16HostClassicDdeEvent) -> bool {
        self.matches_identity(event.owner, event.endpoint, event.worker_generation, event.event_id)
    }

    fn matches_identity(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> bool {
        self.owner == owner
            && self.endpoint == endpoint
            && self.worker_generation == worker_generation
            && self.event_id == event_id
    }

    pub(super) fn guest_token(&self) -> Win16ClassicDdeGuestGlobal {
        Win16ClassicDdeGuestGlobal {
            owner: self.owner,
            handle: self.handle,
            generation: self.generation,
        }
    }
}

impl Win16State {
    /// Materialize the decoded full HGLOBAL snapshot as a guest-owned copy.
    /// The host HGLOBAL stays in its independent transfer ledger. Replaying
    /// the same EventId reuses only the exact matching live guest generation.
    pub(super) fn materialize_classic_dde_event_global(
        &mut self,
        event: &mut Win16HostClassicDdeEvent,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16ClassicDdeGuestGlobal>, RuntimeError> {
        if matches!(&event.message, Win16ClassicDdeMessage::Data {
            flags: crate::Win16ClassicDdeDataFlags {
                raw_flags: 0,
                release_after_receive: false,
                acknowledge_requested: false,
                ..
            },
            global: crate::Win16ClassicDdeGlobalBlock {
                transfer: None,
                guest_global: None,
                bytes,
            },
            ..
        } if bytes.is_empty()) {
            // A warm-link notification has an item atom but no data block to
            // materialize as a guest HGLOBAL.
            return Ok(None);
        }
        let owner = event.owner;
        let endpoint = event.endpoint;
        let worker_generation = event.worker_generation;
        let event_id = event.event_id;
        let Some(block) = global_block_mut(&mut event.message) else { return Ok(None); };
        let current = self.tasks.current().ok_or_else(|| dde_global_invariant(
            "classic DDE HGLOBAL materialization has no current task owner"))?;
        if current != event.owner {
            return Err(dde_global_invariant(
                "classic DDE HGLOBAL materialization crossed the current task owner"));
        }
        let mut content = Vec::new();
        content.try_reserve_exact(block.bytes.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain exact classic DDE transfer bytes for retry", error)
        })?;
        content.extend_from_slice(&block.bytes);
        let existing_index = self.classic_dde.guest_globals.iter().position(|lease|
            lease.matches_identity(owner, endpoint, worker_generation, event_id));
        if let Some(index) = existing_index {
            let existing = &self.classic_dde.guest_globals[index];
            if existing.transfer != block.transfer
                || existing.content != content
                || self.global_handles.get(&existing.handle)
                    .is_none_or(|identity| identity.generation() != existing.generation)
            {
                return Err(dde_global_invariant(
                    "classic DDE EventId replay no longer owns its exact guest HGLOBAL"));
            }
            if existing.materialized {
                let token = existing.guest_token();
                if block.guest_global.is_some_and(|incoming| incoming != token) {
                    return Err(dde_global_invariant(
                        "classic DDE EventId changed its exact materialized HGLOBAL token"));
                }
                block.guest_global = Some(token);
                return Ok(Some(token));
            }
        }
        if block.guest_global.is_some() {
            return Err(dde_global_invariant(
                "classic DDE ingress supplied a guest HGLOBAL without its runtime lease"));
        }
        if block.bytes.is_empty() {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "classic DDE transfer block has no validated header bytes"));
        }
        let size = u32::try_from(block.bytes.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "classic DDE guest transfer exceeds GlobalAlloc size", error)
        })?;
        self.classic_dde.guest_globals.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact classic DDE guest HGLOBAL lease", error)
        })?;

        let (handle, identity) = if let Some(index) = existing_index {
            let lease = &self.classic_dde.guest_globals[index];
            (lease.handle, self.global_handles.get(&lease.handle).copied()
                .ok_or_else(|| dde_global_invariant(
                    "retryable classic DDE HGLOBAL generation disappeared"))?)
        } else {
            let handle = self.global_alloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size, memory, host)?;
            if handle == 0 {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "GlobalAlloc could not materialize a classic DDE guest transfer"));
            }
            let Some(identity) = self.global_handles.get(&handle).copied() else {
                let _ = self.global_free(handle)?;
                return Err(dde_global_invariant(
                    "GlobalAlloc omitted the classic DDE guest HGLOBAL generation"));
            };
            self.classic_dde.guest_globals.push(ClassicDdeGuestGlobalLease {
                owner: event.owner,
                endpoint: event.endpoint,
                worker_generation: event.worker_generation,
                event_id: event.event_id,
                transfer: block.transfer,
                handle,
                generation: identity.generation(),
                content,
                materialized: false,
            });
            (handle, identity)
        };
        let far = self.global_lock(handle, memory)?;
        if far == 0 {
            let cleanup = self.free_classic_dde_guest_global_exact(
                event.owner,
                Win16ClassicDdeGuestGlobal {
                    owner: event.owner,
                    handle,
                    generation: identity.generation(),
                },
            );
            if let Err(cleanup) = cleanup {
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "GlobalLock could not expose the classic DDE guest transfer")
                    .with_cleanup("retire failed DDE guest HGLOBAL copy", cleanup));
            }
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "GlobalLock could not expose the classic DDE guest transfer"));
        }
        let write_result = self.selectors.pointer_from_far(far)
            .map_err(crate::runtime_error)
            .and_then(|pointer| self.selectors.write(memory, pointer, &block.bytes).map_err(crate::runtime_error));
        let unlock_result = self.global_unlock(handle);
        if let Err(error) = write_result {
            let cleanup = self.free_classic_dde_guest_global_exact(
                event.owner,
                Win16ClassicDdeGuestGlobal {
                    owner: event.owner,
                    handle,
                    generation: identity.generation(),
                },
            );
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => error.with_cleanup(
                    "release failed classic DDE guest HGLOBAL copy", cleanup),
            });
        }
        unlock_result?;
        let guest_global = Win16ClassicDdeGuestGlobal {
            owner: event.owner,
            handle,
            generation: identity.generation(),
        };
        let lease = self.classic_dde.guest_globals.iter_mut().find(|lease|
            lease.matches_identity(owner, endpoint, worker_generation, event_id) && lease.handle == handle
                && lease.generation == identity.generation())
            .ok_or_else(|| dde_global_invariant(
                "classic DDE HGLOBAL lease disappeared after copy"))?;
        lease.materialized = true;
        block.guest_global = Some(guest_global);
        Ok(Some(guest_global))
    }

    /// Release a runtime-created transfer copy only after a route has proved
    /// that its consumer no longer needs it. A guest-freed or reused handle
    /// is never freed on behalf of the old lease.
    pub(super) fn free_classic_dde_guest_global_exact(
        &mut self,
        owner: OwnerId,
        guest: Win16ClassicDdeGuestGlobal,
    ) -> Result<(), RuntimeError> {
        if guest.owner != owner {
            return Err(dde_global_invariant(
                "classic DDE guest HGLOBAL release crossed task owner"));
        }
        let index = self.classic_dde.guest_globals.iter().position(|lease|
            lease.owner == owner && lease.handle == guest.handle
                && lease.generation == guest.generation)
            .ok_or_else(|| dde_global_invariant(
                "classic DDE guest HGLOBAL release lost its exact lease"))?;
        let identity = self.global_handles.get(&guest.handle).copied();
        if identity.is_none_or(|identity| identity.generation() != guest.generation) {
            self.classic_dde.guest_globals.remove(index);
            return Ok(());
        }
        if self.global_free(guest.handle)? == 0 {
            if self.global_handles.get(&guest.handle).is_some_and(|identity|
                identity.generation() == guest.generation)
            {
                return Err(dde_global_invariant(
                    "GlobalFree reported success without retiring the exact DDE HGLOBAL"));
            }
            self.classic_dde.guest_globals.remove(index);
            Ok(())
        } else {
            Err(RuntimeError::new(Kind::HostFailure,
                "classic DDE guest HGLOBAL remains locked or pinned"))
        }
    }

    pub(super) fn classic_dde_guest_global_for_event(
        &self,
        event: &Win16HostClassicDdeEvent,
    ) -> Option<Win16ClassicDdeGuestGlobal> {
        self.classic_dde.guest_globals.iter().find(|lease|
            lease.matches_event(event))
            .map(ClassicDdeGuestGlobalLease::guest_token)
    }

    /// Retire the runtime-owned copy for one exact EventId after the DDE
    /// consumer's protocol terminal. This key is intentionally independent of
    /// the native HGLOBAL transfer token and never guesses from a raw WORD.
    pub(super) fn retire_classic_dde_guest_global_key(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        worker_generation: u64,
        event_id: Win16ClassicDdeEventId,
    ) -> Result<bool, RuntimeError> {
        let Some(lease) = self.classic_dde.guest_globals.iter().find(|lease|
            lease.owner == owner && lease.endpoint == endpoint
                && lease.worker_generation == worker_generation
                && lease.event_id == event_id)
        else {
            return Ok(false);
        };
        let token = lease.guest_token();
        self.free_classic_dde_guest_global_exact(owner, token)?;
        Ok(true)
    }

    pub(super) fn retire_classic_dde_guest_global_for_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        guest: Win16ClassicDdeGuestGlobal,
    ) -> Result<(), RuntimeError> {
        if !self.classic_dde_guest_global_for_event(event).is_some_and(|expected|
            expected == guest)
        {
            return Err(dde_global_invariant(
                "classic DDE HGLOBAL retirement changed its exact event lease"));
        }
        self.free_classic_dde_guest_global_exact(event.owner, guest)
    }
}

fn global_block_mut(message: &mut Win16ClassicDdeMessage) -> Option<&mut Win16ClassicDdeGlobalBlock> {
    match message {
        Win16ClassicDdeMessage::Advise { global, .. }
        | Win16ClassicDdeMessage::Poke { global, .. }
        | Win16ClassicDdeMessage::Data { global, .. }
        | Win16ClassicDdeMessage::Execute { global } => Some(global),
        Win16ClassicDdeMessage::Initiate { .. }
        | Win16ClassicDdeMessage::Terminate
        | Win16ClassicDdeMessage::Ack { .. }
        | Win16ClassicDdeMessage::Unadvise { .. }
        | Win16ClassicDdeMessage::Request { .. } => None,
    }
}

fn dde_global_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
