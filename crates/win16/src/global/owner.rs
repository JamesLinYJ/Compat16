use super::{GlobalHandle, GlobalHeap, RawGuestHandle, Win16Error};

/// Raw Win16 owner handle recorded for public global-memory blocks. It is a
/// guest HTASK, HMODULE, HGLOBAL, or other owner token; never a heap `OwnerId`
/// or a native handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GuestMemoryOwner(u16);

impl GuestMemoryOwner {
    pub const fn from_raw(raw: u16) -> Self { Self(raw) }
    pub const fn raw(self) -> u16 { self.0 }
}

impl GlobalHeap {
    /// Read the raw Win16 arena owner token attached to a public global block.
    /// Internal-only allocations deliberately return `None`.
    pub fn guest_owner(
        &self,
        handle: GlobalHandle,
    ) -> Result<Option<GuestMemoryOwner>, Win16Error> {
        Ok(self.lookup(handle)?.guest_owner)
    }

    /// Replace a public global block's raw Win16 owner token. This does not
    /// change the separate allocator `OwnerId`, which governs runtime-owned
    /// teardown and is never exposed as a guest handle.
    pub fn set_guest_owner(
        &mut self,
        handle: GlobalHandle,
        owner: GuestMemoryOwner,
    ) -> Result<(), Win16Error> {
        self.lookup(handle)?;
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.guest_owner = Some(owner);
        Ok(())
    }

    /// Snapshot exact live allocation generations whose Win16 arena owner
    /// equals `owner`. Callers still choose public-free or teardown semantics.
    pub fn guest_owned_handles(
        &self,
        owner: GuestMemoryOwner,
    ) -> Result<Vec<GlobalHandle>, Win16Error> {
        let mut handles = Vec::new();
        handles.try_reserve_exact(self.blocks_by_handle.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        for (&raw, block) in &self.blocks_by_handle {
            if block.guest_owner != Some(owner) { continue; }
            let generation = self.generations.get(&raw).copied()
                .ok_or(Win16Error::InvalidHandle)?;
            handles.push(GlobalHandle {
                raw: RawGuestHandle(raw), generation, heap_id: self.id,
            });
        }
        Ok(handles)
    }
}
