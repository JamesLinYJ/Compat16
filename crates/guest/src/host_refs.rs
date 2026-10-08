//! Owned, typed references for host objects exposed to guest-facing code.
//!
//! A [`HostRef`] contains only an opaque table identity, slot number, and
//! generation. It never contains or casts a native pointer. The associated
//! [`HostRefTable`] owns each value and can release all values belonging to an
//! [`OwnerId`] when that guest owner exits.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::OwnerId;

static NEXT_TABLE_ID: AtomicU64 = AtomicU64::new(1);

/// A typed, opaque reference to an owned host value.
///
/// This handle is safe to copy and store in Rust-side guest state. It is not a
/// host address, and its private fields prevent callers from manufacturing a
/// valid reference by guessing a slot or generation.
pub struct HostRef<T> {
    table_id: u64,
    slot: u32,
    generation: u64,
    value_type: PhantomData<fn() -> T>,
}

impl<T> HostRef<T> {
    fn new(table_id: u64, slot: u32, generation: u64) -> Self {
        Self {
            table_id,
            slot,
            generation,
            value_type: PhantomData,
        }
    }

    /// Return this handle's slot number for diagnostics only.
    pub fn slot_index(self) -> u32 {
        self.slot
    }

    /// Return this handle's generation for diagnostics only.
    pub fn generation(self) -> u64 {
        self.generation
    }
}

impl<T> Copy for HostRef<T> {}

impl<T> Clone for HostRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for HostRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.table_id == other.table_id
            && self.slot == other.slot
            && self.generation == other.generation
    }
}

impl<T> Eq for HostRef<T> {}

impl<T> Hash for HostRef<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.table_id.hash(state);
        self.slot.hash(state);
        self.generation.hash(state);
    }
}

impl<T> fmt::Debug for HostRef<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostRef")
            .field("table_id", &self.table_id)
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish()
    }
}

/// Failures from host-reference lookup or allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostRefError {
    /// The reference came from a different table or names no table slot.
    InvalidHandle,
    /// The slot has been released or reused since this reference was issued.
    StaleHandle,
    /// The table cannot represent another slot or reserve its backing storage.
    CapacityExhausted,
}

impl fmt::Display for HostRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => {
                f.write_str("host reference is invalid or belongs to another table")
            }
            Self::StaleHandle => {
                f.write_str("host reference is stale because its slot was released or reused")
            }
            Self::CapacityExhausted => {
                f.write_str("host reference table cannot allocate another slot")
            }
        }
    }
}

impl std::error::Error for HostRefError {}

struct Slot<T> {
    generation: u64,
    owner: Option<OwnerId>,
    value: Option<T>,
    next_free: Option<u32>,
}

/// Owns host values exposed by opaque, generation-checked references.
///
/// Tables reject handles from other tables, and a released slot receives a
/// new generation before it can be reused. A generation that reaches `u64::MAX`
/// is retired rather than wrapped, so an old handle can never become valid
/// again. Values can be grouped by guest [`OwnerId`] and deterministically
/// dropped with [`HostRefTable::release_owner`].
pub struct HostRefTable<T> {
    table_id: u64,
    slots: Vec<Slot<T>>,
    free_head: Option<u32>,
    len: usize,
}

impl<T> HostRefTable<T> {
    /// Create an empty table with an identity unique to this process lifetime.
    pub fn new() -> Self {
        let table_id = NEXT_TABLE_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .expect("host-reference table identity space exhausted");
        Self {
            table_id,
            slots: Vec::new(),
            free_head: None,
            len: 0,
        }
    }

    /// Number of currently-owned values.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the table owns no values.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a value owned by `owner` and return its opaque typed reference.
    pub fn insert(&mut self, owner: OwnerId, value: T) -> Result<HostRef<T>, HostRefError> {
        if let Some(slot_index) = self.free_head {
            let slot = &mut self.slots[slot_index as usize];
            self.free_head = slot.next_free.take();
            debug_assert!(slot.value.is_none());
            debug_assert!(slot.owner.is_none());
            slot.owner = Some(owner);
            slot.value = Some(value);
            self.len += 1;
            return Ok(HostRef::new(self.table_id, slot_index, slot.generation));
        }

        let slot_index =
            u32::try_from(self.slots.len()).map_err(|_| HostRefError::CapacityExhausted)?;
        self.slots
            .try_reserve(1)
            .map_err(|_| HostRefError::CapacityExhausted)?;
        self.slots.push(Slot {
            generation: 1,
            owner: Some(owner),
            value: Some(value),
            next_free: None,
        });
        self.len += 1;
        Ok(HostRef::new(self.table_id, slot_index, 1))
    }

    /// Borrow a live value, rejecting stale and foreign-table handles.
    pub fn get(&self, reference: HostRef<T>) -> Result<&T, HostRefError> {
        let slot = self.checked_slot(reference)?;
        slot.value.as_ref().ok_or(HostRefError::StaleHandle)
    }

    /// Mutably borrow a live value, rejecting stale and foreign-table handles.
    pub fn get_mut(&mut self, reference: HostRef<T>) -> Result<&mut T, HostRefError> {
        let index = self.checked_slot_index(reference)?;
        self.slots[index]
            .value
            .as_mut()
            .ok_or(HostRefError::StaleHandle)
    }

    /// Return the owner associated with a live reference.
    pub fn owner_of(&self, reference: HostRef<T>) -> Result<OwnerId, HostRefError> {
        self.checked_slot(reference)?
            .owner
            .ok_or(HostRefError::StaleHandle)
    }

    /// Remove a live value from the table and transfer ownership to the caller.
    pub fn remove(&mut self, reference: HostRef<T>) -> Result<T, HostRefError> {
        let index = self.checked_slot_index(reference)?;
        Ok(self.retire_slot(index))
    }

    /// Release a live reference and drop its value immediately.
    pub fn release(&mut self, reference: HostRef<T>) -> Result<(), HostRefError> {
        drop(self.remove(reference)?);
        Ok(())
    }

    /// Drop every value owned by `owner`, invalidating all of its handles.
    ///
    /// Returns the number of values released. Other owners' values and handles
    /// retain their slots and generations.
    pub fn release_owner(&mut self, owner: OwnerId) -> usize {
        let mut released = 0;
        for index in 0..self.slots.len() {
            if self.slots[index].owner == Some(owner) {
                drop(self.retire_slot(index));
                released += 1;
            }
        }
        released
    }

    fn checked_slot(&self, reference: HostRef<T>) -> Result<&Slot<T>, HostRefError> {
        let index = self.checked_slot_index(reference)?;
        Ok(&self.slots[index])
    }

    fn checked_slot_index(&self, reference: HostRef<T>) -> Result<usize, HostRefError> {
        if reference.table_id != self.table_id {
            return Err(HostRefError::InvalidHandle);
        }
        let index = reference.slot as usize;
        let slot = self.slots.get(index).ok_or(HostRefError::InvalidHandle)?;
        if slot.generation != reference.generation || slot.value.is_none() {
            return Err(HostRefError::StaleHandle);
        }
        Ok(index)
    }

    fn retire_slot(&mut self, index: usize) -> T {
        let previous_free_head = self.free_head;
        let slot = &mut self.slots[index];
        let value = slot
            .value
            .take()
            .expect("retiring a live host-reference slot");
        slot.owner = None;
        if let Some(next_generation) = slot.generation.checked_add(1) {
            slot.generation = next_generation;
            slot.next_free = previous_free_head;
            self.free_head = Some(index as u32);
        } else {
            // Never wrap: that could make an ancient reference valid again.
            slot.next_free = None;
        }
        self.len -= 1;
        value
    }
}

impl<T> Default for HostRefTable<T> {
    fn default() -> Self {
        Self::new()
    }
}
