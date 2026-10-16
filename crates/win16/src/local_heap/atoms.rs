//! Guest-resident local atoms. This private format is an implementation policy,
//! not an SDK layout guarantee: DS:8 contains a fixed table handle; the table
//! holds a WORD bucket count followed by WORD entry handles. Each fixed entry
//! holds its next handle, reference count, byte length, original name and NUL.
//! Runtime code performs ANSI decoding and Unicode name comparison. This layer
//! owns only guest bytes and never caches names or atom membership on the host.
//! Reinitializing the underlying local heap can invalidate these allocations.
//! LocalInit preserves DS:8; a dangling nonzero pointer is consequently reported
//! as atom-table corruption rather than silently cleared or reinitialized.

use super::{
    ARENA_HEADER_BYTES, LMEM_ZEROINIT, MIN_ARENA_EXTENT, MOVEABLE_PREFIX_BYTES,
    LocalHeap, LocalHeapError, read_word, write_byte, write_word,
};

const INSTANCE_ATOM_POINTER_OFFSET: usize = 8;
const DEFAULT_BUCKETS: u16 = 37;
const STRING_ATOM_BASE: u16 = 0xc000;
const TABLE_HEADER_BYTES: usize = 2;
const ENTRY_NAME_OFFSET: usize = 5;

/// An owned snapshot of one validated guest-resident string atom.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAtomEntry {
    pub atom: u16,
    /// Fixed local-heap handle, also the entry's near address.
    pub handle: u16,
    pub references: u16,
    /// Original guest ANSI/DBCS bytes, excluding the terminating NUL.
    pub name: Vec<u8>,
}

struct StoredAtom {
    entry: LocalAtomEntry,
    /// WORD that points to this entry, either a bucket head or predecessor.
    link_offset: usize,
    next: u16,
}

struct AtomTable {
    handle: u16,
    buckets: u16,
    entries: Vec<StoredAtom>,
}

impl LocalHeap<'_> {
    /// Validates the complete table and returns all guest string atoms.
    /// An unset DS:8 pointer is an empty table and does not allocate anything.
    pub fn atom_entries(&self) -> Result<Vec<LocalAtomEntry>, LocalHeapError> {
        let Some(table) = self.atom_table()? else { return Ok(Vec::new()) };
        let mut entries = Vec::new();
        entries.try_reserve_exact(table.entries.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
        entries.extend(table.entries.into_iter().map(|stored| stored.entry));
        Ok(entries)
    }

    /// Initializes a fixed atom table. Zero requests the 37-bucket default;
    /// negative requests and unrepresentable initial sizes fail. Once
    /// initialized, a valid repeated request succeeds without resizing or
    /// discarding existing atoms.
    /// This bounded initialization policy does not promise Windows' private
    /// resizing behavior. Returns a Win16 BOOL.
    pub fn atom_init(&mut self, buckets: i16) -> Result<u16, LocalHeapError> {
        self.transaction_when(|heap| {
            let Some(count) = bucket_count(buckets) else { return Ok(0) };
            if heap.atom_table()?.is_some() {
                return Ok(1);
            }
            Ok(u16::from(heap.allocate_atom_table(count)? != 0))
        }, |value| value != 0)
    }

    /// Adds original guest bytes, or increments a previously matched atom.
    /// `matching_atom` must come from this heap's current validated snapshot;
    /// the caller supplies the hash of its Unicode-normalized comparison key.
    /// Empty, embedded-NUL, overlong, exhausted and saturated requests return
    /// zero with the entire guest segment and write set unchanged.
    pub fn atom_add(
        &mut self,
        name: &[u8],
        matching_atom: Option<u16>,
        hash: u32,
    ) -> Result<u16, LocalHeapError> {
        self.transaction_when(|heap| {
            if name.is_empty() || name.len() > u8::MAX as usize || name.contains(&0) {
                return Ok(0);
            }
            let table = heap.atom_table()?;
            if let Some(atom) = matching_atom {
                let Some(stored) = table.as_ref()
                    .and_then(|table| table.entries.iter().find(|stored| stored.entry.atom == atom))
                else { return Ok(0) };
                let Some(references) = stored.entry.references.checked_add(1) else { return Ok(0) };
                heap.atom_write_word(usize::from(stored.entry.handle) + 2, references)?;
                return Ok(atom);
            }
            let (table_handle, buckets) = match table {
                Some(table) => (table.handle, table.buckets),
                None => {
                    let handle = heap.allocate_atom_table(DEFAULT_BUCKETS)?;
                    if handle == 0 {
                        return Ok(0);
                    }
                    (handle, DEFAULT_BUCKETS)
                }
            };
            let size = (ENTRY_NAME_OFFSET + name.len() + 1) as u16;
            let handle = heap.alloc_inner(0, size)?;
            if handle == 0 {
                return Ok(0);
            }
            let bucket_offset = usize::from(table_handle) + TABLE_HEADER_BYTES
                + (hash % u32::from(buckets)) as usize * 2;
            let next = heap.atom_read_word(bucket_offset)?;
            let offset = usize::from(handle);
            heap.atom_write_word(offset, next)?;
            heap.atom_write_word(offset + 2, 1)?;
            heap.atom_write_byte(offset + 4, name.len() as u8)?;
            for (index, byte) in name.iter().copied().enumerate() {
                heap.atom_write_byte(offset + ENTRY_NAME_OFFSET + index, byte)?;
            }
            heap.atom_write_byte(offset + ENTRY_NAME_OFFSET + name.len(), 0)?;
            heap.atom_write_word(bucket_offset, handle)?;
            Ok(atom_for_handle(handle))
        }, |value| value != 0)
    }

    /// Decrements an atom reference, freeing and unlinking the entry at zero.
    /// A stale or nonmember atom returns its original value without writes.
    pub fn atom_delete(&mut self, atom: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| {
            let Some(table) = heap.atom_table()? else { return Ok(atom) };
            let Some(stored) = table.entries.iter().find(|stored| stored.entry.atom == atom)
            else { return Ok(atom) };
            if stored.entry.references > 1 {
                heap.atom_write_word(usize::from(stored.entry.handle) + 2,
                    stored.entry.references - 1)?;
            } else {
                heap.atom_write_word(stored.link_offset, stored.next)?;
                if heap.free_inner(stored.entry.handle)? != 0 {
                    return Err(corrupt(usize::from(stored.entry.handle)));
                }
            }
            Ok(0)
        })
    }

    /// Returns a live string atom's fixed entry handle, or zero if not a member.
    pub fn atom_handle(&self, atom: u16) -> Result<u16, LocalHeapError> {
        Ok(self.atom_table()?.and_then(|table| table.entries.into_iter()
            .find(|stored| stored.entry.atom == atom)).map_or(0, |stored| stored.entry.handle))
    }

    /// Returns the atom's original guest bytes, or None for a nonmember atom.
    pub fn atom_name(&self, atom: u16) -> Result<Option<Vec<u8>>, LocalHeapError> {
        Ok(self.atom_table()?.and_then(|table| table.entries.into_iter()
            .find(|stored| stored.entry.atom == atom)).map(|stored| stored.entry.name))
    }

    /// Returns a conservative fixed-block extent budget for a growth retry.
    /// Pass `buckets` for initialization, or `name_length` for adding a new
    /// string. Lazy addition includes both allocations and their alignment and
    /// arena overhead. None means no allocation is needed or sizes cannot fit.
    pub fn atom_allocation_size(
        &self,
        buckets: Option<i16>,
        name_length: Option<usize>,
    ) -> Result<Option<u16>, LocalHeapError> {
        let table = self.atom_table()?;
        let count = match bucket_count(buckets.unwrap_or(0)) {
            Some(count) => count,
            None => return Ok(None),
        };
        if name_length.is_some_and(|length| !(1..=u8::MAX as usize).contains(&length)) {
            return Ok(None);
        }
        let table_bytes = if table.is_none() {
            let Some(bytes) = table_size(count) else { return Ok(None) };
            allocation_extent(usize::from(bytes))
        } else { 0 };
        let entry_bytes = name_length.map_or(0, |length|
            allocation_extent(ENTRY_NAME_OFFSET + length + 1));
        let total = table_bytes + entry_bytes;
        if total == 0 {
            return Ok(None);
        }
        // Growth uses this as added segment capacity; include every arena
        // header here rather than relying on the retry's allocation logic.
        Ok(u16::try_from(total).ok())
    }

    fn allocate_atom_table(&mut self, buckets: u16) -> Result<u16, LocalHeapError> {
        let Some(size) = table_size(buckets) else { return Ok(0) };
        let handle = self.alloc_inner(LMEM_ZEROINIT, size)?;
        if handle != 0 {
            self.atom_write_word(usize::from(handle), buckets)?;
            self.atom_write_word(INSTANCE_ATOM_POINTER_OFFSET, handle)?;
        }
        Ok(handle)
    }

    fn atom_table(&self) -> Result<Option<AtomTable>, LocalHeapError> {
        let handle = self.atom_read_word(INSTANCE_ATOM_POINTER_OFFSET)?;
        if handle == 0 {
            return Ok(None);
        }
        let arenas = self.arenas()?;
        let tables = self.handle_tables(&arenas)?;
        let handles = self.handle_entries(&arenas)?;
        let mut fixed = Vec::new();
        fixed.try_reserve_exact(arenas.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
        for arena in &arenas {
            fixed.push(!arena.free && arena.start != self.first
                && arena.start != self.info.saturating_sub(ARENA_HEADER_BYTES as u16)
                && !tables.iter().any(|table| table.arena_start == arena.start)
                && !handles.iter().any(|entry| entry.addr != 0 && entry.addr.checked_sub(
                    (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16) == Some(arena.start)));
        }
        let owner = |pointer: u16| -> Result<usize, LocalHeapError> {
            let offset = usize::from(pointer);
            let start = pointer.checked_sub(ARENA_HEADER_BYTES as u16).ok_or_else(|| corrupt(offset))?;
            if pointer & 3 != 0 {
                return Err(corrupt(offset));
            }
            let index = arenas.binary_search_by_key(&start, |arena| arena.start)
                .map_err(|_| corrupt(offset))?;
            if !fixed[index] {
                return Err(corrupt(offset));
            }
            Ok(index)
        };
        let table_index = owner(handle)?;
        let table_start = usize::from(handle);
        let buckets = self.atom_read_word(table_start)?;
        let table_end = table_start + TABLE_HEADER_BYTES + usize::from(buckets) * 2;
        if buckets == 0 || table_end > usize::from(arenas[table_index].end) {
            return Err(corrupt(table_start));
        }
        let mut seen = Vec::new();
        seen.try_reserve_exact(arenas.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
        seen.resize(arenas.len(), false);
        seen[table_index] = true;
        let mut entries = Vec::new();
        for bucket in 0..usize::from(buckets) {
            let mut link_offset = table_start + TABLE_HEADER_BYTES + bucket * 2;
            let mut current = self.atom_read_word(link_offset)?;
            while current != 0 {
                let index = owner(current)?;
                let offset = usize::from(current);
                if seen[index] {
                    return Err(corrupt(offset));
                }
                seen[index] = true;
                let next = self.atom_read_word(offset)?;
                let references = self.atom_read_word(offset + 2)?;
                let length = usize::from(*self.dgroup.get(offset + 4)
                    .ok_or_else(|| corrupt(offset + 4))?);
                let name_start = offset + ENTRY_NAME_OFFSET;
                let name_end = name_start + length;
                if references == 0 || length == 0 || name_end >= usize::from(arenas[index].end)
                    || self.dgroup.get(name_end) != Some(&0)
                {
                    return Err(corrupt(offset));
                }
                let bytes = self.dgroup.get(name_start..name_end).ok_or_else(|| corrupt(name_start))?;
                if bytes.contains(&0) {
                    return Err(corrupt(name_start));
                }
                let mut name = Vec::new();
                name.try_reserve_exact(length).map_err(|_| LocalHeapError::OutOfMemory)?;
                name.extend_from_slice(bytes);
                entries.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
                entries.push(StoredAtom {
                    entry: LocalAtomEntry { atom: atom_for_handle(current), handle: current,
                        references, name },
                    link_offset,
                    next,
                });
                link_offset = offset;
                current = next;
            }
        }
        Ok(Some(AtomTable { handle, buckets, entries }))
    }

    fn atom_read_word(&self, offset: usize) -> Result<u16, LocalHeapError> {
        read_word(self.dgroup, offset).ok_or_else(|| corrupt(offset))
    }

    fn atom_write_word(&mut self, offset: usize, value: u16) -> Result<(), LocalHeapError> {
        write_word(self.dgroup, &mut self.write_spans, offset, value)
            .map_err(|error| LocalHeapError::preserve_write_error(error, corrupt(offset)))
    }

    fn atom_write_byte(&mut self, offset: usize, value: u8) -> Result<(), LocalHeapError> {
        write_byte(self.dgroup, &mut self.write_spans, offset, value)
            .map_err(|error| LocalHeapError::preserve_write_error(error, corrupt(offset)))
    }
}

fn corrupt(offset: usize) -> LocalHeapError {
    LocalHeapError::CorruptAtomTable { offset }
}

fn atom_for_handle(handle: u16) -> u16 {
    STRING_ATOM_BASE | (handle >> 2)
}

fn bucket_count(buckets: i16) -> Option<u16> {
    match buckets {
        0 => Some(DEFAULT_BUCKETS),
        1.. => Some(buckets as u16),
        _ => None,
    }
}

fn table_size(buckets: u16) -> Option<u16> {
    u16::try_from(TABLE_HEADER_BYTES + usize::from(buckets) * 2).ok()
}

fn allocation_extent(payload: usize) -> usize {
    ((payload + ARENA_HEADER_BYTES + 3) & !3).max(MIN_ARENA_EXTENT)
}

#[cfg(test)]
#[path = "atoms_tests.rs"]
mod tests;
