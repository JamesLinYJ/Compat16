//! Pre-reserved indexes keep native creation and teardown linear in item count.
use std::collections::{HashMap, TryReserveError};
use runtime::{Win16CreationId, Win16HostWindow};
type PayloadKey = (u64, u64, usize);
struct Entry<T> { window: Win16HostWindow, payload: PayloadKey, value: T }
pub(in crate::windows::win16_windows) struct IndexedSidecars<T> {
    entries: Vec<Entry<T>>,
    windows: HashMap<u64, usize>,
    payloads: HashMap<PayloadKey, u64>,
}
impl<T> IndexedSidecars<T> {
    pub(in crate::windows::win16_windows) fn new() -> Self {
        Self { entries: Vec::new(), windows: HashMap::new(), payloads: HashMap::new() }
    }
    pub(super) fn try_reserve(&mut self, count: usize) -> Result<(), TryReserveError> {
        self.entries.try_reserve(count)?;
        self.windows.try_reserve(count)?;
        self.payloads.try_reserve(count)
    }
    pub(super) fn insert(&mut self, window: Win16HostWindow, operation: u64,
        creation: Win16CreationId, pointer: usize, value: T) -> Result<(), T>
    {
        let payload = (operation, creation.0, pointer);
        if self.windows.contains_key(&window.0) || self.payloads.contains_key(&payload)
            || self.entries.len() == self.entries.capacity()
            || self.windows.len() == self.windows.capacity()
            || self.payloads.len() == self.payloads.capacity()
        { return Err(value); }
        self.windows.insert(window.0, self.entries.len());
        self.payloads.insert(payload, window.0);
        self.entries.push(Entry { window, payload, value });
        Ok(())
    }
    pub(super) fn by_window(&self, window: Win16HostWindow) -> Option<&T> {
        self.windows.get(&window.0).and_then(|index| self.entries.get(*index)).map(|entry| &entry.value)
    }
    pub(super) fn by_window_mut(&mut self, window: Win16HostWindow) -> Option<&mut T> {
        let index = *self.windows.get(&window.0)?;
        self.entries.get_mut(index).map(|entry| &mut entry.value)
    }
    pub(super) fn by_payload(&self, operation: u64, creation: Win16CreationId, pointer: usize) -> Option<&T> {
        self.payloads.get(&(operation, creation.0, pointer)).and_then(|window|
            self.by_window(Win16HostWindow(*window)))
    }
    pub(super) fn get(&self, index: usize) -> Option<&T> { self.entries.get(index).map(|entry| &entry.value) }
    pub(super) fn len(&self) -> usize { self.entries.len() }
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> { self.entries.iter().map(|entry| &entry.value) }
    pub(super) fn swap_remove(&mut self, index: usize) -> T {
        let removed = self.entries.swap_remove(index);
        self.windows.remove(&removed.window.0);
        self.payloads.remove(&removed.payload);
        if let Some(moved) = self.entries.get(index) {
            if let Some(slot) = self.windows.get_mut(&moved.window.0) { *slot = index; }
        }
        removed.value
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dialog_icon_indexes_repair_moved_slots_and_remove_both_keys() {
        let mut slots = IndexedSidecars::new(); slots.try_reserve(1024).unwrap();
        for id in 1..=1024 { slots.insert(Win16HostWindow(id), 7, Win16CreationId(8), id as usize, id).unwrap(); }
        while !slots.is_empty() {
            let id = *slots.get(0).unwrap();
            assert_eq!(slots.by_window(Win16HostWindow(id)), Some(&id));
            assert_eq!(slots.by_payload(7, Win16CreationId(8), id as usize), Some(&id));
            assert_eq!(slots.swap_remove(0), id);
            assert!(slots.by_window(Win16HostWindow(id)).is_none());
            assert!(slots.by_payload(7, Win16CreationId(8), id as usize).is_none());
        }
        assert!(slots.windows.is_empty()); assert!(slots.payloads.is_empty());
    }
    #[test]
    fn dialog_icon_payload_index_distinguishes_nested_operation_and_creation() {
        let mut slots = IndexedSidecars::new();
        assert_eq!(slots.insert(Win16HostWindow(1), 4, Win16CreationId(5), 20, 1), Err(1));
        slots.try_reserve(3).unwrap();
        slots.insert(Win16HostWindow(1), 4, Win16CreationId(5), 20, 1).unwrap();
        slots.insert(Win16HostWindow(2), 6, Win16CreationId(5), 20, 2).unwrap();
        slots.insert(Win16HostWindow(3), 4, Win16CreationId(7), 20, 3).unwrap();
        assert_eq!(slots.by_payload(4, Win16CreationId(5), 20), Some(&1));
        assert_eq!(slots.by_payload(6, Win16CreationId(5), 20), Some(&2));
        assert_eq!(slots.by_payload(4, Win16CreationId(7), 20), Some(&3));
        assert!(slots.by_payload(6, Win16CreationId(7), 20).is_none());
        slots.try_reserve(1).unwrap();
        assert_eq!(slots.insert(Win16HostWindow(4), 4, Win16CreationId(5), 20, 4), Err(4));
        assert_eq!(slots.insert(Win16HostWindow(1), 9, Win16CreationId(9), 21, 4), Err(4));
        assert_eq!(slots.len(), 3);
    }
}
