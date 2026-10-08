//! Guest-owned GDI priority queues used by the Windows 3.1 printer-driver API.

use super::Win16State;
use std::collections::HashMap;
use win16_abi::Win16PrintQueueRequest;

impl Win16State {
    pub(super) fn print_queue_api(&mut self, request: Win16PrintQueueRequest) -> u32 {
        use Win16PrintQueueRequest as Request;
        let value = match request {
            Request::Create { capacity } => return u32::from(self.print_queues.create(capacity)),
            Request::Min { queue } => self.print_queues.min(queue),
            Request::Extract { queue } => self.print_queues.extract(queue),
            Request::Insert {
                queue,
                tag,
                priority,
            } => self.print_queues.insert(queue, tag, priority),
            Request::Resize { queue, size_change } => self.print_queues.resize(queue, size_change),
            Request::Delete { queue } => {
                self.print_queues.delete(queue);
                0
            }
        };
        u32::from(value as u16)
    }
}

#[derive(Default)]
pub(crate) struct Win16PrintQueueState {
    queues: HashMap<u16, PriorityQueue>,
    next_handle: u16,
}

struct PriorityQueue {
    capacity: usize,
    entries: Vec<QueueEntry>,
}

#[derive(Clone, Copy)]
struct QueueEntry {
    tag: i16,
    priority: u16,
}

impl Win16PrintQueueState {
    /// Use the NTVDM SORT failure value PQERROR (-1). The older SDK 3.0
    /// driver guide instead specifies zero; SDK 3.1 PRINT.H names PQERROR
    /// without settling this version difference in the available reference.
    pub(crate) fn create(&mut self, capacity: i16) -> u16 {
        let Ok(capacity) = usize::try_from(capacity) else {
            return PQERROR_HANDLE;
        };
        let mut entries = Vec::new();
        if entries.try_reserve_exact(capacity).is_err() || self.queues.try_reserve(1).is_err() {
            return PQERROR_HANDLE;
        }
        let Some(handle) = self.allocate_handle() else {
            return PQERROR_HANDLE;
        };
        self.queues
            .insert(handle, PriorityQueue { capacity, entries });
        handle
    }

    /// MinPQ returns the tag for the lowest unsigned priority, or -1 if empty.
    pub(crate) fn min(&self, handle: u16) -> i16 {
        self.queues
            .get(&handle)
            .and_then(|queue| min_entry(&queue.entries).map(|entry| entry.tag))
            .unwrap_or(-1)
    }

    /// ExtractPQ removes and returns the lowest-priority tag, or -1 if empty.
    pub(crate) fn extract(&mut self, handle: u16) -> i16 {
        let Some(queue) = self.queues.get_mut(&handle) else {
            return -1;
        };
        let Some(index) = min_entry_index(&queue.entries) else {
            return -1;
        };
        queue.entries.remove(index).tag
    }

    /// InsertPQ returns TRUE on success and -1 for a full or invalid queue.
    pub(crate) fn insert(&mut self, handle: u16, tag: i16, priority: i16) -> i16 {
        let Some(queue) = self.queues.get_mut(&handle) else {
            return -1;
        };
        if queue.entries.len() >= queue.capacity {
            return -1;
        }
        // The NTVDM SORT implementation compares key words with unsigned
        // JB/JAE instructions even though PRINT.H spells the arguments int.
        // Preserve all tag bits too; -1 is accepted by InsertPQ in that code.
        queue.entries.push(QueueEntry {
            tag,
            priority: priority as u16,
        });
        1
    }

    /// SizePQ changes the maximum entry count and returns the new capacity.
    pub(crate) fn resize(&mut self, handle: u16, size_change: i16) -> i16 {
        let Some(queue) = self.queues.get_mut(&handle) else {
            return -1;
        };
        let new_capacity = i32::try_from(queue.capacity)
            .ok()
            .and_then(|capacity| capacity.checked_add(i32::from(size_change)));
        let Some(new_capacity) = new_capacity.filter(|capacity| {
            *capacity >= i32::try_from(queue.entries.len()).unwrap_or(i32::MAX)
                && *capacity <= i32::from(i16::MAX)
        }) else {
            return -1;
        };
        let new_capacity = new_capacity as usize;
        if new_capacity > queue.capacity
            && queue
                .entries
                .try_reserve_exact(new_capacity - queue.entries.len())
                .is_err()
        {
            return -1;
        }
        queue.capacity = new_capacity;
        new_capacity as i16
    }

    /// DeletePQ releases the guest queue identity. The SDK 3.1 header declares
    /// a void return; callers must rely on the queue's subsequent invalidity.
    pub(crate) fn delete(&mut self, handle: u16) -> bool {
        self.queues.remove(&handle).is_some()
    }

    fn allocate_handle(&mut self) -> Option<u16> {
        // FFFF is the documented PQERROR return, and zero is the failed
        // GlobalAlloc handle used by the original 16-bit implementation.
        if self.queues.len() >= usize::from(u16::MAX) - 1 {
            return None;
        }
        if self.next_handle == 0 || self.next_handle == PQERROR_HANDLE {
            self.next_handle = 1;
        }
        let first = self.next_handle;
        let mut candidate = first;
        loop {
            if candidate != 0 && !self.queues.contains_key(&candidate) {
                self.next_handle = candidate.wrapping_add(1);
                if self.next_handle == 0 || self.next_handle == PQERROR_HANDLE {
                    self.next_handle = 1;
                }
                return Some(candidate);
            }
            candidate = candidate.wrapping_add(1);
            if candidate == 0 || candidate == PQERROR_HANDLE {
                candidate = 1;
            }
            if candidate == first {
                return None;
            }
        }
    }
}

const PQERROR_HANDLE: u16 = u16::MAX;

fn min_entry(entries: &[QueueEntry]) -> Option<&QueueEntry> {
    min_entry_index(entries).and_then(|index| entries.get(index))
}

fn min_entry_index(entries: &[QueueEntry]) -> Option<usize> {
    let mut minimum = entries.first().map(|_| 0)?;
    for index in 1..entries.len() {
        if entries[index].priority < entries[minimum].priority {
            minimum = index;
        }
    }
    Some(minimum)
}
