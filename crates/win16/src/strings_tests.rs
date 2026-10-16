//! Count-only ANSI reads retain the checked string-copy boundary contract.

use super::{count_ansi_z, read_ansi_z};
use crate::{Access, AccessRights, MAX_WIN16_STRING_BYTES, SegmentedPointer, SelectorTable, Win16Error};
use guest_core::{GuestMemory, MemoryError, PhysAddr, memory::Memory};
use std::cell::{Cell, RefCell};

const BASE: u32 = 0x1000;

struct CountingMemory {
    memory: Memory,
    reads: RefCell<Vec<(u32, usize)>>,
    validations: RefCell<Vec<(u32, usize)>>,
    unreadable_from: Cell<Option<u32>>,
}

impl CountingMemory {
    fn new(bytes: &[u8]) -> Self {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        memory.write(PhysAddr(BASE), bytes).unwrap();
        Self {
            memory, reads: RefCell::new(Vec::new()), validations: RefCell::new(Vec::new()),
            unreadable_from: Cell::new(None),
        }
    }

    fn clear_accesses(&self) {
        self.reads.borrow_mut().clear();
        self.validations.borrow_mut().clear();
    }

    fn assert_byte_reads(&self, start: u32, count: usize) {
        let expected: Vec<_> = (0..count).map(|offset| (start + offset as u32, 1)).collect();
        assert_eq!(*self.reads.borrow(), expected);
        assert_eq!(*self.validations.borrow(), expected);
    }
}

impl GuestMemory for CountingMemory {
    fn len(&self) -> u32 { self.memory.len() }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validations.borrow_mut().push((address.0, length));
        if self.unreadable_from.get().is_some_and(|end| u64::from(address.0) + length as u64 > u64::from(end)) {
            return Err(MemoryError::OutOfBounds { address: address.0, length });
        }
        self.memory.validate_read(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.reads.borrow_mut().push((address.0, bytes.len()));
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(address, bytes)
    }
}

fn fixture(bytes: &[u8], rights: AccessRights) -> (CountingMemory, SelectorTable, SegmentedPointer) {
    let memory = CountingMemory::new(bytes);
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors.alloc_block(PhysAddr(BASE), bytes.len() as u32, rights, &memory).unwrap();
    memory.clear_accesses();
    (memory, selectors, SegmentedPointer::new(selector, 0))
}

#[test]
fn lstrlen_count_empty_ascii_and_dbcs_bytes_match_owned_copy() {
    for bytes in [b"\0".as_slice(), b"ASCII\0", b"\x81\x40A\x82\xa0\0", b"\xff\x81\0"] {
        let (memory, selectors, pointer) = fixture(bytes, AccessRights::read_only());
        let length = count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES).unwrap();
        assert_eq!(length, bytes.len() - 1);
        memory.assert_byte_reads(BASE, length + 1);
        assert_eq!(read_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES).unwrap().len(), length);
    }
}

#[test]
fn lstrlen_count_never_reads_or_validates_past_first_nul() {
    let (memory, selectors, pointer) = fixture(b"abc\0unreadable", AccessRights::read_only());
    memory.unreadable_from.set(Some(BASE + 4));
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES), Ok(3));
    memory.assert_byte_reads(BASE, 4);
}

#[test]
fn lstrlen_count_accepts_nul_at_last_readable_byte_and_offset() {
    let (memory, selectors, pointer) = fixture(b"prefix\0", AccessRights::read_only());
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value() + 6, MAX_WIN16_STRING_BYTES), Ok(0));
    memory.assert_byte_reads(BASE + 6, 1);
}

#[test]
fn lstrlen_count_maximum_word_length_reads_exactly_64k_bytes() {
    let mut bytes = vec![b'x'; MAX_WIN16_STRING_BYTES];
    *bytes.last_mut().unwrap() = 0;
    let (memory, selectors, pointer) = fixture(&bytes, AccessRights::read_only());
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES), Ok(65535));
    memory.assert_byte_reads(BASE, 65536);
}

#[test]
fn lstrlen_count_rejects_terminator_outside_scan_bound_without_reading_it() {
    let mut bytes = vec![b'x'; MAX_WIN16_STRING_BYTES];
    bytes.push(0);
    let (memory, selectors, pointer) = fixture(&bytes, AccessRights::read_only());
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES), Err(Win16Error::InvalidRange));
    memory.assert_byte_reads(BASE, MAX_WIN16_STRING_BYTES);
    memory.clear_accesses();
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), 0), Err(Win16Error::InvalidRange));
    memory.assert_byte_reads(BASE, 0);
}

#[test]
fn lstrlen_count_rejects_missing_nul_at_allocation_limit() {
    let (memory, selectors, pointer) = fixture(b"abc", AccessRights::read_only());
    assert!(matches!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES),
        Err(Win16Error::LimitViolation { .. })));
    memory.assert_byte_reads(BASE, 3);
}

#[test]
fn lstrlen_count_rejects_freed_and_unreadable_selectors_before_guest_reads() {
    let (memory, mut selectors, pointer) = fixture(b"A\0", AccessRights::read_only());
    selectors.free_block(pointer.selector()).unwrap();
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES), Err(Win16Error::InvalidSelector));
    memory.assert_byte_reads(BASE, 0);
    let (memory, selectors, pointer) = fixture(b"A\0", AccessRights::new(false, false, true));
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES),
        Err(Win16Error::AccessDenied { access: Access::Read }));
    memory.assert_byte_reads(BASE, 0);
}

#[test]
fn lstrlen_count_propagates_guest_read_validation_failure_including_nul() {
    for readable in 0..=2 {
        let (memory, selectors, pointer) = fixture(b"AB\0", AccessRights::read_only());
        memory.unreadable_from.set(Some(BASE + readable));
        assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES),
            Err(Win16Error::Memory(MemoryError::OutOfBounds { address: BASE + readable, length: 1 })));
        assert_eq!(memory.reads.borrow().len(), readable as usize);
        assert_eq!(memory.validations.borrow().len(), readable as usize + 1);
    }
}

#[test]
fn lstrlen_count_rejects_adjacent_unrelated_selector_allocation() {
    let mut bytes = vec![b'x'; 0x10000];
    bytes.push(0);
    let memory = CountingMemory::new(&bytes);
    let mut selectors = SelectorTable::new().unwrap();
    let first = selectors.alloc_block(PhysAddr(BASE), 0x10000, AccessRights::read_only(), &memory).unwrap();
    let second = selectors.alloc_block(PhysAddr(BASE + 0x10000), 1, AccessRights::read_only(), &memory).unwrap();
    assert_eq!(second.raw().0, first.raw().0 + 8);
    memory.clear_accesses();
    let pointer = SegmentedPointer::new(first, 0xffff);
    assert!(matches!(count_ansi_z(&selectors, &memory, pointer.far_value(), MAX_WIN16_STRING_BYTES),
        Err(Win16Error::LimitViolation { .. })));
    memory.assert_byte_reads(BASE + 0xffff, 1);
}

#[test]
fn lstrlen_count_crosses_selectors_only_within_same_owned_allocation() {
    let mut bytes = vec![b'x'; 0x10002];
    bytes[0xffff..].copy_from_slice(b"\x81\x40\0");
    let (memory, selectors, pointer) = fixture(&bytes, AccessRights::read_only());
    assert_eq!(count_ansi_z(&selectors, &memory, pointer.far_value() + 0xffff, MAX_WIN16_STRING_BYTES), Ok(2));
    memory.assert_byte_reads(BASE + 0xffff, 3);
}
