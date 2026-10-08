use crate::{
    Access, AccessRights, AllocationFlags, GlobalHeap, SegmentedPointer, SelectorTable,
    TaskRegistry, TaskState, Win16Error,
};
use guest_core::{GuestMemory, MemoryError, OwnerId, PhysAddr, Selector};

#[test]
fn win16_error_display_keeps_range_and_access_details() {
    let error = Win16Error::LimitViolation { offset: 0x12, length: 4, limit: 0x13 };
    let display = error.to_string();
    assert!(display.contains("0x00000012"));
    assert!(display.contains("4 bytes"));
    assert!(display.contains("0x00000013"));
    assert!(!display.contains("LimitViolation"));

    assert_eq!(
        Win16Error::AccessDenied { access: Access::Execute }.to_string(),
        "Win16 selector does not permit execute access"
    );
}

#[test]
fn win16_error_display_and_source_keep_memory_causes() {
    use std::error::Error;

    let error = Win16Error::ReallocRollbackFailed {
        write: MemoryError::ReadOnly { address: 0x1000, length: 2 },
        rollback: MemoryError::OutOfBounds { address: 0x2000, length: 2 },
    };
    let display = error.to_string();
    assert!(display.contains("0x00001000"));
    assert!(display.contains("0x00002000"));
    assert!(error.source().is_some());
}

#[derive(Clone, Debug)]
struct TestMemory {
    bytes: Vec<u8>,
    readonly: Option<(u32, u32)>,
    fail_next_write: bool,
}

impl TestMemory {
    fn new(size: usize) -> Self {
        Self { bytes: vec![0; size], readonly: None, fail_next_write: false }
    }

    fn range(&self, address: PhysAddr, length: usize) -> Result<std::ops::Range<usize>, MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(length).ok_or(MemoryError::AddressOverflow)?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address: address.0, length });
        }
        Ok(start..end)
    }
}

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 { self.bytes.len() as u32 }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.range(address, length)?;
        let start = u64::from(address.0);
        let end = start.checked_add(u64::try_from(length).map_err(|_| MemoryError::AddressOverflow)?)
            .ok_or(MemoryError::AddressOverflow)?;
        if let Some((readonly_start, readonly_end)) = self.readonly {
            if start < u64::from(readonly_end) && u64::from(readonly_start) < end {
                return Err(MemoryError::ReadOnly { address: address.0, length });
            }
        }
        Ok(())
    }

    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        let range = self.range(address, output.len())?;
        output.copy_from_slice(&self.bytes[range]);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, input.len())?;
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(MemoryError::AllocationFailed);
        }
        let range = self.range(address, input.len())?;
        self.bytes[range].copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn selector_access_and_segment_limit_are_enforced() {
    let mut memory = TestMemory::new(0x1000);
    memory.write(PhysAddr(0x100), &[0x12, 0x34, 0x56]).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let read_only = selectors.alloc_block(PhysAddr(0x100), 3, AccessRights::read_only(), &memory).unwrap();

    let mut byte = [0];
    selectors.read(&memory, SegmentedPointer::new(read_only, 2), &mut byte).unwrap();
    assert_eq!(byte, [0x56]);
    assert_eq!(
        selectors.read(&memory, SegmentedPointer::new(read_only, 2), &mut [0; 2]),
        Err(Win16Error::LimitViolation { offset: 2, length: 2, limit: 2 }),
    );
    assert_eq!(
        selectors.write(&mut memory, SegmentedPointer::new(read_only, 0), &[0xff]),
        Err(Win16Error::AccessDenied { access: Access::Write }),
    );
    assert_eq!(
        selectors.translate(SegmentedPointer::new(read_only, 0), Access::Execute, 1, &memory),
        Err(Win16Error::AccessDenied { access: Access::Execute }),
    );
}

#[test]
fn freed_selector_reference_does_not_revive_when_slot_is_reused() {
    let memory = TestMemory::new(0x1000);
    let mut selectors = SelectorTable::with_capacity(3).unwrap();
    let old = selectors.alloc_block(PhysAddr(0x100), 8, AccessRights::read_write(), &memory).unwrap();
    selectors.free_block(old).unwrap();
    let replacement = selectors.alloc_block(PhysAddr(0x200), 8, AccessRights::read_write(), &memory).unwrap();
    assert_eq!(old.raw(), replacement.raw());
    assert_ne!(old.generation(), replacement.generation());
    assert_eq!(
        selectors.read(&memory, SegmentedPointer::new(old, 0), &mut [0]),
        Err(Win16Error::StaleSelector),
    );
}

#[test]
fn segmented_pointer_addition_advances_to_the_next_descriptor() {
    let mut memory = TestMemory::new(0x30_000);
    let mut selectors = SelectorTable::new().unwrap();
    let start = selectors.alloc_block(PhysAddr(0x1000), 0x1_0004, AccessRights::read_write(), &memory).unwrap();
    let pointer = selectors.add_bytes(SegmentedPointer::new(start, 0xfffe), 4).unwrap();
    assert_eq!(pointer.selector().raw(), Selector(start.raw().0 + 8));
    assert_eq!(pointer.offset(), 2);
    assert_eq!(selectors.pointer_from_far(pointer.far_value()).unwrap(), pointer);
    selectors.write(&mut memory, pointer, &[0xa5]).unwrap();
    assert_eq!(memory.bytes[0x1000 + 0x1_0002], 0xa5);
}

#[test]
fn movable_global_blocks_copy_on_realloc_and_owner_cleanup_invalidates_pointers() {
    let mut memory = TestMemory::new(0x10_000);
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x800).unwrap();
    let owner_a = OwnerId(11);
    let owner_b = OwnerId(22);
    let movable = heap.alloc(&mut memory, owner_a, 32, AllocationFlags::movable().with_zero_init()).unwrap();
    let other = heap.alloc(&mut memory, owner_b, 32, AllocationFlags::fixed()).unwrap();
    let original_base = heap.info(movable).unwrap().base;

    let pointer = heap.lock(movable, &mut selectors, &memory).unwrap();
    selectors.write(&mut memory, pointer, &[0x4d, 0x5a]).unwrap();
    assert_eq!(heap.unlock(movable, &mut selectors).unwrap(), 0);
    assert_eq!(selectors.read(&memory, pointer, &mut [0]), Err(Win16Error::StaleSelector));

    heap.realloc(movable, 48, false, &mut memory, &mut selectors).unwrap();
    let moved_info = heap.info(movable).unwrap();
    assert!(moved_info.base.0 > original_base.0);
    assert_eq!(moved_info.size, 48);
    let moved_pointer = heap.lock(movable, &mut selectors, &memory).unwrap();
    let mut marker = [0; 2];
    selectors.read(&memory, moved_pointer, &mut marker).unwrap();
    assert_eq!(marker, [0x4d, 0x5a]);
    assert_eq!(heap.free(movable, &mut selectors), Err(Win16Error::Locked));

    assert_eq!(heap.free_owner(owner_a, &mut selectors).unwrap(), 1);
    assert_eq!(heap.info(movable), Err(Win16Error::InvalidHandle));
    assert_eq!(selectors.read(&memory, moved_pointer, &mut [0]), Err(Win16Error::StaleSelector));
    assert_eq!(heap.info(other).unwrap().owner, owner_b);
    assert_eq!(heap.free_owner(owner_b, &mut selectors).unwrap(), 1);
}

#[test]
fn fixed_global_blocks_cannot_move_and_free_retires_their_selector() {
    let mut memory = TestMemory::new(0x1000);
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x80).unwrap();
    let owner = OwnerId(4);
    let fixed = heap.alloc(&mut memory, owner, 16, AllocationFlags::fixed()).unwrap();
    let adjacent = heap.alloc(&mut memory, owner, 16, AllocationFlags::fixed()).unwrap();
    let pointer = heap.lock(fixed, &mut selectors, &memory).unwrap();
    assert_eq!(heap.unlock(fixed, &mut selectors).unwrap(), 0);
    assert_eq!(
        heap.realloc(fixed, 32, false, &mut memory, &mut selectors),
        Err(Win16Error::OutOfMemory),
    );
    selectors.write(&mut memory, pointer, &[0x77]).unwrap();
    heap.free(fixed, &mut selectors).unwrap();
    assert_eq!(selectors.read(&memory, pointer, &mut [0]), Err(Win16Error::StaleSelector));
    assert_eq!(heap.info(adjacent).unwrap().size, 16);
}

#[test]
fn recycled_guest_handle_is_generation_checked() {
    let mut memory = TestMemory::new(0x2000);
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::with_handle_capacity(PhysAddr(0x100), 0x1000, 1).unwrap();
    let first = heap.alloc(&mut memory, OwnerId(1), 8, AllocationFlags::fixed()).unwrap();
    heap.free(first, &mut selectors).unwrap();
    let second = heap.alloc(&mut memory, OwnerId(2), 8, AllocationFlags::fixed()).unwrap();
    assert_eq!(first.raw(), second.raw());
    assert_ne!(first.generation(), second.generation());
    assert_eq!(heap.info(first), Err(Win16Error::StaleHandle));
    assert_eq!(heap.info(second).unwrap().owner, OwnerId(2));
}

#[test]
fn task_transitions_and_termination_reclaim_owned_allocations() {
    let mut memory = TestMemory::new(0x4000);
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x1000).unwrap();
    let owner = OwnerId(7);
    let mut tasks = TaskRegistry::new();
    tasks.create(owner, None).unwrap();
    tasks.dispatch(owner).unwrap();
    assert_eq!(tasks.current(), Some(owner));
    tasks.suspend(owner).unwrap();
    assert_eq!(tasks.info(owner).unwrap().state, TaskState::Suspended);
    tasks.resume(owner).unwrap();
    tasks.dispatch(owner).unwrap();

    let handle = heap.alloc(&mut memory, owner, 16, AllocationFlags::movable()).unwrap();
    let pointer = heap.lock(handle, &mut selectors, &memory).unwrap();
    assert_eq!(tasks.terminate(owner, 3, &mut heap, &mut selectors).unwrap(), 1);
    assert_eq!(tasks.current(), None);
    assert_eq!(tasks.info(owner).unwrap().state, TaskState::Exited);
    assert_eq!(tasks.info(owner).unwrap().exit_code, Some(3));
    assert_eq!(selectors.read(&memory, pointer, &mut [0]), Err(Win16Error::StaleSelector));
    assert_eq!(tasks.dispatch(owner), Err(Win16Error::InvalidTaskState));
}

#[test]
fn selector_references_are_scoped_to_their_table_identity() {
    let memory = TestMemory::new(0x1000);
    let mut first = SelectorTable::with_capacity(4).unwrap();
    let mut second = SelectorTable::with_capacity(4).unwrap();
    let first_ref = first.alloc_block(
        PhysAddr(0x100), 16, AccessRights::read_write(), &memory,
    ).unwrap();
    let second_ref = second.alloc_block(
        PhysAddr(0x200), 16, AccessRights::read_write(), &memory,
    ).unwrap();

    assert_eq!(first_ref.raw(), second_ref.raw());
    assert_eq!(first_ref.generation(), second_ref.generation());
    assert_eq!(second.describe(first_ref), Err(Win16Error::ForeignSelector));
    assert_eq!(first.describe(second_ref), Err(Win16Error::ForeignSelector));
}

#[test]
fn global_handles_are_scoped_to_their_heap_identity() {
    let mut memory = TestMemory::new(0x2000);
    let mut first = GlobalHeap::with_handle_capacity(PhysAddr(0x100), 0x800, 4).unwrap();
    let mut second = GlobalHeap::with_handle_capacity(PhysAddr(0x1000), 0x800, 4).unwrap();
    let handle = first.alloc(&mut memory, OwnerId(1), 16, AllocationFlags::fixed()).unwrap();
    let other = second.alloc(&mut memory, OwnerId(1), 16, AllocationFlags::fixed()).unwrap();

    assert_eq!(handle.raw(), other.raw());
    assert_eq!(handle.generation(), other.generation());
    let shared = first.resolve_handle(handle.raw()).unwrap();
    assert_eq!(first.info(shared).unwrap().owner, OwnerId(1));
    assert_eq!(second.info(handle), Err(Win16Error::ForeignHandle));
}

#[test]
fn allocation_without_zero_init_still_rejects_read_only_memory() {
    let mut memory = TestMemory::new(0x1000);
    memory.readonly = Some((0x100, 0x200));
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x80).unwrap();

    assert_eq!(
        heap.alloc(&mut memory, OwnerId(1), 8, AllocationFlags::fixed()),
        Err(Win16Error::Memory(MemoryError::ReadOnly { address: 0x100, length: 8 })),
    );
    assert_eq!(heap.allocation_count(), 0);
}

#[test]
fn fixed_realloc_fails_without_replacing_its_raw_selector() {
    let mut memory = TestMemory::new(0x40000);
    let mut selectors = SelectorTable::with_capacity(2).unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x20000).unwrap();
    let fixed = heap.alloc(
        &mut memory, OwnerId(1), 0x1_0000, AllocationFlags::fixed(),
    ).unwrap();
    let pointer = heap.lock(fixed, &mut selectors, &memory).unwrap();
    heap.unlock(fixed, &mut selectors).unwrap();

    assert_eq!(
        heap.realloc(fixed, 0x1_0001, false, &mut memory, &mut selectors),
        Err(Win16Error::SelectorTableFull),
    );
    assert_eq!(heap.info(fixed).unwrap().size, 0x1_0000);
    assert_eq!(selectors.reference(pointer.selector().raw()).unwrap(), pointer.selector());
    assert_eq!(selectors.describe(pointer.selector()).unwrap().selector, pointer.selector().raw());
}

#[test]
fn failed_zero_extension_realloc_restores_selector_bytes_and_heap_metadata() {
    let mut memory = TestMemory::new(0x1000);
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x100), 0x100).unwrap();
    let fixed = heap.alloc(&mut memory, OwnerId(1), 16, AllocationFlags::fixed()).unwrap();
    let base = heap.info(fixed).unwrap().base;
    memory.write(PhysAddr(base.0 + 16), &[0xcc, 0xdd, 0xee, 0xff]).unwrap();
    let pointer = heap.lock(fixed, &mut selectors, &memory).unwrap();
    heap.unlock(fixed, &mut selectors).unwrap();
    memory.fail_next_write = true;

    assert_eq!(
        heap.realloc(fixed, 20, true, &mut memory, &mut selectors),
        Err(Win16Error::Memory(MemoryError::AllocationFailed)),
    );
    assert_eq!(heap.info(fixed).unwrap().size, 16);
    let mut extension = [0; 4];
    memory.read(PhysAddr(base.0 + 16), &mut extension).unwrap();
    assert_eq!(extension, [0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(selectors.reference(pointer.selector().raw()).unwrap(), pointer.selector());
    selectors.write(&mut memory, pointer, &[0x5a]).unwrap();
    assert_eq!(memory.bytes[base.0 as usize], 0x5a);
}
