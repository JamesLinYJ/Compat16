//! Published Win3.1 local-heap results for the seven KERNEL memory calls.
//!
//! Windows 3.1 Programmer's Reference, Volume 2: LocalAlloc pp. 587–588,
//! LocalFlags pp. 590–591, LocalFree p. 591, LocalLock pp. 593–594,
//! LocalReAlloc pp. 595–596, LocalSize p. 597, and LocalUnlock p. 598.
//! Volume 3, p. 436 defines LocalDiscard as LocalReAlloc(h, 0, LMEM_MOVEABLE).
//! Learn's LocalAlloc page also states that a zero size with LMEM_MOVEABLE
//! returns a handle marked discarded.

use super::*;

const SENTINEL: &[u8] = b"local-contract";

fn segment() -> Vec<u8> {
    let mut bytes = vec![0; 0x800];
    prepare_local_heap_init(bytes.len(), 0x10, 0x7ff)
        .unwrap()
        .apply_to_slice(&mut bytes)
        .unwrap();
    bytes
}

fn payload<'a>(heap: &'a LocalHeap<'_>, address: u16) -> &'a [u8] {
    let start = usize::from(address);
    &heap.dgroup[start..start + SENTINEL.len()]
}

#[test]
fn local_memory_contract_fixed_block() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    let fixed = heap.alloc(LMEM_ZEROINIT, 32).unwrap();
    assert_ne!(fixed, 0);
    assert_eq!(
        fixed & 3,
        0,
        "a fixed LocalAlloc result is the near pointer"
    );
    assert!(heap.size(fixed).unwrap() >= 32);
    assert_eq!(heap.flags(fixed), Ok(0));
    assert_eq!(
        &heap.dgroup[usize::from(fixed)..usize::from(fixed) + 32],
        &[0; 32]
    );

    // LocalLock does not increment a lock count for fixed memory. The pointer
    // is the handle. LocalUnlock has no effect.
    assert_eq!(heap.lock(fixed), Ok(fixed));
    assert_eq!(heap.flags(fixed), Ok(0));
    assert_eq!(heap.unlock(fixed), Ok(0));
    assert_eq!(heap.flags(fixed), Ok(0));
    assert_eq!(heap.handle(fixed), Ok(fixed));

    assert_eq!(heap.free(fixed), Ok(0));
    assert_eq!(heap.flags(fixed), Ok(LMEM_INVALID_HANDLE));
    assert_eq!(heap.size(fixed), Ok(0));
    assert_eq!(heap.lock(fixed), Ok(0));
}

#[test]
fn local_memory_contract_moveable_block() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    let handle = heap.alloc(LMEM_MOVEABLE | LMEM_ZEROINIT, 32).unwrap();
    assert_ne!(handle, 0);
    assert_ne!(handle & 3, 0, "a movable LocalAlloc result is a handle");
    assert!(heap.size(handle).unwrap() >= 32);
    assert_eq!(heap.flags(handle), Ok(0));

    let address = heap.lock(handle).unwrap();
    assert_ne!(address, 0);
    assert_ne!(address, handle);
    assert_eq!(heap.flags(handle), Ok(1));
    assert_eq!(
        &heap.dgroup[usize::from(address)..usize::from(address) + 32],
        &[0; 32]
    );
    let start = usize::from(address);
    heap.dgroup[start..start + SENTINEL.len()].copy_from_slice(SENTINEL);

    // A second lock stays nonzero after one unlock. The last unlock returns
    // zero once the lock count reaches zero.
    assert_eq!(heap.lock(handle), Ok(address));
    assert_eq!(heap.flags(handle), Ok(2));
    assert_ne!(heap.unlock(handle).unwrap(), 0);
    assert_eq!(heap.flags(handle), Ok(1));
    assert_eq!(payload(&heap, address), SENTINEL);
    assert_eq!(heap.unlock(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(0));
    assert_eq!(heap.handle(address), Ok(handle));

    assert_eq!(heap.free(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(LMEM_INVALID_HANDLE));
    assert_eq!(heap.size(handle), Ok(0));
    assert_eq!(heap.lock(handle), Ok(0));
}

#[test]
fn local_memory_contract_unlocked_discardable_block() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    let handle = heap.alloc(LMEM_MOVEABLE | LMEM_DISCARDABLE, 32).unwrap();
    assert_ne!(handle, 0);
    let address = heap.lock(handle).unwrap();
    let start = usize::from(address);
    heap.dgroup[start..start + SENTINEL.len()].copy_from_slice(SENTINEL);
    assert_eq!(heap.unlock(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE));
    assert!(heap.size(handle).unwrap() >= 32);

    // Unlocked discardable memory is discarded by LocalDiscard and can be
    // allocated again with the same handle.
    let free_before = heap.count_free().unwrap();
    assert_eq!(heap.realloc(handle, 0, LMEM_MOVEABLE), Ok(handle));
    assert_eq!(heap.size(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(u16::from(LMEM_DISCARDED) << 8));
    assert_eq!(heap.lock(handle), Ok(0));
    assert!(heap.count_free().unwrap() > free_before);
    assert_eq!(
        heap.realloc(handle, 32, LMEM_MOVEABLE | LMEM_DISCARDABLE),
        Ok(handle)
    );
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE));
    assert!(heap.size(handle).unwrap() >= 32);
    assert_eq!(heap.free(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(LMEM_INVALID_HANDLE));
}

#[test]
fn local_memory_contract_zero_size_allocation() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    assert_eq!(heap.alloc(0, 0), Ok(0));
    assert_eq!(heap.alloc(LMEM_ZEROINIT, 0), Ok(0));

    let handle = heap.alloc(LMEM_MOVEABLE, 0).unwrap();
    assert_ne!(handle, 0);
    assert_eq!(heap.size(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(u16::from(LMEM_DISCARDED) << 8));
    assert_eq!(heap.lock(handle), Ok(0));
    heap.take_write_spans();
    assert_eq!(heap.lock(handle), Ok(0));
    assert!(heap.take_write_spans().is_empty());

    let discardable = heap.alloc(LMEM_MOVEABLE | LMEM_DISCARDABLE, 0).unwrap();
    assert_ne!(discardable, 0);
    assert_ne!(discardable, handle);
    assert_eq!(heap.flags(discardable), Ok(u16::from(LMEM_DISCARDED) << 8));
    assert_eq!(heap.size(discardable), Ok(0));
    assert_eq!(heap.free(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(LMEM_INVALID_HANDLE));
    assert_eq!(heap.free(discardable), Ok(0));
}

#[test]
fn local_memory_contract_free_of_locked_block() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    let handle = heap.alloc(LMEM_MOVEABLE | LMEM_DISCARDABLE, 32).unwrap();
    let address = heap.lock(handle).unwrap();
    let start = usize::from(address);
    heap.dgroup[start..start + SENTINEL.len()].copy_from_slice(SENTINEL);
    assert_eq!(heap.lock(handle), Ok(address));
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE | 2));

    // Vol. 2, p. 591: LocalFree cannot free an object whose lock count is
    // greater than zero. The call returns that handle and leaves the object.
    heap.take_write_spans();
    let before = heap.dgroup.to_vec();
    assert_eq!(heap.free(handle), Ok(handle));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before.as_slice());
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE | 2));
    assert!(heap.size(handle).unwrap() >= 32);
    assert_eq!(payload(&heap, address), SENTINEL);

    assert_ne!(heap.unlock(handle).unwrap(), 0);
    assert_eq!(heap.free(handle), Ok(handle));
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE | 1));
    assert_eq!(heap.unlock(handle), Ok(0));
    assert_eq!(heap.free(handle), Ok(0));
    assert_eq!(heap.flags(handle), Ok(LMEM_INVALID_HANDLE));
    assert_eq!(heap.size(handle), Ok(0));
}
