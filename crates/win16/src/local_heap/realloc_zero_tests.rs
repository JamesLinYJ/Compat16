use super::*;

const SENTINEL: &[u8] = b"live local allocation";

fn segment() -> Vec<u8> {
    let mut bytes = vec![0; 0x800];
    prepare_local_heap_init(bytes.len(), 0x10, 0x7ff).unwrap()
        .apply_to_slice(&mut bytes).unwrap();
    bytes
}

fn live_block(heap: &mut LocalHeap<'_>, attributes: u16) -> (u16, u16) {
    let handle = heap.alloc(LMEM_MOVEABLE | attributes, 32).unwrap();
    assert_ne!(handle, 0);
    let address = heap.lock(handle).unwrap();
    assert_ne!(address, 0);
    let start = usize::from(address);
    heap.dgroup[start..start + SENTINEL.len()].copy_from_slice(SENTINEL);
    assert_eq!(heap.unlock(handle), Ok(0));
    (handle, address)
}

#[test]
fn local_realloc_zero_without_moveable_preserves_unlocked_live_blocks() {
    for attributes in [0, LMEM_DISCARDABLE] {
        let mut bytes = segment();
        let mut heap = LocalHeap::open(&mut bytes).unwrap();
        let (handle, address) = live_block(&mut heap, attributes);
        let size = heap.size(handle).unwrap();
        assert!(size >= 32);
        heap.take_write_spans();
        let before = heap.dgroup.to_vec();
        assert_eq!(heap.realloc(handle, 0, 0), Ok(0));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, before.as_slice());
        assert_eq!(heap.size(handle), Ok(size));
        assert_eq!(heap.flags(handle), Ok(attributes));
        assert_eq!(heap.handle(address), Ok(handle));
        assert_eq!(heap.lock(handle), Ok(address));
        let start = usize::from(address);
        assert_eq!(&heap.dgroup[start..start + SENTINEL.len()], SENTINEL);
        assert_eq!(heap.unlock(handle), Ok(0));
        assert_eq!(heap.free(handle), Ok(0));
        assert_eq!(heap.flags(handle), Ok(LMEM_INVALID_HANDLE));
    }
}

#[test]
fn local_realloc_zero_locked_blocks_fail_without_writes_with_or_without_moveable() {
    for attributes in [0, LMEM_DISCARDABLE] {
        let mut bytes = segment();
        let mut heap = LocalHeap::open(&mut bytes).unwrap();
        let (handle, address) = live_block(&mut heap, attributes);
        assert_eq!(heap.lock(handle), Ok(address));
        heap.take_write_spans();
        let before = heap.dgroup.to_vec();
        for flags in [0, LMEM_MOVEABLE] {
            assert_eq!(heap.realloc(handle, 0, flags), Ok(0));
            assert!(heap.take_write_spans().is_empty());
            assert_eq!(heap.dgroup, before.as_slice());
            assert_eq!(heap.flags(handle), Ok(attributes | 1));
        }
        assert_eq!(heap.unlock(handle), Ok(0));
        assert_eq!(heap.free(handle), Ok(0));
    }
}

#[test]
fn local_realloc_zero_moveable_discards_and_keeps_reusable_handle() {
    for attributes in [0, LMEM_DISCARDABLE] {
        let mut bytes = segment();
        let mut heap = LocalHeap::open(&mut bytes).unwrap();
        let (handle, _) = live_block(&mut heap, attributes);
        let free_before = heap.count_free().unwrap();
        heap.take_write_spans();
        assert_eq!(heap.realloc(handle, 0, LMEM_MOVEABLE), Ok(handle));
        assert!(!heap.take_write_spans().is_empty());
        assert_eq!(heap.size(handle), Ok(0));
        assert_eq!(heap.flags(handle), Ok(u16::from(LMEM_DISCARDED) << 8));
        assert_eq!(heap.lock(handle), Ok(0));
        assert!(heap.count_free().unwrap() > free_before);
        let before = heap.dgroup.to_vec();
        assert_eq!(heap.realloc(handle, 0, 0), Ok(0));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, before.as_slice());
        assert_eq!(heap.realloc(handle, 32, LMEM_MOVEABLE), Ok(handle));
        assert_ne!(heap.lock(handle).unwrap(), 0);
        assert_eq!(heap.unlock(handle), Ok(0));
        assert_eq!(heap.free(handle), Ok(0));
    }
}

#[test]
fn local_realloc_zero_preserves_fixed_and_modify_contracts() {
    let mut bytes = segment();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    let fixed = heap.alloc(0, 32).unwrap();
    assert_ne!(fixed, 0);
    heap.take_write_spans();
    let before = heap.dgroup.to_vec();
    assert_eq!(heap.realloc(fixed, 0, 0), Ok(0));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before.as_slice());
    assert_eq!(heap.realloc(fixed, 0, LMEM_MOVEABLE), Ok(0));
    assert_eq!(heap.flags(fixed), Ok(LMEM_INVALID_HANDLE));

    let (handle, address) = live_block(&mut heap, 0);
    let size = heap.size(handle).unwrap();
    assert_eq!(heap.realloc(handle, 0, LMEM_MODIFY | LMEM_DISCARDABLE), Ok(handle));
    assert_eq!(heap.flags(handle), Ok(LMEM_DISCARDABLE));
    assert_eq!(heap.size(handle), Ok(size));
    assert_eq!(heap.lock(handle), Ok(address));
    let start = usize::from(address);
    assert_eq!(&heap.dgroup[start..start + SENTINEL.len()], SENTINEL);
    assert_eq!(heap.unlock(handle), Ok(0));
    assert_eq!(heap.free(handle), Ok(0));
}
