use super::*;

fn segment(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    prepare_local_heap_init(size, 0x10, (size - 1) as u16).unwrap()
        .apply_to_slice(&mut bytes).unwrap();
    bytes
}

#[test]
fn local_handle_delta_query_is_byte_pure_and_sets_return_exact_new_words() {
    let mut bytes = segment(0x400);
    let original = bytes.clone();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    assert_eq!(heap.handle_delta(0), Ok(32));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, original.as_slice());
    let offset = usize::from(heap.info) + HEAP_HANDLE_DELTA_OFFSET;
    for delta in [1, 2, 0x3ffe, 0x3fff, 0x4000, 0x8000, 0xffff] {
        let before = heap.dgroup.to_vec();
        assert_eq!(heap.handle_delta(delta), Ok(delta));
        assert_eq!(heap.take_write_spans(), vec![offset..offset + 2]);
        assert_eq!(&heap.dgroup[..offset], &before[..offset]);
        assert_eq!(&heap.dgroup[offset + 2..], &before[offset + 2..]);
        assert_eq!(read_word(heap.dgroup, offset), Some(delta));
        let after = heap.dgroup.to_vec();
        assert_eq!(heap.handle_delta(0), Ok(delta));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, after.as_slice());
        // Same-value stores retain write intent for the transaction publisher.
        assert_eq!(heap.handle_delta(delta), Ok(delta));
        assert_eq!(heap.take_write_spans(), vec![offset..offset + 2]);
    }
}

#[test]
fn local_handle_delta_small_heap_enables_real_movable_allocation() {
    let mut bytes = segment(0x100);
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    // 96-byte payload plus the default 32-entry table cannot fit together.
    assert_eq!(heap.alloc(LMEM_MOVEABLE | LMEM_NOCOMPACT, 96), Ok(0));
    assert_eq!(heap.handle_delta(1), Ok(1));
    let handle = heap.alloc(LMEM_MOVEABLE | LMEM_NOCOMPACT, 96).unwrap();
    assert_ne!(handle, 0);
    assert!(heap.size(handle).unwrap() >= 96);
    assert_ne!(heap.lock(handle).unwrap(), 0);
    assert_eq!(heap.handle_tables(&heap.arenas().unwrap()).unwrap()[0].count, 1);
    assert_eq!(heap.unlock(handle), Ok(0));
    assert_eq!(heap.free(handle), Ok(0));
}

#[test]
fn local_handle_delta_only_changes_future_expansions_and_reuses_free_slots() {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    assert_eq!(heap.handle_delta(1), Ok(1));
    let first = heap.alloc(LMEM_MOVEABLE, 8).unwrap();
    assert_ne!(first, 0);
    let original_table = heap.handle_tables(&heap.arenas().unwrap()).unwrap()[0];
    assert_eq!(heap.handle_delta(2), Ok(2));
    assert_eq!(heap.handle_tables(&heap.arenas().unwrap()).unwrap(), vec![original_table]);
    let second = heap.alloc(LMEM_MOVEABLE, 8).unwrap();
    let third = heap.alloc(LMEM_MOVEABLE, 8).unwrap();
    assert_ne!(second, 0);
    assert_ne!(third, 0);
    let tables = heap.handle_tables(&heap.arenas().unwrap()).unwrap();
    assert_eq!(tables.len(), 2);
    assert_eq!(tables[0].count, 2);
    assert_eq!(tables[1], original_table);
    assert_eq!(heap.free(second), Ok(0));
    assert_eq!(heap.handle_delta(0xffff), Ok(0xffff));
    assert_eq!(heap.alloc(LMEM_MOVEABLE, 0), Ok(second));
    assert_eq!(heap.alloc(LMEM_MOVEABLE, 0), Ok(0));
    assert_eq!(heap.handle_tables(&heap.arenas().unwrap()).unwrap(), tables);
    assert!(heap.size(first).unwrap() >= 8);
    assert!(heap.size(third).unwrap() >= 8);
}

#[test]
fn local_handle_delta_extremes_fail_table_expansion_without_wraparound() {
    for delta in [0x3ffe, 0x3fff, 0x4000, 0x8000, 0xffff] {
        let mut bytes = segment(0x1_0000);
        let mut heap = LocalHeap::open(&mut bytes).unwrap();
        assert_eq!(heap.handle_delta(delta), Ok(delta));
        heap.take_write_spans();
        let before = heap.dgroup.to_vec();
        // A zero-size movable allocation isolates table expansion from payload
        // allocation and cannot fit even the largest representable table.
        assert_eq!(heap.alloc(LMEM_MOVEABLE | LMEM_NOCOMPACT, 0), Ok(0));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, before.as_slice());
        assert_eq!(heap.handle_delta(0), Ok(delta));
    }
}

#[test]
fn local_handle_delta_rejects_damaged_metadata_without_writes() {
    for delta in [0, 1, 0xffff] {
        let mut bytes = segment(0x400);
        let mut heap = LocalHeap::open(&mut bytes).unwrap();
        let offset = usize::from(heap.info) + HEAP_MAGIC_OFFSET;
        heap.dgroup[offset] ^= 1;
        let before = heap.dgroup.to_vec();
        assert!(matches!(heap.handle_delta(delta), Err(LocalHeapError::CorruptHeapInfo { .. })));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, before.as_slice());
    }
}
