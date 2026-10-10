use super::*;
use crate::local_heap::{LOCAL_ENTRY_FIXED, prepare_local_heap_init};

fn segment(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    prepare_local_heap_init(size, 0x10, (size - 1) as u16)
        .expect("heap initialization plan").apply_to_slice(&mut bytes).expect("heap initialization");
    bytes
}

fn put(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn populated() -> (Vec<u8>, u16, u16, u16) {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    assert_eq!(heap.atom_init(2), Ok(1));
    let atom = heap.atom_add(b"Name", None, 0).expect("add");
    let handle = heap.atom_handle(atom).expect("handle");
    let table = read_word(heap.dgroup, INSTANCE_ATOM_POINTER_OFFSET).expect("table");
    (bytes, atom, handle, table)
}

fn assert_corrupt_without_writes(bytes: &mut [u8], atom: u16) {
    let before = bytes.to_vec();
    let mut heap = LocalHeap::open(bytes).expect("heap metadata remains valid");
    assert!(matches!(heap.atom_entries(), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_handle(atom), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_name(atom), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_init(37), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_add(b"Other", None, 1), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_delete(atom), Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(matches!(heap.atom_allocation_size(None, Some(5)),
        Err(LocalHeapError::CorruptAtomTable { .. })));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
}

#[test]
fn empty_queries_are_lazy_and_nonmembers_are_not_handles() {
    let mut bytes = segment(0x800);
    let before = bytes.clone();
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    assert_eq!(heap.atom_entries(), Ok(Vec::new()));
    assert_eq!(heap.atom_name(0xc123), Ok(None));
    assert_eq!(heap.atom_handle(0xc123), Ok(0));
    assert_eq!(heap.atom_delete(0xc123), Ok(0xc123));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
}

#[test]
fn initialization_is_fixed_defaulted_and_idempotent() {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    let free_before = heap.count_free().expect("free space");
    assert_eq!(heap.atom_init(0), Ok(1));
    let table = read_word(heap.dgroup, 8).expect("table");
    assert_ne!(table, 0);
    assert_eq!(table & 3, 0);
    assert_eq!(read_word(heap.dgroup, usize::from(table)), Some(DEFAULT_BUCKETS));
    assert!(heap.size(table).expect("fixed size") >= 76);
    assert!(heap.count_free().expect("free space") < free_before);
    assert!(heap.take_write_spans().iter().any(|span| span.start <= 8 && span.end >= 10));
    let before = heap.dgroup.to_vec();
    assert_eq!(heap.atom_init(1), Ok(1));
    assert_eq!(heap.atom_init(-1), Ok(0));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
}

#[test]
fn lazy_add_uses_real_fixed_blocks_and_preserves_guest_bytes() {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    let name = [0x82, 0xa0, b'A', 0xe9];
    let atom = heap.atom_add(&name, None, 123).expect("add");
    assert!(atom >= STRING_ATOM_BASE);
    let handle = heap.atom_handle(atom).expect("handle");
    assert_eq!(atom, 0xc000 | handle >> 2);
    assert_eq!(heap.atom_name(atom), Ok(Some(name.to_vec())));
    assert_eq!(heap.flags(handle), Ok(0));
    assert!(heap.size(handle).expect("local size") >= 10);
    let entry = heap.snapshot_entries().expect("local heap snapshot").into_iter()
        .find(|entry| entry.handle == handle).expect("atom is a real arena");
    assert_eq!(entry.flags, LOCAL_ENTRY_FIXED);
    assert_eq!(entry.address, handle);
    assert_eq!(heap.dgroup[usize::from(handle) + 4], 4);
    assert_eq!(&heap.dgroup[usize::from(handle) + 5..usize::from(handle) + 10],
        &[0x82, 0xa0, b'A', 0xe9, 0]);
    let ordinary = heap.alloc(0, 20).expect("ordinary allocation");
    assert_eq!(heap.atom_handle(atom_for_handle(ordinary)), Ok(0));
    assert_eq!(heap.atom_name(atom_for_handle(ordinary)), Ok(None));
}

#[test]
fn duplicates_increment_only_references_and_preserve_original_spelling() {
    let (mut bytes, atom, handle, _) = populated();
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    let free_before = heap.count_free().expect("free");
    assert_eq!(heap.atom_add(b"NAME", Some(atom), 999), Ok(atom));
    assert_eq!(heap.atom_entries().expect("entries")[0].references, 2);
    assert_eq!(heap.atom_name(atom), Ok(Some(b"Name".to_vec())));
    assert_eq!(heap.count_free(), Ok(free_before));
    assert_eq!(heap.take_write_spans(), vec![usize::from(handle) + 2..usize::from(handle) + 4]);
    assert_eq!(heap.atom_delete(atom), Ok(0));
    assert_eq!(heap.atom_entries().expect("entries")[0].references, 1);
    assert_eq!(heap.atom_handle(atom), Ok(handle));
    assert_eq!(heap.take_write_spans(), vec![usize::from(handle) + 2..usize::from(handle) + 4]);
}

#[test]
fn saturated_and_stale_duplicate_requests_are_atomic_failures() {
    let (mut bytes, atom, handle, _) = populated();
    put(&mut bytes, usize::from(handle) + 2, u16::MAX);
    let before = bytes.clone();
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    assert_eq!(heap.atom_add(b"NAME", Some(atom), 0), Ok(0));
    assert_eq!(heap.atom_add(b"Other", Some(0xffff), 1), Ok(0));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
}

#[test]
fn collision_chains_unlink_middle_head_and_tail() {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    assert_eq!(heap.atom_init(1), Ok(1));
    let table_only_free = heap.count_free().expect("free");
    let first = heap.atom_add(b"First", None, 11).expect("first");
    let middle = heap.atom_add(b"Middle", None, 22).expect("middle");
    let last = heap.atom_add(b"Last", None, 33).expect("last");
    assert_eq!(heap.atom_entries().expect("entries").len(), 3);
    assert_eq!(heap.atom_delete(middle), Ok(0));
    assert_eq!(heap.atom_handle(middle), Ok(0));
    assert_eq!(heap.atom_name(first), Ok(Some(b"First".to_vec())));
    assert_eq!(heap.atom_name(last), Ok(Some(b"Last".to_vec())));
    assert_eq!(heap.atom_delete(last), Ok(0));
    assert_eq!(heap.atom_delete(first), Ok(0));
    assert_eq!(heap.count_free(), Ok(table_only_free));
    assert!(heap.atom_entries().expect("empty").is_empty());
    heap.take_write_spans();
    assert_eq!(heap.atom_delete(first), Ok(first));
    assert_eq!(heap.atom_handle(first), Ok(0));
    assert!(heap.take_write_spans().is_empty());
}

#[test]
fn names_are_bounded_by_guest_bytes() {
    let mut bytes = segment(0x800);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    let before = heap.dgroup.to_vec();
    for name in [&b""[..], &b"a\0b"[..], &[b'x'; 256][..]] {
        assert_eq!(heap.atom_add(name, None, 0), Ok(0));
    }
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
    let name = [0xff; 255];
    let atom = heap.atom_add(&name, None, 0).expect("maximum name");
    assert_ne!(atom, 0);
    assert_eq!(heap.atom_name(atom), Ok(Some(name.to_vec())));
}

#[test]
fn failed_lazy_add_rolls_back_table_allocation_and_write_set() {
    let mut bytes = segment(0xd0);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    let before = heap.dgroup.to_vec();
    // The default table fits, but its following 70-byte entry cannot fit.
    assert_eq!(heap.atom_add(&[b'x'; 64], None, 0), Ok(0));
    assert_eq!(read_word(heap.dgroup, 8), Some(0));
    assert!(heap.take_write_spans().is_empty());
    assert_eq!(heap.dgroup, before);
    assert_ne!(heap.atom_add(b"x", None, 0).expect("smaller retry"), 0);
}

#[test]
fn failed_add_rolls_back_intermediate_movable_compaction() {
    for initialized in [false, true] {
        let mut bytes = segment(0x400);
        let mut heap = LocalHeap::open(&mut bytes).expect("open");
        if initialized {
            assert_eq!(heap.atom_init(1), Ok(1));
        }
        // Put the handle table before the hole and movable arena, so it does
        // not become a fixed barrier between them during the attempted move.
        assert_ne!(heap.alloc(super::super::LMEM_MOVEABLE, 0).expect("handle table"), 0);
        let hole = heap.alloc(0, 64).expect("hole");
        let moving = heap.alloc(super::super::LMEM_MOVEABLE, 96).expect("movable");
        let tail = heap.largest_free_payload().expect("remaining capacity");
        assert_ne!(heap.alloc(0, tail).expect("fill remainder"), 0);
        assert_eq!(heap.free(hole), Ok(0));
        let address = heap.entry(moving).expect("entry").expect("live").addr;
        heap.take_write_spans();
        let before = heap.dgroup.to_vec();

        assert_eq!(heap.atom_add(&[b'x'; 255], None, 0), Ok(0));
        assert!(heap.take_write_spans().is_empty());
        assert_eq!(heap.dgroup, before);
        assert_eq!(heap.entry(moving).expect("entry").expect("live").addr, address);

        // A normal failed allocation keeps its compaction. This demonstrates
        // that the atom attempt above really needed to roll that movement back.
        assert_eq!(heap.alloc(0, 300), Ok(0));
        assert!(heap.entry(moving).expect("entry").expect("live").addr < address);
    }
}

#[test]
fn failed_initialization_preserves_bytes_and_existing_write_spans() {
    let mut bytes = segment(0x100);
    let mut heap = LocalHeap::open(&mut bytes).expect("open");
    assert_ne!(heap.alloc(0, 16).expect("ordinary allocation"), 0);
    let before = heap.dgroup.to_vec();
    let prior_spans = heap.write_spans.clone();
    assert_eq!(heap.atom_init(1000), Ok(0));
    assert_eq!(heap.atom_init(i16::MAX), Ok(0));
    assert_eq!(heap.dgroup, before);
    assert_eq!(heap.take_write_spans(), prior_spans);
}

#[test]
fn growth_budget_accounts_for_lazy_table_and_entry_then_retry_succeeds() {
    let mut bytes = segment(0xd0);
    {
        let mut heap = LocalHeap::open(&mut bytes).expect("open");
        assert_eq!(heap.atom_allocation_size(Some(0), None), Ok(Some(80)));
        assert_eq!(heap.atom_allocation_size(None, Some(64)), Ok(Some(156)));
        assert_eq!(heap.atom_allocation_size(Some(-1), None), Ok(None));
        assert_eq!(heap.atom_allocation_size(Some(i16::MAX), None), Ok(None));
        assert_eq!(heap.atom_allocation_size(None, Some(256)), Ok(None));
        assert_eq!(heap.atom_add(&[b'x'; 64], None, 0), Ok(0));
    }
    bytes.resize(0x300, 0);
    let mut heap = LocalHeap::open(&mut bytes).expect("grown backing");
    heap.grow(0xd0).expect("grow arenas");
    let atom = heap.atom_add(&[b'x'; 64], None, 0).expect("retry");
    assert_ne!(atom, 0);
    assert_eq!(heap.atom_name(atom), Ok(Some(vec![b'x'; 64])));
    assert_eq!(heap.atom_allocation_size(Some(37), None), Ok(None));
    assert_eq!(heap.atom_allocation_size(None, Some(64)), Ok(Some(76)));
}

#[test]
fn reopening_and_copying_a_segment_preserves_the_entire_atom_state() {
    let (bytes, atom, handle, _) = populated();
    let mut copied = bytes.clone();
    let mut heap = LocalHeap::open(&mut copied).expect("independent view");
    assert_eq!(heap.atom_name(atom), Ok(Some(b"Name".to_vec())));
    assert_eq!(heap.atom_handle(atom), Ok(handle));
    assert_eq!(heap.atom_add(b"NAME", Some(atom), 0), Ok(atom));
    assert_eq!(heap.atom_entries().expect("entries")[0].references, 2);
    assert_ne!(copied, bytes);
    let mut other = segment(0x800);
    assert_eq!(LocalHeap::open(&mut other).expect("other DS").atom_handle(atom), Ok(0));
}

#[test]
fn invalid_table_owners_and_bounds_are_rejected() {
    for pointer in [1, 8, 0xffff, 0xfffc] {
        let mut bytes = segment(0x800);
        put(&mut bytes, 8, pointer);
        assert_corrupt_without_writes(&mut bytes, 0xc123);
    }
    for damage in 0..4 {
        let (mut bytes, atom, _, table) = populated();
        let heap = LocalHeap::open(&mut bytes).expect("open");
        let pointer = match damage {
            0 => heap.info,
            1 => heap.first + ARENA_HEADER_BYTES as u16,
            2 => table + 4,
            _ => heap.arenas().expect("arenas").into_iter()
                .find(|arena| arena.free && arena.start != heap.last).expect("free arena").start + 4,
        };
        put(heap.dgroup, 8, pointer);
        assert_corrupt_without_writes(&mut bytes, atom);
    }
    for count in [0, u16::MAX] {
        let (mut bytes, atom, _, table) = populated();
        put(&mut bytes, usize::from(table), count);
        assert_corrupt_without_writes(&mut bytes, atom);
    }
}

#[test]
fn table_cannot_alias_a_movable_block_or_its_handle_table() {
    for handle_table in [false, true] {
        let mut bytes = segment(0x800);
        let mut heap = LocalHeap::open(&mut bytes).expect("open");
        let movable = heap.alloc(super::super::LMEM_MOVEABLE, 80).expect("movable");
        assert_ne!(movable, 0);
        let pointer = if handle_table {
            heap.handle_tables(&heap.arenas().expect("arenas")).expect("tables")[0].start
        } else {
            heap.lock(movable).expect("address") - MOVEABLE_PREFIX_BYTES as u16
        };
        put(heap.dgroup, 8, pointer);
        assert_corrupt_without_writes(&mut bytes, 0xc123);
    }
}

#[test]
fn cycles_duplicate_links_and_table_self_links_are_rejected() {
    for damage in 0..3 {
        let (mut bytes, atom, handle, table) = populated();
        match damage {
            0 => put(&mut bytes, usize::from(handle), handle),
            1 => put(&mut bytes, usize::from(table) + 4, handle),
            _ => put(&mut bytes, usize::from(table) + 2, table),
        }
        assert_corrupt_without_writes(&mut bytes, atom);
    }
}

#[test]
fn malformed_entry_lengths_references_and_terminators_are_rejected() {
    for damage in 0..6 {
        let (mut bytes, atom, handle, _) = populated();
        let offset = usize::from(handle);
        match damage {
            0 => put(&mut bytes, offset + 2, 0),
            1 => bytes[offset + 4] = 0,
            2 => bytes[offset + 4] = 255,
            3 => bytes[offset + 6] = 0,
            4 => bytes[offset + 9] = b'x',
            _ => put(&mut bytes, offset, 0xfffc),
        }
        assert_corrupt_without_writes(&mut bytes, atom);
    }
}

#[test]
fn dangling_entries_are_corruption_instead_of_arbitrary_fixed_handles() {
    let (mut bytes, atom, handle, _) = populated();
    assert_eq!(LocalHeap::open(&mut bytes).expect("open").free(handle), Ok(0));
    assert_corrupt_without_writes(&mut bytes, atom);
}
