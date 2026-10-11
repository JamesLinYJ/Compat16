use super::*;
use formats::{NeFixupAddressType, NeFixupTarget, parse_ne};

#[test]
fn local_handle_delta_probe_has_exact_kernel_imports_and_bounded_segments() {
    let image = win16_local_handle_delta_probe_bytes().unwrap();
    assert_eq!(image, win16_local_handle_delta_probe_bytes().unwrap());
    let module = parse_ne(&image).unwrap();
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_sp, 4096);
    assert_eq!(module.segments.len(), 2);
    assert!(module.resource_types.is_empty());
    assert_eq!(module.imported_modules.len(), 1);
    assert_eq!(module.imported_modules[0].name, b"KERNEL");
    let code = &module.segments[0];
    let data = &module.segments[1];
    assert_eq!(data.file_size as usize, DATA_LENGTH);
    let data_start = data.file_offset.unwrap();
    assert_eq!(&image[data_start..data_start + DATA_LENGTH], &[0; DATA_LENGTH]);
    let start = code.file_offset.unwrap();
    let end = start + code.file_size as usize;
    let ordinals = [4, 310, 5, 310, 310, 5, 8, 310, 310, 5, 5, 9, 7, 7, 7];
    assert_eq!(code.fixups.len(), ordinals.len());
    assert!(end + 2 + 8 * ordinals.len() <= data_start);
    for (fixup, ordinal) in code.fixups.iter().zip(ordinals) {
        assert_eq!(fixup.address_type, NeFixupAddressType::FarPointer32);
        assert_eq!(fixup.target, NeFixupTarget::ImportOrdinal { module_index: 1, ordinal });
        assert!(!fixup.additive);
        let source = start + usize::from(fixup.source_offset);
        assert_eq!(image[source - 1], 0x9a);
        assert_eq!(&image[source..source + 4], &[0xff, 0xff, 0, 0]);
        assert!(source + 4 <= end);
    }
}

#[test]
fn local_handle_delta_guest_encodes_pascal_arguments_and_owned_cleanup() {
    let (code, fixups) = guest_code().unwrap();
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    let call = |index: usize| usize::from(u16::from_le_bytes([fixups[index][2], fixups[index][3]])) - 1;
    assert_eq!(&code[call(0) - 8..call(0)], &[0x6a, 0, 0x68, 0, 2, 0x68, 0xef, 2]);
    for (index, delta) in [(1, 0u16), (3, 1), (4, 0), (7, 2), (8, 0)] {
        let [lo, hi] = delta.to_le_bytes();
        assert_eq!(&code[call(index) - 3..call(index)], &[0x68, lo, hi]);
    }
    assert_eq!(&code[call(2) - 4..call(2)], &[0x6a, 0x12, 0x6a, 96]);
    for (index, size) in [(5, 96u16), (9, 0), (10, 0)] {
        let [lo, hi] = size.to_le_bytes();
        assert_eq!(&code[call(index) - 5..call(index)], &[0x6a, 0x12, 0x68, lo, hi]);
    }
    for (index, slot) in [(6, 40), (11, 40), (12, 44), (13, 42), (14, 40)] {
        assert_eq!(&code[call(index) - 4..call(index)], &[0xff, 0x36, slot, 0]);
    }
    for index in [2, 5, 6, 9, 10] {
        assert_eq!(&code[call(index) + 5..call(index) + 7], &[0x36, 0xa3]);
    }
    // Each API boundary checks the independently saved stack and caller DS.
    assert_eq!(code.windows(5).filter(|w| *w == [0x36, 0x3b, 0x26, 34, 0]).count(), fixups.len());
    assert_eq!(code.windows(7).filter(|w| *w == [0x8c, 0xd9, 0x36, 0x3b, 0x0e, 36, 0]).count(), fixups.len());
    for expected in [32, 1, 2] {
        assert!(contains(&[0x66, 0x3d, expected, 0, 0x34, 0x12]));
    }
    for status in (20..=39).chain(60..=61) {
        assert!(contains(&[0xc7, 0x06, 32, 0, status, 0]), "missing assertion {status}");
    }
    assert!(contains(&[0xc7, 0x06, 48, 0, b'L', b'1']));
    assert!(contains(&[0x81, 0x3e, 0xfe, 1, 0x57, 0x13]));
    assert!(contains(&[0x81, 0x3e, 0xf0, 2, 0x68, 0x24]));
    assert!(contains(&[0x81, 0x3f, 0x5a, 0xa5]));
    assert!(contains(&[0x81, 0x7f, 94, 0xa5, 0x5a]));
}

#[test]
fn local_handle_delta_fixture_heap_geometry_supports_the_guest_sequence() {
    use win16_abi::{local_heap::LocalHeap, prepare_local_heap_init};
    // This checks fixture assumptions, not execution of the NE image. The
    // native acceptance runner separately exercises imports and guest code.
    let mut bytes = vec![0; 4096];
    bytes[usize::from(HEAP_START - 2)..usize::from(HEAP_START)].copy_from_slice(&0x1357u16.to_le_bytes());
    bytes[usize::from(HEAP_END + 1)..usize::from(HEAP_END + 3)].copy_from_slice(&0x2468u16.to_le_bytes());
    prepare_local_heap_init(bytes.len(), HEAP_START, HEAP_END).unwrap().apply_to_slice(&mut bytes).unwrap();
    let mut heap = LocalHeap::open(&mut bytes).unwrap();
    assert_eq!(heap.handle_delta(0), Ok(32));
    assert_eq!(heap.alloc(0x12, 96), Ok(0));
    assert_eq!(heap.handle_delta(1), Ok(1));
    let first = heap.alloc(0x12, 96).unwrap();
    assert_ne!(first, 0);
    let pointer = heap.lock(first).unwrap();
    assert!((HEAP_START..=HEAP_END - 95).contains(&pointer));
    assert_eq!(heap.handle_delta(2), Ok(2));
    let second = heap.alloc(0x12, 0).unwrap();
    let third = heap.alloc(0x12, 0).unwrap();
    assert_ne!(second, 0);
    assert_ne!(third, 0);
    assert_ne!(first, second);
    assert_ne!(first, third);
    assert_ne!(second, third);
    assert_eq!(heap.unlock(first), Ok(0));
    for handle in [third, second, first] { assert_eq!(heap.free(handle), Ok(0)); }
    assert_eq!(&bytes[usize::from(HEAP_START - 2)..usize::from(HEAP_START)], &0x1357u16.to_le_bytes());
    assert_eq!(&bytes[usize::from(HEAP_END + 1)..usize::from(HEAP_END + 3)], &0x2468u16.to_le_bytes());
}

#[test]
fn shared_ne_import_name_window_preserves_the_entry_table() {
    let image = build_image_with_import(&[0x90], &[], 1, b"ABCDEFGHIJKL", false).unwrap();
    let module = parse_ne(&image).unwrap();
    assert_eq!(module.imported_modules[0].name, b"ABCDEFGHIJKL");
    assert_eq!(image[0x40 + 0xa0], 0); // empty entry table terminator
    assert!(build_image_with_import(&[0x90], &[], 1, b"ABCDEFGHIJKLM", false).is_err());
}
