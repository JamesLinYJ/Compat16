use super::*;
use crate::{AccessRights, SegmentedPointer};
use guest_core::{PhysAddr, memory::Memory};

fn source(bytes: &[u8]) -> (Memory, SelectorTable, u32) {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    memory.write(PhysAddr(0x100), bytes).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors.alloc_block(
        PhysAddr(0x100), bytes.len() as u32, AccessRights::read_only(), &memory,
    ).unwrap();
    (memory, selectors, SegmentedPointer::new(selector, 0).far_value())
}

fn arguments(source: u32, limit: u16) -> [Win16Argument; 3] {
    [Win16Argument::Dword(0x1234_0000), Win16Argument::Dword(source),
        Win16Argument::Word(limit)]
}

#[test]
fn lstrcpyn_accepts_byte_prefix_at_selector_end_without_source_nul() {
    // A DBCS pair remains two guest bytes; no encoding conversion occurs.
    let (memory, selectors, pointer) = source(&[0x81, 0x40]);
    assert_eq!(
        decode_kernel_string(353, &arguments(pointer, 3), &selectors, &memory).unwrap(),
        Some(Win16KernelStringRequest::Lstrcpyn {
            destination: 0x1234_0000, source: vec![0x81, 0x40], limit: 3,
        }),
    );
}

#[test]
fn lstrcpyn_one_byte_capacity_does_not_dereference_source() {
    let (memory, selectors, _) = source(b"x");
    assert_eq!(
        decode_kernel_string(353, &arguments(0, 1), &selectors, &memory).unwrap(),
        Some(Win16KernelStringRequest::Lstrcpyn {
            destination: 0x1234_0000, source: Vec::new(), limit: 1,
        }),
    );
}

#[test]
fn lstrcpyn_stops_at_source_nul_before_capacity() {
    let (memory, selectors, pointer) = source(b"x\0");
    assert_eq!(
        decode_kernel_string(353, &arguments(pointer, 10), &selectors, &memory).unwrap(),
        Some(Win16KernelStringRequest::Lstrcpyn {
            destination: 0x1234_0000, source: b"x".to_vec(), limit: 10,
        }),
    );
}

#[test]
fn lstrcpyn_still_checks_each_required_source_byte() {
    let (memory, selectors, pointer) = source(b"xy");
    assert!(decode_kernel_string(353, &arguments(pointer, 4), &selectors, &memory).is_err());
    // The unrelated decoder paths retain their original full-string reads.
    for (ordinal, limit) in [(352, 3), (353, 0), (353, 0xffff)] {
        assert!(decode_kernel_string(
            ordinal, &arguments(pointer, limit), &selectors, &memory,
        ).is_err());
    }
}
