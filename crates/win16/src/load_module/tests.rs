use super::*;
use crate::{AccessRights, SegmentedPointer};
use guest_core::{PhysAddr, memory::Memory};

fn fixture() -> (Memory, SelectorTable, u32) {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let block = selectors
        .alloc_block(PhysAddr(0x1000), 256, AccessRights::read_write(), &memory)
        .unwrap();
    let command = selectors
        .alloc_block(PhysAddr(0x2000), 256, AccessRights::read_write(), &memory)
        .unwrap();
    let environment = selectors
        .alloc_block(PhysAddr(0x3000), 256, AccessRights::read_write(), &memory)
        .unwrap();
    let wire = ExecBlock {
        environment: U16::new(environment.raw().0),
        command: U32::new(SegmentedPointer::new(command, 0).far_value()),
        show: U32::new(SegmentedPointer::new(block, 64).far_value()),
        reserved: U32::new(0),
    };
    memory.write(PhysAddr(0x1000), wire.as_bytes()).unwrap();
    memory.write(PhysAddr(0x1040), &[2, 0, 3, 0]).unwrap();
    memory.write(PhysAddr(0x2000), b"\x05  a\0b").unwrap();
    memory.write(PhysAddr(0x3000), b"C16=child\0\0").unwrap();
    (
        memory,
        selectors,
        SegmentedPointer::new(block, 0).far_value(),
    )
}

#[test]
fn snapshots_preserve_counted_bytes_after_the_source_memory_changes() {
    let (mut memory, selectors, raw) = fixture();
    let parameters = LoadModuleParameters::read(raw, &selectors, &memory).unwrap();
    memory.write(PhysAddr(0x2000), &[0; 32]).unwrap();
    memory.write(PhysAddr(0x3000), &[0; 32]).unwrap();
    assert_eq!(parameters.command_tail, b"  a\0b");
    assert_eq!(parameters.environment, Some(b"C16=child\0\0".to_vec()));
    assert_eq!(parameters.show, 3);
}

#[test]
fn inherited_and_explicit_empty_environments_remain_distinct() {
    let (mut memory, selectors, raw) = fixture();
    memory.write(PhysAddr(0x3000), &[0, 0]).unwrap();
    assert_eq!(
        LoadModuleParameters::read(raw, &selectors, &memory)
            .unwrap()
            .environment,
        Some(vec![0, 0])
    );
    memory.write(PhysAddr(0x1000), &[0, 0]).unwrap();
    assert_eq!(
        LoadModuleParameters::read(raw, &selectors, &memory)
            .unwrap()
            .environment,
        None
    );
}

#[test]
fn command_and_environment_scans_stop_at_their_own_selector_limits() {
    let (mut memory, mut selectors, raw) = fixture();
    memory.write(PhysAddr(0x3000), &[b'X'; 256]).unwrap();
    assert!(LoadModuleParameters::read(raw, &selectors, &memory).is_err());
    memory.write(PhysAddr(0x3000), &[0, 0]).unwrap();
    let command = selectors
        .alloc_block(PhysAddr(0x4000), 4, AccessRights::read_write(), &memory)
        .unwrap();
    memory.write(PhysAddr(0x4000), b"\x04abcd").unwrap();
    memory
        .write(
            PhysAddr(0x1002),
            &SegmentedPointer::new(command, 0).far_value().to_le_bytes(),
        )
        .unwrap();
    assert!(LoadModuleParameters::read(raw, &selectors, &memory).is_err());
    memory.write(PhysAddr(0x4000), &[127]).unwrap();
    assert!(LoadModuleParameters::read(raw, &selectors, &memory).is_err());
}

#[test]
fn zero_length_tail_at_the_last_segment_byte_needs_no_next_address() {
    let (mut memory, mut selectors, raw) = fixture();
    let command = selectors
        .alloc_block(
            PhysAddr(0x1_0000),
            65_536,
            AccessRights::read_write(),
            &memory,
        )
        .unwrap();
    memory.write(PhysAddr(0x1_ffff), &[0]).unwrap();
    memory
        .write(
            PhysAddr(0x1002),
            &SegmentedPointer::new(command, u16::MAX)
                .far_value()
                .to_le_bytes(),
        )
        .unwrap();
    let parameters = LoadModuleParameters::read(raw, &selectors, &memory).unwrap();
    assert!(parameters.command_tail.is_empty());
}
