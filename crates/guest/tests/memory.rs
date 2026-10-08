use guest_core::memory::{Memory, DEFAULT_MEMORY_SIZE, ROM_END, ROM_START};
use guest_core::{GuestMemory, MemoryError, PhysAddr};

#[test]
fn default_owner_has_seventeen_mebibytes_and_a20_enabled() {
    let memory = Memory::new().expect("allocate default guest memory");
    assert_eq!(memory.len(), DEFAULT_MEMORY_SIZE);
    assert!(memory.a20_enabled());
}

#[test]
fn physical_zero_is_addressable_and_mappings_borrow_the_owner() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    {
        let first_bytes = memory
            .map_physical_mut(PhysAddr(0), 2)
            .expect("map physical zero");
        first_bytes.copy_from_slice(&[0x34, 0x12]);
    }

    assert_eq!(memory.read_u16(PhysAddr(0)).unwrap(), 0x1234);
    assert_eq!(memory.map_physical(PhysAddr(0), 2).unwrap(), &[0x34, 0x12]);
}

#[test]
fn physical_range_arithmetic_reports_overflow() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    assert_eq!(
        memory.write(PhysAddr(u32::MAX), &[0xaa, 0xbb]),
        Err(MemoryError::AddressOverflow)
    );
}

#[test]
fn rom_crossing_write_is_rejected_without_changing_ram_prefix() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    memory
        .write_physical(PhysAddr(ROM_START - 1), &[0x7b])
        .expect("initialize RAM byte before ROM");

    assert_eq!(
        memory.write(PhysAddr(ROM_START - 1), &[0x11, 0x22]),
        Err(MemoryError::ReadOnly {
            address: ROM_START - 1,
            length: 2,
        })
    );
    let mut observed = [0; 2];
    memory
        .read_physical(PhysAddr(ROM_START - 1), &mut observed)
        .unwrap();
    assert_eq!(observed, [0x7b, 0x00]);
}

#[test]
fn only_privileged_rom_initialization_can_change_rom() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    memory
        .initialize_rom(PhysAddr(ROM_END - 2), &[0x89, 0xab])
        .expect("initialize bytes at end of ROM");
    assert_eq!(
        memory.write(PhysAddr(ROM_END - 1), &[0xff]),
        Err(MemoryError::ReadOnly {
            address: ROM_END - 1,
            length: 1,
        })
    );
    assert_eq!(memory.read_u16(PhysAddr(ROM_END - 2)).unwrap(), 0xab89);
    assert_eq!(
        memory.initialize_rom(PhysAddr(ROM_START - 1), &[0x55]),
        Err(MemoryError::InvalidMapping)
    );
}

#[test]
fn guest_memory_trait_is_raw_while_bus_view_applies_a20() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    memory
        .initialize_rom(PhysAddr(ROM_END - 1), &[0xa1])
        .expect("initialize final ROM byte");
    memory.write(PhysAddr(0), &[0xb2]).unwrap();
    memory.write(PhysAddr(ROM_END), &[0xc3]).unwrap();
    memory.set_a20_enabled(false);

    // The raw memory owner never folds A20, which keeps XMS/DPMI backing
    // accesses independent from the CPU gate state.
    assert_eq!(memory.read_u8(PhysAddr(ROM_END)).unwrap(), 0xc3);

    // The bus decodes each address, so the byte after 0xFFFFF wraps to zero.
    let bus = memory.bus();
    let mut bytes = [0; 2];
    bus.read(PhysAddr(ROM_END - 1), &mut bytes).unwrap();
    assert_eq!(bytes, [0xa1, 0xb2]);
}

#[test]
fn validation_follows_the_same_raw_or_a20_decoded_path_as_access() {
    let mut memory = Memory::with_size(ROM_END).expect("allocate 1 MiB test memory");
    memory.set_a20_enabled(false);

    assert!(matches!(
        memory.validate_read(PhysAddr(ROM_END), 1),
        Err(MemoryError::OutOfBounds { .. })
    ));
    {
        let bus = memory.bus();
        bus.validate_read(PhysAddr(ROM_END), 1).unwrap();
        bus.validate_write(PhysAddr(ROM_END), 1).unwrap();
    }

    assert!(matches!(
        memory.validate_write(PhysAddr(ROM_START), 1),
        Err(MemoryError::ReadOnly { .. })
    ));
}

#[test]
fn a20_bus_write_preflights_rom_crossing_before_mutating_ram() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    memory.write(PhysAddr(ROM_START - 1), &[0x6d]).unwrap();
    memory.set_a20_enabled(false);

    let mut bus = memory.bus();
    assert_eq!(
        bus.write(PhysAddr(ROM_START - 1), &[0xe1, 0xe2]),
        Err(MemoryError::ReadOnly {
            address: ROM_START - 1,
            length: 2,
        })
    );
    drop(bus);

    assert_eq!(memory.read_u8(PhysAddr(ROM_START - 1)).unwrap(), 0x6d);
}

#[test]
fn mappings_reject_rom_mutation_and_out_of_bounds_ranges() {
    let mut memory = Memory::with_size(2 * 1024 * 1024).expect("allocate test memory");
    assert!(matches!(
        memory.map_physical_mut(PhysAddr(ROM_START), 1),
        Err(MemoryError::ReadOnly { .. })
    ));
    assert!(matches!(
        memory.map_physical(PhysAddr(memory.len()), 1),
        Err(MemoryError::OutOfBounds { .. })
    ));
}

#[test]
fn memory_size_must_cover_the_fixed_rom_window() {
    assert_eq!(
        Memory::with_size(ROM_END - 1).err(),
        Some(MemoryError::InvalidMapping)
    );
}
