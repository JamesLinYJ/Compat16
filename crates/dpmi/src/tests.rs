use super::*;
use guest_core::{GuestMemory, LinearAddr, MemoryError, OwnerId, PhysAddr, Registers};

struct TestMemory {
    bytes: Vec<u8>,
    fail_write_at: Option<u32>,
}

impl TestMemory {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            fail_write_at: None,
        }
    }

    fn slice(&self, start: u32, length: usize) -> &[u8] {
        &self.bytes[start as usize..start as usize + length]
    }
}

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn read(&self, address: PhysAddr, output: &mut [u8]) -> Result<(), MemoryError> {
        let start = address.0 as usize;
        let end = start
            .checked_add(output.len())
            .ok_or(MemoryError::AddressOverflow)?;
        let source = self.bytes.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: output.len(),
        })?;
        output.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, input: &[u8]) -> Result<(), MemoryError> {
        if self.fail_write_at == Some(address.0) {
            return Err(MemoryError::AllocationFailed);
        }
        let start = address.0 as usize;
        let end = start
            .checked_add(input.len())
            .ok_or(MemoryError::AddressOverflow)?;
        let destination = self
            .bytes
            .get_mut(start..end)
            .ok_or(MemoryError::OutOfBounds {
                address: address.0,
                length: input.len(),
            })?;
        destination.copy_from_slice(input);
        Ok(())
    }
}

fn setup() -> (DpmiMemory, TestMemory) {
    let manager =
        DpmiMemory::new(PhysAddr(0x1000), LinearAddr(0x8000), 8 * 4096).expect("valid arena");
    (manager, TestMemory::new(64 * 1024))
}

#[test]
fn allocations_are_page_aligned_zeroed_and_owner_scoped() {
    let (mut manager, mut memory) = setup();
    let owner_a = OwnerId(11);
    let owner_b = OwnerId(22);
    let a = manager.allocate(owner_a, 100, &mut memory).unwrap();
    let b = manager.allocate(owner_b, 5000, &mut memory).unwrap();

    assert_eq!(a.linear, LinearAddr(0x8000));
    assert_eq!(b.linear, LinearAddr(0x9000));
    assert_eq!(a.handle, DpmiHandle(1));
    assert_eq!(b.handle, DpmiHandle(2));
    assert!(memory.slice(0x1000, 4096).iter().all(|byte| *byte == 0));
    assert!(memory.slice(0x2000, 8192).iter().all(|byte| *byte == 0));
    assert_eq!(
        manager.translate_linear(owner_a, a.linear, 100).unwrap(),
        PhysAddr(0x1000)
    );
    assert_eq!(
        manager.translate_linear(owner_a, b.linear, 1),
        Err(DpmiError::InvalidLinearAddress)
    );
    assert_eq!(
        manager.free(owner_a, b.handle),
        Err(DpmiError::InvalidHandle)
    );
    assert_eq!(manager.stats().allocated_pages, 3);
}

#[test]
fn same_extent_resize_preserves_bytes_and_zeroes_newly_visible_bytes() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(7);
    let allocation = manager.allocate(owner, 64, &mut memory).unwrap();
    let payload = [0x5a; 64];
    manager
        .write_linear(owner, allocation.linear, &payload, &mut memory)
        .unwrap();

    let grown = manager
        .resize(owner, allocation.handle, 128, &mut memory)
        .unwrap();
    assert_eq!(grown.linear, allocation.linear);
    assert_ne!(grown.handle, allocation.handle);
    assert_eq!(memory.slice(0x1000, 64), &payload);
    assert!(memory.slice(0x1040, 64).iter().all(|byte| *byte == 0));
    assert_eq!(
        manager.free(owner, allocation.handle),
        Err(DpmiError::InvalidHandle)
    );
    assert_eq!(manager.stats().requested_bytes, 128);

    manager
        .write_linear(owner, grown.linear, &[0xcc; 64], &mut memory)
        .unwrap();
    let shrunk = manager
        .resize(owner, grown.handle, 64, &mut memory)
        .unwrap();
    let regrown = manager
        .resize(owner, shrunk.handle, 128, &mut memory)
        .unwrap();
    assert_eq!(regrown.linear, grown.linear);
    assert!(memory.slice(0x1040, 64).iter().all(|byte| *byte == 0));
}

#[test]
fn page_growth_uses_adjacent_pages_and_shrink_releases_the_tail() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(8);
    let first = manager.allocate(owner, 4096, &mut memory).unwrap();
    manager
        .write_linear(owner, first.linear, &[0x42; 32], &mut memory)
        .unwrap();

    let grown = manager
        .resize(owner, first.handle, 6000, &mut memory)
        .unwrap();
    assert_eq!(grown.linear, first.linear);
    assert_eq!(manager.stats().allocated_pages, 2);
    assert_eq!(memory.slice(0x1000, 32), &[0x42; 32]);

    let shrunk = manager
        .resize(owner, grown.handle, 64, &mut memory)
        .unwrap();
    assert_eq!(shrunk.linear, first.linear);
    assert_eq!(manager.stats().allocated_pages, 1);
    let reused = manager.allocate(owner, 4096, &mut memory).unwrap();
    assert_eq!(reused.linear, LinearAddr(0x9000));
    assert!(memory.slice(0x2000, 4096).iter().all(|byte| *byte == 0));
}

#[test]
fn growth_relocates_atomically_and_preserves_only_the_old_extent() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(9);
    let first = manager.allocate(owner, 4096, &mut memory).unwrap();
    let blocker = manager.allocate(owner, 4096, &mut memory).unwrap();
    let payload = [0x3c; 4096];
    manager
        .write_linear(owner, first.linear, &payload, &mut memory)
        .unwrap();

    let moved = manager
        .resize(owner, first.handle, 8192, &mut memory)
        .unwrap();
    assert_eq!(moved.linear, LinearAddr(0xa000));
    assert_ne!(moved.handle, first.handle);
    assert_eq!(memory.slice(0x3000, 4096), &payload);
    assert!(memory.slice(0x4000, 4096).iter().all(|byte| *byte == 0));
    assert_eq!(
        manager.translate_linear(owner, first.linear, 1),
        Err(DpmiError::InvalidLinearAddress)
    );
    assert_eq!(manager.free(owner, blocker.handle), Ok(()));
    assert_eq!(manager.stats().allocation_count, 1);
}

#[test]
fn failed_relocation_keeps_old_handle_mapping_and_free_capacity() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(13);
    let first = manager.allocate(owner, 4096, &mut memory).unwrap();
    let blocker = manager.allocate(owner, 4096, &mut memory).unwrap();
    let payload = [0xa5; 32];
    manager
        .write_linear(owner, first.linear, &payload, &mut memory)
        .unwrap();
    let before = manager.stats();
    memory.fail_write_at = Some(0x3000);

    assert_eq!(
        manager.resize(owner, first.handle, 8192, &mut memory),
        Err(DpmiError::GuestMemory(MemoryError::AllocationFailed))
    );
    assert_eq!(manager.stats(), before);
    assert_eq!(
        manager.translate_linear(owner, first.linear, 32),
        Ok(PhysAddr(0x1000))
    );
    let mut observed = [0; 32];
    manager
        .read_linear(owner, first.linear, &mut observed, &memory)
        .unwrap();
    assert_eq!(observed, payload);
    memory.fail_write_at = None;
    assert_eq!(manager.free(owner, blocker.handle), Ok(()));
    assert_eq!(manager.stats().free_pages, 7);
}

#[test]
fn free_reuse_scrubs_old_contents_and_coalesces_extents() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(2);
    let first = manager.allocate(owner, 4096, &mut memory).unwrap();
    let second = manager.allocate(owner, 4096, &mut memory).unwrap();
    manager
        .write_linear(owner, first.linear, &[0x7f; 16], &mut memory)
        .unwrap();
    manager.free(owner, first.handle).unwrap();
    manager.free(owner, second.handle).unwrap();
    assert_eq!(manager.stats().largest_free_block, 8 * 4096);

    let reused = manager.allocate(owner, 4096, &mut memory).unwrap();
    assert_eq!(reused.linear, first.linear);
    assert!(memory.slice(0x1000, 4096).iter().all(|byte| *byte == 0));
}

#[test]
fn release_owner_cleans_exact_owner_and_stale_addresses_stop_translating() {
    let (mut manager, mut memory) = setup();
    let first_owner = OwnerId(31);
    let second_owner = OwnerId(32);
    let first = manager.allocate(first_owner, 4096, &mut memory).unwrap();
    let second = manager.allocate(second_owner, 4096, &mut memory).unwrap();

    assert_eq!(manager.release_owner(first_owner), 1);
    assert_eq!(manager.release_owner(first_owner), 0);
    assert_eq!(
        manager.translate_linear(first_owner, first.linear, 1),
        Err(DpmiError::InvalidLinearAddress)
    );
    assert_eq!(
        manager.translate_linear(second_owner, second.linear, 1),
        Ok(PhysAddr(0x2000))
    );
    assert_eq!(manager.stats().allocation_count, 1);
}

#[test]
fn bounds_zero_size_and_memory_failures_do_not_publish_allocations() {
    let (mut manager, mut memory) = setup();
    assert_eq!(
        manager.allocate(OwnerId(1), 0, &mut memory),
        Err(DpmiError::InvalidSize)
    );
    memory.fail_write_at = Some(0x1000);
    assert_eq!(
        manager.allocate(OwnerId(1), 100, &mut memory),
        Err(DpmiError::GuestMemory(MemoryError::AllocationFailed))
    );
    assert_eq!(manager.stats().allocation_count, 0);
    assert_eq!(manager.stats().free_pages, 8);
    memory.fail_write_at = None;
    let allocation = manager.allocate(OwnerId(1), 100, &mut memory).unwrap();
    assert_eq!(allocation.handle, DpmiHandle(1));
    assert_eq!(
        manager.resize(OwnerId(1), allocation.handle, 0, &mut memory),
        Err(DpmiError::InvalidSize)
    );
    assert_eq!(
        manager.translate_linear(OwnerId(1), allocation.linear, 101),
        Err(DpmiError::InvalidLinearAddress)
    );
}

#[test]
fn guest_memory_bounds_are_checked_before_allocator_state_changes() {
    let mut manager =
        DpmiMemory::new(PhysAddr(0x1000), LinearAddr(0x8000), 8 * 4096).expect("valid arena");
    let mut memory = TestMemory::new(0x2000);
    let owner = OwnerId(1);

    assert!(manager.allocate(owner, 4096, &mut memory).is_ok());
    let before = manager.stats();
    assert!(matches!(
        manager.allocate(owner, 4096, &mut memory),
        Err(DpmiError::GuestMemory(MemoryError::OutOfBounds { .. }))
    ));
    assert_eq!(manager.stats(), before);
}

#[test]
fn int31_subset_sets_dpmi_results_and_rejects_unknown_functions() {
    let (mut manager, mut memory) = setup();
    let owner = OwnerId(5);
    let mut regs = Registers::default();
    regs.set_ax(0x0501);
    // Asymmetric words catch accidentally reversing the documented
    // BX:CX size pair: 0000:2000 is 8192 bytes.
    regs.set_bx(0);
    regs.set_cx(0x2000);
    regs.set_carry(true);
    assert_eq!(
        manager.handle_int31(owner, &mut regs, &mut memory),
        Ok(ServiceDisposition::Handled)
    );
    assert!(!regs.carry());
    assert_eq!((regs.bx(), regs.cx()), (0, 0x8000));
    assert_eq!(manager.stats().requested_bytes, 8192);
    let first_handle = DpmiHandle((u32::from(regs.si()) << 16) | u32::from(regs.di()));

    let mut resize_regs = Registers::default();
    resize_regs.set_ax(0x0503);
    resize_regs.set_bx(0);
    resize_regs.set_cx(0x3000);
    resize_regs.set_si((first_handle.0 >> 16) as u16);
    resize_regs.set_di(first_handle.0 as u16);
    manager
        .handle_int31(owner, &mut resize_regs, &mut memory)
        .unwrap();
    assert!(!resize_regs.carry());
    assert_eq!(manager.stats().requested_bytes, 12288);
    let handle = DpmiHandle((u32::from(resize_regs.si()) << 16) | u32::from(resize_regs.di()));
    assert_ne!(handle, first_handle);
    assert_eq!(
        manager.free(owner, first_handle),
        Err(DpmiError::InvalidHandle)
    );

    let mut page_regs = Registers::default();
    page_regs.set_ax(0x0604);
    manager
        .handle_int31(owner, &mut page_regs, &mut memory)
        .unwrap();
    assert_eq!((page_regs.bx(), page_regs.cx()), (0, 4096));
    assert!(!page_regs.carry());

    let mut unsupported = Registers::default();
    unsupported.set_ax(0x0800);
    let original = unsupported.clone();
    assert_eq!(
        manager.handle_int31(owner, &mut unsupported, &mut memory),
        Err(DpmiError::UnsupportedFunction(0x0800))
    );
    assert_eq!(unsupported, original);

    let mut free_regs = Registers::default();
    free_regs.set_ax(0x0502);
    free_regs.set_si((handle.0 >> 16) as u16);
    free_regs.set_di(handle.0 as u16);
    manager
        .handle_int31(owner, &mut free_regs, &mut memory)
        .unwrap();
    assert!(!free_regs.carry());
    assert_eq!(manager.stats().allocation_count, 0);

    let mut zero_size = Registers::default();
    zero_size.set_ax(0x0501);
    zero_size.set_bx(0);
    zero_size.set_cx(0);
    manager
        .handle_int31(owner, &mut zero_size, &mut memory)
        .unwrap();
    assert!(zero_size.carry());
    assert_eq!(zero_size.ax(), DpmiError::InvalidSize.dpmi_code());
    assert_eq!(manager.stats().allocation_count, 0);
}
