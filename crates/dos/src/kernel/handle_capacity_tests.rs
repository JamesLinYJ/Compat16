//! INT 21h/AH=67h exercises use a real PSP, MCB arena, and published SFT.

use std::ops::Range;

use super::system::{SFT_ENTRY_BYTES, SFT_HEADER_BYTES, SFT_OFFSET, SYSTEM_SEGMENT};
use super::tests::TestHost;
use crate::caller_address_space::{
    DosCallAddressSpace, DosCallerId, DosFarPointer, DosPersistentFarPointer, DosPointerAccess,
    DosSpanPolicy,
};
use crate::{DosAction, DosError, DosErrorCode, DosKernel};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Registers, real_address};

const PSP: u16 = 0x1000;
const INLINE_JFT: u16 = 0x18;
const JFT_HEADER: u16 = 0x32;
const PROGRAM_PARAGRAPHS: u16 = 0x100;

struct CapacityMemory {
    bytes: Vec<u8>,
    read_only: Option<Range<usize>>,
    fail_write: Option<(Range<usize>, usize)>,
    writes: Vec<(u32, usize)>,
}

impl CapacityMemory {
    fn new() -> Self {
        Self {
            bytes: vec![0; 0xa_0000],
            read_only: None,
            fail_write: None,
            writes: Vec::new(),
        }
    }

    fn overlaps(range: &Range<usize>, address: PhysAddr, length: usize) -> bool {
        let start = address.0 as usize;
        start < range.end && range.start < start.saturating_add(length)
    }

    fn copy(&self, address: PhysAddr, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        self.read(address, &mut bytes).unwrap();
        bytes
    }
}

impl GuestMemory for CapacityMemory {
    fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.validate_read(address, length)?;
        if self
            .read_only
            .as_ref()
            .is_some_and(|range| Self::overlaps(range, address, length))
        {
            return Err(MemoryError::ReadOnly { address: address.0, length });
        }
        Ok(())
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.validate_read(address, bytes.len())?;
        let start = address.0 as usize;
        bytes.copy_from_slice(&self.bytes[start..start + bytes.len()]);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_write(address, bytes.len())?;
        self.writes.push((address.0, bytes.len()));
        if self
            .fail_write
            .as_ref()
            .is_some_and(|(range, _)| Self::overlaps(range, address, bytes.len()))
        {
            // A storage failure after successful preflight must stay a typed
            // fatal error, not become an ordinary DOS out-of-memory result.
            let (_, requested_transfer) = self.fail_write.take().unwrap();
            let transferred = requested_transfer.min(bytes.len());
            let start = address.0 as usize;
            self.bytes[start..start + transferred].copy_from_slice(&bytes[..transferred]);
            return Err(MemoryError::StorageAccess {
                address: address.0,
                length: bytes.len(),
                transferred,
                write: true,
                os_error: None,
            });
        }
        let start = address.0 as usize;
        self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

struct Fixture {
    dos: DosKernel,
    memory: CapacityMemory,
    host: TestHost,
}

impl Fixture {
    fn new() -> Self {
        let mut memory = CapacityMemory::new();
        let mut entries = [0xff; 20];
        entries[..3].copy_from_slice(&[0, 1, 2]);
        memory.write(real_address(PSP, INLINE_JFT), &entries).unwrap();
        write_header(&mut memory, 20, INLINE_JFT, PSP);
        let mut dos = DosKernel::new(PSP);
        let mut host = TestHost::default();
        dos.initialize_system_tables(&mut memory).unwrap();
        dos.refresh_system_tables(&mut memory, &mut host).unwrap();
        let mut fixture = Self { dos, memory, host };
        // DOS initially owns all conventional memory. Release the unused
        // program tail exactly as a real process does before growing its JFT.
        let mut regs = call_registers(0x4a00, PROGRAM_PARAGRAPHS, 0);
        regs.es = PSP;
        fixture.interrupt(&mut regs).unwrap();
        assert!(!regs.carry());
        fixture
    }

    fn interrupt(&mut self, regs: &mut Registers) -> Result<DosAction, DosError> {
        self.dos.interrupt(0x21, regs, &mut self.memory, &mut self.host)
    }

    fn set_capacity(&mut self, count: u16) -> Registers {
        let mut regs = call_registers(0x6700, count, 0);
        assert_eq!(self.interrupt(&mut regs).unwrap(), DosAction::Continue);
        regs
    }

    fn grow(&mut self, count: u16) {
        let regs = self.set_capacity(count);
        assert!(!regs.carry(), "AH=67h rejected capacity {count}: AX={:04x}", regs.ax());
        assert_eq!(self.dos.jft_capacity, count.max(20));
    }

    fn duplicate_to(&mut self, source: u16, target: u16) -> Registers {
        let mut regs = call_registers(0x4600, source, target);
        assert_eq!(self.interrupt(&mut regs).unwrap(), DosAction::Continue);
        regs
    }

    fn close(&mut self, handle: u16) {
        let mut regs = call_registers(0x3e00, handle, 0);
        self.interrupt(&mut regs).unwrap();
        assert!(!regs.carry());
    }

    fn header(&self) -> (u16, u16, u16) {
        (
            self.memory.read_u16(real_address(PSP, JFT_HEADER)).unwrap(),
            self.memory.read_u16(real_address(PSP, JFT_HEADER + 2)).unwrap(),
            self.memory.read_u16(real_address(PSP, JFT_HEADER + 4)).unwrap(),
        )
    }

    fn jft(&self) -> Vec<u8> {
        let (count, offset, segment) = self.header();
        self.memory.copy(real_address(segment, offset), usize::from(count))
    }

    fn sft_references(&self, index: u8) -> u16 {
        let offset = usize::from(SFT_OFFSET)
            + SFT_HEADER_BYTES
            + usize::from(index) * SFT_ENTRY_BYTES;
        self.memory.read_u16(real_address(SYSTEM_SEGMENT, offset as u16)).unwrap()
    }

    fn arena(&mut self) -> Vec<(u16, [u8; 16])> {
        self.dos.mcb_chain(&mut self.memory).unwrap().into_iter()
            .map(|mcb| (mcb.segment, mcb.raw)).collect()
    }

    fn exhaust_free_arena(&mut self) {
        let largest = self.dos.largest_free_block(&mut self.memory).unwrap();
        assert!(largest > 0);
        let mut regs = call_registers(0x4800, largest, 0);
        self.interrupt(&mut regs).unwrap();
        assert!(!regs.carry());
        assert_eq!(self.dos.largest_free_block(&mut self.memory).unwrap(), 0);
    }
}

fn call_registers(ax: u16, bx: u16, cx: u16) -> Registers {
    let mut regs = Registers::default();
    regs.set_ax(ax);
    regs.set_bx(bx);
    regs.set_cx(cx);
    regs
}

fn write_header(memory: &mut CapacityMemory, count: u16, offset: u16, segment: u16) {
    let mut header = [0; 6];
    header[..2].copy_from_slice(&count.to_le_bytes());
    header[2..4].copy_from_slice(&offset.to_le_bytes());
    header[4..].copy_from_slice(&segment.to_le_bytes());
    memory.write(real_address(PSP, JFT_HEADER), &header).unwrap();
}

fn assert_dos_error(regs: &Registers, error: DosErrorCode) {
    assert!(regs.carry());
    assert_eq!(regs.ax(), error as u16);
}

#[test]
fn default_capacity_limits_duplicate_and_force_duplicate_to_twenty_slots() {
    let mut fixture = Fixture::new();
    for expected in 3..20 {
        let mut regs = call_registers(0x4500, 0, 0);
        fixture.interrupt(&mut regs).unwrap();
        assert!(!regs.carry());
        assert_eq!(regs.ax(), expected);
    }
    let mut regs = call_registers(0x4500, 0, 0);
    fixture.interrupt(&mut regs).unwrap();
    assert_dos_error(&regs, DosErrorCode::TooManyOpenFiles);
    let regs = fixture.duplicate_to(0, 20);
    assert_dos_error(&regs, DosErrorCode::InvalidHandle);
    assert_eq!(fixture.dos.jft_capacity, 20);
    assert_eq!(fixture.header(), (20, INLINE_JFT, PSP));
    assert_eq!(fixture.sft_references(0), 18);
}

#[test]
fn expanded_capacity_drives_lowest_free_duplicate_search_past_ff() {
    let mut fixture = Fixture::new();
    fixture.grow(257);
    for expected in 3..257 {
        let mut regs = call_registers(0x4500, 0, 0);
        fixture.interrupt(&mut regs).unwrap();
        assert!(!regs.carry());
        assert_eq!(regs.ax(), expected);
    }
    let mut regs = call_registers(0x4500, 0, 0);
    fixture.interrupt(&mut regs).unwrap();
    assert_dos_error(&regs, DosErrorCode::TooManyOpenFiles);
    assert_eq!(&fixture.jft()[255..257], &[0, 0]);
    assert_eq!(fixture.sft_references(0), 255);
    fixture.close(7);
    let mut regs = call_registers(0x4500, 0, 0);
    fixture.interrupt(&mut regs).unwrap();
    assert!(!regs.carry());
    assert_eq!(regs.ax(), 7);
    assert_eq!(fixture.sft_references(0), 255);
}

#[test]
fn successful_capacity_changes_preserve_registers_and_flags_except_carry() {
    let mut fixture = Fixture::new();
    for count in [21u16, 256, 20] {
        let mut regs = Registers {
            eax: 0x1234_67a5, ebx: 0xabcd_0000 | u32::from(count),
            ecx: 0x2345_6789, edx: 0x3456_789a, esp: 0x4567_89ab,
            ebp: 0x5678_9abc, esi: 0x6789_abcd, edi: 0x789a_bcde,
            eip: 0x89ab_cdef, eflags: 0x0000_0ad7, cs: 0x1111,
            ds: 0x2222, es: 0x3333, ss: 0x4444, fs: 0x5555, gs: 0x6666,
        };
        let mut expected = regs.clone();
        expected.eflags &= !1;
        fixture.interrupt(&mut regs).unwrap();
        assert_eq!(regs, expected);
        assert_eq!(fixture.header().0, count);
    }
}

#[test]
fn ah67_boundaries_publish_count_pointer_and_closed_new_entries() {
    for count in [20, 21, 255, 256, 0xfffe] {
        let mut fixture = Fixture::new();
        fixture.grow(count);
        let (published, offset, segment) = fixture.header();
        assert_eq!(published, count);
        let entries = fixture.jft();
        assert_eq!(&entries[..3], &[0, 1, 2]);
        assert!(entries[3..].iter().all(|&entry| entry == 0xff));
        assert_eq!(fixture.sft_references(0), 1);
        assert_eq!(fixture.sft_references(1), 1);
        assert_eq!(fixture.sft_references(2), 1);
        if count == 20 {
            assert_eq!((offset, segment), (INLINE_JFT, PSP));
            assert!(fixture.dos.jft_storage.is_none());
        } else {
            assert_eq!(offset, 0);
            let extent = fixture.dos.jft_storage.as_ref().unwrap().extent();
            assert_eq!(segment, extent.data_segment());
            assert_eq!(extent.owner_psp_segment(), PSP);
            assert!(extent.byte_length().unwrap() >= usize::from(count));
            assert!(fixture.dos.block_leases.is_pinned(segment, PSP).unwrap());
        }
    }
}

#[test]
fn ah67_rejects_ffff_without_changing_registers_other_than_ax_and_carry() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let arena = fixture.arena();
    let header = fixture.header();
    let entries = fixture.jft();
    let mut regs = Registers {
        eax: 0x1234_6789, ebx: 0xabcd_ffff, ecx: 0x2345_6789,
        edx: 0x3456_789a, esp: 0x4567_89ab, ebp: 0x5678_9abc,
        esi: 0x6789_abcd, edi: 0x789a_bcde, eip: 0x89ab_cdef,
        eflags: 0x0000_0ad6, cs: 0x1111, ds: 0x2222, es: 0x3333,
        ss: 0x4444, fs: 0x5555, gs: 0x6666,
    };
    let mut expected = regs.clone();
    expected.set_ax(DosErrorCode::InvalidFunction as u16);
    expected.eflags |= 1;
    fixture.memory.writes.clear();
    assert_eq!(fixture.interrupt(&mut regs).unwrap(), DosAction::Continue);
    assert_eq!(regs, expected);
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.header(), header);
    assert_eq!(fixture.jft(), entries);
    assert_eq!(fixture.arena(), arena);
    assert_eq!(fixture.dos.jft_capacity, 256);
}

#[test]
fn ah67_clamps_small_counts_and_restores_inline_storage() {
    for requested in [0, 1, 19, 20] {
        let mut fixture = Fixture::new();
        fixture.grow(256);
        let old_segment = fixture.header().2;
        fixture.grow(requested);
        assert_eq!(fixture.header(), (20, INLINE_JFT, PSP));
        assert!(fixture.dos.jft_storage.is_none());
        assert!(!fixture.dos.block_leases.is_pinned(old_segment, PSP).unwrap());
        assert_eq!(&fixture.jft()[..3], &[0, 1, 2]);
        assert!(fixture.jft()[3..].iter().all(|&entry| entry == 0xff));
        assert!(fixture.dos.owned_block_extent(&mut fixture.memory, old_segment, PSP).unwrap().is_none());
    }
}

#[test]
fn ah67_same_count_is_noop_even_without_free_dos_memory() {
    for capacity in [20, 256] {
        let mut fixture = Fixture::new();
        fixture.grow(capacity);
        fixture.exhaust_free_arena();
        let header = fixture.header();
        let arena = fixture.arena();
        let bytes = fixture.memory.bytes.clone();
        let mut regs = call_registers(0x67a5, capacity, 0x3456);
        regs.eflags = 0x0ad7;
        let mut expected = regs.clone();
        expected.eflags &= !1;
        fixture.memory.writes.clear();
        fixture.interrupt(&mut regs).unwrap();
        assert_eq!(regs, expected);
        assert!(fixture.memory.writes.is_empty());
        assert_eq!(fixture.memory.bytes, bytes);
        assert_eq!(fixture.header(), header);
        assert_eq!(fixture.arena(), arena);
    }
}

#[test]
fn high_jft_indices_are_aliases_not_byte_sized_sft_indices() {
    for (capacity, target) in [(256, 255), (0xfffe, 0xfffd)] {
        let mut fixture = Fixture::new();
        fixture.grow(capacity);
        let regs = fixture.duplicate_to(0, target);
        assert!(!regs.carry());
        assert_eq!(fixture.jft()[usize::from(target)], 0);
        assert_eq!(fixture.sft_references(0), 2);
        let arena = fixture.arena();
        let header = fixture.header();
        let regs = fixture.set_capacity(target);
        assert_dos_error(&regs, DosErrorCode::TooManyOpenFiles);
        assert_eq!(fixture.header(), header);
        assert_eq!(fixture.arena(), arena);
        assert_eq!(fixture.sft_references(0), 2);
        let regs = fixture.duplicate_to(0, capacity);
        assert_dos_error(&regs, DosErrorCode::InvalidHandle);
        fixture.close(target);
        assert_eq!(fixture.sft_references(0), 1);
        fixture.grow(target);
        assert!(fixture.jft()[3..].iter().all(|&entry| entry == 0xff));
    }
}

#[test]
fn resizing_uses_owned_mappings_and_never_imports_forged_jft_entries() {
    let mut fixture = Fixture::new();
    fixture.memory.write_u8(real_address(PSP, INLINE_JFT), 0xff).unwrap();
    fixture.memory.write_u8(real_address(PSP, INLINE_JFT + 3), 1).unwrap();
    fixture.grow(256);
    assert_eq!(&fixture.jft()[..4], &[0, 1, 2, 0xff]);
    assert_eq!(fixture.sft_references(0), 1);
    assert_eq!(fixture.sft_references(1), 1);
    assert!(!fixture.dos.handles.contains_key(&3));
}

#[test]
fn redirected_default_jft_never_transfers_ownership_of_guest_supplied_storage() {
    for owner in [PSP, 0x3000] {
        let mut fixture = Fixture::new();
        let guest_segment = fixture.dos.allocate_owned_block(&mut fixture.memory, owner, 4).unwrap();
        let guest_lease = fixture.dos.pin_owned_block(&mut fixture.memory, guest_segment, owner).unwrap().unwrap();
        let extent = guest_lease.extent();
        let guest_address = real_address(guest_segment, 0);
        let guest_bytes = [1; 64];
        fixture.memory.write(guest_address, &guest_bytes).unwrap();
        write_header(&mut fixture.memory, 20, 0, guest_segment);
        let guest_mcb = fixture.memory.copy(real_address(guest_segment - 1, 0), 16);

        fixture.grow(256);

        assert_ne!(fixture.header().2, guest_segment);
        assert_eq!(&fixture.jft()[..3], &[0, 1, 2]);
        assert!(fixture.jft()[3..].iter().all(|&entry| entry == 0xff));
        assert_eq!(fixture.memory.copy(guest_address, 64), guest_bytes);
        assert_eq!(fixture.memory.copy(real_address(guest_segment - 1, 0), 16), guest_mcb);
        assert_eq!(fixture.dos.owned_block_extent(&mut fixture.memory, guest_segment, owner).unwrap(), Some(extent));
        assert!(fixture.dos.block_leases.is_pinned(guest_segment, owner).unwrap());
        assert!(fixture.dos.block_lease_is_last_pin(&mut fixture.memory, &guest_lease).unwrap());
        assert!(fixture.dos.retired_jft_storage.is_empty());
        // Only the caller holding this original lease may release the
        // redirected block; AH=67h merely replaced its published pointer.
        fixture.dos.release_block_lease(&mut fixture.memory, &guest_lease, true).unwrap();
        assert!(fixture.dos.owned_block_extent(&mut fixture.memory, guest_segment, owner).unwrap().is_none());
        assert_eq!(fixture.dos.jft_capacity, 256);
    }
}

#[test]
fn growth_shrink_and_regrowth_preserve_aliases_and_clear_closed_slots() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    assert!(!fixture.duplicate_to(0, 200).carry());
    assert!(!fixture.duplicate_to(1, 19).carry());
    fixture.grow(512);
    assert_eq!(fixture.jft()[200], 0);
    assert_eq!(fixture.jft()[19], 1);
    assert_eq!(fixture.sft_references(0), 2);
    assert_eq!(fixture.sft_references(1), 2);
    fixture.close(200);
    fixture.grow(20);
    assert_eq!(fixture.jft()[19], 1);
    fixture.grow(256);
    assert_eq!(fixture.jft()[200], 0xff);
    assert_eq!(fixture.sft_references(0), 1);
    assert_eq!(fixture.sft_references(1), 2);
}

#[test]
fn out_of_memory_does_not_free_old_jft_to_satisfy_replacement_allocation() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    assert!(!fixture.duplicate_to(0, 200).carry());
    fixture.exhaust_free_arena();
    let header = fixture.header();
    let entries = fixture.jft();
    let arena = fixture.arena();
    for requested in [255, 512] {
        let regs = fixture.set_capacity(requested);
        assert_dos_error(&regs, DosErrorCode::InsufficientMemory);
        assert_eq!(fixture.dos.jft_capacity, 256);
        assert_eq!(fixture.header(), header);
        assert_eq!(fixture.jft(), entries);
        assert_eq!(fixture.arena(), arena);
        assert_eq!(fixture.sft_references(0), 2);
        assert!(fixture.dos.block_leases.is_pinned(header.2, PSP).unwrap());
    }
    // Returning to the PSP does not need a new allocation.
    fixture.close(200);
    fixture.grow(20);
    assert_eq!(fixture.header(), (20, INLINE_JFT, PSP));
}

#[test]
fn forged_count_and_expanded_pointer_are_rejected_before_any_write() {
    for (count, offset, segment) in [
        (255, 0, 0x7000),
        (256, 0, 0x7000),
        (256, 0xff80, 0x1000),
        (256, SFT_OFFSET, SYSTEM_SEGMENT),
    ] {
        let mut fixture = Fixture::new();
        fixture.grow(256);
        let old_segment = fixture.header().2;
        let arena = fixture.arena();
        write_header(&mut fixture.memory, count, offset, segment);
        let bytes = fixture.memory.bytes.clone();
        fixture.memory.writes.clear();
        let mut regs = call_registers(0x6700, 512, 0);
        let before = regs.clone();
        assert!(fixture.interrupt(&mut regs).is_err());
        assert_eq!(regs, before);
        assert!(fixture.memory.writes.is_empty());
        assert_eq!(fixture.memory.bytes, bytes);
        assert_eq!(fixture.dos.jft_capacity, 256);
        assert!(fixture.dos.block_leases.is_pinned(old_segment, PSP).unwrap());
        assert_eq!(fixture.arena(), arena);
    }
}

#[test]
fn forged_inline_count_segment_wrap_and_rom_jft_are_rejected() {
    for (count, offset, segment, read_only) in [
        (21, INLINE_JFT, PSP, None),
        (20, 0xfff0, PSP, None),
        (20, 0, 0x7000, Some(0x70000..0x70014)),
    ] {
        let mut fixture = Fixture::new();
        write_header(&mut fixture.memory, count, offset, segment);
        fixture.memory.read_only = read_only;
        let bytes = fixture.memory.bytes.clone();
        fixture.memory.writes.clear();
        let mut regs = call_registers(0x6700, 256, 0);
        assert!(fixture.interrupt(&mut regs).is_err());
        assert_eq!(fixture.memory.bytes, bytes);
        assert!(fixture.memory.writes.is_empty());
        assert_eq!(fixture.dos.jft_capacity, 20);
    }
}

#[test]
fn jft_lease_blocks_dos_free_and_resize_of_its_backing_mcb() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let segment = fixture.header().2;
    let arena = fixture.arena();
    let header = fixture.header();
    let mut regs = call_registers(0x4900, 0, 0);
    regs.es = segment;
    fixture.interrupt(&mut regs).unwrap();
    assert_dos_error(&regs, DosErrorCode::InvalidMemoryBlock);
    for paragraphs in [1, 17] {
        let mut regs = call_registers(0x4a00, paragraphs, 0);
        regs.es = segment;
        fixture.interrupt(&mut regs).unwrap();
        assert_dos_error(&regs, DosErrorCode::InsufficientMemory);
        assert_eq!(fixture.header(), header);
        assert_eq!(fixture.arena(), arena);
    }
    fixture.grow(512);
    assert!(!fixture.dos.block_leases.is_pinned(segment, PSP).unwrap());
}

#[test]
fn tampered_jft_mcb_owner_cannot_be_reallocated_or_silently_repaired() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let segment = fixture.header().2;
    fixture.memory.write_u16(real_address(segment - 1, 1), 0).unwrap();
    let bytes = fixture.memory.bytes.clone();
    fixture.memory.writes.clear();
    let mut regs = call_registers(0x6700, 512, 0);
    assert!(fixture.interrupt(&mut regs).is_err());
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.memory.bytes, bytes);
    assert_eq!(fixture.dos.jft_capacity, 256);
}

#[test]
fn read_only_psp_header_prevents_relocation_before_arena_mutation() {
    let mut fixture = Fixture::new();
    let arena = fixture.arena();
    let start = real_address(PSP, JFT_HEADER).0 as usize;
    fixture.memory.read_only = Some(start..start + 6);
    fixture.memory.writes.clear();
    let mut regs = call_registers(0x6700, 256, 0);
    assert!(fixture.interrupt(&mut regs).is_err());
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.arena(), arena);
    assert_eq!(fixture.header(), (20, INLINE_JFT, PSP));
    assert_eq!(fixture.dos.jft_capacity, 20);
}

#[test]
fn backing_storage_failure_stays_fatal_and_does_not_publish_new_capacity() {
    let mut fixture = Fixture::new();
    let header = fixture.header();
    let entries = fixture.jft();
    // The first free MCB starts immediately after the shrunken program;
    // the following paragraph is where the new JFT payload will be written.
    let new_jft = real_address(PSP + PROGRAM_PARAGRAPHS + 1, 0).0 as usize;
    fixture.memory.fail_write = Some((new_jft..new_jft + 256, 0));
    let mut regs = call_registers(0x6700, 256, 0);
    let before = regs.clone();
    let result = fixture.interrupt(&mut regs);
    assert!(matches!(result, Err(DosError::Memory(MemoryError::StorageAccess { .. }))));
    assert_eq!(regs, before);
    assert_eq!(fixture.dos.jft_capacity, 20);
    assert_eq!(fixture.header(), header);
    assert_eq!(fixture.jft(), entries);
    assert_eq!(fixture.sft_references(0), 1);
    assert_eq!(fixture.dos.handles.len(), 3);
}

fn assert_arena_stays_faulted(fixture: &mut Fixture, related: &mut DosKernel) {
    let bytes = fixture.memory.bytes.clone();
    let writes = fixture.memory.writes.clone();
    for dos in [&mut fixture.dos, related] {
        let mut regs = call_registers(0x3000, 0, 0);
        let before = regs.clone();
        assert!(matches!(
            dos.interrupt(0x21, &mut regs, &mut fixture.memory, &mut fixture.host),
            Err(DosError::HostContractViolation(_))
        ));
        assert_eq!(regs, before);
        assert!(matches!(
            dos.free_process_blocks(&mut fixture.memory, PSP),
            Err(DosError::HostContractViolation(_))
        ));
        assert!(matches!(
            dos.allocate_pinned_block(&mut fixture.memory, PSP, 1),
            Err(DosError::HostContractViolation(_))
        ));
        assert!(matches!(
            dos.release_jft_storage(&mut fixture.memory),
            Err(DosError::HostContractViolation(_))
        ));
        assert!(matches!(
            dos.initialize_system_tables(&mut fixture.memory),
            Err(DosError::HostContractViolation(_))
        ));
        let handles = dos.handles.clone();
        let mappings = dos.file_table.live_handles().collect::<Vec<_>>();
        let error = dos.close_all_handles_checked(&mut fixture.host).unwrap_err();
        assert_eq!(error.code, DosErrorCode::GeneralFailure);
        assert_eq!(dos.handles, handles);
        assert_eq!(dos.file_table.live_handles().collect::<Vec<_>>(), mappings);
    }
    assert_eq!(fixture.memory.bytes, bytes);
    assert_eq!(fixture.memory.writes, writes);
}

#[test]
fn partial_psp_publication_retains_both_leases_and_faults_shared_arena() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let old_segment = fixture.dos.jft_storage.as_ref().unwrap().extent().data_segment();
    let mut child = DosKernel::child_allocation_owner(&fixture.dos, 0x3000);
    let start = real_address(PSP, JFT_HEADER).0 as usize;
    fixture.memory.fail_write = Some((start..start + 6, 3));
    let mut regs = call_registers(0x6700, 512, 0);
    let before = regs.clone();
    assert!(matches!(
        fixture.interrupt(&mut regs),
        Err(DosError::Memory(MemoryError::StorageAccess { transferred: 3, .. }))
    ));
    assert_eq!(regs, before);
    assert_eq!(fixture.dos.jft_capacity, 256);
    assert_eq!(fixture.header().0, 512); // Partial publication was not rolled back.
    assert_eq!(fixture.dos.jft_storage.as_ref().unwrap().extent().data_segment(), old_segment);
    assert_eq!(fixture.dos.retired_jft_storage.len(), 1);
    let prepared = fixture.dos.retired_jft_storage[0].extent().data_segment();
    assert_ne!(prepared, old_segment);
    assert!(fixture.dos.block_leases.is_pinned(old_segment, PSP).unwrap());
    assert!(fixture.dos.block_leases.is_pinned(prepared, PSP).unwrap());
    assert_eq!(fixture.memory.writes.last(), Some(&(start as u32, 6)));
    assert_arena_stays_faulted(&mut fixture, &mut child);
}

#[test]
fn partial_allocation_mcb_write_faults_arena_before_a_lease_can_be_returned() {
    let mut fixture = Fixture::new();
    let mut child = DosKernel::child_allocation_owner(&fixture.dos, 0x3000);
    let start = real_address(PSP + PROGRAM_PARAGRAPHS, 0).0 as usize;
    let original = fixture.memory.copy(PhysAddr(start as u32), 16);
    fixture.memory.fail_write = Some((start..start + 16, 3));
    fixture.memory.writes.clear();
    let mut regs = call_registers(0x6700, 256, 0);
    let before = regs.clone();
    assert!(matches!(
        fixture.interrupt(&mut regs),
        Err(DosError::Memory(MemoryError::StorageAccess { transferred: 3, .. }))
    ));
    assert_eq!(regs, before);
    assert_eq!(fixture.memory.writes, vec![(start as u32, 16)]);
    assert_ne!(fixture.memory.copy(PhysAddr(start as u32), 16), original);
    assert_eq!(fixture.dos.jft_capacity, 20);
    assert_eq!(fixture.header(), (20, INLINE_JFT, PSP));
    assert!(fixture.dos.jft_storage.is_none());
    assert!(fixture.dos.retired_jft_storage.is_empty());
    // No lease was returned, so the shared pending-allocation guard must
    // still stop both the original owner and related process from reuse.
    assert_arena_stays_faulted(&mut fixture, &mut child);
}

#[test]
fn partial_release_mcb_write_retains_current_lease_and_faults_shared_arena() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let segment = fixture.dos.jft_storage.as_ref().unwrap().extent().data_segment();
    let mut child = DosKernel::child_allocation_owner(&fixture.dos, 0x3000);
    let start = real_address(segment - 1, 0).0 as usize;
    fixture.memory.fail_write = Some((start..start + 16, 3));
    fixture.memory.writes.clear();
    assert!(matches!(
        fixture.dos.release_jft_storage(&mut fixture.memory),
        Err(DosError::Memory(MemoryError::StorageAccess { transferred: 3, .. }))
    ));
    assert_eq!(fixture.memory.writes, vec![(start as u32, 16)]);
    assert_eq!(fixture.memory.read_u16(real_address(segment - 1, 1)).unwrap(), 0);
    assert_eq!(fixture.dos.jft_storage.as_ref().unwrap().extent().data_segment(), segment);
    assert!(fixture.dos.block_leases.is_pinned(segment, PSP).unwrap());
    assert_eq!(fixture.dos.jft_capacity, 256);
    assert_arena_stays_faulted(&mut fixture, &mut child);
}

#[test]
fn ah67_rejects_current_psp_changes_without_writing_either_process() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let owner = fixture.dos.jft_owner_psp;
    fixture.dos.psp_segment = 0x3000;
    let bytes = fixture.memory.bytes.clone();
    fixture.memory.writes.clear();
    let regs = fixture.set_capacity(512);
    assert_dos_error(&regs, DosErrorCode::InvalidFunction);
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.memory.bytes, bytes);
    assert_eq!(fixture.dos.jft_owner_psp, owner);
    assert_eq!(fixture.dos.jft_capacity, 256);
}

#[test]
fn ah50_switch_rejects_capacity_changes_until_the_original_psp_is_restored() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let foreign_psp = fixture.dos.allocate_child_process_block(&mut fixture.memory, 0x100).unwrap();
    let foreign_bytes = [0xa5; 256];
    fixture.memory.write(real_address(foreign_psp, 0), &foreign_bytes).unwrap();
    let mut regs = call_registers(0x5000, foreign_psp, 0);
    assert_eq!(fixture.interrupt(&mut regs).unwrap(), DosAction::Continue);
    assert_eq!(fixture.dos.psp_segment, foreign_psp);
    assert_eq!(fixture.dos.jft_owner_psp, PSP);
    let header = fixture.header();
    let arena = fixture.arena();
    let bytes = fixture.memory.bytes.clone();
    fixture.memory.writes.clear();

    let regs = fixture.set_capacity(512);

    assert_dos_error(&regs, DosErrorCode::InvalidFunction);
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.memory.bytes, bytes);
    assert_eq!(fixture.arena(), arena);
    assert_eq!(fixture.header(), header);
    assert_eq!(fixture.dos.jft_capacity, 256);
    let mut regs = call_registers(0x5000, PSP, 0);
    assert_eq!(fixture.interrupt(&mut regs).unwrap(), DosAction::Continue);
    assert_eq!(fixture.dos.psp_segment, PSP);
    fixture.grow(512);
    assert_eq!(&fixture.jft()[..3], &[0, 1, 2]);
    assert!(fixture.jft()[3..].iter().all(|&entry| entry == 0xff));
    assert_eq!(fixture.memory.copy(real_address(foreign_psp, 0), 256), foreign_bytes);
}

// AH=67h is scalar, so a protected caller must be rejected using its identity
// before invoking any caller-pointer adapter method.
struct ProtectedCaller<'a>(&'a mut CapacityMemory);

impl GuestMemory for ProtectedCaller<'_> {
    fn len(&self) -> u32 { self.0.len() }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.0.validate_read(address, length)
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.0.validate_write(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.0.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.write(address, bytes)
    }
}

impl DosCallAddressSpace for ProtectedCaller<'_> {
    fn caller_id(&self) -> DosCallerId { DosCallerId::new(1).unwrap() }
    fn resolve_caller_pointer(&mut self, _: u16, _: u16) -> Result<DosFarPointer, DosError> {
        panic!("AH=67h must not resolve protected pointers")
    }
    fn validate_caller_range(&mut self, _: DosFarPointer, _: usize, _: usize, _: DosPointerAccess, _: DosSpanPolicy) -> Result<(), DosError> {
        panic!("AH=67h must not validate protected pointers")
    }
    fn read_caller_range(&mut self, _: DosFarPointer, _: usize, _: &mut [u8], _: DosSpanPolicy) -> Result<(), DosError> {
        panic!("AH=67h must not read protected pointers")
    }
    fn write_caller_range(&mut self, _: DosFarPointer, _: usize, _: &[u8], _: DosSpanPolicy) -> Result<(), DosError> {
        panic!("AH=67h must not write protected pointers")
    }
    fn read_caller_terminated(&mut self, _: DosFarPointer, _: u8, _: usize, _: DosSpanPolicy) -> Result<Vec<u8>, DosError> {
        panic!("AH=67h must not read protected strings")
    }
    fn retain_caller_pointer(&mut self, _: DosFarPointer) -> Result<DosPersistentFarPointer, DosError> {
        panic!("AH=67h must not retain protected pointers")
    }
    fn release_caller_pointer(&mut self, _: DosPersistentFarPointer) -> Result<(), DosError> {
        panic!("AH=67h must not release protected pointers")
    }
    fn validate_persistent_range(&mut self, _: DosPersistentFarPointer, _: usize, _: usize, _: DosPointerAccess) -> Result<(), DosError> {
        panic!("AH=67h must not validate retained pointers")
    }
    fn read_persistent_range(&mut self, _: DosPersistentFarPointer, _: usize, _: &mut [u8]) -> Result<(), DosError> {
        panic!("AH=67h must not read retained pointers")
    }
    fn write_persistent_range(&mut self, _: DosPersistentFarPointer, _: usize, _: &[u8]) -> Result<(), DosError> {
        panic!("AH=67h must not write retained pointers")
    }
    fn expose_dos_pointer(&mut self, _: u16, _: u16, _: usize, _: DosPointerAccess) -> Result<DosFarPointer, DosError> {
        panic!("AH=67h must not expose real-mode JFT storage to protected callers")
    }
}

#[test]
fn ah67_rejects_protected_caller_identity_before_writes_or_allocation() {
    let mut fixture = Fixture::new();
    fixture.grow(256);
    let bytes = fixture.memory.bytes.clone();
    fixture.memory.writes.clear();
    let mut regs = call_registers(0x6700, 512, 0);
    let mut caller = ProtectedCaller(&mut fixture.memory);
    assert_eq!(fixture.dos.interrupt_with_address_space(0x21, &mut regs, &mut caller, &mut fixture.host).unwrap(), DosAction::Continue);
    assert_dos_error(&regs, DosErrorCode::InvalidFunction);
    assert!(fixture.memory.writes.is_empty());
    assert_eq!(fixture.memory.bytes, bytes);
    assert_eq!(fixture.dos.jft_capacity, 256);
}
