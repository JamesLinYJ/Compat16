use std::collections::HashMap;
use formats::{
    extract_ne_resource, load_ne_segments, FarAddress, FormatError, NeEntry, NeEntryKind,
    NeFixup, NeFixupAddressType, NeFixupTarget, NeHeader, NeImportTarget, NeLoadResolver,
    NeModule, NeRelocationKind, NeResource, NeResourceId, NeSegment,
};
use guest_core::{GuestMemory, MemoryError, PhysAddr, Selector};

const SEGMENT_FLAG_ITERATED: u16 = 0x0008;
const SEGMENT_FLAG_HAS_FIXUPS: u16 = 0x0100;

#[derive(Clone, Debug)]
struct TestMemory(Vec<u8>);

impl GuestMemory for TestMemory {
    fn len(&self) -> u32 {
        u32::try_from(self.0.len()).unwrap_or(u32::MAX)
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let source = self.0.get(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        bytes.copy_from_slice(source);
        Ok(())
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        let start = usize::try_from(address.0).map_err(|_| MemoryError::AddressOverflow)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryError::AddressOverflow)?;
        let target = self.0.get_mut(start..end).ok_or(MemoryError::OutOfBounds {
            address: address.0,
            length: bytes.len(),
        })?;
        target.copy_from_slice(bytes);
        Ok(())
    }
}

// Inject failures before any bytes are changed, matching GuestMemory's
// validate-before-mutate write contract.
struct FaultMemory {
    inner: TestMemory,
    write_count: usize,
    faults: HashMap<usize, MemoryError>,
}

impl GuestMemory for FaultMemory {
    fn len(&self) -> u32 {
        self.inner.len()
    }

    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.inner.read(address, bytes)
    }

    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.write_count = self.write_count.checked_add(1).ok_or(MemoryError::AddressOverflow)?;
        if let Some(error) = self.faults.get(&self.write_count).cloned() {
            return Err(error);
        }
        self.inner.write(address, bytes)
    }
}

struct TestResolver {
    next_selector: u16,
    next_base: u32,
    allocations: HashMap<Selector, (u32, u32)>,
    released: Vec<Selector>,
    fail_allocation_at: Option<u16>,
}

impl TestResolver {
    fn new() -> Self {
        Self {
            next_selector: 0x100,
            next_base: 0x1000,
            allocations: HashMap::new(),
            released: Vec::new(),
            fail_allocation_at: None,
        }
    }
}

impl NeLoadResolver for TestResolver {
    fn allocate_segment(
        &mut self,
        _module: &NeModule,
        segment_number: u16,
        size: u32,
        _flags: u16,
    ) -> Result<Selector, FormatError> {
        if self.fail_allocation_at == Some(segment_number) {
            return Err(FormatError::AllocationFailed);
        }
        let selector = Selector(self.next_selector);
        self.next_selector = self.next_selector.checked_add(8)
            .ok_or(FormatError::AllocationFailed)?;
        let next_base = self.next_base.checked_add(0x1_0000)
            .ok_or(FormatError::AllocationFailed)?;
        self.allocations.insert(selector, (self.next_base, size));
        self.next_base = next_base;
        Ok(selector)
    }

    fn selector_range(
        &self,
        selector: Selector,
        offset: u32,
        length: usize,
    ) -> Result<PhysAddr, FormatError> {
        let (base, size) = self.allocations.get(&selector).copied()
            .ok_or(FormatError::InvalidNeLoad("test selector is not allocated"))?;
        let length = u32::try_from(length).map_err(|_| FormatError::ArithmeticOverflow)?;
        let end = offset.checked_add(length).ok_or(FormatError::ArithmeticOverflow)?;
        if end > size {
            return Err(FormatError::InvalidNeLoad("test selector range is too long"));
        }
        Ok(PhysAddr(base.checked_add(offset).ok_or(FormatError::ArithmeticOverflow)?))
    }

    fn release_segment(&mut self, selector: Selector) {
        self.allocations.remove(&selector);
        self.released.push(selector);
    }

    fn resolve_import(
        &mut self,
        _module_name: &[u8],
        _target: &NeImportTarget,
    ) -> Result<FarAddress, FormatError> {
        Err(FormatError::InvalidNeLoad("unexpected import in test"))
    }
}

#[test]
fn iterated_segments_expand_and_publish_ordinal_entries() {
    let module = one_segment(13, 16, SEGMENT_FLAG_ITERATED, Vec::new());
    let bytes = [2, 0, 3, 0, b'A', b'B', b'C', 1, 0, 2, 0, b'D', b'E'];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let mut resolver = TestResolver::new();
    let loaded = load_ne_segments(&bytes, &module, &mut resolver, &mut memory).expect("iterated segment");
    let segment = loaded.segments.first().expect("loaded segment");
    let base = resolver.selector_range(segment.selector, 0, 16).expect("segment mapping").0;
    let start = usize::try_from(base).expect("host index");
    let end = start.checked_add(16).expect("segment end");
    assert_eq!(
        memory.0.get(start..end).expect("loaded bytes"),
        &[b'A', b'B', b'C', b'A', b'B', b'C', b'D', b'E', 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(loaded.entrypoint(1), Some(FarAddress { selector: segment.selector, offset: 1 }));
    assert_eq!(loaded.code_entry, Some(FarAddress { selector: segment.selector, offset: 2 }));
    assert_eq!(loaded.stack, Some(FarAddress { selector: segment.selector, offset: 16 }));
    assert_eq!(loaded.entrypoint(0), None);
}

#[test]
fn internal_fixup_writes_the_resolved_far_pointer_bytes() {
    let mut module = two_segment_module(vec![NeFixup {
        source_offset: 0,
        address_type: NeFixupAddressType::FarPointer32,
        relocation_kind: NeRelocationKind::Internal,
        additive: false,
        target: NeFixupTarget::InternalSegment { segment: 2, offset: 0x21 },
        raw_target1: 2,
        raw_target2: 0x21,
    }]);
    let first = module.segments.first_mut().expect("first segment");
    first.file_size = 4;
    first.memory_size = 8;
    let bytes = [0xff, 0xff, 0, 0, 0x90, 0x90, 0xc3, 0];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let mut resolver = TestResolver::new();
    let loaded = load_ne_segments(&bytes, &module, &mut resolver, &mut memory).expect("fixed segments");
    let first_selector = loaded.segment_selector(1).expect("first selector");
    let second_selector = loaded.segment_selector(2).expect("second selector");
    let address = resolver.selector_range(first_selector, 0, 4).expect("first map").0;
    let start = usize::try_from(address).expect("host index");
    assert_eq!(
        memory.0.get(start..start + 4).expect("relocated pointer"),
        &[0x21, 0, second_selector.0 as u8, (second_selector.0 >> 8) as u8]
    );
}

#[test]
fn overlapping_fixups_apply_in_record_order_and_additive_values_accumulate() {
    let additive_fixups = vec![fixup_at(0, true, 2), fixup_at(0, true, 3)];
    let mut module = two_segment_module(additive_fixups);
    let first = module.segments.first_mut().expect("first segment");
    first.file_size = 4;
    first.memory_size = 8;
    let bytes = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let mut resolver = TestResolver::new();
    let loaded = load_ne_segments(&bytes, &module, &mut resolver, &mut memory).expect("additive fixups");
    let selector = loaded.segment_selector(1).expect("first selector");
    let address = resolver.selector_range(selector, 0, 2).expect("first map").0;
    let start = usize::try_from(address).expect("host index");
    assert_eq!(memory.0.get(start..start + 2), Some(&[6, 0][..]));

    let overwriting_fixups = vec![fixup_at(0, false, 2), fixup_at(0, false, 3)];
    let mut module = two_segment_module(overwriting_fixups);
    let first = module.segments.first_mut().expect("first segment");
    first.file_size = 4;
    first.memory_size = 8;
    let bytes = [0xff, 0xff, 0, 0, 0, 0, 0, 0];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let mut resolver = TestResolver::new();
    let loaded = load_ne_segments(&bytes, &module, &mut resolver, &mut memory).expect("overlapping fixups");
    let selector = loaded.segment_selector(1).expect("first selector");
    let address = resolver.selector_range(selector, 0, 2).expect("first map").0;
    let start = usize::try_from(address).expect("host index");
    assert_eq!(memory.0.get(start..start + 2), Some(&[3, 0][..]));
}

#[test]
fn fixup_chain_cycle_fails_and_releases_all_allocated_selectors() {
    let fixup = NeFixup {
        source_offset: 0,
        address_type: NeFixupAddressType::Offset16,
        relocation_kind: NeRelocationKind::Internal,
        additive: false,
        target: NeFixupTarget::InternalSegment { segment: 1, offset: 0 },
        raw_target1: 1,
        raw_target2: 0,
    };
    let module = one_segment(4, 8, SEGMENT_FLAG_HAS_FIXUPS, vec![fixup]);
    let bytes = [2, 0, 0, 0];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let before = memory.0.clone();
    let mut resolver = TestResolver::new();
    assert!(matches!(
        load_ne_segments(&bytes, &module, &mut resolver, &mut memory),
        Err(FormatError::InvalidNeLoad("fixup chain contains a cycle"))
    ));
    assert!(resolver.allocations.is_empty());
    assert_eq!(resolver.released.len(), 1);
    assert_eq!(memory.0, before);
}

#[test]
fn allocation_failure_releases_prior_segment_selectors() {
    let module = two_segment_module(Vec::new());
    let bytes = [0x90, 0x90, 0xc3, 0, 0x90, 0x90, 0xc3, 0];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let before = memory.0.clone();
    let mut resolver = TestResolver::new();
    resolver.fail_allocation_at = Some(2);
    assert!(matches!(
        load_ne_segments(&bytes, &module, &mut resolver, &mut memory),
        Err(FormatError::AllocationFailed)
    ));
    assert!(resolver.allocations.is_empty());
    assert_eq!(resolver.released.len(), 1);
    assert_eq!(memory.0, before);
}

#[test]
fn commit_failure_rolls_back_previously_committed_ranges() {
    let module = two_segment_module(Vec::new());
    let bytes = [0x90, 0x90, 0xc3, 0, 0x90, 0x90, 0xc3, 0];
    let mut memory = FaultMemory {
        inner: TestMemory(vec![0; 0x2_0000]),
        write_count: 0,
        faults: HashMap::from([(2, MemoryError::InvalidMapping)]),
    };
    let before = memory.inner.0.clone();
    let mut resolver = TestResolver::new();

    let result = load_ne_segments(&bytes, &module, &mut resolver, &mut memory);

    assert_eq!(result, Err(FormatError::GuestMemory(MemoryError::InvalidMapping)));
    assert_eq!(memory.inner.0, before);
    assert!(resolver.allocations.is_empty());
    assert_eq!(resolver.released.len(), 2);
}

#[test]
fn rollback_failure_reports_primary_and_rollback_context_and_releases_selectors() {
    let module = two_segment_module(Vec::new());
    let bytes = [0x90, 0x90, 0xc3, 0, 0x90, 0x90, 0xc3, 0];
    let mut memory = FaultMemory {
        inner: TestMemory(vec![0; 0x2_0000]),
        write_count: 0,
        faults: HashMap::from([
            (2, MemoryError::InvalidMapping),
            (3, MemoryError::ReadOnly { address: 0x1000, length: 8 }),
        ]),
    };
    let before = memory.inner.0.clone();
    let mut resolver = TestResolver::new();

    let result = load_ne_segments(&bytes, &module, &mut resolver, &mut memory);

    assert_eq!(
        result,
        Err(FormatError::GuestMemoryRollback {
            failed_address: PhysAddr(0x11000),
            primary_error: MemoryError::InvalidMapping,
            rollback_failures: vec![formats::GuestMemoryRollbackFailure {
                address: PhysAddr(0x1000),
                error: MemoryError::ReadOnly { address: 0x1000, length: 8 },
            }],
        })
    );
    let first_range = memory.inner.0.get(0x1000..0x1008).expect("first segment range");
    assert_eq!(first_range, &[0x90, 0x90, 0xc3, 0, 0, 0, 0, 0]);
    let failed_range = memory.inner.0.get(0x11000..0x11040).expect("failed segment range");
    assert_eq!(failed_range, before.get(0x11000..0x11040).expect("original failed range"));
    assert!(resolver.allocations.is_empty());
    assert_eq!(resolver.released.len(), 2);
}

#[test]
fn malformed_iterated_stream_and_resource_ranges_fail_explicitly() {
    let module = one_segment(5, 16, SEGMENT_FLAG_ITERATED, Vec::new());
    let bytes = [1, 0, 4, 0, 0xaa];
    let mut memory = TestMemory(vec![0; 0x2_0000]);
    let mut resolver = TestResolver::new();
    assert!(matches!(
        load_ne_segments(&bytes, &module, &mut resolver, &mut memory),
        Err(FormatError::Truncated { context: "NE iterated-segment record data", .. })
    ));
    assert!(resolver.allocations.is_empty());
    let resource = NeResource {
        id: NeResourceId::Numeric(1),
        file_offset: 4,
        byte_length: 2,
        flags: 0,
        handle: 0,
        usage: 0,
    };
    assert!(matches!(
        extract_ne_resource(&[0; 5], &resource),
        Err(FormatError::Truncated { context: "NE resource data", .. })
    ));
}

fn fixup_at(source: u16, additive: bool, target_offset: u16) -> NeFixup {
    NeFixup {
        source_offset: source,
        address_type: NeFixupAddressType::Offset16,
        relocation_kind: NeRelocationKind::Internal,
        additive,
        target: NeFixupTarget::InternalSegment { segment: 2, offset: target_offset },
        raw_target1: 2,
        raw_target2: target_offset,
    }
}

fn one_segment(
    file_size: u32,
    memory_size: u32,
    flags: u16,
    fixups: Vec<NeFixup>,
) -> NeModule {
    NeModule {
        ne_header_offset: 0,
        header: test_header(1),
        segments: vec![NeSegment {
            number: 1,
            file_offset: Some(0),
            file_size,
            memory_size,
            flags,
            fixups,
        }],
        entries: vec![NeEntry {
            ordinal: 1,
            kind: NeEntryKind::Fixed { segment: 1, offset: 1 },
            flags: 0,
        }],
        resident_names: Vec::new(),
        nonresident_names: Vec::new(),
        imported_modules: Vec::new(),
        resource_types: Vec::new(),
    }
}

fn two_segment_module(first_fixups: Vec<NeFixup>) -> NeModule {
    let mut module = one_segment(4, 8, SEGMENT_FLAG_HAS_FIXUPS, first_fixups);
    module.header.segment_count = 2;
    module.header.initial_cs = 1;
    module.header.initial_ip = 2;
    module.header.initial_ss = 2;
    module.header.initial_sp = 8;
    module.segments.push(NeSegment {
        number: 2,
        file_offset: Some(4),
        file_size: 4,
        memory_size: 64,
        flags: 0,
        fixups: Vec::new(),
    });
    module
}

fn test_header(segment_count: u16) -> NeHeader {
    NeHeader {
        linker_version: 0,
        linker_revision: 0,
        entry_table_offset: 0,
        entry_table_length: 0,
        checksum: 0,
        flags: 0,
        automatic_data_segment: 0,
        heap_size: 0,
        stack_size: 0,
        initial_ip: 2,
        initial_cs: 1,
        initial_sp: 16,
        initial_ss: 1,
        segment_count,
        module_reference_count: 0,
        nonresident_name_length: 0,
        segment_table_offset: 0,
        resource_table_offset: 0,
        resident_name_table_offset: 0,
        module_reference_table_offset: 0,
        imported_name_table_offset: 0,
        nonresident_name_table_offset: 0,
        movable_entry_count: 0,
        alignment_shift: 0,
        resource_segment_count: 0,
        target_os: 0,
        other_flags: 0,
        return_thunk_offset: 0,
        segment_reference_thunk_offset: 0,
        minimum_code_swap_area: 0,
        expected_windows_version: 0,
    }
}
