use super::*;
use compat_services::automation::{
    FADF_BSTR, FADF_DISPATCH, FADF_UNKNOWN, FADF_VARIANT, SafeArray16, SafeArrayBound16,
    VT_ARRAY, VT_BYREF, VT_I2, VT_I4,
};
use guest_core::{GuestMemory, PhysAddr};
use win16_abi::{
    AccessRights, AllocationFlags, ExportLookupTarget, ReturnAddressWidth, SegmentedPointer,
    Win16ApiRequest, Win16CallFrame, Win16Error, Win16ReturnKind, decode_export_call, lookup_export,
};
use super::super::Win16AutomationGuestResult;

const OWNER: OwnerId = OwnerId(1);
const HEAP_BASE: PhysAddr = PhysAddr(0x10_0000);
const HEAP_SIZE: u32 = 0x30_0000;

struct Fixture {
    state: Win16AutomationState,
    heap: GlobalHeap,
    selectors: SelectorTable,
    memory: Memory,
    metadata: SegmentedPointer,
    array: u32,
    warnings: usize,
}

impl Fixture {
    fn new(features: u16, width: u16, bounds: &[(u32, i32)]) -> Self {
        let memory = Memory::with_size(0x40_0000).unwrap();
        // Keep the whole heap above the protected 0xF0000..0x100000 ROM.
        // Exhaustion tests must reach allocator OOM, not a memory-write fault.
        memory.validate_write(HEAP_BASE, HEAP_SIZE as usize).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let selector = selectors.alloc_block(
            PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory,
        ).unwrap();
        let mut this = Self {
            state: Win16AutomationState::default(),
            heap: GlobalHeap::new(HEAP_BASE, HEAP_SIZE).unwrap(),
            selectors, memory, metadata: SegmentedPointer::new(selector, 0), array: 0,
            warnings: 0,
        };
        this.array = this.array(features, width, bounds);
        this
    }

    fn array(&mut self, features: u16, width: u16, bounds: &[(u32, i32)]) -> u32 {
        let descriptor = SafeArray16 {
            dimensions: bounds.len() as u16, features, element_size: width, locks: 0,
            handle: 0, data: 0,
            bounds: bounds.iter().map(|&(elements, lower_bound)| SafeArrayBound16 {
                elements, lower_bound,
            }).collect(),
        };
        let length = bounds.iter().map(|b| b.0 as usize).product::<usize>() * usize::from(width);
        self.state.allocate_safe_array(&mut self.heap, &mut self.selectors, &mut self.memory,
            OWNER, descriptor, &vec![0; length]).unwrap()
    }

    fn bstr(&mut self, value: &[u8]) -> u32 {
        self.state.allocate_bstr(&mut self.heap, &mut self.selectors, &mut self.memory,
            OWNER, value).unwrap()
    }

    fn input(&mut self, bytes: &[u8]) -> u32 {
        let pointer = self.selectors.add_bytes(self.metadata, 0x100).unwrap();
        self.selectors.write(&mut self.memory, pointer, bytes).unwrap();
        pointer.far_value()
    }

    fn descriptor(&self, far: u32) -> SafeArray16 {
        self.state.read_safe_array_descriptor(&self.selectors, &self.memory, far).unwrap()
    }

    fn set_descriptor(&mut self, far: u32, descriptor: SafeArray16) {
        let pointer = self.selectors.pointer_from_far(far).unwrap();
        self.selectors.write(&mut self.memory, pointer, &descriptor.encode().unwrap()).unwrap();
    }

    fn data(&self, far: u32) -> Vec<u8> {
        self.state.read_safe_array(&self.selectors, &self.memory, far).unwrap().1
    }

    fn set_data(&mut self, far: u32, bytes: &[u8]) {
        let data = self.descriptor(far).data;
        let pointer = self.selectors.pointer_from_far(data).unwrap();
        write_safe_array_huge_bytes(&self.selectors, &mut self.memory, pointer, bytes).unwrap();
    }

    fn count(&self) -> usize { self.state.owner_allocations(OWNER).unwrap().len() }

    fn put(&mut self, input: u32, indices: &[i32]) -> u32 {
        self.try_put(input, indices).unwrap()
    }

    fn try_put(&mut self, input: u32, indices: &[i32]) -> Result<u32, RuntimeError> {
        let pointer = self.selectors.add_bytes(self.metadata, 0x200).unwrap();
        let bytes: Vec<u8> = indices.iter().flat_map(|n| n.to_le_bytes()).collect();
        self.selectors.write(&mut self.memory, pointer, &bytes).unwrap();
        self.try_put_at(input, pointer.far_value())
    }

    fn put_at(&mut self, input: u32, indices: u32) -> u32 {
        self.try_put_at(input, indices).unwrap()
    }

    fn try_put_at(&mut self, input: u32, indices: u32) -> Result<u32, RuntimeError> {
        let export = lookup_export(b"OLE2DISP", ExportLookupTarget::Ordinal(26)).unwrap();
        let named = lookup_export(b"OLE2DISP", ExportLookupTarget::Name(b"SafeArrayPutElement")).unwrap();
        assert_eq!(export.id, named.id);
        assert_eq!(export.return_kind, Win16ReturnKind::Dword);
        let mut frame = vec![0; 4];
        for far in [input, indices, self.array] { frame.extend_from_slice(&far.to_le_bytes()); }
        self.selectors.write(&mut self.memory, self.metadata, &frame).unwrap();
        let call = decode_export_call(export, Win16CallFrame::new(self.metadata, ReturnAddressWidth::Far),
            &self.selectors, &self.memory).unwrap();
        assert_eq!(call.stack_cleanup.callee_pop_bytes, 12);
        assert_eq!(call.stack_cleanup.caller_pop_bytes, 0);
        let Win16ApiRequest::Ole2Disp(call) = call.request else { panic!("wrong request route") };
        let result = self.state.execute_guest_ole2disp_call(&call, &mut self.heap,
            &mut self.selectors, &mut self.memory, OWNER, &mut |_| self.warnings += 1)?;
        let Win16AutomationGuestResult::HResult(status) = result else { panic!("wrong return class") };
        Ok(status)
    }
}

fn pointer_value(bytes: &[u8]) -> u32 { u32::from_le_bytes(bytes[..4].try_into().unwrap()) }
fn variant(vt: u16, value: u32) -> Variant16 {
    super::super::variant::with_guest_far(Variant16 { vt, ..Variant16::EMPTY }, value)
}

#[test]
fn put_element_scalar_abi_multidimensional_and_huge_cell() {
    let mut f = Fixture::new(0, 2, &[(2, 5), (3, -2)]);
    let mut descriptor = f.descriptor(f.array);
    descriptor.locks = 3;
    f.set_descriptor(f.array, descriptor.clone());
    let input = f.input(&0x1234_u16.to_le_bytes());
    assert_eq!(f.put(input, &[-1, 6]), 0);
    assert_eq!(&f.data(f.array)[8..10], &0x1234_u16.to_le_bytes());
    assert_eq!(f.descriptor(f.array), descriptor);
    let mut f = Fixture::new(0, 3, &[(21847, 0)]);
    let input = f.input(&[7, 8, 9]);
    assert_eq!(f.put(input, &[21845]), 0);
    assert_eq!(&f.data(f.array)[65535..65538], &[7, 8, 9]);
}

#[test]
fn put_element_bstr_direct_clone_self_alias_and_null() {
    let mut f = Fixture::new(FADF_BSTR, 4, &[(1, 0)]);
    let source = f.bstr(b"a\0b");
    assert_eq!(f.put(source, &[0]), 0);
    let first = pointer_value(&f.data(f.array));
    assert_ne!(first, source);
    assert_eq!(f.state.read_bstr(&f.selectors, &f.memory, first).unwrap(), Some(b"a\0b".to_vec()));
    assert_eq!(f.put(first, &[0]), 0);
    let second = pointer_value(&f.data(f.array));
    assert_ne!(second, first);
    assert!(!f.state.allocations.contains_key(&first));
    assert_eq!(f.put(0, &[0]), 0);
    assert_eq!(pointer_value(&f.data(f.array)), 0);
    assert!(!f.state.allocations.contains_key(&second));
    assert!(f.state.allocations.contains_key(&source));
}

#[test]
fn put_element_variant_scalar_bstr_byref_and_nested_array() {
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    let input = f.input(&variant(VT_I4, 17).encode());
    assert_eq!(f.put(input, &[0]), 0);
    assert_eq!(Variant16::decode(&f.data(f.array)).unwrap(), variant(VT_I4, 17));
    let bstr = f.bstr(b"nested");
    let input = f.input(&variant(VT_BSTR, bstr).encode());
    assert_eq!(f.put(input, &[0]), 0);
    let copied_bstr = Variant16::decode(&f.data(f.array)).unwrap().guest_far();
    assert_ne!(copied_bstr, bstr);
    let borrowed = variant(VT_BYREF | VT_I4, 0xffff_fffe);
    let input = f.input(&borrowed.encode());
    assert_eq!(f.put(input, &[0]), 0);
    assert!(!f.state.allocations.contains_key(&copied_bstr));
    assert_eq!(Variant16::decode(&f.data(f.array)).unwrap(), borrowed);
    let inner = f.array(0, 2, &[(2, 0)]);
    f.set_data(inner, &[1, 0, 2, 0]);
    let input = f.input(&variant(VT_ARRAY | VT_I2, inner).encode());
    assert_eq!(f.put(input, &[0]), 0);
    let copy = Variant16::decode(&f.data(f.array)).unwrap().guest_far();
    assert_ne!(copy, inner);
    assert_eq!(f.data(copy), f.data(inner));
    // Source is the destination cell itself: snapshot before release.
    let source_cell = f.descriptor(f.array).data;
    assert_eq!(f.put(source_cell, &[0]), 0);
    assert!(!f.state.allocations.contains_key(&copy));
    assert!(f.state.allocations.contains_key(&inner));
}

#[test]
fn put_element_interface_nulls_work_nonnull_old_or_new_reject() {
    for features in [FADF_UNKNOWN, FADF_DISPATCH] {
        let mut f = Fixture::new(features, 4, &[(1, 0)]);
        assert_eq!(f.put(0, &[0]), 0);
        let count = f.count();
        assert_eq!(f.put(0x1234_5678, &[0]), 0x8000_0001);
        assert_eq!(f.data(f.array), [0; 4]);
        assert_eq!(f.count(), count);
        f.set_data(f.array, &0x1234_5678_u32.to_le_bytes());
        assert_eq!(f.put(0, &[0]), 0x8000_0001);
        assert_eq!(pointer_value(&f.data(f.array)), 0x1234_5678);
        assert_eq!(f.descriptor(f.array).locks, 0);
        assert_eq!(f.warnings, 2);
    }
}

#[test]
fn put_element_nested_interfaces_reject_without_leaks() {
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    let inner = f.array(FADF_VARIANT, 16, &[(2, 0)]);
    let bstr = f.bstr(b"clone then roll back");
    let mut data = variant(VT_BSTR, bstr).encode().to_vec();
    data.extend_from_slice(&variant(VT_UNKNOWN, 1).encode());
    f.set_data(inner, &data);
    let input = f.input(&variant(VT_ARRAY | VT_VARIANT, inner).encode());
    let count = f.count();
    assert_eq!(f.put(input, &[0]), 0x8000_0001);
    assert_eq!(f.count(), count);
    assert_eq!(f.data(f.array), [0; 16]);
    assert_eq!(f.descriptor(f.array).locks, 0);
    f.set_data(f.array, &variant(VT_ARRAY | VT_VARIANT, inner).encode());
    let input = f.input(&Variant16::EMPTY.encode());
    assert_eq!(f.put(input, &[0]), 0x8000_0001);
    assert!(f.state.allocations.contains_key(&inner));
}

#[test]
fn put_element_invalid_index_source_and_overflow_preserve_storage() {
    let mut f = Fixture::new(0, 2, &[(1, 0)]);
    f.set_data(f.array, &[9, 9]);
    let input = f.input(&[1, 2]);
    assert_eq!(f.put(input, &[1]), 0x8002_000b);
    assert_eq!(f.put(0, &[0]), 0x8000_0003);
    assert_eq!(f.data(f.array), [9, 9]);
    let mut d = f.descriptor(f.array);
    d.locks = u16::MAX;
    f.set_descriptor(f.array, d.clone());
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.descriptor(f.array), d);
    assert_eq!(f.data(f.array), [9, 9]);
}

#[test]
fn put_element_descriptor_input_and_indices_are_snapshotted() {
    let mut f = Fixture::new(0, 2, &[(1, 1)]);
    let mut d = f.descriptor(f.array);
    d.locks = 7;
    f.set_descriptor(f.array, d.clone());
    let pointer = f.selectors.pointer_from_far(f.array).unwrap();
    let input = f.selectors.add_bytes(pointer, 6).unwrap().far_value();
    let indices = f.selectors.add_bytes(pointer, 16).unwrap().far_value();
    assert_eq!(f.put_at(input, indices), 0);
    assert_eq!(f.data(f.array), [7, 0]);
    assert_eq!(f.descriptor(f.array), d);
}

#[test]
fn put_element_static_and_untracked_descriptors_are_explicitly_unsupported() {
    let mut f = Fixture::new(0, 2, &[(1, 0)]);
    let input = f.input(&[1, 2]);
    let original = f.array;
    let mut d = f.descriptor(original);
    d.features = FADF_STATIC;
    f.set_descriptor(original, d.clone());
    assert_eq!(f.put(input, &[0]), 0x8000_0001);
    d.features = 0;
    let external = f.selectors.add_bytes(f.metadata, 0x300).unwrap();
    f.selectors.write(&mut f.memory, external, &d.encode().unwrap()).unwrap();
    f.array = external.far_value();
    assert_eq!(f.put(input, &[0]), 0x8000_0001);
    assert_eq!(f.data(original), [0, 0]);
}

#[test]
fn put_element_rejects_foreign_owner_and_descriptor_data_overlap() {
    let mut f = Fixture::new(0, 2, &[(1, 0)]);
    let input = f.input(&[1, 2]);
    f.state.allocations.get_mut(&f.array).unwrap().owner = OwnerId(2);
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    f.state.allocations.get_mut(&f.array).unwrap().owner = OWNER;
    let mut d = f.descriptor(f.array);
    d.data = f.array;
    f.set_descriptor(f.array, d.clone());
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.descriptor(f.array), d);
}

#[test]
fn put_element_locked_or_self_owned_variant_graph_is_preserved() {
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    let inner = f.array(0, 2, &[(1, 0)]);
    let mut d = f.descriptor(inner);
    d.locks = 1;
    f.set_descriptor(inner, d);
    let old = variant(VT_ARRAY | VT_I2, inner);
    f.set_data(f.array, &old.encode());
    let input = f.input(&Variant16::EMPTY.encode());
    assert_eq!(f.put(input, &[0]), 0x8002_000d);
    assert_eq!(f.data(f.array), old.encode());
    let self_owned = variant(VT_ARRAY | VT_VARIANT, f.array);
    f.set_data(f.array, &self_owned.encode());
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.data(f.array), self_owned.encode());
    assert_eq!(f.descriptor(f.array).locks, 0);
}

#[test]
fn put_element_oom_preserves_old_bstr_and_source() {
    let mut f = Fixture::new(FADF_BSTR, 4, &[(1, 0)]);
    let old = f.bstr(b"old");
    let source = f.bstr(&[b'x'; 256]);
    f.set_data(f.array, &old.to_le_bytes());
    for size in [65536, 1024, 16] {
        loop {
            match f.heap.alloc(&mut f.memory, OWNER, size, AllocationFlags::fixed()) {
                Ok(_) => {}
                Err(Win16Error::OutOfMemory) => break,
                Err(error) => panic!("heap fill failed before exhaustion: {error:?}"),
            }
        }
    }
    let count = f.count();
    let heap_count = f.heap.allocation_count();
    assert_eq!(f.put(source, &[0]), 0x8000_0002);
    assert_eq!(pointer_value(&f.data(f.array)), old);
    assert!(f.state.allocations.contains_key(&old));
    assert!(f.state.allocations.contains_key(&source));
    assert_eq!(f.count(), count);
    assert_eq!(f.heap.allocation_count(), heap_count);
    assert_eq!(f.state.read_bstr(&f.selectors, &f.memory, old).unwrap(), Some(b"old".to_vec()));
    assert_eq!(f.state.read_bstr(&f.selectors, &f.memory, source).unwrap(), Some(vec![b'x'; 256]));
    assert_eq!(f.descriptor(f.array).locks, 0);
}

#[test]
fn put_element_rejects_duplicate_nested_data_retirement_before_mutation() {
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    let graph = f.array(FADF_VARIANT, 16, &[(2, 0)]);
    let a = f.array(0, 2, &[(1, 0)]);
    let b = f.array(0, 2, &[(1, 0)]);
    let mut b_descriptor = f.descriptor(b);
    b_descriptor.data = f.descriptor(a).data;
    f.set_descriptor(b, b_descriptor);
    let mut graph_data = variant(VT_ARRAY | VT_I2, a).encode().to_vec();
    graph_data.extend_from_slice(&variant(VT_ARRAY | VT_I2, b).encode());
    f.set_data(graph, &graph_data);
    let old = variant(VT_ARRAY | VT_VARIANT, graph);
    f.set_data(f.array, &old.encode());
    let input = f.input(&Variant16::EMPTY.encode());
    let count = f.count();
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.data(f.array), old.encode());
    assert_eq!(f.count(), count);
    assert!(f.state.allocations.contains_key(&f.descriptor(a).data));
    assert_eq!(f.descriptor(f.array).locks, 0);
}

#[test]
fn put_element_nested_descriptor_cannot_retire_parent_data() {
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    let nested = f.array(0, 2, &[(1, 0)]);
    let mut d = f.descriptor(nested);
    d.data = f.descriptor(f.array).data;
    f.set_descriptor(nested, d);
    let old = variant(VT_ARRAY | VT_I2, nested);
    f.set_data(f.array, &old.encode());
    let input = f.input(&Variant16::EMPTY.encode());
    let count = f.count();
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.data(f.array), old.encode());
    assert_eq!(f.count(), count);
}

#[test]
fn put_element_far_input_does_not_wrap_into_a_huge_selector() {
    let mut f = Fixture::new(0, 3, &[(1, 0)]);
    let huge = f.array(0, 3, &[(21847, 0)]);
    let pointer = f.selectors.pointer_from_far(f.descriptor(huge).data).unwrap();
    let crossing = f.selectors.add_bytes(pointer, 65535).unwrap().far_value();
    // pv is FAR, while SAFEARRAY pvData is huge. An ordinary caller buffer
    // that crosses its segment must fail rather than wrap or read its neighbor.
    assert_eq!(f.try_put(crossing, &[0]).unwrap_err().kind(), crate::DiagnosticKind::GuestFault);
    assert_eq!(f.data(f.array), [0; 3]);
    assert_eq!(f.descriptor(f.array).locks, 0);
    let mut f = Fixture::new(FADF_VARIANT, 16, &[(1, 0)]);
    assert_eq!(f.put(0, &[0]), 0x8000_0003);
    assert_eq!(f.data(f.array), [0; 16]);
}

#[test]
fn put_element_selector_alias_cannot_replace_tracked_storage_identity() {
    let mut f = Fixture::new(0, 2, &[(1, 0)]);
    let descriptor = f.descriptor(f.array);
    let data = f.selectors.pointer_from_far(descriptor.data).unwrap();
    let alias = f.selectors.alloc_selector_copy(data.selector(), &f.memory).unwrap()[0];
    let array_pointer = f.selectors.pointer_from_far(f.array).unwrap();
    let array_base = f.selectors.translate(array_pointer, Access::Read, 2, &f.memory).unwrap();
    f.selectors.set_selector_base(alias, array_base, &f.memory).unwrap();
    let alias_far = SegmentedPointer::new(alias, 0).far_value();
    // Even a retained allocator record cannot authorize a selector that now
    // resolves to another allocation. This models stale/aliased selector state.
    let allocation = f.state.allocations.get(&descriptor.data).unwrap().clone();
    f.state.allocations.insert(alias_far, allocation);
    let mut changed = descriptor.clone();
    changed.data = alias_far;
    f.set_descriptor(f.array, changed.clone());
    let input = f.input(&[1, 2]);
    assert_eq!(f.put(input, &[0]), 0x8000_0003);
    assert_eq!(f.descriptor(f.array), changed);
}
