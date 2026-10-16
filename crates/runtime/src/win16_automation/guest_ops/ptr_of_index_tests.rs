use super::*;
use super::super::Win16AutomationGuestResult;
use compat_services::automation::{SafeArray16, SafeArrayBound16};
use guest_core::{OwnerId, PhysAddr};
use win16_abi::{
    AccessRights, ExportLookupTarget, GlobalHeap, ReturnAddressWidth, SegmentedPointer,
    Win16ApiRequest, Win16CallFrame, Win16ReturnKind, decode_export_call, lookup_export,
};

const OUTPUT_SENTINEL: u32 = 0xa55a_5aa5;
const DISP_E_BADINDEX: u32 = 0x8002_000b;

struct Fixture {
    state: Win16AutomationState,
    memory: Memory,
    selectors: SelectorTable,
    heap: GlobalHeap,
    array: u32,
    indices: u32,
    output: u32,
    stack: SegmentedPointer,
    data: u32,
}

impl Fixture {
    fn new(bounds: &[(u32, i32)], indices: &[i32], width: u16) -> Self {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let metadata = selectors.alloc_block(
            PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory,
        ).unwrap();
        let length = bounds.iter().map(|b| b.0).product::<u32>() * u32::from(width);
        let data = selectors.alloc_block(
            PhysAddr(0x20000), length.max(1), AccessRights::read_write(), &memory,
        ).unwrap();
        let far = |offset| SegmentedPointer::new(metadata, offset).far_value();
        let descriptor = SafeArray16 {
            dimensions: bounds.len() as u16,
            features: 0,
            element_size: width,
            locks: 3,
            handle: 0,
            data: SegmentedPointer::new(data, 0).far_value(),
            bounds: bounds.iter().map(|&(elements, lower_bound)| SafeArrayBound16 {
                elements, lower_bound,
            }).collect(),
        };
        selectors.write(&mut memory, SegmentedPointer::new(metadata, 0), &descriptor.encode().unwrap()).unwrap();
        let index_bytes: Vec<u8> = indices.iter().flat_map(|i| i.to_le_bytes()).collect();
        selectors.write(&mut memory, SegmentedPointer::new(metadata, 0x100), &index_bytes).unwrap();
        selectors.write(&mut memory, SegmentedPointer::new(metadata, 0x200), &OUTPUT_SENTINEL.to_le_bytes()).unwrap();
        Self {
            state: Win16AutomationState::default(), memory, selectors,
            heap: GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap(),
            array: far(0), indices: far(0x100), output: far(0x200),
            stack: SegmentedPointer::new(metadata, 0x300), data: descriptor.data,
        }
    }

    fn call(&mut self, array: u32, indices: u32, output: u32) -> Result<Win16AutomationGuestResult, crate::RuntimeError> {
        let descriptor = lookup_export(b"OLE2DISP", ExportLookupTarget::Ordinal(109)).unwrap();
        let named = lookup_export(b"OLE2DISP", ExportLookupTarget::Name(b"SafeArrayPtrOfIndex")).unwrap();
        assert_eq!(descriptor.id, named.id);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
        // FAR return address followed by the three Pascal arguments in reverse.
        let mut frame = vec![0; 4];
        for argument in [output, indices, array] {
            frame.extend_from_slice(&argument.to_le_bytes());
        }
        self.selectors.write(&mut self.memory, self.stack, &frame).unwrap();
        let decoded = decode_export_call(
            descriptor, Win16CallFrame::new(self.stack, ReturnAddressWidth::Far),
            &self.selectors, &self.memory,
        ).unwrap();
        assert_eq!(decoded.stack_cleanup.callee_pop_bytes, 12);
        assert_eq!(decoded.stack_cleanup.caller_pop_bytes, 0);
        let Win16ApiRequest::Ole2Disp(call) = decoded.request else {
            panic!("OLE2DISP.109 must use the checked guest Automation route");
        };
        self.state.execute_guest_ole2disp_call(
            &call, &mut self.heap, &mut self.selectors, &mut self.memory, OwnerId(1),
            &mut |_| panic!("pointer lookup must not need a host service"),
        )
    }

    fn output_value(&self) -> u32 {
        let pointer = self.selectors.pointer_from_far(self.output).unwrap();
        let mut bytes = [0; 4];
        self.selectors.read(&self.memory, pointer, &mut bytes).unwrap();
        u32::from_le_bytes(bytes)
    }

    fn descriptor(&self) -> SafeArray16 {
        self.state.read_safe_array_descriptor(&self.selectors, &self.memory, self.array).unwrap()
    }

    fn set_descriptor(&mut self, descriptor: SafeArray16) {
        let pointer = self.selectors.pointer_from_far(self.array).unwrap();
        self.selectors.write(&mut self.memory, pointer, &descriptor.encode().unwrap()).unwrap();
    }
}

#[test]
fn safe_array_ptr_of_index_decodes_and_preserves_multidimensional_order_and_locks() {
    // Stored bounds are reversed: index[0] uses the last bound and varies fastest.
    let mut fixture = Fixture::new(&[(2, 5), (3, -2)], &[-1, 6], 2);
    let before = fixture.descriptor();
    assert_eq!(fixture.call(fixture.array, fixture.indices, fixture.output).unwrap(), Win16AutomationGuestResult::HResult(0));
    let pointer = fixture.selectors.pointer_from_far(fixture.output_value()).unwrap();
    assert_eq!(fixture.selectors.translate(pointer, Access::Read, 2, &fixture.memory).unwrap(), PhysAddr(0x20008));
    assert_eq!(fixture.descriptor(), before);
}

#[test]
fn safe_array_ptr_of_index_uses_huge_selector_arithmetic_beyond_64k() {
    let mut fixture = Fixture::new(&[(32770, -5)], &[32764], 2);
    let before = fixture.descriptor();
    assert_eq!(fixture.call(fixture.array, fixture.indices, fixture.output).unwrap(), Win16AutomationGuestResult::HResult(0));
    let pointer = fixture.selectors.pointer_from_far(fixture.output_value()).unwrap();
    assert_ne!(pointer.selector(), fixture.selectors.pointer_from_far(fixture.data).unwrap().selector());
    assert_eq!(pointer.offset(), 2);
    assert_eq!(fixture.selectors.translate(pointer, Access::Read, 2, &fixture.memory).unwrap(), PhysAddr(0x30002));
    assert_eq!(fixture.descriptor(), before);
}

#[test]
fn safe_array_ptr_of_index_rejects_bad_indices_without_output_or_lock_changes() {
    for indices in [[-3, 5], [1, 5], [-2, 4], [-2, 7]] {
        let mut fixture = Fixture::new(&[(2, 5), (3, -2)], &indices, 2);
        let before = fixture.descriptor();
        assert_eq!(fixture.call(fixture.array, fixture.indices, fixture.output).unwrap(), Win16AutomationGuestResult::HResult(DISP_E_BADINDEX));
        assert_eq!(fixture.output_value(), OUTPUT_SENTINEL);
        assert_eq!(fixture.descriptor(), before);
    }
}

#[test]
fn safe_array_ptr_of_index_rejects_nulls_and_invalid_data_without_writes() {
    for null_argument in 0..3 {
        let mut fixture = Fixture::new(&[(2, 0)], &[1], 2);
        let mut arguments = [fixture.array, fixture.indices, fixture.output];
        arguments[null_argument] = 0;
        assert_eq!(fixture.call(arguments[0], arguments[1], arguments[2]).unwrap(), Win16AutomationGuestResult::HResult(E_INVALIDARG));
        assert_eq!(fixture.output_value(), OUTPUT_SENTINEL);
        assert_eq!(fixture.descriptor().locks, 3);
    }
    for malformed in 0..3 {
        let mut fixture = Fixture::new(&[(2, 0)], &[1], 2);
        let mut descriptor = fixture.descriptor();
        match malformed {
            0 => descriptor.data = 0,
            1 => descriptor.element_size = 0,
            _ => descriptor.bounds[0].elements = 3, // exceeds the four-byte allocation
        }
        fixture.set_descriptor(descriptor.clone());
        assert_eq!(fixture.call(fixture.array, fixture.indices, fixture.output).unwrap(), Win16AutomationGuestResult::HResult(E_INVALIDARG));
        assert_eq!(fixture.output_value(), OUTPUT_SENTINEL);
        assert_eq!(fixture.descriptor(), descriptor);
    }
}

#[test]
fn safe_array_ptr_of_index_keeps_invalid_selector_and_output_range_as_guest_faults() {
    for argument in 0..3 {
        let mut fixture = Fixture::new(&[(2, 0)], &[1], 2);
        let mut arguments = [fixture.array, fixture.indices, fixture.output];
        arguments[argument] = 0xfff8_0000;
        let error = fixture.call(arguments[0], arguments[1], arguments[2]).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
        assert_eq!(fixture.output_value(), OUTPUT_SENTINEL);
        assert_eq!(fixture.descriptor().locks, 3);
    }
    let mut fixture = Fixture::new(&[(2, 0)], &[1], 2);
    let output = (fixture.output & 0xffff_0000) | 0x0ffe;
    let error = fixture.call(fixture.array, fixture.indices, output).unwrap_err();
    assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
    assert_eq!(fixture.output_value(), OUTPUT_SENTINEL);
    assert_eq!(fixture.descriptor().locks, 3);
}

#[test]
fn safe_array_ptr_of_index_reads_indices_before_publishing_an_aliased_output() {
    let mut fixture = Fixture::new(&[(2, 0)], &[1], 2);
    fixture.output = fixture.indices;
    assert_eq!(fixture.call(fixture.array, fixture.indices, fixture.output).unwrap(), Win16AutomationGuestResult::HResult(0));
    let pointer = fixture.selectors.pointer_from_far(fixture.output_value()).unwrap();
    assert_eq!(fixture.selectors.translate(pointer, Access::Read, 2, &fixture.memory).unwrap(), PhysAddr(0x20002));
    assert_eq!(fixture.descriptor().locks, 3);
}
