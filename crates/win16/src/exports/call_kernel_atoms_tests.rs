use crate::{
    Access, AccessRights, ArgumentKind, DecodedWin16Call, ExportCallingConvention,
    ExportLookupTarget, KERNEL_ADD_ATOM, KERNEL_DELETE_ATOM, KERNEL_FIND_ATOM,
    KERNEL_GET_ATOM_HANDLE, KERNEL_GET_ATOM_NAME, KERNEL_INIT_ATOM_TABLE,
    ReturnAddressWidth, SegmentedPointer, SelectorRef, SelectorTable, StackCleanup,
    Win16ApiRequest, Win16AtomName, Win16CallFrame, Win16Error, Win16ExportAbiKind,
    Win16ExportDescriptor, Win16ExportId, Win16ExportStackCleanup, Win16KernelAtomsRequest,
    Win16KernelRequest, Win16OutputBuffer, Win16ParameterType, Win16ReturnKind,
    decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

struct Fixture {
    memory: Memory,
    selectors: SelectorTable,
    stack: SelectorRef,
}

impl Fixture {
    fn new() -> Self {
        let memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(
            PhysAddr(0x1000), 0x100, AccessRights::read_write(), &memory,
        ).unwrap();
        Self { memory, selectors, stack }
    }

    fn buffer(&mut self, bytes: &[u8], rights: AccessRights) -> SegmentedPointer {
        self.memory.write(PhysAddr(0x2000), bytes).unwrap();
        let selector = self.selectors.alloc_block(
            PhysAddr(0x2000), bytes.len() as u32, rights, &self.memory,
        ).unwrap();
        SegmentedPointer::new(selector, 0)
    }

    fn decode(
        &mut self,
        descriptor: &Win16ExportDescriptor,
        stack_arguments: &[u8],
    ) -> Result<DecodedWin16Call, Win16Error> {
        // The physical bytes are independently supplied in Pascal stack order.
        self.memory.write(PhysAddr(0x1000), &[0x34, 0x12, 0x78, 0x56]).unwrap();
        self.memory.write(PhysAddr(0x1004), stack_arguments).unwrap();
        decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(self.stack, 0), ReturnAddressWidth::Far),
            &self.selectors,
            &self.memory,
        )
    }
}

fn atom_request(request: Win16KernelAtomsRequest) -> Win16ApiRequest {
    Win16ApiRequest::Kernel(Win16KernelRequest::Atoms(request))
}

fn name_output_arguments(atom: u16, far: u32, capacity: u16) -> Vec<u8> {
    // At entry: return address, signed capacity, FAR output, atom.
    let mut bytes = capacity.to_le_bytes().to_vec();
    bytes.extend_from_slice(&far.to_le_bytes());
    bytes.extend_from_slice(&atom.to_le_bytes());
    bytes
}

#[test]
fn local_atom_catalog_has_exact_ordinals_pascal_slots_and_word_results() {
    use ArgumentKind::{Dword, Word};
    use Win16ParameterType::{AtomName, FarOutputBuffer, Scalar, SignedScalar};

    let cases: &[(Win16ExportDescriptor, Win16ExportId, u16, &[u8], u16,
        &[(ArgumentKind, Win16ParameterType)])] = &[
        (KERNEL_INIT_ATOM_TABLE, Win16ExportId::KernelInitAtomTable, 68,
            b"InitAtomTable", 2, &[(Word, SignedScalar)]),
        (KERNEL_FIND_ATOM, Win16ExportId::KernelFindAtom, 69,
            b"FindAtom", 4, &[(Dword, AtomName)]),
        (KERNEL_ADD_ATOM, Win16ExportId::KernelAddAtom, 70,
            b"AddAtom", 4, &[(Dword, AtomName)]),
        (KERNEL_DELETE_ATOM, Win16ExportId::KernelDeleteAtom, 71,
            b"DeleteAtom", 2, &[(Word, Scalar)]),
        (KERNEL_GET_ATOM_NAME, Win16ExportId::KernelGetAtomName, 72,
            b"GetAtomName", 8, &[(Word, Scalar), (Dword, FarOutputBuffer),
                (Word, SignedScalar)]),
        (KERNEL_GET_ATOM_HANDLE, Win16ExportId::KernelGetAtomHandle, 73,
            b"GetAtomHandle", 2, &[(Word, Scalar)]),
    ];
    for &(descriptor, id, ordinal, name, argument_bytes, parameters) in cases {
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.module(), "KERNEL");
        assert_eq!(descriptor.ordinal(), ordinal);
        assert_eq!(descriptor.name().as_bytes(), name);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: argument_bytes,
            caller_pop_bytes: 0,
        }));
        assert_eq!(descriptor.parameters.iter().map(|parameter| {
            (parameter.kind, parameter.parameter_type)
        }).collect::<Vec<_>>(), parameters);
        assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)),
            Some(&descriptor));
        assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(name)),
            Some(&descriptor));
    }
}

#[test]
fn local_atom_word_frames_preserve_signed_buckets_and_unsigned_atoms() {
    let mut fixture = Fixture::new();
    for raw in [0u16, 1, 37, 0x7fff, 0x8000, 0xffff] {
        let decoded = fixture.decode(&KERNEL_INIT_ATOM_TABLE, &raw.to_le_bytes()).unwrap();
        assert_eq!(decoded.request, atom_request(Win16KernelAtomsRequest::InitAtomTable {
            buckets: raw as i16,
        }));
        assert_eq!(decoded.stack_cleanup, StackCleanup {
            callee_pop_bytes: 2, caller_pop_bytes: 0,
        });
    }
    for atom in [0u16, 1, 0xbfff, 0xc000, 0xffff] {
        for (descriptor, expected) in [
            (KERNEL_DELETE_ATOM, Win16KernelAtomsRequest::DeleteAtom { atom }),
            (KERNEL_GET_ATOM_HANDLE, Win16KernelAtomsRequest::GetAtomHandle { atom }),
        ] {
            let decoded = fixture.decode(&descriptor, &atom.to_le_bytes()).unwrap();
            assert_eq!(decoded.export, descriptor.id);
            assert_eq!(decoded.request, atom_request(expected));
            assert_eq!(decoded.stack_cleanup, StackCleanup {
                callee_pop_bytes: 2, caller_pop_bytes: 0,
            });
        }
    }
}

#[test]
fn local_atom_integer_names_do_not_access_selector_zero() {
    let mut fixture = Fixture::new();
    for atom in [0u16, 1, 0xbfff, 0xc000, 0xffff] {
        let argument = u32::from(atom).to_le_bytes();
        for (descriptor, expected) in [
            (KERNEL_ADD_ATOM, Win16KernelAtomsRequest::AddAtom {
                name: Win16AtomName::Integer(atom),
            }),
            (KERNEL_FIND_ATOM, Win16KernelAtomsRequest::FindAtom {
                name: Win16AtomName::Integer(atom),
            }),
        ] {
            let decoded = fixture.decode(&descriptor, &argument).unwrap();
            assert_eq!(decoded.request, atom_request(expected));
            assert_eq!(decoded.stack_cleanup, StackCleanup {
                callee_pop_bytes: 4, caller_pop_bytes: 0,
            });
        }
    }
}

#[test]
fn local_atom_far_names_are_owned_ansi_bytes_without_normalization() {
    for name in [b"\x81\x40MiXeD".as_slice(), b"#123", b""] {
        let mut fixture = Fixture::new();
        let mut terminated = name.to_vec();
        terminated.push(0);
        let pointer = fixture.buffer(&terminated, AccessRights::read_only());
        for (descriptor, expected) in [
            (KERNEL_ADD_ATOM, Win16KernelAtomsRequest::AddAtom {
                name: Win16AtomName::String(name.to_vec()),
            }),
            (KERNEL_FIND_ATOM, Win16KernelAtomsRequest::FindAtom {
                name: Win16AtomName::String(name.to_vec()),
            }),
        ] {
            let decoded = fixture.decode(&descriptor, &pointer.far_value().to_le_bytes()).unwrap();
            assert_eq!(decoded.request, atom_request(expected));
        }
    }
}

#[test]
fn local_atom_far_names_reject_invalid_or_unterminated_memory() {
    let mut fixture = Fixture::new();
    let unterminated = fixture.buffer(b"abc", AccessRights::read_only());
    for descriptor in [KERNEL_ADD_ATOM, KERNEL_FIND_ATOM] {
        assert!(fixture.decode(&descriptor, &unterminated.far_value().to_le_bytes()).is_err());
        assert!(fixture.decode(&descriptor, &0xfff7_0000u32.to_le_bytes()).is_err());
    }
}

#[test]
fn local_atom_name_output_decodes_pascal_order_and_checks_the_full_buffer() {
    let mut fixture = Fixture::new();
    let pointer = fixture.buffer(&[0xa5; 5], AccessRights::read_write());
    let decoded = fixture.decode(
        &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, pointer.far_value(), 5),
    ).unwrap();
    assert_eq!(decoded.export, Win16ExportId::KernelGetAtomName);
    assert_eq!(decoded.request, atom_request(Win16KernelAtomsRequest::GetAtomName {
        atom: 0xc123,
        output_buffer: Some(Win16OutputBuffer { pointer, capacity: 5 }),
    }));
    assert_eq!(decoded.stack_cleanup, StackCleanup {
        callee_pop_bytes: 8, caller_pop_bytes: 0,
    });
    let mut unchanged = [0; 5];
    fixture.memory.read(PhysAddr(0x2000), &mut unchanged).unwrap();
    assert_eq!(unchanged, [0xa5; 5]);
    assert!(fixture.decode(
        &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, pointer.far_value(), 6),
    ).is_err());
}

#[test]
fn local_atom_name_nonpositive_signed_capacities_do_not_access_output() {
    let mut fixture = Fixture::new();
    for capacity in [0u16, 0x8000, 0xffff] {
        for far in [0, 0xfff7_ffff] {
            let decoded = fixture.decode(
                &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, far, capacity),
            ).unwrap();
            assert_eq!(decoded.request, atom_request(Win16KernelAtomsRequest::GetAtomName {
                atom: 0xc123,
                output_buffer: None,
            }));
        }
    }
}

#[test]
fn local_atom_name_positive_capacities_reject_null_invalid_and_readonly_output() {
    let mut fixture = Fixture::new();
    for far in [0, 0xfff7_ffff] {
        assert!(fixture.decode(
            &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, far, 1),
        ).is_err());
    }
    let pointer = fixture.buffer(&[0xa5; 5], AccessRights::read_only());
    assert_eq!(fixture.decode(
        &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, pointer.far_value(), 1),
    ), Err(Win16Error::AccessDenied { access: Access::Write }));
}

#[test]
fn local_atom_name_output_rechecks_every_segment_of_a_cross_segment_buffer() {
    let mut fixture = Fixture::new();
    let selector = fixture.selectors.alloc_block(
        PhysAddr(0x2000), 0x1_0002, AccessRights::read_write(), &fixture.memory,
    ).unwrap();
    let pointer = SegmentedPointer::new(selector, 0xffff);
    let decoded = fixture.decode(
        &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, pointer.far_value(), 3),
    ).unwrap();
    assert_eq!(decoded.request, atom_request(Win16KernelAtomsRequest::GetAtomName {
        atom: 0xc123,
        output_buffer: Some(Win16OutputBuffer { pointer, capacity: 3 }),
    }));
    assert!(fixture.decode(
        &KERNEL_GET_ATOM_NAME, &name_output_arguments(0xc123, pointer.far_value(), 4),
    ).is_err());
}
