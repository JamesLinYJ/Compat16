use crate::{
    AccessRights, ArgumentKind, DecodedWin16Call, ExportCallingConvention,
    ExportLookupTarget, ReturnAddressWidth, SegmentedPointer, SelectorRef, SelectorTable,
    StackCleanup, Win16ApiRequest, Win16Argument, Win16CallFrame, Win16ClassDataRequest,
    Win16Error, Win16ExportAbiKind, Win16ExportDescriptor, Win16ExportId,
    Win16ExportStackCleanup, Win16ParameterType, Win16ReturnKind, Win16WindowDataRequest,
    decode_export_call, lookup_export,
};
use crate::exports::{
    USER_GET_CLASS_LONG, USER_GET_CLASS_WORD, USER_SET_CLASS_LONG, USER_SET_CLASS_WORD,
    USER_GET_WINDOW_LONG, USER_GET_WINDOW_WORD, USER_SET_WINDOW_LONG, USER_SET_WINDOW_WORD,
    class_data::decode_class_data,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

struct Fixture {
    memory: Memory,
    selectors: SelectorTable,
    stack: SelectorRef,
}

impl Fixture {
    fn new(stack_bytes: u32) -> Self {
        let memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors.alloc_block(
            PhysAddr(0x1000), stack_bytes, AccessRights::read_write(), &memory,
        ).unwrap();
        Self { memory, selectors, stack }
    }

    fn decode(
        &mut self,
        descriptor: &Win16ExportDescriptor,
        stack_arguments: &[u8],
    ) -> Result<DecodedWin16Call, Win16Error> {
        // Supply physical Pascal stack order independently of the descriptor:
        // FAR return address, value (setters only), signed index, window.
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

#[test]
fn class_data_catalog_preserves_ordinals_signed_slots_result_widths_and_pascal_cleanup() {
    use ArgumentKind::{Dword, Word};
    use Win16ParameterType::{Scalar, SignedScalar};

    let cases: &[(Win16ExportDescriptor, Win16ExportId, u16, &[u8], u16,
        Win16ReturnKind, &[(ArgumentKind, Win16ParameterType)])] = &[
        (USER_GET_CLASS_WORD, Win16ExportId::UserGetClassWord, 129, b"GetClassWord", 4,
            Win16ReturnKind::Word, &[(Word, Scalar), (Word, SignedScalar)]),
        (USER_SET_CLASS_WORD, Win16ExportId::UserSetClassWord, 130, b"SetClassWord", 6,
            Win16ReturnKind::Word, &[(Word, Scalar), (Word, SignedScalar), (Word, Scalar)]),
        (USER_GET_CLASS_LONG, Win16ExportId::UserGetClassLong, 131, b"GetClassLong", 4,
            Win16ReturnKind::Dword, &[(Word, Scalar), (Word, SignedScalar)]),
        (USER_SET_CLASS_LONG, Win16ExportId::UserSetClassLong, 132, b"SetClassLong", 8,
            Win16ReturnKind::Dword, &[(Word, Scalar), (Word, SignedScalar), (Dword, SignedScalar)]),
    ];
    for &(descriptor, id, ordinal, name, argument_bytes, result, parameters) in cases {
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.module(), "USER");
        assert_eq!(descriptor.ordinal(), ordinal);
        assert_eq!(descriptor.name().as_bytes(), name);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.return_kind, result);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: argument_bytes,
            caller_pop_bytes: 0,
        }));
        assert_eq!(descriptor.parameters.iter().map(|parameter| {
            (parameter.kind, parameter.parameter_type)
        }).collect::<Vec<_>>(), parameters);
        assert_eq!(lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)),
            Some(&descriptor));
        assert_eq!(lookup_export(b"USER", ExportLookupTarget::Name(name)),
            Some(&descriptor));
    }
}

#[test]
fn class_data_word_physical_frames_preserve_signed_indexes_and_unsigned_values() {
    let mut fixture = Fixture::new(0x100);
    for index in [i16::MIN, -32, -26, -20, -1, 0, 1, i16::MAX] {
        // The topmost argument is the index, followed by window 0xa135.
        let mut get_stack = index.to_le_bytes().to_vec();
        get_stack.extend_from_slice(&[0x35, 0xa1]);
        let decoded = fixture.decode(&USER_GET_CLASS_WORD, &get_stack).unwrap();
        assert_eq!(decoded.export, Win16ExportId::UserGetClassWord);
        assert_eq!(decoded.request, Win16ApiRequest::ClassData(
            Win16ClassDataRequest::GetClassWord { window: 0xa135, index },
        ));
        assert_eq!(decoded.stack_cleanup, StackCleanup {
            callee_pop_bytes: 4, caller_pop_bytes: 0,
        });
        for value in [0u16, 1, 0x7fff, 0x8000, 0xbeef, 0xffff] {
            let mut set_stack = value.to_le_bytes().to_vec();
            set_stack.extend_from_slice(&get_stack);
            let decoded = fixture.decode(&USER_SET_CLASS_WORD, &set_stack).unwrap();
            assert_eq!(decoded.export, Win16ExportId::UserSetClassWord);
            assert_eq!(decoded.request, Win16ApiRequest::ClassData(
                Win16ClassDataRequest::SetClassWord { window: 0xa135, index, value },
            ));
            assert_eq!(decoded.stack_cleanup, StackCleanup {
                callee_pop_bytes: 6, caller_pop_bytes: 0,
            });
        }
    }
}

#[test]
fn class_data_long_physical_frames_preserve_full_dword_bits_and_signed_indexes() {
    let mut fixture = Fixture::new(0x100);
    for index in [i16::MIN, -24, -8, -1, 0, 2, i16::MAX] {
        let mut get_stack = index.to_le_bytes().to_vec();
        get_stack.extend_from_slice(&[0x13, 0xc2]);
        let decoded = fixture.decode(&USER_GET_CLASS_LONG, &get_stack).unwrap();
        assert_eq!(decoded.export, Win16ExportId::UserGetClassLong);
        assert_eq!(decoded.request, Win16ApiRequest::ClassData(
            Win16ClassDataRequest::GetClassLong { window: 0xc213, index },
        ));
        assert_eq!(decoded.stack_cleanup, StackCleanup {
            callee_pop_bytes: 4, caller_pop_bytes: 0,
        });
        for raw in [0u32, 0x1234_5678, 0x7fff_ffff, 0x8000_0000, 0xbeef_cafe, 0xffff_ffff] {
            let mut set_stack = raw.to_le_bytes().to_vec();
            set_stack.extend_from_slice(&get_stack);
            let decoded = fixture.decode(&USER_SET_CLASS_LONG, &set_stack).unwrap();
            assert_eq!(decoded.export, Win16ExportId::UserSetClassLong);
            assert_eq!(decoded.request, Win16ApiRequest::ClassData(
                Win16ClassDataRequest::SetClassLong {
                    window: 0xc213, index, value: raw as i32,
                },
            ));
            assert_eq!(decoded.stack_cleanup, StackCleanup {
                callee_pop_bytes: 8, caller_pop_bytes: 0,
            });
        }
    }
}

#[test]
fn class_data_neighbor_ordinals_keep_their_existing_requests() {
    let mut fixture = Fixture::new(0x100);
    let cases: &[(Win16ExportDescriptor, u16, &[u8], Win16WindowDataRequest)] = &[
        (USER_GET_WINDOW_WORD, 133, &[0xfc, 0xff, 0x34, 0x12],
            Win16WindowDataRequest::GetWindowWord { window: 0x1234, index: -4 }),
        (USER_SET_WINDOW_WORD, 134, &[0xef, 0xbe, 0xfa, 0xff, 0x34, 0x12],
            Win16WindowDataRequest::SetWindowWord { window: 0x1234, index: -6, value: 0xbeef }),
        (USER_GET_WINDOW_LONG, 135, &[0xf0, 0xff, 0x34, 0x12],
            Win16WindowDataRequest::GetWindowLong { window: 0x1234, index: -16 }),
        (USER_SET_WINDOW_LONG, 136, &[0x78, 0x56, 0x34, 0x82, 0xec, 0xff, 0x34, 0x12],
            Win16WindowDataRequest::SetWindowLong {
                window: 0x1234, index: -20, value: 0x8234_5678u32 as i32,
            }),
    ];
    for &(descriptor, ordinal, bytes, request) in cases {
        assert_eq!(lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)), Some(&descriptor));
        assert_eq!(fixture.decode(&descriptor, bytes).unwrap().request,
            Win16ApiRequest::WindowData(request));
    }
    for (ordinal, id, name) in [
        (128, Win16ExportId::UserValidateRgn, "ValidateRgn"),
        (137, Win16ExportId::UserOpenClipboard, "OpenClipboard"),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.name(), name);
    }
}

#[test]
fn class_data_physical_frames_reject_truncated_argument_slots() {
    for (descriptor, bytes) in [
        (USER_GET_CLASS_WORD, 4u32),
        (USER_SET_CLASS_WORD, 6),
        (USER_GET_CLASS_LONG, 4),
        (USER_SET_CLASS_LONG, 8),
    ] {
        // Physical bytes exist, but the guest stack descriptor ends one byte
        // before the complete frame. Decoding must respect the selector limit.
        let mut fixture = Fixture::new(4 + bytes - 1);
        assert!(matches!(fixture.decode(&descriptor, &vec![0xff; bytes as usize]),
            Err(Win16Error::LimitViolation { .. })));
    }
}

#[test]
fn class_data_scalar_decoder_rejects_wrong_widths_counts_and_adjacent_ordinals() {
    use Win16Argument::{Dword, Word};

    let cases: &[(u16, &[Win16Argument])] = &[
        (129, &[Word(1)]),
        (129, &[Word(1), Word(0), Word(2)]),
        (129, &[Dword(1), Word(0)]),
        (130, &[Word(1), Word(0), Dword(2)]),
        (131, &[Word(1), Dword(0)]),
        (132, &[Word(1), Word(0), Word(2)]),
        (132, &[Word(1), Word(0), Dword(2), Word(3)]),
        (128, &[Word(1), Word(0)]),
        (133, &[Word(1), Word(0)]),
        (134, &[Word(1), Word(0), Word(2)]),
        (135, &[Word(1), Word(0)]),
        (136, &[Word(1), Word(0), Dword(2)]),
    ];
    for &(ordinal, arguments) in cases {
        assert_eq!(decode_class_data(ordinal, arguments), Err(Win16Error::InvalidRange));
    }
}
