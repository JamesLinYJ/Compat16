//! Windows 3.1 SDK BOOL WINAPI IsChar*(char), USER.433–436, RETF 2.
use crate::{AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame,
    Win16CharacterClassification as Classification, Win16ExportAbiKind, Win16ExportId,
    Win16ExportStackCleanup, Win16ReturnKind, Win16UserAnsiRequest, Win16UserRequest,
    decode_export_call, lookup_export};
use crate::exports::{ExportImplementationState, resolve_export};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn character_classification_abi_consumes_low_byte_of_one_pascal_word() {
    for (ordinal, name, id, classification) in [
        (433, "IsCharAlpha", Win16ExportId::UserIsCharAlpha, Classification::Alpha),
        (434, "IsCharAlphaNumeric", Win16ExportId::UserIsCharAlphaNumeric, Classification::AlphaNumeric),
        (435, "IsCharUpper", Win16ExportId::UserIsCharUpper, Classification::Upper),
        (436, "IsCharLower", Win16ExportId::UserIsCharLower, Classification::Lower),
    ] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor, lookup_export(b"user.exe", ExportLookupTarget::Name(name.as_bytes())).unwrap());
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.name(), name);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(descriptor.parameters.len(), 1);
        let cleanup = StackCleanup { callee_pop_bytes: 2, caller_pop_bytes: 0 };
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(cleanup));
        assert_eq!(resolve_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap().state,
            ExportImplementationState::BoundToRequest);
        for value in [0x0041_u16, 0xff41, 0, 0xffe9] {
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let stack = selectors.alloc_block(PhysAddr(0x1000), 6,
                AccessRights::read_write(), &memory).unwrap();
            let bytes = [0x34, 0x12, 0x78, 0x56, value as u8, (value >> 8) as u8];
            memory.write(PhysAddr(0x1000), &bytes).unwrap();
            let decoded = decode_export_call(descriptor,
                Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                &selectors, &memory).unwrap();
            assert_eq!(decoded.stack_cleanup, cleanup);
            assert_eq!(decoded.request, Win16ApiRequest::User(Win16UserRequest::Ansi(
                Win16UserAnsiRequest::ClassifyCharacter { value: value as u8, classification })));
            let mut actual = [0; 6];
            memory.read(PhysAddr(0x1000), &mut actual).unwrap();
            assert_eq!(actual, bytes);
        }
    }
}
