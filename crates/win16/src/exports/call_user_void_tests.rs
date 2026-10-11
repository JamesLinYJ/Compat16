//! SDK WINDOWS.H void declarations and LIBW ordinal identity, independent of Win32 BOOL.
use crate::{AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16ExportAbiKind, Win16ExportStackCleanup, Win16ParameterType,
    Win16ReturnKind, Win16UserRequest, Win16UserWindowRequest, Win16UserMessagesRequest,
    decode_export_call, lookup_export};
use crate::exports::{Win16UserRuntimeRequest, Win16UserSystemRequest};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn remaining_user_void_descriptors_match_sdk_identity_and_pascal_frames() {
    for (ordinal, name, words) in [(19, "ReleaseCapture", 0), (20, "SetDoubleClickTime", 1),
        (104, "MessageBeep", 1), (112, "WaitMessage", 0), (168, "SetCaretBlinkTime", 1)] {
        let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(descriptor, lookup_export(b"user.exe", ExportLookupTarget::Name(name.as_bytes())).unwrap());
        assert_eq!(descriptor.name(), name);
        assert_eq!(descriptor.ordinal(), ordinal);
        assert_eq!(descriptor.module(), "USER");
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(descriptor.parameters.len(), words);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: words as u16 * 2, caller_pop_bytes: 0 }));
        for parameter in descriptor.parameters {
            assert_eq!(parameter.kind, ArgumentKind::Word);
            assert_eq!(parameter.parameter_type, Win16ParameterType::Scalar);
        }
        for argument in [0u16, 1, 0x7fff, 0x8000, 0xffff] {
            for missing in [0, 1] {
                let mut memory = Memory::with_size(0x10_0000).unwrap();
                let mut selectors = SelectorTable::new().unwrap();
                let size = 4 + words as u32 * 2;
                let stack = selectors.alloc_block(PhysAddr(0x1000), size - missing,
                    AccessRights::read_write(), &memory).unwrap();
                let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
                if words != 0 { bytes.extend_from_slice(&argument.to_le_bytes()); }
                memory.write(PhysAddr(0x1000), &bytes).unwrap();
                let decoded = decode_export_call(descriptor,
                    Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
                    &selectors, &memory);
                if missing != 0 { assert!(decoded.is_err()); continue; }
                let request = match ordinal {
                    19 => Win16ApiRequest::User(Win16UserRequest::Window(Win16UserWindowRequest::ReleaseCapture)),
                    112 => Win16ApiRequest::User(Win16UserRequest::Messages(Win16UserMessagesRequest::WaitMessage)),
                    20 => Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetDoubleClickTime { milliseconds: argument }),
                    168 => Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetCaretBlinkTime { milliseconds: argument }),
                    104 => Win16ApiRequest::User(Win16UserRequest::Runtime(Win16UserRuntimeRequest::MessageBeep { beep_type: argument })),
                    _ => unreachable!(),
                };
                assert_eq!(decoded.unwrap().request, request);
            }
        }
    }
}
