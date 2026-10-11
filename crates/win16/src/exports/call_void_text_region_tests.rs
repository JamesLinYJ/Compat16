//! Win16 SDK void declarations retain their original Pascal argument contracts.

use crate::{AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget,
    ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportId, Win16ExportStackCleanup,
    Win16GdiDrawingRequest, Win16ParameterType, Win16ReturnKind, Win16UserRequest,
    Win16UserWindowRequest, decode_export_call, lookup_export};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

pub(super) fn decode(module: &[u8], ordinal: u16, words: &[u16], stack_bytes: u32)
    -> Result<Win16ApiRequest, Win16Error>
{
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors.alloc_block(PhysAddr(0x1000), stack_bytes,
        AccessRights::read_write(), &memory).unwrap();
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
    bytes.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let descriptor = lookup_export(module, ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let call = decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors, &memory)?;
    assert_eq!(call.stack_cleanup, StackCleanup {
        callee_pop_bytes: (words.len() * 2) as u16, caller_pop_bytes: 0,
    });
    Ok(call.request)
}

#[test]
fn set_window_text_and_set_rect_rgn_catalog_have_void_pascal_contracts() {
    for (module, ordinal, name, id, cleanup) in [
        (b"USER".as_slice(), 37, b"SetWindowText".as_slice(), Win16ExportId::UserSetWindowText, 6),
        (b"GDI".as_slice(), 172, b"SetRectRgn".as_slice(), Win16ExportId::GdiSetRectRgn, 10),
    ] {
        let descriptor = lookup_export(module, ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(lookup_export(module, ExportLookupTarget::Name(name)), Some(descriptor));
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: cleanup, caller_pop_bytes: 0,
        }));
        let parameters: Vec<_> = descriptor.parameters.iter()
            .map(|parameter| (parameter.kind, parameter.parameter_type)).collect();
        assert_eq!(parameters, if ordinal == 37 {
            vec![(ArgumentKind::Word, Win16ParameterType::Scalar),
                (ArgumentKind::Dword, Win16ParameterType::NullableFarString)]
        } else {
            vec![(ArgumentKind::Word, Win16ParameterType::Scalar),
                (ArgumentKind::Word, Win16ParameterType::SignedScalar),
                (ArgumentKind::Word, Win16ParameterType::SignedScalar),
                (ArgumentKind::Word, Win16ParameterType::SignedScalar),
                (ArgumentKind::Word, Win16ParameterType::SignedScalar)]
        });
    }
}

#[test]
fn void_text_region_decode_preserves_nullable_text_and_signed_coordinate_order() {
    assert_eq!(decode(b"USER", 37, &[0, 0, 0x1234], 10).unwrap(),
        Win16ApiRequest::User(Win16UserRequest::Window(Win16UserWindowRequest::SetWindowText {
            window: 0x1234, text: None,
        })));
    assert_eq!(decode(b"GDI", 172, &[0xffff, 0x7fff, 0xffed, 0x8000, 0x1234], 14).unwrap(),
        Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::SetRectRgn {
            region: 0x1234, left: i16::MIN, top: -19, right: i16::MAX, bottom: -1,
        }));
}

#[test]
fn void_text_region_reject_every_truncated_argument_frame() {
    for (module, ordinal, words) in [
        (b"USER".as_slice(), 37, vec![0, 0, 0x1234]),
        (b"GDI".as_slice(), 172, vec![0xffff, 0x7fff, 0xffed, 0x8000, 0x1234]),
    ] {
        for length in 4..(4 + words.len() * 2) {
            assert!(matches!(decode(module, ordinal, &words, length as u32),
                Err(Win16Error::LimitViolation { .. })), "ordinal {ordinal}, length {length}");
        }
    }
}
