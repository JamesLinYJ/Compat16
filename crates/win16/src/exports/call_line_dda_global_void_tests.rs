//! SDK void contracts override the imported specification's WORD result.
use super::void_text_region_tests::decode;
use crate::{ArgumentKind, ExportCallingConvention, ExportLookupTarget, StackCleanup,
    Win16ApiRequest, Win16Error, Win16ExportId, Win16ExportStackCleanup,
    Win16GdiDrawingRequest, Win16KernelGlobalHeapRequest, Win16ParameterType,
    Win16ReturnKind, lookup_export};

#[test]
fn line_dda_global_fix_unfix_have_sdk_void_pascal_contracts() {
    for (module, ordinal, name, id, cleanup) in [
        (b"GDI".as_slice(), 100, b"LineDDA".as_slice(), Win16ExportId::GdiLineDda, 16),
        (b"KERNEL".as_slice(), 197, b"GlobalFix".as_slice(), Win16ExportId::KernelGlobalFix, 2),
        (b"KERNEL".as_slice(), 198, b"GlobalUnfix".as_slice(), Win16ExportId::KernelGlobalUnfix, 2),
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
        if ordinal == 100 {
            assert_eq!(&parameters[..4], &[(ArgumentKind::Word, Win16ParameterType::SignedScalar); 4]);
            assert_eq!(parameters.len(), 6);
            assert_eq!(parameters[4], (ArgumentKind::Dword, Win16ParameterType::FarPointer));
            assert_eq!(parameters[5], (ArgumentKind::Dword, Win16ParameterType::Scalar));
        } else {
            assert_eq!(parameters, [(ArgumentKind::Word, Win16ParameterType::Scalar)]);
        }
    }
}

#[test]
fn line_dda_void_decode_preserves_signed_endpoints_far_callback_and_data() {
    assert_eq!(decode(b"GDI", 100,
        &[0xcdef, 0x89ab, 0x1234, 0x5678, 0xffff, 0x7fff, 0xffed, 0x8000], 20).unwrap(),
        Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::LineDda {
            x_start: i16::MIN, y_start: -19, x_end: i16::MAX, y_end: -1,
            callback: 0x56781234, data: 0x89abcdef,
        }));
    assert_eq!(decode(b"GDI", 100, &[0; 8], 20).unwrap(),
        Win16ApiRequest::GdiDrawing(Win16GdiDrawingRequest::LineDda {
            x_start: 0, y_start: 0, x_end: 0, y_end: 0, callback: 0, data: 0,
        }));
    for handle in [0, 1, 0x8000, 0xffff] {
        assert_eq!(decode(b"KERNEL", 197, &[handle], 6).unwrap(),
            Win16ApiRequest::KernelGlobalHeap(Win16KernelGlobalHeapRequest::GlobalFix { handle }));
        assert_eq!(decode(b"KERNEL", 198, &[handle], 6).unwrap(),
            Win16ApiRequest::KernelGlobalHeap(Win16KernelGlobalHeapRequest::GlobalUnfix { handle }));
    }
}

#[test]
fn line_dda_global_void_reject_every_truncated_argument_frame() {
    for (module, ordinal, words) in [
        (b"GDI".as_slice(), 100, vec![0; 8]),
        (b"KERNEL".as_slice(), 197, vec![0xffff]),
        (b"KERNEL".as_slice(), 198, vec![0xffff]),
    ] {
        for length in 4..4 + words.len() * 2 {
            assert!(matches!(decode(module, ordinal, &words, length as u32),
                Err(Win16Error::LimitViolation { .. })), "ordinal {ordinal}, length {length}");
        }
    }
}
