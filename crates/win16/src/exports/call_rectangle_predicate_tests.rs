//! SDK-backed rectangle export identities and existing checked request decoding.
//! These tests preserve the current request boundary, not historical geometry.

use crate::{
    AccessRights, ArgumentKind, DecodedWin16Call, ExportCallingConvention, ExportLookupTarget,
    Rect16, ReturnAddressWidth, SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest,
    Win16CallFrame, Win16Error, Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup,
    Win16GdiDrawingRequest, Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use crate::exports::{
    ExportArchitecture, ExportArgumentType, ExportImplementationState, ExportReturnModifier,
    WIN16_EXPORTS, export_descriptors, lookup_export_metadata, resolve_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

const EXPORTS: &[(u16, &str, Win16ExportId)] = &[
    (104, "RectVisible", Win16ExportId::GdiRectVisibleOld),
    (181, "RectInRegion", Win16ExportId::GdiRectInRegion),
    (465, "RectVisible_EHH", Win16ExportId::GdiRectVisible),
    (466, "RectInRegion_EHH", Win16ExportId::GdiRectInRegionEhh),
];
const ALIASES: &[(u16, &str)] = &[(104, "RectVisibleOld"), (181, "RectInRegionOld")];
const CLEANUP: StackCleanup = StackCleanup { callee_pop_bytes: 6, caller_pop_bytes: 0 };

#[test]
fn rectangle_predicate_catalog_matches_sdk_names_ordinals_and_abi() {
    for &(ordinal, name, id) in EXPORTS {
        let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        let named = lookup_export(b"GDI", ExportLookupTarget::Name(name.as_bytes())).unwrap();
        assert_eq!(named, descriptor);
        assert_eq!(descriptor.id, id);
        assert_eq!(descriptor.name(), name);
        assert_eq!(descriptor.module(), "GDI");
        assert_eq!(descriptor.ordinal(), ordinal);
        assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
        assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(CLEANUP));
        assert_eq!(descriptor.parameters.len(), 2);
        assert_eq!(descriptor.parameters[0].kind, ArgumentKind::Word);
        assert_eq!(descriptor.parameters[0].parameter_type, Win16ParameterType::Scalar);
        assert_eq!(descriptor.parameters[1].kind, ArgumentKind::Dword);
        assert_eq!(descriptor.parameters[1].parameter_type, Win16ParameterType::FarBuffer);

        let metadata = lookup_export_metadata(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(metadata.name, Some(name));
        assert_eq!(metadata.declared_name, name);
        assert_eq!(metadata.architecture, ExportArchitecture::Win16);
        let abi = metadata.abi.unwrap();
        assert_eq!(abi.calling_convention, Some(ExportCallingConvention::Pascal));
        assert_eq!(abi.arguments, &[ExportArgumentType::Word, ExportArgumentType::Pointer]);
        assert_eq!(abi.return_modifier, ExportReturnModifier::Ret16);
    }
}

#[test]
fn rectangle_predicate_names_and_old_aliases_share_normalized_lookup() {
    for (ordinal, name) in EXPORTS.iter().map(|&(ordinal, name, _)| (ordinal, name))
        .chain(ALIASES.iter().copied()) {
        let expected = resolve_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(expected.state, ExportImplementationState::BoundToRequest);
        for module in [b"GDI".as_slice(), b"gdi.exe", b"GdI.dLl", b"gDi.DrV", b"gdi.MOD"] {
            for imported_name in [name.as_bytes().to_vec(), name.to_ascii_lowercase().into_bytes(),
                name.to_ascii_uppercase().into_bytes()] {
                let target = ExportLookupTarget::Name(&imported_name);
                assert_eq!(lookup_export_metadata(module, target), Some(expected.declaration));
                assert_eq!(lookup_export(module, target), expected.descriptor);
                assert_eq!(resolve_export(module, target), Some(expected));
            }
        }
    }
    // The two original ordinals stay distinct despite sharing a request type.
    assert_ne!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(104)).unwrap().id,
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(465)).unwrap().id);
    assert_ne!(lookup_export(b"GDI", ExportLookupTarget::Ordinal(181)).unwrap().id,
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(466)).unwrap().id);
}

#[test]
fn rectangle_predicate_aliases_are_exact_and_module_scoped() {
    for module in [b"USER".as_slice(), b"KERNEL.EXE", b"GDI32.DLL", b"MYGDI", b"GDI.EXE.DLL"] {
        for &(_, name) in ALIASES {
            let target = ExportLookupTarget::Name(name.as_bytes());
            assert!(lookup_export_metadata(module, target).is_none());
            assert!(lookup_export(module, target).is_none());
            assert!(resolve_export(module, target).is_none());
        }
    }
    for name in [b"RectVisibleOl".as_slice(), b"RectVisibleOld_EHH", b"RectInRegionOldOld",
        b"RectVisibleOld\0", b" RectInRegionOld", b"RectVisible@6", b"RectVisibleEHH"] {
        let target = ExportLookupTarget::Name(name);
        assert!(lookup_export_metadata(b"GDI", target).is_none());
        assert!(lookup_export(b"GDI", target).is_none());
        assert!(resolve_export(b"GDI", target).is_none());
    }
}

#[test]
fn rectangle_predicate_aliases_do_not_duplicate_canonical_declarations() {
    for &(ordinal, name, _) in EXPORTS {
        let declarations: Vec<_> = WIN16_EXPORTS.iter().flat_map(|group| group.iter())
            .filter(|entry| entry.module == "GDI" && entry.ordinal == ordinal
                && entry.architecture == ExportArchitecture::Win16).collect();
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].name, Some(name));
        assert_eq!(export_descriptors().iter().filter(|entry| {
            entry.module() == "GDI" && entry.ordinal() == ordinal
        }).count(), 1);
    }
    for &(_, alias) in ALIASES {
        assert!(!WIN16_EXPORTS.iter().flat_map(|group| group.iter()).any(|entry| {
            entry.module == "GDI" && entry.name == Some(alias)
        }));
    }
}

fn decode_frame(
    ordinal: u16,
    handle: u16,
    rect_far: u32,
    stack_size: u32,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
) -> Result<DecodedWin16Call, Win16Error> {
    let stack = selectors.alloc_block(PhysAddr(0x1000), stack_size,
        AccessRights::read_write(), memory).unwrap();
    // Physical Pascal frame: return IP:CS, RECT offset:selector, HDC/HRGN.
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
    bytes.extend_from_slice(&rect_far.to_le_bytes());
    bytes.extend_from_slice(&handle.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    decode_export_call(descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        selectors, memory)
}

fn expected_request(ordinal: u16, handle: u16, rect: Option<Rect16>) -> Win16ApiRequest {
    Win16ApiRequest::GdiDrawing(match ordinal {
        104 | 465 => Win16GdiDrawingRequest::RectVisible { dc: handle, rect },
        181 | 466 => Win16GdiDrawingRequest::RectInRegion { region: handle, rect },
        _ => unreachable!(),
    })
}

#[test]
fn rectangle_predicate_physical_pascal_frames_preserve_raw_coordinates_and_handles() {
    for &(ordinal, _, _) in EXPORTS {
        for edges in [[-3_i16, 2, 17, 29], [0; 4], [9, 8, -7, -6],
            [i16::MIN, -1, i16::MAX, 0]] {
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let rect_selector = selectors.alloc_block(PhysAddr(0x2000), 12,
                AccessRights::read_only(), &memory).unwrap();
            let rect_far = SegmentedPointer::new(rect_selector, 4).far_value();
            let rect_bytes: Vec<_> = edges.into_iter().flat_map(i16::to_le_bytes).collect();
            memory.write(PhysAddr(0x2004), &rect_bytes).unwrap();
            let decoded = decode_frame(ordinal, 0x8765, rect_far, 10, &mut selectors, &mut memory).unwrap();
            assert_eq!(decoded.request, expected_request(ordinal, 0x8765, Some(Rect16 {
                left: edges[0], top: edges[1], right: edges[2], bottom: edges[3],
            })));
            assert_eq!(decoded.stack_cleanup, CLEANUP);
            let mut unchanged = [0; 8];
            memory.read(PhysAddr(0x2004), &mut unchanged).unwrap();
            assert_eq!(unchanged.as_slice(), rect_bytes.as_slice());
        }
    }
}

#[test]
fn rectangle_predicate_null_rect_and_unvalidated_handles_keep_existing_requests() {
    for &(ordinal, _, _) in EXPORTS {
        for handle in [0, 0xffff] {
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let decoded = decode_frame(ordinal, handle, 0, 10, &mut selectors, &mut memory).unwrap();
            assert_eq!(decoded.request, expected_request(ordinal, handle, None));
            assert_eq!(decoded.stack_cleanup, CLEANUP);
        }
    }
}

#[test]
fn rectangle_predicate_invalid_nonnull_rects_keep_checked_decode_failures() {
    for &(ordinal, _, _) in EXPORTS {
        for handle in [0, 0xffff] {
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let short_rect = selectors.alloc_block(PhysAddr(0x2000), 7,
                AccessRights::read_only(), &memory).unwrap();
            assert!(matches!(decode_frame(ordinal, handle,
                SegmentedPointer::new(short_rect, 0).far_value(), 10, &mut selectors, &mut memory),
                Err(Win16Error::LimitViolation { .. })));
            assert_eq!(decode_frame(ordinal, handle, 1, 10, &mut selectors, &mut memory),
                Err(Win16Error::InvalidSelector));
        }
    }
}

#[test]
fn rectangle_predicate_physical_frame_rejects_truncated_handle_slot() {
    for &(ordinal, _, _) in EXPORTS {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        assert!(matches!(decode_frame(ordinal, 0x8765, 0, 9, &mut selectors, &mut memory),
            Err(Win16Error::LimitViolation { .. })));
    }
}
