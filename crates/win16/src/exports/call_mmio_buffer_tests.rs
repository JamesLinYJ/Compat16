//! MMSYSTEM 1215–1217, 1219, 1221, and 1222 catalog and Pascal frames.

use crate::exports::lookup_export_metadata;
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame,
    Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup, Win16MediaIoRequest,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

fn spec(
    ordinal: u16,
    name: &'static [u8],
    id: Win16ExportId,
    id_value: u32,
    return_kind: Win16ReturnKind,
    cleanup: u16,
    parameters: &[(&str, ArgumentKind, Win16ParameterType)],
) {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(
        lookup_export(b"MMSYSTEM", ExportLookupTarget::Name(name)),
        Some(descriptor)
    );
    assert_eq!(descriptor.id, id);
    assert_eq!(descriptor.id as u32, id_value);
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, return_kind);
    assert_eq!(
        descriptor.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: cleanup,
            caller_pop_bytes: 0,
        })
    );
    let actual: Vec<_> = descriptor
        .parameters
        .iter()
        .map(|parameter| (parameter.name, parameter.kind, parameter.parameter_type))
        .collect();
    assert_eq!(actual, parameters);
    let metadata =
        lookup_export_metadata(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(metadata.source.spec_path, "groups/mmsystem/media_io.toml");
}

fn decode(ordinal: u16, payload: &[u8]) -> Win16MediaIoRequest {
    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(
            PhysAddr(0x1000),
            4 + payload.len() as u32,
            AccessRights::read_write(),
            &memory,
        )
        .unwrap();
    let mut frame = vec![0x34, 0x12, 0x78, 0x56];
    frame.extend_from_slice(payload);
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(decoded.export, descriptor.id);
    assert_eq!(
        decoded.stack_cleanup.callee_pop_bytes,
        match descriptor.stack_cleanup {
            Win16ExportStackCleanup::Fixed(cleanup) => cleanup.callee_pop_bytes,
            Win16ExportStackCleanup::Variable => panic!("mmio buffer helpers use a fixed frame"),
        }
    );
    match decoded.request {
        Win16ApiRequest::MediaIo(request) => request,
        other => panic!("mmio buffer helper decoded as {other:?}"),
    }
}

#[test]
fn mmio_buffer_helpers_keep_ordinals_names_and_return_widths() {
    use ArgumentKind::{Dword, Word};
    use Win16ParameterType::{FarBuffer, FarPointer, Scalar, SignedScalar};
    use Win16ReturnKind::{Dword as DwordReturn, FarPointer as FarReturn, Word as WordReturn};
    spec(
        1215,
        b"mmioGetInfo",
        Win16ExportId::MediaIoGetInfo,
        1285,
        WordReturn,
        8,
        &[
            ("handle", Word, Scalar),
            ("info", Dword, FarBuffer),
            ("flags", Word, Scalar),
        ],
    );
    spec(
        1216,
        b"mmioSetInfo",
        Win16ExportId::MediaIoSetInfo,
        1286,
        WordReturn,
        8,
        &[
            ("handle", Word, Scalar),
            ("info", Dword, FarBuffer),
            ("flags", Word, Scalar),
        ],
    );
    spec(
        1217,
        b"mmioSetBuffer",
        Win16ExportId::MediaIoSetBuffer,
        1287,
        WordReturn,
        12,
        &[
            ("handle", Word, Scalar),
            ("buffer", Dword, FarPointer),
            ("size", Dword, SignedScalar),
            ("flags", Word, Scalar),
        ],
    );
    spec(
        1219,
        b"mmioAdvance",
        Win16ExportId::MediaIoAdvance,
        1288,
        WordReturn,
        8,
        &[
            ("handle", Word, Scalar),
            ("info", Dword, FarBuffer),
            ("flags", Word, Scalar),
        ],
    );
    spec(
        1221,
        b"mmioInstallIOProc",
        Win16ExportId::MediaIoInstallIoProc,
        1289,
        FarReturn,
        12,
        &[
            ("fourcc", Dword, Scalar),
            ("procedure", Dword, FarPointer),
            ("flags", Dword, Scalar),
        ],
    );
    spec(
        1222,
        b"mmioSendMessage",
        Win16ExportId::MediaIoSendMessage,
        1290,
        DwordReturn,
        12,
        &[
            ("handle", Word, Scalar),
            ("message", Word, Scalar),
            ("param1", Dword, SignedScalar),
            ("param2", Dword, SignedScalar),
        ],
    );
    assert!(lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(1218)).is_some());
    assert!(lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(1220)).is_some());
}

#[test]
fn mmio_buffer_helpers_decode_pascal_arguments_last_closest_to_the_return() {
    assert_eq!(
        decode(1215, &{
            let mut bytes = 7_u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&0x2222_3333_u32.to_le_bytes());
            bytes.extend_from_slice(&0x1111_u16.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::GetInfo {
            handle: 0x1111,
            info: 0x2222_3333,
            flags: 7
        }
    );
    assert_eq!(
        decode(1216, &{
            let mut bytes = 0_u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&0x4444_5555_u32.to_le_bytes());
            bytes.extend_from_slice(&0x0002_u16.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::SetInfo {
            handle: 2,
            info: 0x4444_5555,
            flags: 0
        }
    );
    assert_eq!(
        decode(1217, &{
            let mut bytes = 9_u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&(-1_i32).to_le_bytes());
            bytes.extend_from_slice(&0x1000_0000_u32.to_le_bytes());
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::SetBuffer {
            handle: 1,
            buffer: 0x1000_0000,
            size: -1,
            flags: 9,
        }
    );
    assert_eq!(
        decode(1219, &{
            let mut bytes = 1_u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&4_u16.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::Advance {
            handle: 4,
            info: 0,
            flags: 1
        }
    );
    assert_eq!(
        decode(1221, &{
            let mut bytes = 0x0001_0000_u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&0x2222_2222_u32.to_le_bytes());
            bytes.extend_from_slice(&0x1111_1111_u32.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::InstallIoProc {
            fourcc: 0x1111_1111,
            procedure: 0x2222_2222,
            flags: 0x0001_0000,
        }
    );
    assert_eq!(
        decode(1222, &{
            let mut bytes = 6_i32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&5_i32.to_le_bytes());
            bytes.extend_from_slice(&4_u16.to_le_bytes());
            bytes.extend_from_slice(&3_u16.to_le_bytes());
            bytes
        }),
        Win16MediaIoRequest::SendMessage {
            handle: 3,
            message: 4,
            param1: 5,
            param2: 6
        }
    );

    let descriptor = lookup_export(b"MMSYSTEM", ExportLookupTarget::Ordinal(1215)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x2000), 11, AccessRights::read_write(), &memory)
        .unwrap();
    memory.write(PhysAddr(0x2000), &[0; 11]).unwrap();
    assert!(
        decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory
        )
        .is_err()
    );
}
