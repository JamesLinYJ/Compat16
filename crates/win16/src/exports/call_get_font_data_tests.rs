//! GDI.311 Pascal frame and Win16 GetFontData retrieval plan.
//!
//! Wine's public export is `311 pascal GetFontData(word long long ptr long)`
//! (`dlls/gdi.exe16/gdi.exe16.spec`) and `DWORD GetFontData16` forwards to the
//! Win32 call. Win32 failure is `GDI_ERROR`. The guest result is zero.

use crate::exports::GDI_GET_FONT_DATA;
use crate::gdi_abi::{Win16FontDataPlan, plan_win16_font_data};
use crate::{
    AccessRights, ArgumentKind, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, StackCleanup, Win16ApiRequest, Win16CallFrame, Win16Error,
    Win16ExportAbiKind, Win16ExportId, Win16ExportStackCleanup, Win16GdiServicesRequest,
    Win16ParameterType, Win16ReturnKind, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn get_font_data_catalog_is_dword_pascal_gdi_311() {
    let descriptor = &GDI_GET_FONT_DATA;
    assert_eq!(descriptor.id, Win16ExportId::GdiGetFontData);
    assert_eq!(descriptor.module(), "GDI");
    assert_eq!(descriptor.ordinal(), 311);
    assert_eq!(descriptor.name(), "GetFontData");
    assert_eq!(descriptor.abi_kind, Win16ExportAbiKind::Stack);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    assert_eq!(
        descriptor.stack_cleanup,
        Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 18,
            caller_pop_bytes: 0,
        })
    );
    assert_eq!(
        descriptor
            .parameters
            .iter()
            .map(|parameter| (parameter.name, parameter.kind, parameter.parameter_type))
            .collect::<Vec<_>>(),
        vec![
            ("dc", ArgumentKind::Word, Win16ParameterType::Scalar),
            ("table", ArgumentKind::Dword, Win16ParameterType::Scalar),
            ("offset", ArgumentKind::Dword, Win16ParameterType::Scalar),
            (
                "buffer",
                ArgumentKind::Dword,
                Win16ParameterType::FarOutputBuffer
            ),
            (
                "byte_count",
                ArgumentKind::Dword,
                Win16ParameterType::Scalar
            ),
        ]
    );
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Ordinal(311)),
        Some(descriptor)
    );
    assert_eq!(
        lookup_export(b"GDI", ExportLookupTarget::Name(b"GetFontData")),
        Some(descriptor)
    );
}

#[test]
fn get_font_data_physical_frame_keeps_dword_slots_in_pascal_order() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 22, AccessRights::read_write(), &memory)
        .unwrap();
    let mut bytes = vec![0x34, 0x12, 0x78, 0x56];
    // Pascal: return IP:CS, then byte count, buffer, offset, table, and HDC.
    bytes.extend_from_slice(&0x0000_0008_u32.to_le_bytes());
    bytes.extend_from_slice(&0xabcd_1234_u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0004_u32.to_le_bytes());
    bytes.extend_from_slice(&0x656d_616e_u32.to_le_bytes());
    bytes.extend_from_slice(&0x1111_u16.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes).unwrap();
    let decoded = decode_export_call(
        &GDI_GET_FONT_DATA,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::GdiServices(Win16GdiServicesRequest::GetFontData {
            dc: 0x1111,
            table: 0x656d_616e,
            offset: 4,
            output: 0xabcd_1234,
            byte_count: 8,
        })
    );
    assert_eq!(
        decoded.stack_cleanup,
        StackCleanup {
            callee_pop_bytes: 18,
            caller_pop_bytes: 0
        }
    );
}

#[test]
fn get_font_data_physical_frame_rejects_a_truncated_dword_slot() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 21, AccessRights::read_write(), &memory)
        .unwrap();
    memory.write(PhysAddr(0x1000), &[0; 21]).unwrap();
    assert!(matches!(
        decode_export_call(
            &GDI_GET_FONT_DATA,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        ),
        Err(Win16Error::LimitViolation { .. })
    ));
}

#[test]
fn get_font_data_plan_covers_a_miss_a_short_buffer_and_a_fitting_copy() {
    let size = 16;
    assert_eq!(
        plan_win16_font_data(size, 16, 4, true),
        Win16FontDataPlan::Failure
    );
    assert_eq!(
        plan_win16_font_data(size, 20, 0, false),
        Win16FontDataPlan::Failure
    );
    assert_eq!(
        plan_win16_font_data(size, 0, 17, true),
        Win16FontDataPlan::Failure
    );
    assert_eq!(
        plan_win16_font_data(size, 12, 8, true),
        Win16FontDataPlan::Failure
    );
    assert_eq!(
        plan_win16_font_data(size, 0, 4, true),
        Win16FontDataPlan::Copy { len: 4 }
    );
    assert_eq!(
        plan_win16_font_data(size, 4, 4, true),
        Win16FontDataPlan::Copy { len: 4 }
    );
    assert_eq!(
        plan_win16_font_data(size, 0, 16, true),
        Win16FontDataPlan::Copy { len: 16 }
    );
    assert_eq!(
        plan_win16_font_data(size, 0, 0, true),
        Win16FontDataPlan::TableSize
    );
    assert_eq!(
        plan_win16_font_data(size, 3, 8, false),
        Win16FontDataPlan::TableSize
    );
}
