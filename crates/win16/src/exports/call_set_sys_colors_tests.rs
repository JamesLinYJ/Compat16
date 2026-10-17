//! Win16 USER.181 SetSysColors ABI and checked input-array decoding.

use crate::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, ReturnAddressWidth,
    SegmentedPointer, SelectorTable, Win16ApiRequest, Win16CallFrame, Win16ExportId,
    Win16ReturnKind, Win16UserSystemRequest, decode_export_call, lookup_export,
};
use guest_core::{GuestMemory, PhysAddr, memory::Memory};

#[test]
fn set_sys_colors_matches_win31_header_and_decodes_parallel_arrays() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(181)).unwrap();
    assert_eq!(descriptor.id, Win16ExportId::UserSetSysColors);
    assert_eq!(
        descriptor.calling_convention,
        ExportCallingConvention::Pascal
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    assert_eq!(descriptor.parameters.len(), 3);

    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 14, AccessRights::read_write(), &memory)
        .unwrap();
    let indices_selector = selectors
        .alloc_block(PhysAddr(0x2000), 4, AccessRights::read_write(), &memory)
        .unwrap();
    let colors_selector = selectors
        .alloc_block(PhysAddr(0x2100), 8, AccessRights::read_write(), &memory)
        .unwrap();

    let indices = [-1_i16, 7_i16];
    let mut index_bytes = Vec::new();
    for index in indices {
        index_bytes.extend_from_slice(&index.to_le_bytes());
    }
    memory.write(PhysAddr(0x2000), &index_bytes).unwrap();
    let colors = [0x00aa_bbcc_u32, 0x0001_0203_u32];
    let mut color_bytes = Vec::new();
    for color in colors {
        color_bytes.extend_from_slice(&color.to_le_bytes());
    }
    memory.write(PhysAddr(0x2100), &color_bytes).unwrap();

    let mut frame = [0_u8; 14];
    frame[4..8].copy_from_slice(
        &SegmentedPointer::new(colors_selector, 0)
            .far_value()
            .to_le_bytes(),
    );
    frame[8..12].copy_from_slice(
        &SegmentedPointer::new(indices_selector, 0)
            .far_value()
            .to_le_bytes(),
    );
    frame[12..14].copy_from_slice(&2_i16.to_le_bytes());
    memory.write(PhysAddr(0x1000), &frame).unwrap();

    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetSysColors {
            indices: vec![-1, 7],
            colors: vec![0x00aa_bbcc, 0x0001_0203],
        })
    );
}

#[test]
fn set_sys_colors_empty_arrays_ignore_null_pointers_and_negative_count_fails() {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(181)).unwrap();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let stack = selectors
        .alloc_block(PhysAddr(0x1000), 14, AccessRights::read_write(), &memory)
        .unwrap();
    let mut frame = [0_u8; 14];
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    let decoded = decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        &selectors,
        &memory,
    )
    .unwrap();
    assert_eq!(
        decoded.request,
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetSysColors {
            indices: Vec::new(),
            colors: Vec::new(),
        })
    );

    frame[12..14].copy_from_slice(&(-1_i16).to_le_bytes());
    memory.write(PhysAddr(0x1000), &frame).unwrap();
    assert!(
        decode_export_call(
            descriptor,
            Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
            &selectors,
            &memory,
        )
        .is_err()
    );
}

fn decode_arrays(
    count: i16,
    indices: u32,
    colors: u32,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
) -> Result<Win16ApiRequest, crate::Win16Error> {
    let stack = selectors.alloc_block(PhysAddr(0x1000), 14, AccessRights::read_write(), memory)?;
    decode_arrays_frame(count, indices, colors, stack, selectors, memory)
}
fn decode_arrays_frame(
    count: i16,
    indices: u32,
    colors: u32,
    stack: crate::SelectorRef,
    selectors: &SelectorTable,
    memory: &mut Memory,
) -> Result<Win16ApiRequest, crate::Win16Error> {
    let mut bytes = [0_u8; 14];
    bytes[4..8].copy_from_slice(&colors.to_le_bytes());
    bytes[8..12].copy_from_slice(&indices.to_le_bytes());
    bytes[12..14].copy_from_slice(&count.to_le_bytes());
    memory.write(PhysAddr(0x1000), &bytes)?;
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(181)).unwrap();
    Ok(decode_export_call(
        descriptor,
        Win16CallFrame::new(SegmentedPointer::new(stack, 0), ReturnAddressWidth::Far),
        selectors,
        memory,
    )?
    .request)
}
#[test]
fn set_sys_colors_accepts_the_full_signed_count_and_owned_selector_continuation() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let count = i16::MAX as usize;
    let index = selectors
        .alloc_block(
            PhysAddr(0x10000),
            (count * 2) as u32,
            AccessRights::read_only(),
            &memory,
        )
        .unwrap();
    let color = selectors
        .alloc_block(
            PhysAddr(0x30000),
            (count * 4) as u32,
            AccessRights::read_only(),
            &memory,
        )
        .unwrap();
    let indices: Vec<_> = (0..count).map(|n| ((n % 32) as i16) - 1).collect();
    let colors: Vec<_> = (0..count).map(|n| 0xab00_0000 | n as u32).collect();
    memory
        .write(
            PhysAddr(0x10000),
            &indices
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    memory
        .write(
            PhysAddr(0x30000),
            &colors
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let request = decode_arrays(
        i16::MAX,
        SegmentedPointer::new(index, 0).far_value(),
        SegmentedPointer::new(color, 0).far_value(),
        &mut selectors,
        &mut memory,
    )
    .unwrap();
    assert_eq!(
        request,
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetSysColors {
            indices: indices.into_iter().map(i32::from).collect(),
            colors,
        })
    );
}
#[test]
fn set_sys_colors_reads_an_array_split_at_a_huge_selector_boundary() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let index = selectors
        .alloc_block(PhysAddr(0x2000), 4, AccessRights::read_only(), &memory)
        .unwrap();
    let color = selectors
        .alloc_block(
            PhysAddr(0x10000),
            0x10004,
            AccessRights::read_only(),
            &memory,
        )
        .unwrap();
    memory.write(PhysAddr(0x2000), &[1, 0, 2, 0]).unwrap();
    memory
        .write(
            PhysAddr(0x1fffc),
            &[0x44, 0x33, 0x22, 0x11, 0xdd, 0xcc, 0xbb, 0xaa],
        )
        .unwrap();
    assert_eq!(
        decode_arrays(
            2,
            SegmentedPointer::new(index, 0).far_value(),
            SegmentedPointer::new(color, 0xfffc).far_value(),
            &mut selectors,
            &mut memory
        )
        .unwrap(),
        Win16ApiRequest::UserSystem(Win16UserSystemRequest::SetSysColors {
            indices: vec![1, 2],
            colors: vec![0x1122_3344, 0xaabb_ccdd],
        })
    );
}
#[test]
fn set_sys_colors_cannot_continue_into_an_adjacent_unrelated_allocation() {
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let index = selectors
        .alloc_block(PhysAddr(0x2000), 4, AccessRights::read_only(), &memory)
        .unwrap();
    let color = selectors
        .alloc_block(
            PhysAddr(0x10000),
            0x10000,
            AccessRights::read_only(),
            &memory,
        )
        .unwrap();
    let adjacent = selectors
        .alloc_block(PhysAddr(0x20000), 4, AccessRights::read_only(), &memory)
        .unwrap();
    assert_eq!(adjacent.raw().0, color.raw().0 + 8);
    assert!(
        decode_arrays(
            2,
            SegmentedPointer::new(index, 0).far_value(),
            SegmentedPointer::new(color, 0xfffc).far_value(),
            &mut selectors,
            &mut memory
        )
        .is_err()
    );
}
#[test]
fn set_sys_colors_rejects_freed_or_truncated_arrays() {
    for failure in 0..3 {
        let mut memory = Memory::with_size(0x10_0000).unwrap();
        let mut selectors = SelectorTable::new().unwrap();
        let stack = selectors
            .alloc_block(PhysAddr(0x1000), 14, AccessRights::read_write(), &memory)
            .unwrap();
        let index = selectors
            .alloc_block(
                PhysAddr(0x2000),
                if failure == 0 { 2 } else { 4 },
                AccessRights::read_only(),
                &memory,
            )
            .unwrap();
        let color = selectors
            .alloc_block(
                PhysAddr(0x2100),
                if failure == 1 { 7 } else { 8 },
                AccessRights::read_only(),
                &memory,
            )
            .unwrap();
        let far = SegmentedPointer::new(color, 0).far_value();
        if failure == 2 {
            selectors.free_selector(color).unwrap();
        }
        // The caller stack already exists: do not reuse the freed selector
        // for a new allocation before evaluating this raw FAR pointer.
        assert!(
            decode_arrays_frame(
                2,
                SegmentedPointer::new(index, 0).far_value(),
                far,
                stack,
                &selectors,
                &mut memory
            )
            .is_err()
        );
    }
}
