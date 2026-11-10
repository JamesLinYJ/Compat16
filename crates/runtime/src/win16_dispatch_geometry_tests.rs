//! Service-gate regression coverage for guest-only USER rectangle helpers.

use super::super::ImportBinding;
use super::super::test_support::{NoHost, tiny_ne_executable};
use crate::{Runtime, RuntimeError};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

const FIRST: u16 = 0x10;
const SECOND: u16 = 0x20;
const OUTPUT: u16 = 0x30;
const AX_SENTINEL: u16 = 0xa55a;
const DX_SENTINEL: u16 = 0x5aa5;

fn write_rect(runtime: &mut Runtime, offset: u16, edges: [i16; 4]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), offset).unwrap();
    let bytes: Vec<u8> = edges.into_iter().flat_map(i16::to_le_bytes).collect();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
}

fn read_rect(runtime: &Runtime, offset: u16) -> [i16; 4] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), offset).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    std::array::from_fn(|i| i16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
}

fn prepare_call(runtime: &mut Runtime, ordinal: u16, offsets: &[u16]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    // Pascal arguments appear right-to-left when read upwards from the FAR
    // return address. Every argument here is a four-byte guest FAR pointer.
    for &offset in offsets.iter().rev() {
        let far = if offset == u16::MAX { 0 } else {
            (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
        };
        bytes.extend_from_slice(&far.to_le_bytes());
    }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    )
}

#[test]
fn rectangle_exports_reach_existing_handlers_through_service_gate() {
    let first = [1, 2, 8, 9];
    let second = [0, 2, 4, 9];
    // Void APIs must preserve AX; BOOL APIs must publish their real result.
    for (ordinal, offsets, expected, ax) in [
        (73, vec![OUTPUT], [0; 4], AX_SENTINEL),
        (74, vec![OUTPUT, FIRST], first, AX_SENTINEL),
        (80, vec![OUTPUT, FIRST, SECOND], [0, 2, 8, 9], 1),
        (244, vec![FIRST, FIRST], [99; 4], 1),
        (244, vec![FIRST, SECOND], [99; 4], 0),
        (373, vec![OUTPUT, FIRST, SECOND], [4, 2, 8, 9], 1),
        (373, vec![OUTPUT, FIRST, FIRST], [0; 4], 0),
        // Both source values must be read before overwriting an aliased output.
        (74, vec![FIRST, FIRST], [99; 4], AX_SENTINEL),
        (80, vec![FIRST, FIRST, SECOND], [99; 4], 1),
        (373, vec![FIRST, FIRST, SECOND], [99; 4], 1),
    ] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
        write_rect(&mut runtime, FIRST, first);
        write_rect(&mut runtime, SECOND, second);
        write_rect(&mut runtime, OUTPUT, [99; 4]);
        let return_to = prepare_call(&mut runtime, ordinal, &offsets);
        assert_eq!(dispatch(&mut runtime).unwrap(), None, "USER.{ordinal}");
        assert_eq!(read_rect(&runtime, OUTPUT), expected, "USER.{ordinal}");
        if offsets[0] == FIRST && ordinal != 244 {
            let expected_first = match ordinal {
                80 => [0, 2, 8, 9],
                373 => [4, 2, 8, 9],
                _ => first,
            };
            assert_eq!(read_rect(&runtime, FIRST), expected_first, "USER.{ordinal}");
        }
        assert_eq!(runtime.cpu.regs.ax(), ax, "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    }
}

#[test]
fn rectangle_exports_reject_invalid_far_pointers_before_writing() {
    for (ordinal, offsets) in [
        (73, vec![u16::MAX]),
        (74, vec![OUTPUT, u16::MAX]),
        (80, vec![OUTPUT, FIRST, u16::MAX]),
        (244, vec![FIRST, u16::MAX]),
        (373, vec![OUTPUT, FIRST, u16::MAX]),
    ] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
        write_rect(&mut runtime, FIRST, [1, 2, 8, 9]);
        write_rect(&mut runtime, OUTPUT, [99; 4]);
        prepare_call(&mut runtime, ordinal, &offsets);
        let error = dispatch(&mut runtime).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault, "USER.{ordinal}");
        assert_eq!(read_rect(&runtime, OUTPUT), [99; 4], "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL, "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
    }
}

fn far_arg(runtime: &Runtime, offset: u16) -> [u8; 4] {
    let far = if offset == u16::MAX {
        0
    } else {
        (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
    };
    far.to_le_bytes()
}

fn prepare_mixed(runtime: &mut Runtime, ordinal: u16, args: &[&[u8]]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    // Pascal arguments are pushed left to right, so the rightmost argument
    // sits immediately above the FAR return address.
    for arg in args.iter().rev() {
        bytes.extend_from_slice(arg);
    }
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn call_rect_adjust(ordinal: u16, edges: [i16; 4], x: i16, y: i16) -> [i16; 4] {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
    write_rect(&mut runtime, OUTPUT, edges);
    let rect = far_arg(&runtime, OUTPUT);
    let x_bytes = x.to_le_bytes();
    let y_bytes = y.to_le_bytes();
    let return_to = prepare_mixed(&mut runtime, ordinal, &[&rect, &x_bytes, &y_bytes]);
    assert_eq!(dispatch(&mut runtime).unwrap(), None, "USER.{ordinal}");
    assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL, "USER.{ordinal}");
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        return_to,
        "USER.{ordinal}"
    );
    read_rect(&runtime, OUTPUT)
}

#[test]
fn offset_rect_moves_signed_edges_and_leaves_an_overflow_unchanged() {
    assert_eq!(call_rect_adjust(77, [10, 20, 30, 40], 5, -3), [15, 17, 35, 37]);
    // A span wider than a signed int still moves when every edge fits.
    assert_eq!(
        call_rect_adjust(77, [-20_000, 0, 20_000, 10], 1, 0),
        [-19_999, 0, 20_001, 10]
    );
    for (edges, x, y) in [
        ([32_767, 0, 32_767, 1], 1, 0),
        ([-32_768, 0, -32_760, 1], -1, 0),
        ([0, 32_767, 1, 32_767], 0, 1),
        ([0, -32_768, 1, -32_760], 0, -1),
        ([0, 0, 10, 32_767], 1, 1),
    ] {
        assert_eq!(call_rect_adjust(77, edges, x, y), edges, "OffsetRect {edges:?} by {x},{y}");
    }
}

#[test]
fn inflate_rect_grows_outward_and_rejects_an_edge_or_span_that_does_not_fit() {
    assert_eq!(call_rect_adjust(78, [10, 20, 30, 40], 2, 3), [8, 17, 32, 43]);
    assert_eq!(call_rect_adjust(78, [10, 20, 30, 40], -2, -1), [12, 21, 28, 39]);
    // Width 1 + 2*16383 = 32767 still fits. One more unit does not.
    assert_eq!(call_rect_adjust(78, [0, 0, 1, 1], 16_383, 0), [-16_383, 0, 16_384, 1]);
    assert_eq!(call_rect_adjust(78, [0, 0, 1, 1], 16_384, 0), [0, 0, 1, 1]);
    // Height 0 + 2*(-16384) = -32768 still fits. One more unit does not,
    // even though both edges would fit in a signed int.
    assert_eq!(call_rect_adjust(78, [0, 0, 10, 0], 0, -16_384), [0, 16_384, 10, -16_384]);
    assert_eq!(call_rect_adjust(78, [0, 0, 10, 0], 0, -16_385), [0, 0, 10, 0]);
    for (edges, x, y) in [
        ([0, 0, 30_000, 10], 2_000, 0),
        ([0, 0, 10, 10], -20_000, 0),
        ([32_767, 0, 32_767, 10], 1, 0),
        ([-32_768, 0, 0, 10], 1, 0),
        ([-20_000, 0, 20_000, 10], 1, 0),
    ] {
        assert_eq!(call_rect_adjust(78, edges, x, y), edges, "InflateRect {edges:?} by {x},{y}");
    }
}

#[test]
fn offset_and_inflate_rect_fault_on_a_null_rectangle_before_writing() {
    for ordinal in [77, 78] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
        write_rect(&mut runtime, OUTPUT, [9, 8, 7, 6]);
        let rect = far_arg(&runtime, u16::MAX);
        let x = 1_i16.to_le_bytes();
        let y = 1_i16.to_le_bytes();
        prepare_mixed(&mut runtime, ordinal, &[&rect, &x, &y]);
        let error = dispatch(&mut runtime).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault, "USER.{ordinal}");
        assert_eq!(read_rect(&runtime, OUTPUT), [9, 8, 7, 6], "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL, "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
    }
}
