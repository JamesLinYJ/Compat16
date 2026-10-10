//! COMPOBJ.18 lookup, checked GUID inputs, and service-gate return coverage.

use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{Runtime, RuntimeError};
use guest_core::Selector;
use win16_abi::{Access, AccessRights, ExportLookupTarget, SegmentedPointer, Win16ReturnKind, Win16ExportStackCleanup, lookup_export};

const AX_SENTINEL: u16 = 0xa55a;
const DX_SENTINEL: u16 = 0x5aa5;

fn fixture(right: [u8; 16]) -> (Runtime, u32, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\GUID.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let left = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x10).unwrap();
    let right_pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x30).unwrap();
    state.selectors.write(&mut runtime.memory, left, &[0x35; 16]).unwrap();
    state.selectors.write(&mut runtime.memory, right_pointer, &right).unwrap();
    // Give each input an exact, read-only 16-byte selector. Successful reads
    // exercise permission checks and the last valid byte of each descriptor.
    let mut pointers = [0; 2];
    for (index, pointer) in [left, right_pointer].into_iter().enumerate() {
        let address = state.selectors.translate(pointer, Access::Read, 16, &runtime.memory).unwrap();
        let selector = state.selectors.alloc_block(address, 16, AccessRights::read_only(), &runtime.memory).unwrap();
        pointers[index] = SegmentedPointer::new(selector, 0).far_value();
    }
    (runtime, pointers[0], pointers[1])
}

fn prepare(runtime: &mut Runtime, left: u32, right: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"COMPOBJ", ExportLookupTarget::Ordinal(18)).unwrap();
    let named = lookup_export(b"COMPOBJ", ExportLookupTarget::Name(b"IsEqualGUID")).unwrap();
    assert_eq!(descriptor.id, named.id);
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("IsEqualGUID must use a fixed Pascal frame");
    };
    assert_eq!(cleanup.callee_pop_bytes, 8);
    assert_eq!(cleanup.caller_pop_bytes, 0);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(&right.to_le_bytes());
    frame.extend_from_slice(&left.to_le_bytes());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + 12)
}

fn dispatch(runtime: &mut Runtime) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    )
}

#[test]
fn is_equal_guid_service_gate_compares_every_byte_and_returns_bool16() {
    for changed in 0..=16 {
        let mut right = [0x35; 16];
        if changed < 16 { right[changed] ^= 0x80; }
        let (mut runtime, left, right_pointer) = fixture(right);
        let return_to = prepare(&mut runtime, left, right_pointer);
        assert_eq!(dispatch(&mut runtime).unwrap(), None);
        assert_eq!(runtime.cpu.regs.ax(), u16::from(changed == 16));
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        let state = runtime.win16.as_ref().unwrap();
        let mut bytes = [0; 16];
        state.selectors.read(&runtime.memory, state.selectors.pointer_from_far(left).unwrap(), &mut bytes).unwrap();
        assert_eq!(bytes, [0x35; 16]);
        state.selectors.read(&runtime.memory, state.selectors.pointer_from_far(right_pointer).unwrap(), &mut bytes).unwrap();
        assert_eq!(bytes, right);
    }
}

#[test]
fn is_equal_guid_service_gate_accepts_aliases_without_com_initialization() {
    let (mut runtime, left, _) = fixture([0x35; 16]);
    prepare(&mut runtime, left, left);
    dispatch(&mut runtime).unwrap();
    assert_eq!(runtime.cpu.regs.ax(), 1);
    assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
}

#[test]
fn is_equal_guid_service_gate_rejects_null_invalid_and_truncated_inputs() {
    for (left_bad, bad) in [(true, 0), (false, 0), (true, 0xfff8_0000), (false, 0xfff8_0000)] {
        let (mut runtime, left, right) = fixture([0x35; 16]);
        prepare(&mut runtime, if left_bad { bad } else { left }, if left_bad { right } else { bad });
        let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
        assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), crate::DiagnosticKind::GuestFault);
        assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL);
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    }
    for left_bad in [false, true] {
        let (mut runtime, left, right) = fixture([0x35; 16]);
        // An offset of one leaves only 15 readable bytes in the input selector.
        prepare(&mut runtime, left + u32::from(left_bad), right + u32::from(!left_bad));
        assert_eq!(dispatch(&mut runtime).unwrap_err().kind(), crate::DiagnosticKind::GuestFault);
        assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL);
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL);
    }
}
