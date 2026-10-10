//! KERNEL.90 byte counts and checked-memory failures through the service gate.

use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, lookup_export};

const BASE: u32 = 0x80000;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;

fn fixture(bytes: &[u8], rights: AccessRights) -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\LENGTH.NE").unwrap();
    runtime.memory.write_physical(PhysAddr(BASE), bytes).unwrap();
    let selector = runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(BASE), bytes.len() as u32, rights, &runtime.memory).unwrap();
    (runtime, SegmentedPointer::new(selector, 0).far_value())
}

fn prepare(runtime: &mut Runtime, pointer: u32) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(90)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    // Entry frame: far return address followed by the four-byte FAR string.
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(&pointer.to_le_bytes());
    let stack_pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, stack_pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    (return_cs, return_ip, stack + 8)
}

fn dispatch(runtime: &mut Runtime) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    )
}

fn assert_return(runtime: &mut Runtime, pointer: u32, byte_count: u16) {
    let return_to = prepare(runtime, pointer);
    assert_eq!(dispatch(runtime).unwrap(), None);
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | u32::from(byte_count));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
}

fn assert_fault(runtime: &mut Runtime, pointer: u32) {
    prepare(runtime, pointer);
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    assert_eq!(dispatch(runtime).unwrap_err().kind(), Kind::GuestFault);
    assert_eq!((runtime.cpu.regs.eax, runtime.cpu.regs.edx), (EAX_SENTINEL, EDX_SENTINEL));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
}

#[test]
fn lstrlen_service_gate_returns_byte_count_in_ax_with_pascal_cleanup() {
    for source in [Vec::new(), b"ASCII".to_vec(), b"\x81\x40A\x82\xa0".to_vec(), vec![b'x'; 65535]] {
        let mut terminated = source.clone();
        terminated.push(0);
        let (mut runtime, pointer) = fixture(&terminated, AccessRights::read_only());
        assert_return(&mut runtime, pointer, source.len() as u16);
        let mut unchanged = vec![0; terminated.len()];
        runtime.memory.read_physical(PhysAddr(BASE), &mut unchanged).unwrap();
        assert_eq!(unchanged, terminated);
    }
}

#[test]
fn lstrlen_service_gate_null_input_returns_zero_without_host() {
    let (mut runtime, _) = fixture(b"A\0", AccessRights::read_only());
    assert_return(&mut runtime, 0, 0);
}

#[test]
fn lstrlen_service_gate_rejects_invalid_freed_unreadable_and_unterminated_inputs() {
    for case in 0..4 {
        let rights = if case == 2 { AccessRights::new(false, false, true) }
            else { AccessRights::read_only() };
        let bytes = if case == 3 { b"AB".as_slice() } else { b"A\0" };
        let (mut runtime, mut pointer) = fixture(bytes, rights);
        if case == 0 { pointer = 0xfff8_0000; }
        if case == 1 {
            let state = runtime.win16.as_mut().unwrap();
            let selector = state.selectors.pointer_from_far(pointer).unwrap().selector();
            state.selectors.free_block(selector).unwrap();
        }
        assert_fault(&mut runtime, pointer);
    }
    let mut bytes = vec![b'x'; 65536];
    bytes.push(0);
    let (mut runtime, pointer) = fixture(&bytes, AccessRights::read_only());
    assert_fault(&mut runtime, pointer);
}

#[test]
fn lstrlen_service_gate_accepts_owned_cross_selector_string() {
    let mut bytes = vec![0; 0x10002];
    bytes[0xffff..].copy_from_slice(b"\x81\x40\0");
    let (mut runtime, pointer) = fixture(&bytes, AccessRights::read_only());
    assert_return(&mut runtime, pointer | 0xffff, 2);
}

#[test]
fn lstrlen_service_gate_rejects_adjacent_unrelated_allocation() {
    let mut bytes = vec![0; 0x10000];
    bytes[0xffff] = b'A';
    let (mut runtime, pointer) = fixture(&bytes, AccessRights::read_only());
    runtime.memory.write_physical(PhysAddr(BASE + 0x10000), &[0]).unwrap();
    runtime.win16.as_mut().unwrap().selectors.alloc_block(
        PhysAddr(BASE + 0x10000), 1, AccessRights::read_only(), &runtime.memory,
    ).unwrap();
    assert_fault(&mut runtime, pointer | 0xffff);
}
