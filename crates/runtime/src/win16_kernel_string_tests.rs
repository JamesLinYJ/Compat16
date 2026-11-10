//! KERNEL.352 `lstrcatn` results for a filled destination buffer.

use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::Runtime;
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16Argument, Win16ExportStackCleanup,
    Win16ReturnKind, lookup_export,
};

const DEST_BASE: u32 = 0x80000;
const SOURCE_BASE: u32 = 0x81000;

fn runtime() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\STRCATN.NE").unwrap()
}

fn place(runtime: &mut Runtime, base: u32, bytes: &[u8], rights: AccessRights) -> u32 {
    runtime.memory.write_physical(PhysAddr(base), bytes).unwrap();
    let selector = runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(base), bytes.len() as u32, rights, &runtime.memory).unwrap();
    SegmentedPointer::new(selector, 0).far_value()
}

fn read_physical(runtime: &Runtime, base: u32, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    runtime.memory.read_physical(PhysAddr(base), &mut bytes).unwrap();
    bytes
}

fn call(runtime: &mut Runtime, destination: u32, source: u32, limit: u16) -> u32 {
    use Win16Argument::{Dword, Word};
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(352)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::FarPointer);
    assert_eq!(descriptor.name().as_bytes(), b"lstrcatn");
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("lstrcatn must have a fixed Pascal frame");
    };
    assert_eq!((cleanup.callee_pop_bytes, cleanup.caller_pop_bytes), (10, 0));
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let arguments = [Dword(destination), Dword(source), Word(limit)];
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    for argument in arguments.iter().rev() {
        match argument {
            Word(value) => frame.extend_from_slice(&value.to_le_bytes()),
            Dword(value) => frame.extend_from_slice(&value.to_le_bytes()),
            _ => panic!("unexpected lstrcatn argument width"),
        }
    }
    assert_eq!(frame.len(), 4 + usize::from(cleanup.callee_pop_bytes));
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(state.dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    ).unwrap(), None);
    assert_eq!(
        (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + frame.len() as u16),
    );
    u32::from(runtime.cpu.regs.dx()) << 16 | u32::from(runtime.cpu.regs.ax())
}

#[test]
fn lstrcatn_returns_a_filled_destination_without_writing() {
    for (bytes, rights) in [
        (b"AB".as_slice(), AccessRights::read_write()),
        (b"ABCD", AccessRights::read_write()),
        (b"ABCD", AccessRights::read_only()),
        (&[0x81, 0x40, b'Z'], AccessRights::read_only()),
    ] {
        let mut runtime = runtime();
        let destination = place(&mut runtime, DEST_BASE, bytes, rights);
        let source = place(&mut runtime, SOURCE_BASE, b"more\0", AccessRights::read_only());
        assert_eq!(call(&mut runtime, destination, source, bytes.len() as u16), destination);
        assert_eq!(read_physical(&runtime, DEST_BASE, bytes.len()), bytes);
        assert_eq!(read_physical(&runtime, SOURCE_BASE, 5), b"more\0");
    }
}

#[test]
fn lstrcatn_appends_within_the_declared_byte_limit() {
    let mut runtime = runtime();
    let destination = place(&mut runtime, DEST_BASE, b"\0???", AccessRights::read_write());
    let source = place(&mut runtime, SOURCE_BASE, b"\x81\x40Z\0", AccessRights::read_only());
    assert_eq!(call(&mut runtime, destination, source, 3), destination);
    // Two guest bytes fit before the terminator. The next source byte does not.
    assert_eq!(read_physical(&runtime, DEST_BASE, 4), b"\x81\x40\0?");
    assert_eq!(read_physical(&runtime, SOURCE_BASE, 4), b"\x81\x40Z\0");
}

#[test]
fn lstrcatn_empty_source_keeps_the_existing_terminator() {
    let mut runtime = runtime();
    let destination = place(&mut runtime, DEST_BASE, b"AB\0xx", AccessRights::read_write());
    let source = place(&mut runtime, SOURCE_BASE, b"\0", AccessRights::read_only());
    assert_eq!(call(&mut runtime, destination, source, 5), destination);
    assert_eq!(read_physical(&runtime, DEST_BASE, 5), b"AB\0xx");
}

#[test]
fn lstrcatn_nonpositive_limit_does_not_read_the_destination() {
    let mut runtime = runtime();
    let source = place(&mut runtime, SOURCE_BASE, b"Z\0", AccessRights::read_only());
    for limit in [0_u16, 0x8000, 0xffff] {
        assert_eq!(call(&mut runtime, 0xffff_0000, source, limit), 0xffff_0000);
    }
    assert_eq!(read_physical(&runtime, SOURCE_BASE, 2), b"Z\0");
}

#[test]
fn lstrcatn_missing_destination_and_readonly_append_return_null() {
    let mut runtime = runtime();
    let source = place(&mut runtime, SOURCE_BASE, b"Z\0", AccessRights::read_only());
    assert_eq!(call(&mut runtime, 0, source, 4), 0);
    let destination = place(&mut runtime, DEST_BASE, b"A\0B", AccessRights::read_only());
    assert_eq!(call(&mut runtime, destination, source, 3), 0);
    assert_eq!(read_physical(&runtime, DEST_BASE, 3), b"A\0B");
    assert_eq!(read_physical(&runtime, SOURCE_BASE, 2), b"Z\0");
}
