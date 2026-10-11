//! KERNEL.310 through checked DS selectors and the real service gate.

use super::LocalOperation;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SelectorRef, lookup_export};

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\DELTA.NE").unwrap()
}

fn segment(runtime: &mut Runtime, base: u32, size: u32, rights: AccessRights) -> SelectorRef {
    runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(base), size, rights, &runtime.memory).unwrap()
}

fn heap_segment(runtime: &mut Runtime, base: u32, size: u16) -> u16 {
    let ds = segment(runtime, base, u32::from(size), AccessRights::read_write()).raw().0;
    assert_eq!(runtime.win16.as_ref().unwrap()
        .local_init(ds, ds, 0x10, size - 1, &mut runtime.memory).unwrap(), 1);
    ds
}

fn snapshot(runtime: &Runtime, ds: u16) -> (PhysAddr, Vec<u8>) {
    let state = runtime.win16.as_ref().unwrap();
    let reference = state.selectors.reference(Selector(ds)).unwrap();
    let descriptor = state.selectors.describe(reference).unwrap();
    let mut bytes = vec![0; descriptor.limit as usize + 1];
    runtime.memory.read_physical(descriptor.base, &mut bytes).unwrap();
    (descriptor.base, bytes)
}

fn delta(runtime: &mut Runtime, ds: u16, delta: u16) -> Result<u32, RuntimeError> {
    runtime.win16.as_mut().unwrap().local_operation(ds,
        LocalOperation::HandleDelta { delta }, &mut runtime.memory)
}

fn gate(runtime: &mut Runtime, delta: u16) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(310)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&delta.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, &mut NoHost, 0).unwrap(), None);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + 6));
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
    runtime.cpu.regs.ax()
}

#[test]
fn local_handle_delta_service_gate_returns_new_word_and_cleans_pascal_frame() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    runtime.cpu.regs.ds = ds;
    assert_eq!(gate(&mut runtime, 0), 32);
    for value in [1, 2, 0x8000, 0xffff] {
        assert_eq!(gate(&mut runtime, value), value);
        assert_eq!(gate(&mut runtime, 0), value);
    }
}

#[test]
fn local_handle_delta_uses_calling_dgroup_and_shared_alias_backing() {
    let mut runtime = fixture();
    let first = heap_segment(&mut runtime, 0x80000, 4096);
    let second = heap_segment(&mut runtime, 0x82000, 4096);
    let alias = segment(&mut runtime, 0x80000, 4096, AccessRights::read_write()).raw().0;
    runtime.cpu.regs.ds = first;
    assert_eq!(gate(&mut runtime, 1), 1);
    runtime.cpu.regs.ds = second;
    assert_eq!(gate(&mut runtime, 0), 32);
    assert_eq!(gate(&mut runtime, 2), 2);
    runtime.cpu.regs.ds = alias;
    assert_eq!(gate(&mut runtime, 0), 1);
    assert_eq!(gate(&mut runtime, 7), 7);
    assert_eq!(delta(&mut runtime, first, 0).unwrap(), 7);
    assert_eq!(delta(&mut runtime, second, 0).unwrap(), 2);
}

#[test]
fn local_handle_delta_readonly_query_is_byte_pure_and_set_is_rejected() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let alias = segment(&mut runtime, 0x80000, 4096, AccessRights::read_only()).raw().0;
    let before = snapshot(&runtime, ds);
    assert_eq!(delta(&mut runtime, alias, 0).unwrap(), 32);
    assert_eq!(snapshot(&runtime, ds), before);
    for value in [1, 32, 0xffff] {
        assert_eq!(delta(&mut runtime, alias, value).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(snapshot(&runtime, ds), before);
    }
}

#[test]
fn local_handle_delta_set_publishes_only_the_heap_delta_word() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let (_, before) = snapshot(&runtime, ds);
    let info = usize::from(u16::from_le_bytes([before[6], before[7]]));
    assert_eq!(delta(&mut runtime, ds, 0xabcd).unwrap(), 0xabcd);
    let (_, after) = snapshot(&runtime, ds);
    // This is this implementation's private layout, not the historical offset.
    let offset = info + 0x18;
    assert_eq!(&after[offset..offset + 2], &[0xcd, 0xab]);
    assert_eq!(&before[..offset], &after[..offset]);
    assert_eq!(&before[offset + 2..], &after[offset + 2..]);
}

#[test]
fn local_handle_delta_invalid_and_malformed_heaps_do_not_change_memory() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 4096);
    let (address, mut bytes) = snapshot(&runtime, ds);
    let info = usize::from(u16::from_le_bytes([bytes[6], bytes[7]]));
    bytes[info + 0x28] ^= 1;
    runtime.memory.write_physical(address, &bytes).unwrap();
    for value in [0, 1, 0xffff] {
        assert_eq!(delta(&mut runtime, ds, value).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(snapshot(&runtime, ds).1, bytes);
        assert_eq!(delta(&mut runtime, 0, value).unwrap_err().kind(), Kind::GuestFault);
        assert_eq!(snapshot(&runtime, ds).1, bytes);
    }
    let empty = segment(&mut runtime, 0x82000, 4096, AccessRights::read_write()).raw().0;
    let before = snapshot(&runtime, empty);
    assert_eq!(delta(&mut runtime, empty, 0).unwrap(), 0);
    assert_eq!(delta(&mut runtime, empty, 2).unwrap(), 0);
    assert_eq!(snapshot(&runtime, empty), before);
}

#[test]
fn local_handle_delta_small_custom_heap_supports_payload_and_later_table_expansion() {
    let mut runtime = fixture();
    let ds = heap_segment(&mut runtime, 0x80000, 256);
    let allocate = |runtime: &mut Runtime, size| runtime.win16.as_mut().unwrap()
        .local_operation(ds, LocalOperation::Alloc { flags: 0x12, size }, &mut runtime.memory).unwrap();
    assert_eq!(allocate(&mut runtime, 96), 0);
    assert_eq!(delta(&mut runtime, ds, 1).unwrap(), 1);
    let first = allocate(&mut runtime, 96);
    assert_ne!(first, 0);
    assert_eq!(delta(&mut runtime, ds, 2).unwrap(), 2);
    let second = allocate(&mut runtime, 0);
    let third = allocate(&mut runtime, 0);
    assert_ne!(second, 0);
    assert_ne!(third, 0);
    assert_ne!(second, third);
    let size = runtime.win16.as_mut().unwrap().local_operation(ds,
        LocalOperation::Size { handle: first as u16 }, &mut runtime.memory).unwrap();
    assert!(size >= 96);
    // Custom backing remains bounded; changing policy does not resize DGROUP.
    assert_eq!(snapshot(&runtime, ds).1.len(), 256);
}
