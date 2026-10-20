//! KERNEL.6 zero-size reallocation through the real Pascal service gate.

use super::LocalOperation;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::Runtime;
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, lookup_export};

const LMEM_MOVEABLE: u16 = 0x0002;
const LMEM_DISCARDABLE: u16 = 0x0f00;
const SENTINEL: &[u8] = b"caller DS payload";

fn heap_segment(runtime: &mut Runtime, base: u32) -> u16 {
    let ds = runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(base), 4096, AccessRights::read_write(), &runtime.memory)
        .unwrap().raw().0;
    assert_eq!(runtime.win16.as_ref().unwrap()
        .local_init(ds, ds, 0x10, 4095, &mut runtime.memory).unwrap(), 1);
    ds
}

fn operation(runtime: &mut Runtime, ds: u16, operation: LocalOperation) -> u32 {
    runtime.win16.as_mut().unwrap()
        .local_operation(ds, operation, &mut runtime.memory).unwrap()
}

fn snapshot(runtime: &Runtime, ds: u16) -> Vec<u8> {
    runtime.win16.as_ref().unwrap().local_segment(ds, false, &runtime.memory).unwrap().1
}

fn live_block(runtime: &mut Runtime, ds: u16, attributes: u16) -> (u16, u16) {
    let handle = operation(runtime, ds,
        LocalOperation::Alloc { flags: LMEM_MOVEABLE | attributes, size: 32 }) as u16;
    assert_ne!(handle, 0);
    let address = operation(runtime, ds, LocalOperation::Lock { handle }) as u16;
    assert_ne!(address, 0);
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(ds), address).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, SENTINEL).unwrap();
    assert_eq!(operation(runtime, ds, LocalOperation::Unlock { handle }), 0);
    (handle, address)
}

fn gate(runtime: &mut Runtime, handle: u16, flags: u16) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(6)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let caller_ds = runtime.cpu.regs.ds;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    // Pascal parameters are nearest-to-farthest in reverse declaration order.
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&handle.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    assert_eq!(state.dispatch(&mut runtime.cpu, &mut runtime.memory,
        &mut runtime.dos, &mut NoHost, 0).unwrap(), None);
    // Four return-address bytes plus all six parameter bytes are consumed.
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()),
        (return_cs, return_ip, stack + 10));
    assert_eq!(runtime.cpu.regs.ds, caller_ds);
    runtime.cpu.regs.ax()
}

#[test]
fn local_realloc_zero_service_gate_preserves_unlocked_caller_ds_allocation() {
    for attributes in [0, LMEM_DISCARDABLE] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\REALLOC.NE").unwrap();
        let ds = heap_segment(&mut runtime, 0x80000);
        let other_ds = heap_segment(&mut runtime, 0x82000);
        let (handle, address) = live_block(&mut runtime, ds, attributes);
        let (other_handle, _) = live_block(&mut runtime, other_ds, 0);
        assert_eq!(other_handle, handle);
        let size = operation(&mut runtime, ds, LocalOperation::Size { handle });
        assert!(size >= 32);
        let before = snapshot(&runtime, ds);
        let other_before = snapshot(&runtime, other_ds);
        runtime.cpu.regs.ds = ds;
        assert_eq!(gate(&mut runtime, handle, 0), 0);
        assert_eq!(snapshot(&runtime, ds), before);
        assert_eq!(snapshot(&runtime, other_ds), other_before);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Size { handle }), size);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Flags { handle }),
            u32::from(attributes));
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Handle { offset: address }),
            u32::from(handle));
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Lock { handle }) as u16, address);
        let bytes = snapshot(&runtime, ds);
        let start = usize::from(address);
        assert_eq!(&bytes[start..start + SENTINEL.len()], SENTINEL);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Unlock { handle }), 0);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Free { handle }), 0);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Flags { handle }), 0x8000);
        assert_eq!(snapshot(&runtime, other_ds), other_before);
    }
}

#[test]
fn local_realloc_zero_service_gate_rejects_locked_blocks_and_allows_explicit_discard() {
    for attributes in [0, LMEM_DISCARDABLE] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\REALLOC.NE").unwrap();
        let ds = heap_segment(&mut runtime, 0x80000);
        let (handle, address) = live_block(&mut runtime, ds, attributes);
        runtime.cpu.regs.ds = ds;
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Lock { handle }) as u16, address);
        let before = snapshot(&runtime, ds);
        for flags in [0, LMEM_MOVEABLE] {
            assert_eq!(gate(&mut runtime, handle, flags), 0);
            assert_eq!(snapshot(&runtime, ds), before);
        }
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Unlock { handle }), 0);
        if attributes == 0 {
            let resident = snapshot(&runtime, ds);
            assert_eq!(gate(&mut runtime, handle, LMEM_MOVEABLE), 0);
            assert_eq!(snapshot(&runtime, ds), resident);
            assert!(operation(&mut runtime, ds, LocalOperation::Size { handle }) >= 32);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Flags { handle }), 0);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Lock { handle }) as u16, address);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Unlock { handle }), 0);
        } else {
            assert_eq!(gate(&mut runtime, handle, LMEM_MOVEABLE), handle);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Size { handle }), 0);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Flags { handle }), 0x4000);
            assert_eq!(operation(&mut runtime, ds, LocalOperation::Lock { handle }), 0);
        }
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Free { handle }), 0);
        assert_eq!(operation(&mut runtime, ds, LocalOperation::Flags { handle }), 0x8000);
    }
}
