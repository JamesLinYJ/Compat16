//! GlobalFix/GlobalUnfix void service returns preserve independent heap effects.
use super::*;
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::Runtime;
use win16_abi::{ExportLookupTarget, lookup_export};

fn fixture() -> Runtime {
    Runtime::load(&tiny_ne_executable(), &[], br"C:\GLOBALFIX.NE").unwrap()
}

fn call(runtime: &mut Runtime, ordinal: u16, handle: u16, expected_cx: u16) {
    // Reuse the fixture's bounded stack frame for every service call.
    runtime.cpu.regs.set_sp(0x80);
    let return_to = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), 0x86_u16);
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes.extend_from_slice(&[0x12, 0x34]);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), 0x80).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap()));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a); runtime.cpu.regs.set_dx(0x5aa5); runtime.cpu.regs.set_cx(0x9876);
    state.dispatch(&mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0).unwrap();
    // Project Void policy; CX is a separate, existing compatibility result.
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
    assert_eq!(runtime.cpu.regs.cx(), expected_cx);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    let mut after = vec![0; bytes.len()]; state.selectors.read(&runtime.memory, pointer, &mut after).unwrap();
    assert_eq!(after, bytes);
}

fn allocate(runtime: &mut Runtime, flags: u16) -> u16 {
    let handle = runtime.win16.as_mut().unwrap().global_alloc(flags, 32, &mut runtime.memory, &mut NoHost).unwrap();
    assert_ne!(handle, 0);
    handle
}
fn locks(runtime: &Runtime, handle: u16) -> u16 {
    let state = runtime.win16.as_ref().unwrap();
    state.heap.info(state.global_handles[&handle]).unwrap().lock_count
}

#[test]
fn global_fix_unfix_void_preserve_counts_cx_and_independent_global_lock() {
    for flags in [0, GMEM_MOVEABLE, GMEM_MOVEABLE | GMEM_DISCARDABLE] {
        let mut runtime = fixture();
        let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
        let handle = allocate(&mut runtime, flags);
        let discardable = flags & GMEM_DISCARDABLE != 0;
        let global_count = u16::from(discardable);
        assert_ne!(runtime.win16.as_mut().unwrap().global_lock(handle, &runtime.memory).unwrap(), 0);
        assert_eq!(locks(&runtime, handle), global_count);
        call(&mut runtime, 197, handle, 0x9876);
        call(&mut runtime, 197, handle, 0x9876);
        assert_eq!(locks(&runtime, handle), global_count + 2);
        assert_eq!(runtime.win16.as_mut().unwrap().global_free(handle).unwrap(), handle);
        call(&mut runtime, 198, handle, global_count + 1);
        assert_eq!(locks(&runtime, handle), global_count + 1);
        call(&mut runtime, 198, handle, global_count);
        assert_eq!(locks(&runtime, handle), global_count);
        // Underflow never consumes a remaining GlobalLock reference.
        call(&mut runtime, 198, handle, 0);
        assert_eq!(locks(&runtime, handle), global_count);
        if discardable { assert_eq!(runtime.win16.as_mut().unwrap().global_free(handle).unwrap(), handle); }
        assert_eq!(runtime.win16.as_mut().unwrap().global_unlock(handle).unwrap(), 0);
        assert_eq!(runtime.win16.as_mut().unwrap().global_free(handle).unwrap(), 0);
        assert_eq!(runtime.win16.as_ref().unwrap().heap.allocation_count(), allocations);
    }
}

#[test]
fn global_fix_unfix_void_invalid_handles_and_overflow_do_not_invent_results() {
    let mut runtime = fixture();
    let allocations = runtime.win16.as_ref().unwrap().heap.allocation_count();
    for handle in [0, 0xffff] {
        call(&mut runtime, 197, handle, 0x9876);
        call(&mut runtime, 198, handle, 0);
    }
    assert_eq!(runtime.win16.as_ref().unwrap().heap.allocation_count(), allocations);
    let handle = allocate(&mut runtime, GMEM_MOVEABLE | GMEM_DISCARDABLE);
    let state = runtime.win16.as_mut().unwrap();
    let identity = state.global_handles[&handle];
    state.global_lock(handle, &runtime.memory).unwrap();
    for _ in 1..u16::MAX { state.heap.fix(identity).unwrap(); }
    assert_eq!(locks(&runtime, handle), u16::MAX);
    call(&mut runtime, 197, handle, 0x9876);
    assert_eq!(locks(&runtime, handle), u16::MAX);
    call(&mut runtime, 198, handle, u16::MAX - 1);
    assert_eq!(locks(&runtime, handle), u16::MAX - 1);
    let state = runtime.win16.as_mut().unwrap();
    for _ in 0..u16::MAX - 2 { state.heap.unfix(identity).unwrap(); }
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 1);
    state.global_unlock(handle).unwrap();
    assert_eq!(state.global_free(handle).unwrap(), 0);
}

#[test]
fn global_fix_unfix_void_dos_blocks_retain_pins_and_handle_count_saturation() {
    for protected_overlap in [true, false] {
        let mut runtime = fixture();
        if !protected_overlap {
            // Free conventional RAM above the canonical PSP through DOS's real
            // resize operation. A 64KiB request cannot fit in the low free gap,
            // so first-fit places it outside the bootstrap __0000H selector.
            let mut regs = guest_core::Registers { es: runtime.dos.psp_segment(), ..Default::default() };
            regs.set_ax(0x4a00);
            regs.set_bx(0x100);
            assert_eq!(runtime.dos.interrupt(0x21, &mut regs, &mut runtime.memory.bus(), &mut NoHost).unwrap(),
                dos_kernel::DosAction::Continue);
            assert!(!regs.carry());
        }
        let handle = runtime.win16.as_mut().unwrap()
            .kernel_global_dos_alloc(if protected_overlap { 32 } else { 0x10000 },
                &mut runtime.dos, &mut runtime.memory).unwrap() as u16;
        assert_ne!(handle, 0);
        call(&mut runtime, 197, handle, 0x9876);
        call(&mut runtime, 197, handle, 0x9876);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.dos_global_blocks[&handle].fix_count, 2);
        assert_eq!(state.kernel_global_dos_free(handle, &mut runtime.dos, &mut runtime.memory).unwrap(), handle);
        call(&mut runtime, 198, handle, 1);
        assert_eq!(runtime.win16.as_ref().unwrap().dos_global_blocks[&handle].fix_count, 1);
        runtime.win16.as_mut().unwrap().dos_global_blocks.get_mut(&handle).unwrap().fix_count = u16::MAX;
        call(&mut runtime, 197, handle, 0x9876);
        assert_eq!(runtime.win16.as_ref().unwrap().dos_global_blocks[&handle].fix_count, u16::MAX);
        call(&mut runtime, 198, handle, u16::MAX - 1);
        runtime.win16.as_mut().unwrap().dos_global_blocks.get_mut(&handle).unwrap().fix_count = 1;
        call(&mut runtime, 198, handle, 0);
        call(&mut runtime, 198, handle, 0);
        let state = runtime.win16.as_mut().unwrap();
        assert_eq!(state.dos_global_blocks[&handle].fix_count, 0);
        let block = &state.dos_global_blocks[&handle];
        let extent = block.extent;
        let base = extent.guest_base().unwrap();
        let size = block.size;
        let selector = state.global_selectors[&handle];
        // No hidden lease is responsible for a busy result here.
        assert!(runtime.dos.block_lease_is_last_pin(&mut runtime.memory, &block.lease).unwrap());
        if protected_overlap {
            assert!(base.0 < 0x10000);
            assert!(matches!(state.selectors.suspend_allocation_views(base, size),
                Err(Win16Error::SelectorBlockInterior)));
            assert_eq!(state.kernel_global_dos_free(handle, &mut runtime.dos, &mut runtime.memory).unwrap(), handle);
            let retained = &state.dos_global_blocks[&handle];
            assert_eq!(retained.fix_count, 0);
            assert!(!retained.mcb_released);
            assert!(retained.suspended_views.is_none());
            assert!(state.selectors.describe(selector).unwrap().present);
            assert!(runtime.dos.block_lease_is_last_pin(&mut runtime.memory, &retained.lease).unwrap());
        } else {
            assert!(base.0 >= 0x10000);
            assert_eq!(state.kernel_global_dos_free(handle, &mut runtime.dos, &mut runtime.memory).unwrap(), 0);
            assert!(!state.dos_global_blocks.contains_key(&handle));
            assert!(!state.global_selectors.contains_key(&handle));
            assert!(state.selectors.describe(selector).is_err());
            assert_eq!(runtime.dos.owned_block_containing_range(&mut runtime.memory, base, size as usize).unwrap(), None);
        }
    }
}

#[test]
fn global_unfix_void_does_not_release_page_pins_or_let_global_unlock_consume_fixes() {
    let mut runtime = fixture();
    let handle = allocate(&mut runtime, GMEM_MOVEABLE | GMEM_DISCARDABLE);
    let identity = runtime.win16.as_ref().unwrap().global_handles[&handle];
    call(&mut runtime, 197, handle, 0x9876);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.heap.page_lock(identity).unwrap(), 1);
    assert_eq!(state.global_unlock(handle).unwrap(), 1);
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 1);
    call(&mut runtime, 198, handle, 0);
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.heap.info(identity).unwrap().lock_count, 0);
    assert_eq!(state.heap.info(identity).unwrap().page_lock_count, 1);
    assert_eq!(state.global_free(handle).unwrap(), handle);
    assert_eq!(state.heap.page_unlock(identity).unwrap(), 0);
    assert_eq!(state.global_free(handle).unwrap(), 0);
}
