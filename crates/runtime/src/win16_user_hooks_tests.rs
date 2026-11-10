//! Results for a Win16 hook that is not installed.
//!
//! `UnhookWindowsHook` returns zero when the procedure is not in the chain.
//! `DefHookProc` and `CallNextHookEx` have no next procedure to call, so they
//! return zero and leave the caller's slot unchanged.

use super::super::{
    ImportBinding,
    test_support::{NoHost, tiny_ne_executable},
};
use crate::Runtime;
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, Win16ReturnKind, lookup_export};

fn invoke(runtime: &mut Runtime, ordinal: u16, args: &[u8]) -> (u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let stack_sp = runtime.cpu.regs.sp();
    runtime.cpu.regs.set_ax(0xA55A);
    runtime.cpu.regs.set_dx(0xBEEF);
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let mut bytes = return_ip.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(args);
    let state = runtime.win16.as_mut().unwrap();
    let stack = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack_sp)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, stack, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime
        .win16
        .as_mut()
        .unwrap()
        .dispatch(
            &mut runtime.cpu,
            &mut runtime.memory,
            &mut runtime.dos,
            &mut NoHost,
            0,
        )
        .unwrap();
    (runtime.cpu.regs.ax(), runtime.cpu.regs.dx())
}

fn words(values: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn read_dword(runtime: &Runtime, offset: u16) -> u32 {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), offset)
        .unwrap();
    let mut bytes = [0_u8; 4];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn a_hook_that_is_not_installed_returns_zero_and_leaves_the_slot_unchanged() {
    let set = lookup_export(b"USER", ExportLookupTarget::Ordinal(121)).unwrap();
    let unhook = lookup_export(b"USER", ExportLookupTarget::Ordinal(234)).unwrap();
    let def_hook = lookup_export(b"USER", ExportLookupTarget::Ordinal(235)).unwrap();
    let next = lookup_export(b"USER", ExportLookupTarget::Ordinal(293)).unwrap();
    assert_eq!(set.return_kind, Win16ReturnKind::Dword);
    assert_eq!(unhook.return_kind, Win16ReturnKind::Word);
    assert_eq!(def_hook.return_kind, Win16ReturnKind::Dword);
    assert_eq!(next.return_kind, Win16ReturnKind::Dword);

    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\HOOKS.NE").unwrap();
    let stack = runtime.cpu.regs.sp();
    let ss = runtime.cpu.regs.ss;
    const SLOT: u16 = 0x20;
    const SENTINEL: u32 = 0xA5A5_5A5A;
    {
        let state = runtime.win16.as_mut().unwrap();
        let slot = state
            .selectors
            .pointer_from_raw(Selector(ss), SLOT)
            .unwrap();
        state
            .selectors
            .write(&mut runtime.memory, slot, &SENTINEL.to_le_bytes())
            .unwrap();
    }

    // A null procedure is not a filter. WH_MSGFILTER (-1) and any other type
    // both fail, which is the same zero result as an empty chain.
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(invoke(&mut runtime, 121, &words(&[0, 0, 0xFFFF])), (0, 0));
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(
        invoke(&mut runtime, 121, &words(&[0x5678, 0x1234, 2])),
        (0, 0)
    );

    // UnhookWindowsHook of a procedure that was never installed is FALSE.
    // The word result leaves DX alone.
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(
        invoke(&mut runtime, 234, &words(&[0x5678, 0x1234, 0xFFFF])),
        (0, 0xBEEF)
    );
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(invoke(&mut runtime, 234, &words(&[0, 0, 2])), (0, 0xBEEF));

    // DefHookProc outside an installed filter does not rewrite the slot.
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(
        invoke(
            &mut runtime,
            235,
            &words(&[SLOT, ss, 0xFFFF, 0xFFFF, 0xABCD, 0xFFFF]),
        ),
        (0, 0)
    );
    assert_eq!(read_dword(&runtime, SLOT), SENTINEL);

    // CallNextHookEx of an unknown HHOOK returns zero and does not use lParam
    // as a guest pointer.
    runtime.cpu.regs.set_sp(stack);
    assert_eq!(
        invoke(
            &mut runtime,
            293,
            &words(&[0xFFFF, 0xFFFF, 0xABCD, 0xFFFF, 0x2222, 0x1111]),
        ),
        (0, 0)
    );
    assert_eq!(read_dword(&runtime, SLOT), SENTINEL);
}
