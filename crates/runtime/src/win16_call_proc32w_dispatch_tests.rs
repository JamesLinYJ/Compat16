//! Guest-visible `CallProc32W` dispatch for a count above 32.

use super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::Runtime;
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

#[test]
fn over_long_call_proc32w_returns_zero_and_pops_the_pascal_frame() {
    for encoded in [33_u32, 33 | 0x8000_0000] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\THUNK.NE").unwrap();
        let mut host = NoHost;
        let return_cs = runtime.cpu.regs.cs;
        let start_sp = 0x20_u16;
        runtime.cpu.regs.set_sp(start_sp);
        let mut frame = Vec::from(0x12_u16.to_le_bytes());
        frame.extend_from_slice(&return_cs.to_le_bytes());
        // Pascal: nParams, mask, then the procedure token sit above the return.
        frame.extend_from_slice(&encoded.to_le_bytes());
        frame.extend_from_slice(&0_u32.to_le_bytes());
        frame.extend_from_slice(&0x0040_0000_u32.to_le_bytes());
        let state = runtime.win16.as_mut().unwrap();
        let pointer = state
            .selectors
            .pointer_from_raw(Selector(runtime.cpu.regs.ss), start_sp)
            .unwrap();
        state
            .selectors
            .write(&mut runtime.memory, pointer, &frame)
            .unwrap();
        let slot = state.bindings.len();
        state.bindings.push(ImportBinding::Supported(
            lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(517)).unwrap(),
        ));
        runtime.cpu.regs.cs = state.gate_selector.0;
        runtime.cpu.regs.set_ip((slot * 2) as u16);
        runtime.cpu.regs.eax = 0x1111_2222;
        runtime.cpu.regs.edx = 0x3333_4444;
        runtime
            .win16
            .as_mut()
            .unwrap()
            .dispatch(
                &mut runtime.cpu,
                &mut runtime.memory,
                &mut runtime.dos,
                &mut host,
                8,
            )
            .unwrap();
        assert_eq!(runtime.cpu.regs.cs, return_cs);
        assert_eq!(runtime.cpu.regs.ip(), 0x12);
        assert_eq!(runtime.cpu.regs.ax(), 0);
        assert_eq!(runtime.cpu.regs.dx(), 0);
        // Three fixed DWORDs plus 33 declared parameter DWORDs, then the far return.
        let pascal_pop = (3 + 33) * 4;
        assert_eq!(runtime.cpu.regs.sp(), start_sp + 4 + pascal_pop);
    }
}
