//! Strict mock-only scalar void USER calls; never change desktop settings or beep.
use super::*;

fn scalar_fixture(ordinal: u16, argument: u16) -> (Runtime, (u16, u16, u16)) {
    let (mut runtime, mut return_to, _) = prepare();
    let state = runtime.win16.as_mut().unwrap();
    *state.bindings.last_mut().unwrap() = ImportBinding::Supported(
        lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap());
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp() + 4).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &argument.to_le_bytes()).unwrap();
    return_to.2 += 2;
    (runtime, return_to)
}

#[test]
fn scalar_void_results_preserve_registers_and_unsigned_values_even_when_native_false() {
    for ordinal in [20, 104, 168] {
        for argument in [0, 1, 0x7fff, 0x8000, 0xffff] {
            for result in [false, true] {
                let (mut runtime, return_to) = scalar_fixture(ordinal, argument);
                let mut host = PopupHost { result, ..Default::default() };
                let stack = runtime.cpu.regs.sp();
                let original = stack_bytes(&runtime, stack);
                runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu, &mut runtime.memory,
                    &mut runtime.dos, &mut host, 0).unwrap();
                // Deterministic project Void policy; historical void did not specify AX/DX.
                assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
                assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
                assert_eq!(stack_bytes(&runtime, stack), original);
                assert_eq!(host.scalar_calls, [(ordinal, u32::from(argument))]);
                assert_eq!(host.calls, 0);
            }
        }
    }
}

#[test]
fn scalar_void_errors_and_default_unsupported_do_not_commit_a_return() {
    for ordinal in [20, 104, 168] {
        let (mut runtime, _) = scalar_fixture(ordinal, 0xffff);
        let before = runtime.cpu.regs.clone();
        let mut host = PopupHost { fail: true, ..Default::default() };
        let error = runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
            &mut runtime.memory, &mut runtime.dos, &mut host, 0).unwrap_err();
        assert_eq!(error.kind(), Kind::HostFailure);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(host.scalar_calls, [(ordinal, 65535)]);
        let (mut runtime, _) = scalar_fixture(ordinal, 0xffff);
        let before = runtime.cpu.regs.clone();
        let error = runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
            &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0).unwrap_err();
        assert_eq!(error.kind(), Kind::CompatibilityGap);
        assert_eq!(runtime.cpu.regs, before);
    }
}
