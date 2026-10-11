//! ReleaseCapture and WaitMessage retain native BOOL validation and exact ownership.
use super::*;

fn prepare_zero(runtime: &mut Runtime, ordinal: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Void);
    let return_to = (runtime.cpu.regs.cs, 0x12_u16, runtime.cpu.regs.sp() + 4);
    let state = runtime.win16.as_mut().unwrap();
    state.window_handles.insert(0x1234, crate::Win16HostWindow(0x1111));
    state.window_handles.insert(0x2345, crate::Win16HostWindow(0x2222));
    state.owned_window_handles.insert(0x1234);
    state.window_parents.insert(0x1234, 0x2345);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    let mut bytes = return_to.1.to_le_bytes().to_vec();
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX);
    runtime.cpu.regs.set_dx(DX);
    return_to
}

#[test]
fn message_void_true_false_and_deferred_readback_preserve_registers_and_ownership() {
    for ordinal in [19, 112] {
        for native_result in [false, true] {
            for defer in [0, 1, 2] {
                let mut runtime = fixture();
                let return_to = prepare_zero(&mut runtime, ordinal);
                let before = runtime.cpu.regs.clone();
                let handles = runtime.win16.as_ref().unwrap().window_handles.clone();
                let owners = runtime.win16.as_ref().unwrap().owned_window_handles.clone();
                let mut host = KeyboardHost { result: Some(Win16MessageCallResult::Boolean(native_result)),
                    fail_readback_once: defer == 1, fail_consume_once: defer == 2, ..Default::default() };
                let result = dispatch(&mut runtime, &mut host);
                if defer != 0 {
                    assert_eq!(result.unwrap_err().kind(), Kind::HostFailure);
                    if defer == 1 { assert_eq!(runtime.cpu.regs, before); }
                    else {
                        assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (AX, DX));
                        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
                    }
                    assert_eq!((host.calls, host.consumed), (1, 0));
                    resume(&mut runtime, &mut host).unwrap();
                } else { result.unwrap(); }
                assert_return(&runtime, return_to);
                assert_eq!(host.zero_arg_calls, [ordinal]);
                assert_eq!((host.calls, host.consumed), (1, 1));
                assert_eq!(runtime.win16.as_ref().unwrap().window_handles, handles);
                assert_eq!(runtime.win16.as_ref().unwrap().owned_window_handles, owners);
                assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
                assert_eq!(bytes(&runtime), [0xa7; 258]);
            }
        }
    }
}

#[test]
fn message_void_failure_and_wrong_native_type_do_not_publish_guest_return() {
    for ordinal in [19, 112] {
        for fail_begin in [false, true] {
            let mut runtime = fixture();
            prepare_zero(&mut runtime, ordinal);
            let before = runtime.cpu.regs.clone();
            let mut host = KeyboardHost { result: Some(Win16MessageCallResult::Dword(123)),
                fail_begin, ..Default::default() };
            let error = dispatch(&mut runtime, &mut host).unwrap_err();
            assert_eq!(error.kind(), if fail_begin { Kind::HostFailure } else { Kind::InternalInvariant });
            assert_eq!(runtime.cpu.regs, before);
            assert_eq!((host.calls, host.consumed), (1, 0));
            assert_eq!(bytes(&runtime), [0xa7; 258]);
        }
    }
}

#[test]
fn wait_message_parks_without_spinning_or_resubmitting_and_finishes_original_wait() {
    let mut runtime = fixture();
    let return_to = prepare_zero(&mut runtime, 112);
    let before = runtime.cpu.regs.clone();
    let mut host = KeyboardHost { result: Some(Win16MessageCallResult::Boolean(true)),
        park_wait: true, ..Default::default() };
    dispatch(&mut runtime, &mut host).unwrap();
    assert_eq!(runtime.cpu.regs, before);
    assert_eq!((host.calls, host.wait_resumes, host.consumed), (1, 0, 0));
    assert_eq!(runtime.win16.as_ref().unwrap().window_operations.len(), 1);
    assert!(!runtime.win16.as_mut().unwrap().service_pending_window_guest_work(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, false).unwrap());
    assert_eq!((host.calls, host.wait_resumes, host.consumed), (1, 0, 0));
    runtime.win16.as_mut().unwrap().service_pending_window_guest_work(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, true).unwrap();
    assert_return(&runtime, return_to);
    assert_eq!((host.calls, host.wait_resumes, host.consumed), (1, 1, 1));
    assert_eq!(host.zero_arg_calls, [112]);
    assert_eq!(bytes(&runtime), [0xa7; 258]);
    // Finish the separate safe-point poll; it cannot consume or replay USER.
    for _ in 0..2 {
        runtime.win16.as_mut().unwrap().service_classic_dde_safe_point(
            &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, &mut host).unwrap();
    }
    assert_eq!((host.calls, host.wait_resumes, host.consumed), (1, 1, 1));
    assert_eq!(host.dde_polls, 1);
    assert_return(&runtime, return_to);
}

#[test]
fn zero_argument_void_default_host_remains_explicitly_unsupported() {
    for ordinal in [19, 112] {
        let mut runtime = fixture();
        prepare_zero(&mut runtime, ordinal);
        let before = runtime.cpu.regs.clone();
        let error = runtime.win16.as_mut().unwrap().dispatch(&mut runtime.cpu,
            &mut runtime.memory, &mut runtime.dos,
            &mut super::super::super::test_support::NoHost, 0).unwrap_err();
        assert_eq!(error.kind(), Kind::CompatibilityGap);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(runtime.win16.as_ref().unwrap().window_parents[&0x1234], 0x2345);
    }
}
