use super::super::super::test_support::{NoHost, tiny_ne_executable};
use super::*;
use crate::Runtime;
use guest_core::{GuestMemory, PhysAddr, Selector};
use win16_abi::{AccessRights, SelectorRef, gdi_abi::encode_wow_devmode_extra};

fn fixture(capacity: usize) -> (Runtime, GuestOutputRange, SelectorRef, PhysAddr) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\MODE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ds), 0)
        .unwrap();
    let base = state.selectors.describe(pointer.selector()).unwrap().base;
    runtime.memory.write(base, &[0xa5; 224]).unwrap();
    let range = GuestOutputRange::capture(state, &runtime.memory, pointer, capacity).unwrap();
    state.common_dialog_state.last_extended_error = 77;
    (runtime, range, pointer.selector(), base)
}

fn data() -> crate::Win16HostDevMode {
    crate::Win16HostDevMode {
        public_size: 68,
        device_name: [0; 32],
        spec_version: 0x030a,
        driver_version: 7,
        fields: 1,
        settings: [2; 12],
        public_extension: vec![],
        driver_extra: encode_wow_devmode_extra(0x0401, &[0; 88], &[0, 0xff, 7]).unwrap(),
    }
}

fn complete(
    runtime: &mut Runtime,
    range: Option<GuestOutputRange>,
    result: Win16HostPrinterModeResult,
) -> Result<u32, RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    state
        .finish_common_dialog(
            Win16CommonDialogContinuation {
                return_kind: Win16ReturnKind::Word,
                guest_failure_value: 65535,
                output: Win16CommonDialogOutput::PrinterMode { output: range },
            },
            crate::Win16HostCommonDialogResult::PrinterMode(result),
            &mut runtime.memory,
            &mut NoHost,
        )
        .map(|(value, _)| value)
}

#[test]
fn ext_device_mode_completion_writes_only_idok_prefix_and_keeps_commdlg_error() {
    let (mut runtime, range, _, base) = fixture(200);
    let value = data();
    let expected = super::super::support::encode_devmode16(&value).unwrap();
    assert_eq!(
        complete(
            &mut runtime,
            Some(range),
            Win16HostPrinterModeResult {
                value: 1,
                output: Some(value)
            }
        )
        .unwrap(),
        1
    );
    let mut actual = vec![0; 224];
    runtime.memory.read(base, &mut actual).unwrap();
    assert_eq!(&actual[..expected.len()], &expected);
    assert!(actual[expected.len()..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        runtime
            .win16
            .as_ref()
            .unwrap()
            .common_dialog_state
            .last_extended_error,
        77
    );
}

#[test]
fn ext_device_mode_cancel_and_failures_never_touch_guest_output() {
    for value in [2, -1, -7] {
        let (mut runtime, range, _, base) = fixture(200);
        assert_eq!(
            complete(
                &mut runtime,
                Some(range),
                Win16HostPrinterModeResult {
                    value,
                    output: None
                }
            )
            .unwrap(),
            value as u16 as u32
        );
        let mut bytes = [0; 224];
        runtime.memory.read(base, &mut bytes).unwrap();
        assert_eq!(bytes, [0xa5; 224]);
    }
}

#[test]
fn ext_device_mode_short_output_is_unchanged_and_returns_failure() {
    let (mut runtime, range, _, base) = fixture(100);
    assert_eq!(
        complete(
            &mut runtime,
            Some(range),
            Win16HostPrinterModeResult {
                value: 1,
                output: Some(data())
            }
        )
        .unwrap(),
        65535
    );
    let mut bytes = [0; 224];
    runtime.memory.read(base, &mut bytes).unwrap();
    assert_eq!(bytes, [0xa5; 224]);
}

#[test]
fn ext_device_mode_reused_selector_cannot_receive_suspended_output() {
    let (mut runtime, range, selector, base) = fixture(200);
    let state = runtime.win16.as_mut().unwrap();
    let size = state.selectors.allocation_size(selector).unwrap();
    state.selectors.free_block(selector).unwrap();
    let reused = state
        .selectors
        .alloc_block(base, size, AccessRights::read_write(), &runtime.memory)
        .unwrap();
    assert_eq!(reused.raw(), selector.raw());
    assert_ne!(reused, selector);
    assert_eq!(
        complete(
            &mut runtime,
            Some(range),
            Win16HostPrinterModeResult {
                value: 1,
                output: Some(data())
            }
        )
        .unwrap(),
        65535
    );
    let mut bytes = [0; 224];
    runtime.memory.read(base, &mut bytes).unwrap();
    assert_eq!(bytes, [0xa5; 224]);
}

#[test]
fn ext_device_mode_inconsistent_host_output_is_rejected() {
    for (value, output) in [(2, Some(data())), (1, None)] {
        let (mut runtime, range, _, _) = fixture(200);
        assert!(
            complete(
                &mut runtime,
                Some(range),
                Win16HostPrinterModeResult { value, output }
            )
            .is_err()
        );
    }
}

#[test]
fn ext_device_mode_size_queries_and_noncopy_idok_need_no_output() {
    let (mut runtime, _, _, _) = fixture(200);
    for value in [168, 40000, 1] {
        assert_eq!(
            complete(
                &mut runtime,
                None,
                Win16HostPrinterModeResult {
                    value,
                    output: None
                }
            )
            .unwrap(),
            value as u32
        );
    }
}

#[test]
fn ext_device_mode_bad_input_returns_api_failure_before_native_execution() {
    for invalid_selector in [true, false] {
        let (mut runtime, _, _, base) = fixture(200);
        let mut bytes = [0; 68];
        bytes[36..38].copy_from_slice(&39_u16.to_le_bytes());
        runtime.memory.write(base, &bytes).unwrap();
        let input = if invalid_selector {
            0xffff_0000
        } else {
            u32::from(runtime.cpu.regs.ds) << 16
        };
        let return_to = (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            u32::from(runtime.cpu.regs.sp()),
        );
        let request = Win16PrinterRequest::ExtDeviceMode {
            owner: 0,
            driver_instance: 0,
            output: 0,
            device: None,
            port: None,
            input,
            profile: None,
            mode: 8,
        };
        runtime
            .win16
            .as_mut()
            .unwrap()
            .begin_ext_device_mode(
                request,
                &mut runtime.cpu.regs,
                &mut runtime.memory,
                &mut NoHost,
                return_to,
                Win16ReturnKind::Word,
            )
            .unwrap();
        assert_eq!(runtime.cpu.regs.ax(), 65535);
        assert_eq!(
            runtime
                .win16
                .as_ref()
                .unwrap()
                .common_dialog_state
                .last_extended_error,
            77
        );
    }
}
