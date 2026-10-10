use super::*;
use guest_core::PhysAddr;
use win16_abi::{
    AccessRights, SegmentedPointer, Win16Ole2DispConvertCall, Win16Ole2DispConvertInput,
    Win16Ole2DispConvertOperation,
};

#[test]
fn guest_runtime_failures_use_win16_scode_values() {
    for (kind, expected) in [
        (Kind::InvalidInput, 0x8000_0003),
        (Kind::ResourceExhausted, 0x8000_0002),
        (Kind::CompatibilityGap, 0x8000_0001),
    ] {
        assert_eq!(
            hresult_from_runtime(RuntimeError::new(kind, "test failure")).unwrap(),
            expected,
        );
        assert_eq!(
            AutomationFailure::from(RuntimeError::new(kind, "test failure"))
                .into_runtime()
                .unwrap(),
            expected,
        );
    }
    assert_eq!(E_POINTER, 0x8000_0005);
    assert_eq!(DISP_E_BADVARTYPE, 0x8002_0008);
    assert_eq!(DISP_E_ARRAYISLOCKED, 0x8002_000d);
}

struct NativeConversion {
    calls: usize,
    status: u32,
    value: Option<crate::Win16Ole2DispConversionValue>,
}

impl crate::Win16AutomationConversionServices for NativeConversion {
    fn report_diagnostic(&mut self, _: crate::Diagnostic) {}

    fn convert(
        &mut self,
        _: crate::Win16Ole2DispConversionOperation,
    ) -> Result<crate::Win16Ole2DispConversionResult, RuntimeError> {
        self.calls += 1;
        Ok(crate::Win16Ole2DispConversionResult {
            hresult: self.status,
            value: self.value.clone(),
        })
    }
}

#[test]
fn guest_conversion_errors_and_known_native_failures_use_win16_statuses() {
    let mut state = Win16AutomationState::default();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors
        .alloc_block(PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory)
        .unwrap();
    let output = SegmentedPointer::new(selector, 0).far_value();
    let mut heap = GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap();
    let mut services = NativeConversion {
        calls: 0,
        status: 0x8007_0057,
        value: None,
    };
    for (input, output_far, expected) in [
        (Win16Ole2DispConvertInput::I4(1), 0, 0x8000_0005),
        (Win16Ole2DispConvertInput::AnsiString(None), output, 0x8000_0003),
        (Win16Ole2DispConvertInput::InterfaceFar(1), output, 0x8000_0001),
        (Win16Ole2DispConvertInput::I4(1), output, 0x8000_0003),
    ] {
        let call = Win16Ole2DispConvertCall {
            operation: Win16Ole2DispConvertOperation::VarFrom {
                ordinal: 43,
                input,
                locale: None,
                output_far,
            },
        };
        let result = convert_calls::execute(
            &mut state, &call, &mut heap, &mut selectors, &mut memory, OwnerId(1),
            &mut services,
        ).unwrap();
        assert_eq!(result, Win16AutomationGuestResult::HResult(expected));
    }
    assert_eq!(services.calls, 1);
}

#[test]
fn null_get_element_returns_win16_invalid_argument() {
    let mut state = Win16AutomationState::default();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let mut heap = GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap();
    let error = get_element::safe_array_get_element(
        &mut state, 0, 0, 0, &mut heap, &mut selectors, &mut memory, OwnerId(1),
        &mut |_, _| panic!("null array must not touch interface ownership"),
    ).unwrap_err();
    assert_eq!(error.into_runtime().unwrap(), 0x8000_0003);
}

#[test]
fn native_failures_translate_only_known_codes_without_publishing() {
    use compat_services::automation::{VT_I4, Variant16};

    // Expected literals are independently paired by the named Win16/native
    // header definitions, rather than calculated through the mapping helper.
    let statuses = [
        (0x8000_4001, 0x8000_0001),
        (0x8007_000e, 0x8000_0002),
        (0x8007_0057, 0x8000_0003),
        (0x8000_4002, 0x8000_0004),
        (0x8000_4003, 0x8000_0005),
        (0x8007_0006, 0x8000_0006),
        (0x8000_4004, 0x8000_0007),
        (0x8000_4005, 0x8000_0008),
        (0x8007_0005, 0x8000_0009),
        (0x8000_ffff, 0x8000_ffff),
        (0x8002_0005, 0x8002_0005),
        (0x8002_0008, 0x8002_0008),
        (0x8002_000a, 0x8002_000a),
        (0x8002_000d, 0x8002_000d),
        (0x8007_1234, 0x8007_1234),
        (0x8123_4567, 0x8123_4567),
        (0xdead_beef, 0xdead_beef),
        (0x8000_0003, 0x8000_0003),
    ];
    for (status, expected) in statuses {
        for branch in 0..3 {
            let mut state = Win16AutomationState::default();
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let selector = selectors
                .alloc_block(PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory)
                .unwrap();
            let destination = SegmentedPointer::new(selector, 0).far_value();
            let source = SegmentedPointer::new(selector, 32).far_value();
            let sentinel = Variant16 {
                vt: VT_I4,
                payload: 12345_i64.to_le_bytes(),
                ..Variant16::EMPTY
            };
            variant::write_variant(&selectors, &mut memory, destination, sentinel).unwrap();
            variant::write_variant(&selectors, &mut memory, source, sentinel).unwrap();
            let operation = if branch == 0 {
                Win16Ole2DispConvertOperation::VarFrom {
                    ordinal: 43,
                    input: Win16Ole2DispConvertInput::I4(1),
                    locale: None,
                    output_far: destination,
                }
            } else {
                Win16Ole2DispConvertOperation::VariantChangeType {
                    destination_far: destination,
                    source_far: source,
                    target_vartype: VT_I4,
                    flags: 0,
                    lcid: (branch == 2).then_some(0x0409),
                }
            };
            let call = Win16Ole2DispConvertCall { operation };
            let mut heap = GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap();
            let mut services = NativeConversion {
                calls: 0,
                status,
                value: None,
            };
            let result = convert_calls::execute(
                &mut state, &call, &mut heap, &mut selectors, &mut memory,
                OwnerId(1), &mut services,
            )
            .unwrap();
            assert_eq!(result, Win16AutomationGuestResult::HResult(expected));
            assert_eq!(services.calls, 1);
            assert_eq!(
                variant::read_variant(&selectors, &memory, destination).unwrap(),
                sentinel,
            );
            assert_eq!(
                variant::read_variant(&selectors, &memory, source).unwrap(),
                sentinel,
            );
        }
    }
}

#[test]
fn native_success_status_and_variant_error_payload_remain_opaque() {
    use compat_services::automation::{VT_ERROR, Variant16};
    use crate::{Win16AutomationValue, Win16Ole2DispConversionValue as Value};

    for status in [0, 1, 0x0004_0001] {
        for variant_output in [false, true] {
            let mut state = Win16AutomationState::default();
            let mut memory = Memory::with_size(0x10_0000).unwrap();
            let mut selectors = SelectorTable::new().unwrap();
            let selector = selectors
                .alloc_block(PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory)
                .unwrap();
            let destination = SegmentedPointer::new(selector, 0).far_value();
            let source = SegmentedPointer::new(selector, 32).far_value();
            variant::write_variant(&selectors, &mut memory, destination, Variant16::EMPTY).unwrap();
            variant::write_variant(&selectors, &mut memory, source, Variant16::EMPTY).unwrap();
            let (operation, value) = if variant_output {
                (
                    Win16Ole2DispConvertOperation::VariantChangeType {
                        destination_far: destination,
                        source_far: source,
                        target_vartype: VT_ERROR,
                        flags: 0,
                        lcid: None,
                    },
                    Value::Variant(Win16AutomationValue::Error(0x8007_0057_u32 as i32)),
                )
            } else {
                (
                    Win16Ole2DispConvertOperation::VarFrom {
                        ordinal: 43,
                        input: Win16Ole2DispConvertInput::I4(1),
                        locale: None,
                        output_far: destination,
                    },
                    Value::I2(123),
                )
            };
            let mut services = NativeConversion {
                calls: 0,
                status,
                value: Some(value),
            };
            let mut heap = GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap();
            let result = convert_calls::execute(
                &mut state, &Win16Ole2DispConvertCall { operation }, &mut heap,
                &mut selectors, &mut memory, OwnerId(1), &mut services,
            )
            .unwrap();
            assert_eq!(result, Win16AutomationGuestResult::HResult(status));
            assert_eq!(services.calls, 1);
            let published = variant::read_variant(&selectors, &memory, destination).unwrap();
            if variant_output {
                assert_eq!(published.vt, VT_ERROR);
                assert_eq!(&published.payload[..4], &0x8007_0057_u32.to_le_bytes());
            } else {
                assert_eq!(published.vt, 123); // Scalar output occupies the first two bytes.
            }
        }
    }
}
