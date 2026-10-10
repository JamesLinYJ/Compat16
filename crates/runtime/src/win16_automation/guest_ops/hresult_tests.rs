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

struct NativeFailure {
    calls: usize,
}

impl crate::Win16AutomationConversionServices for NativeFailure {
    fn report_diagnostic(&mut self, _: crate::Diagnostic) {}

    fn convert(
        &mut self,
        _: crate::Win16Ole2DispConversionOperation,
    ) -> Result<crate::Win16Ole2DispConversionResult, RuntimeError> {
        self.calls += 1;
        Ok(crate::Win16Ole2DispConversionResult {
            hresult: 0x8007_0057,
            value: None,
        })
    }
}

#[test]
fn guest_conversion_errors_are_win16_but_native_hresult_stays_opaque() {
    let mut state = Win16AutomationState::default();
    let mut memory = Memory::with_size(0x10_0000).unwrap();
    let mut selectors = SelectorTable::new().unwrap();
    let selector = selectors
        .alloc_block(PhysAddr(0x1000), 0x1000, AccessRights::read_write(), &memory)
        .unwrap();
    let output = SegmentedPointer::new(selector, 0).far_value();
    let mut heap = GlobalHeap::new(PhysAddr(0x50000), 0x10000).unwrap();
    let mut services = NativeFailure { calls: 0 };
    for (input, output_far, expected) in [
        (Win16Ole2DispConvertInput::I4(1), 0, 0x8000_0005),
        (Win16Ole2DispConvertInput::AnsiString(None), output, 0x8000_0003),
        (Win16Ole2DispConvertInput::InterfaceFar(1), output, 0x8000_0001),
        (Win16Ole2DispConvertInput::I4(1), output, 0x8007_0057),
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
