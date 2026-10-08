//! Checked guest-side transactions for scalar and VARIANT conversions.
use std::collections::BTreeSet;

use compat_services::automation::{VT_DISPATCH, VT_TYPEMASK, VT_UNKNOWN};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use win16_abi::{
    Access, GlobalHeap, SelectorTable, Win16Ole2DispConvertCall,
    Win16Ole2DispConvertInput as Input, Win16Ole2DispConvertOperation as CallOperation,
};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, Win16AutomationConversionServices,
    Win16Ole2DispConversionInput as NativeInput, Win16Ole2DispConversionOperation as NativeCall,
    Win16Ole2DispConversionValue as NativeValue,
};

use super::super::{validate_guest_far_range, write_guest_far_bytes};
use super::*;

#[path = "convert_values.rs"]
mod convert_values;
use convert_values::{read_owned_variant, stage_variant, value_vartype};

pub(super) fn execute(
    state: &mut Win16AutomationState,
    call: &Win16Ole2DispConvertCall,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    services: &mut impl Win16AutomationConversionServices,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match &call.operation {
        CallOperation::VarFrom {
            ordinal,
            input,
            locale,
            output_far,
        } => execute_var_from(
            state,
            *ordinal,
            input,
            *locale,
            *output_far,
            heap,
            selectors,
            memory,
            owner,
            services,
        ),
        CallOperation::VariantChangeType {
            destination_far,
            source_far,
            target_vartype,
            flags,
            lcid,
        } => execute_variant_change(
            state,
            *destination_far,
            *source_far,
            *target_vartype,
            *flags,
            *lcid,
            heap,
            selectors,
            memory,
            owner,
            services,
        ),
    }
}

fn execute_var_from(
    state: &mut Win16AutomationState,
    ordinal: u16,
    input: &Input,
    locale: Option<win16_abi::Win16Ole2DispLocaleFlags>,
    output_far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    services: &mut impl Win16AutomationConversionServices,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    let output_size = var_output_size(ordinal).ok_or_else(unsupported_call)?;
    if output_far == 0 {
        return guest_hresult(E_POINTER);
    }
    if let Err(error) =
        validate_guest_far_range(selectors, memory, output_far, output_size, Access::Write)
    {
        return map_guest_error(error, services, "Win16 Var*From* output preflight failed");
    }

    if matches!(input, Input::InterfaceFar(_)) {
        services.report_diagnostic(Diagnostic::warning(
            Kind::CompatibilityGap,
            "Win16 OLE2DISP interface conversion has no checked COM lease bridge",
        ));
        return guest_hresult(E_NOTIMPL);
    }
    if matches!(input, Input::AnsiString(None)) {
        return guest_hresult(E_INVALIDARG);
    }
    let input = match input_to_native(input) {
        Ok(input) => input,
        Err(error) => return map_guest_error(error, services, "decode Win16 Var*From* input"),
    };
    let locale = locale.map(|value| crate::Win16Ole2DispLocale {
        lcid: value.lcid,
        dw_flags: value.dw_flags,
    });
    let operation = NativeCall::VarFrom {
        ordinal,
        input,
        locale,
    };
    let converted = match services.convert(operation) {
        Ok(result) => result,
        Err(error) => {
            return map_guest_error(error, services, "native Var*From* conversion failed");
        }
    };
    if !hresult_succeeded(converted.hresult) {
        return guest_hresult(converted.hresult);
    }
    let Some(value) = converted.value else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native Var*From* succeeded without returning its typed output",
        ));
    };
    publish_scalar_or_bstr(
        state,
        ordinal,
        output_far,
        converted.hresult,
        value,
        heap,
        selectors,
        memory,
        owner,
        services,
    )
}

fn execute_variant_change(
    state: &mut Win16AutomationState,
    destination_far: u32,
    source_far: u32,
    target_vartype: u16,
    flags: u16,
    lcid: Option<u32>,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    services: &mut impl Win16AutomationConversionServices,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    if destination_far == 0 || source_far == 0 {
        return guest_hresult(E_POINTER);
    }
    if let Err(error) =
        validate_guest_far_range(selectors, memory, destination_far, 16, Access::Write)
    {
        return map_guest_error(
            error,
            services,
            "VariantChangeType destination preflight failed",
        );
    }
    if let Err(error) = validate_guest_far_range(selectors, memory, source_far, 16, Access::Read) {
        return map_guest_error(error, services, "VariantChangeType source preflight failed");
    }

    let destination = match variant::read_variant(selectors, memory, destination_far) {
        Ok(value) => value,
        Err(error) => {
            return map_guest_error(error, services, "read VariantChangeType destination");
        }
    };
    let source = match variant::read_variant(selectors, memory, source_far) {
        Ok(value) => value,
        Err(error) => return map_guest_error(error, services, "read VariantChangeType source"),
    };
    let mut reject_interface = |_action: AutomationInterfaceAction, _far: u32| {
        services.report_diagnostic(Diagnostic::warning(
            Kind::CompatibilityGap,
            "Win16 OLE2DISP interface-valued VARIANT has no checked COM lease bridge",
        ));
        Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 interface value cannot be passed to native OleAut as a pointer",
        ))
    };
    let preflight = variant::preflight_variant_release(
        state,
        destination,
        selectors,
        memory,
        owner,
        &mut reject_interface,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        0,
        true,
    );
    drop(reject_interface);
    if let Err(error) = preflight {
        return failure_result(error);
    }
    if matches!(target_vartype & VT_TYPEMASK, VT_DISPATCH | VT_UNKNOWN) {
        services.report_diagnostic(Diagnostic::warning(
            Kind::CompatibilityGap,
            "VariantChangeType interface targets need an apartment-bound COM lease bridge",
        ));
        return guest_hresult(E_NOTIMPL);
    }

    let owned_source = match read_owned_variant(state, selectors, memory, source, 0) {
        Ok(value) => value,
        Err(error) => {
            return failure_result_with_warning(error, services, "copy VariantChangeType source");
        }
    };
    let converted = match services.convert(NativeCall::VariantChangeType {
        source: owned_source,
        target_vartype,
        flags,
        lcid,
    }) {
        Ok(result) => result,
        Err(error) => return map_guest_error(error, services, "native VariantChangeType failed"),
    };
    if !hresult_succeeded(converted.hresult) {
        return guest_hresult(converted.hresult);
    }
    let Some(NativeValue::Variant(value)) = converted.value else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native VariantChangeType succeeded without a VARIANT result",
        ));
    };
    if value_vartype(&value) != Some(target_vartype) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native VariantChangeType result VARTYPE does not match the requested type",
        ));
    }

    let (staged, staged_bstr) = match stage_variant(state, &value, heap, selectors, memory, owner) {
        Ok(value) => value,
        Err(error) => return map_guest_error(error, services, "stage converted guest VARIANT"),
    };
    let mut reject_interface = |_action: AutomationInterfaceAction, _far: u32| {
        services.report_diagnostic(Diagnostic::warning(
            Kind::CompatibilityGap,
            "Win16 OLE2DISP interface-valued VARIANT cannot be released without a COM lease",
        ));
        Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 interface value has no releaseable COM lease",
        ))
    };
    let mut released = BTreeSet::new();
    if let Err(error) = variant::release_variant(
        state,
        destination,
        heap,
        selectors,
        memory,
        owner,
        &mut reject_interface,
        &mut released,
    ) {
        drop(reject_interface);
        let primary = error
            .after_destructive_commit("VariantChangeType failed after destination release began");
        return Err(rollback_staged_bstr(
            state,
            staged_bstr,
            primary,
            heap,
            selectors,
            owner,
            "VariantChangeType destination-release failure also failed to roll back its staged BSTR",
        ));
    }
    drop(reject_interface);
    if let Err(error) = variant::write_variant(selectors, memory, destination_far, staged) {
        let primary = AutomationFailure::from(error).after_destructive_commit(
            "VariantChangeType could not publish after releasing the old destination",
        );
        return Err(rollback_staged_bstr(
            state,
            staged_bstr,
            primary,
            heap,
            selectors,
            owner,
            "VariantChangeType publication failure also failed to roll back its staged BSTR",
        ));
    }
    Ok(Win16AutomationGuestResult::HResult(converted.hresult))
}

fn input_to_native(input: &Input) -> Result<NativeInput, RuntimeError> {
    Ok(match input {
        Input::I2(value) => NativeInput::I2(*value),
        Input::I4(value) => NativeInput::I4(*value),
        Input::R4Bits(value) => NativeInput::R4Bits(*value),
        Input::R8Bits(value) => NativeInput::R8Bits(*value),
        Input::CurrencyBits(value) => NativeInput::CurrencyBits(*value),
        Input::DateBits(value) => NativeInput::DateBits(*value),
        Input::Bool(value) => NativeInput::Bool(*value),
        Input::Ui1(value) => NativeInput::Ui1(*value),
        Input::AnsiString(Some(value)) => NativeInput::AnsiString(copy_bytes(value)?),
        Input::AnsiString(None) => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 OLE2DISP conversion string is null",
            ));
        }
        Input::InterfaceFar(_) => {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 interface value has no native pointer representation",
            ));
        }
    })
}

fn publish_scalar_or_bstr(
    state: &mut Win16AutomationState,
    ordinal: u16,
    output_far: u32,
    hresult: u32,
    value: NativeValue,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    services: &mut impl Win16AutomationConversionServices,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    let output_pointer = selectors
        .pointer_from_far(output_far)
        .map_err(crate::runtime_error)?;
    let mut bytes = [0_u8; 8];
    let length = match (ordinal, value) {
        (43..=50, NativeValue::I2(value)) => {
            bytes[..2].copy_from_slice(&value.to_le_bytes());
            2
        }
        (56, NativeValue::I4(value)) => {
            bytes[..4].copy_from_slice(&value.to_le_bytes());
            4
        }
        (61 | 64, NativeValue::R4Bits(value)) => {
            bytes[..4].copy_from_slice(&value.to_le_bytes());
            4
        }
        (72, NativeValue::R8Bits(value))
        | (80, NativeValue::DateBits(value))
        | (88, NativeValue::CurrencyBits(value)) => {
            bytes.copy_from_slice(&value.to_le_bytes());
            8
        }
        (116..=124, NativeValue::Ui1(value)) => {
            bytes[0] = value;
            1
        }
        (125, NativeValue::I2(value)) => {
            bytes[..2].copy_from_slice(&value.to_le_bytes());
            2
        }
        (91..=98 | 131, NativeValue::Bstr(value)) => {
            let far = match value {
                Some(value) => match state.allocate_bstr(heap, selectors, memory, owner, &value) {
                    Ok(far) => far,
                    Err(error) => {
                        return map_guest_error(error, services, "allocate Win16 BSTR result");
                    }
                },
                None => 0,
            };
            bytes[..4].copy_from_slice(&far.to_le_bytes());
            if let Err(error) =
                write_guest_far_bytes(selectors, memory, output_pointer, &bytes[..4])
            {
                if far != 0 {
                    if let Err(cleanup) = state.release_bstr(heap, selectors, owner, far) {
                        let failure = AutomationFailure::cleanup_failed(
                            AutomationFailure::from(error),
                            AutomationFailure::from(cleanup),
                            "VarBstrFrom* output failed and staged BSTR rollback failed",
                        );
                        return match failure.into_runtime() {
                            Err(error) => Err(error),
                            Ok(_) => Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "BSTR publication rollback failure was incorrectly recoverable",
                            )),
                        };
                    }
                }
                return Err(publication_error(
                    error,
                    "VarBstrFrom* could not publish its preflighted BSTR pointer",
                ));
            }
            return Ok(Win16AutomationGuestResult::HResult(hresult));
        }
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native Var*From* result type does not match its export ordinal",
            ));
        }
    };
    write_guest_far_bytes(selectors, memory, output_pointer, &bytes[..length]).map_err(
        |error| {
            publication_error(
                error,
                "Var*From* could not publish its preflighted scalar output",
            )
        },
    )?;
    Ok(Win16AutomationGuestResult::HResult(hresult))
}

fn var_output_size(ordinal: u16) -> Option<usize> {
    Some(match ordinal {
        43..=50 | 125 => 2,
        56 | 61 | 64 => 4,
        72 | 80 | 88 => 8,
        91..=98 | 131 => 4,
        116..=124 => 1,
        _ => return None,
    })
}

fn publication_error(error: RuntimeError, operation: &'static str) -> RuntimeError {
    if error.kind() == Kind::HostFailure {
        error
    } else {
        RuntimeError::with_source(Kind::InternalInvariant, operation, error)
    }
}

fn rollback_staged_bstr(
    state: &mut Win16AutomationState,
    staged_bstr: Option<u32>,
    primary: AutomationFailure,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    owner: OwnerId,
    operation: &'static str,
) -> RuntimeError {
    let Some(far) = staged_bstr else {
        return match primary.into_runtime() {
            Err(error) => error,
            Ok(_) => RuntimeError::new(Kind::InternalInvariant, operation),
        };
    };
    match state.release_bstr(heap, selectors, owner, far) {
        Ok(()) => match primary.into_runtime() {
            Err(error) => error,
            Ok(_) => RuntimeError::new(Kind::InternalInvariant, operation),
        },
        Err(cleanup) => {
            let failure = AutomationFailure::cleanup_failed(
                primary,
                AutomationFailure::from(cleanup),
                operation,
            );
            match failure.into_runtime() {
                Err(error) => error,
                Ok(_) => RuntimeError::new(Kind::InternalInvariant, operation),
            }
        }
    }
}

fn map_guest_error(
    error: RuntimeError,
    services: &mut impl Win16AutomationConversionServices,
    operation: &'static str,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    if error.kind() == Kind::CompatibilityGap {
        services.report_diagnostic(Diagnostic::warning(Kind::CompatibilityGap, operation));
    }
    match hresult_from_runtime(error) {
        Ok(status) => guest_hresult(status),
        Err(error) => Err(error),
    }
}

fn failure_result(failure: AutomationFailure) -> Result<Win16AutomationGuestResult, RuntimeError> {
    guest_hresult(failure.into_runtime()?)
}

fn failure_result_with_warning(
    failure: AutomationFailure,
    services: &mut impl Win16AutomationConversionServices,
    operation: &'static str,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    if matches!(
        &failure,
        AutomationFailure::HResultRuntime { source, .. }
            if source.kind() == Kind::CompatibilityGap
    ) {
        services.report_diagnostic(Diagnostic::warning(Kind::CompatibilityGap, operation));
    }
    failure_result(failure)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy Win16 OLE2DISP conversion input",
            error,
        )
    })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn guest_hresult(status: u32) -> Result<Win16AutomationGuestResult, RuntimeError> {
    Ok(Win16AutomationGuestResult::HResult(status))
}

fn hresult_succeeded(status: u32) -> bool {
    status as i32 >= 0
}

fn unsupported_call() -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        "decoded OLE2DISP conversion has no output layout",
    )
}
