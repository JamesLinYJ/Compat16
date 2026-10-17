use win16_abi::generic_thunk::{
    CPEX_DEST_CDECL, GENERIC_THUNK_MAX_PARAMETERS, Win16GenericThunkApi,
    Win16GenericThunkDisposition, Win16GenericThunkFrame, Win32ThunkTargetConvention,
};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::frame::Pe32CallConvention;

/// Validated target portion of a decoded generic-thunk invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32GenericThunkTarget<'a> {
    /// Documented zero result for a null target or a count above 32.
    ///
    /// `CallProcEx32W` always uses this result. `CallProc32W` uses it only
    /// when the decoded frame already carries that disposition for one of
    /// those two reasons. Other legacy flags stay gaps.
    ReturnZero,
    Invoke {
        procedure: u32,
        convention: Pe32CallConvention,
        /// Values are target-order DWORDs after any documented CallProcEx
        /// far-pointer conversion. This helper does not manufacture pointers.
        arguments: &'a [u32],
    },
}

/// Validate the decoded call contract without inferring a function signature.
/// Source-specific pointer ordering comes from the decoded frame. A null
/// `CallProc32W` target or a count above 32 returns zero when the decoded
/// frame already says so. Other legacy flags stay gaps. This helper does not
/// turn a pointer mask into a host pointer, and it does not decide Win16
/// stack cleanup.
pub(crate) fn validate_generic_thunk_target<'a>(
    frame: &'a Win16GenericThunkFrame,
    prepared_arguments: &'a [u32],
) -> Result<Pe32GenericThunkTarget<'a>, RuntimeError> {
    match frame.api {
        Win16GenericThunkApi::CallProc32W => validate_legacy_call_proc(frame, prepared_arguments),
        Win16GenericThunkApi::CallProcEx32W => validate_call_proc_ex(frame, prepared_arguments),
    }
}

fn validate_legacy_call_proc<'a>(
    frame: &'a Win16GenericThunkFrame,
    prepared_arguments: &'a [u32],
) -> Result<Pe32GenericThunkTarget<'a>, RuntimeError> {
    // Windows 95 generic-thunk notes: a null target or a count above 32 yields
    // zero. The decoder records that as `ReturnZero` and leaves the argument
    // tail unread. The convention bit in `nParams` is not part of that count
    // and is not a reason to invoke.
    let decoded_count = frame.encoded_parameter_count & !CPEX_DEST_CDECL;
    let documented_zero =
        frame.target_procedure == 0 || decoded_count > GENERIC_THUNK_MAX_PARAMETERS;
    if frame.disposition == Win16GenericThunkDisposition::ReturnZero && documented_zero {
        if frame.parameter_count != decoded_count
            || !frame.parameters.is_empty()
            || !prepared_arguments.is_empty()
        {
            return Err(invariant("CallProc32W zero-result frame is inconsistent"));
        }
        return Ok(Pe32GenericThunkTarget::ReturnZero);
    }
    if frame.encoded_parameter_count > GENERIC_THUNK_MAX_PARAMETERS
        || frame.target_convention != Win32ThunkTargetConvention::Stdcall
        || frame.target_procedure == 0
        || frame.disposition != Win16GenericThunkDisposition::Invoke
    {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "CallProc32W flags or rejection contract is not established",
        ));
    }
    if frame.parameter_count != frame.encoded_parameter_count
        || frame.parameter_count as usize != frame.parameters.len()
        || prepared_arguments.len() != frame.parameters.len()
    {
        return Err(invariant(
            "CallProc32W prepared DWORD arguments do not match its decoded frame",
        ));
    }
    validate_prepared_pointers(frame, prepared_arguments)?;
    Ok(Pe32GenericThunkTarget::Invoke {
        procedure: frame.target_procedure,
        convention: Pe32CallConvention::Stdcall,
        arguments: prepared_arguments,
    })
}

fn validate_call_proc_ex<'a>(
    frame: &'a Win16GenericThunkFrame,
    prepared_arguments: &'a [u32],
) -> Result<Pe32GenericThunkTarget<'a>, RuntimeError> {
    let target_convention = if frame.encoded_parameter_count & CPEX_DEST_CDECL != 0 {
        Win32ThunkTargetConvention::Cdecl
    } else {
        Win32ThunkTargetConvention::Stdcall
    };
    if frame.target_convention != target_convention {
        return Err(invariant(
            "CallProcEx32W target convention disagrees with its encoded flag",
        ));
    }
    if frame.disposition == Win16GenericThunkDisposition::ReturnZero {
        if !frame.parameters.is_empty()
            || !prepared_arguments.is_empty()
            || (frame.target_procedure != 0
                && frame.parameter_count <= GENERIC_THUNK_MAX_PARAMETERS)
        {
            return Err(invariant("CallProcEx32W zero-result frame is inconsistent"));
        }
        return Ok(Pe32GenericThunkTarget::ReturnZero);
    }
    if frame.disposition != Win16GenericThunkDisposition::Invoke
        || frame.target_procedure == 0
        || frame.parameter_count > GENERIC_THUNK_MAX_PARAMETERS
        || frame.parameter_count as usize != frame.parameters.len()
        || prepared_arguments.len() != frame.parameters.len()
    {
        return Err(invariant("CallProcEx32W invocation shape is inconsistent"));
    }
    validate_prepared_pointers(frame, prepared_arguments)?;
    let convention = match target_convention {
        Win32ThunkTargetConvention::Cdecl => Pe32CallConvention::Cdecl,
        Win32ThunkTargetConvention::Stdcall => Pe32CallConvention::Stdcall,
    };
    Ok(Pe32GenericThunkTarget::Invoke {
        procedure: frame.target_procedure,
        convention,
        arguments: prepared_arguments,
    })
}

fn validate_prepared_pointers(frame: &Win16GenericThunkFrame, prepared_arguments: &[u32])
    -> Result<(), RuntimeError>
{
    let valid_pointer_bits = match frame.parameter_count {
        32 => u32::MAX,
        count => (1_u32 << count) - 1,
    };
    if frame.pointer_mask & !valid_pointer_bits != 0 {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "generic-thunk pointer mask sets bits outside the declared argument list",
        ));
    }
    for (index, (decoded, prepared)) in frame.parameters.iter().zip(prepared_arguments).enumerate()
    {
        let pointer_bit = frame.parameter_pointer_bit(index).ok_or_else(||
            invariant("generic-thunk parameter has no valid source-order mask bit"))?;
        let converted = frame.pointer_mask & pointer_bit != 0;
        if (!converted && decoded != prepared) || (*decoded == 0 && *prepared != 0) {
            return Err(invariant(
                "generic-thunk changed an unmasked or NULL argument",
            ));
        }
    }
    Ok(())
}

/// Win32 DllMain and TLS process-attach callbacks use the same three-DWORD
/// stdcall frame shape; TLS code must still wait for its real guest TLS/FS state.
pub(crate) const fn process_attach_arguments(module_base: u32) -> [u32; 3] {
    [module_base, 1, 0]
}

/// Win32 DllMain process detach uses the same stdcall boundary and fixed
/// argument layout as attach; the registry decides when detach is required.
pub(crate) const fn process_detach_arguments(module_base: u32) -> [u32; 3] {
    [module_base, 0, 0]
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[cfg(test)]
mod tests {
    use win16_abi::generic_thunk::{
        CPEX_DEST_CDECL, Win16GenericThunkApi, Win16GenericThunkDisposition,
        Win16GenericThunkFrame, Win16GenericThunkStackCleanup, Win32ThunkTargetConvention,
    };

    use crate::DiagnosticKind;

    use super::{Pe32CallConvention, Pe32GenericThunkTarget, validate_generic_thunk_target};

    fn legacy_frame(
        target_procedure: u32,
        encoded_parameter_count: u32,
        parameter_count: u32,
        target_convention: Win32ThunkTargetConvention,
        disposition: Win16GenericThunkDisposition,
        parameters: Vec<u32>,
        pointer_mask: u32,
    ) -> Win16GenericThunkFrame {
        Win16GenericThunkFrame {
            api: Win16GenericThunkApi::CallProc32W,
            target_procedure,
            pointer_mask,
            encoded_parameter_count,
            parameter_count,
            target_convention,
            parameters,
            disposition,
            // Pop counts stay unset. This validator does not choose Win16 cleanup.
            stack_cleanup: Win16GenericThunkStackCleanup {
                fixed_argument_bytes: 12,
                variadic_argument_bytes: None,
                callee_pop_bytes: None,
                caller_pop_bytes: None,
            },
        }
    }

    fn assert_documented_zero(frame: &Win16GenericThunkFrame) {
        assert_eq!(
            validate_generic_thunk_target(frame, &[]).unwrap(),
            Pe32GenericThunkTarget::ReturnZero,
        );
    }

    #[test]
    fn call_proc32w_null_target_returns_zero() {
        for encoded in [1_u32, 1 | CPEX_DEST_CDECL] {
            let convention = if encoded & CPEX_DEST_CDECL == 0 {
                Win32ThunkTargetConvention::Stdcall
            } else {
                Win32ThunkTargetConvention::Cdecl
            };
            let frame = legacy_frame(
                0,
                encoded,
                1,
                convention,
                Win16GenericThunkDisposition::ReturnZero,
                Vec::new(),
                0x0000_0001,
            );
            assert_documented_zero(&frame);
        }
    }

    #[test]
    fn call_proc32w_over_long_count_returns_zero() {
        for encoded in [33_u32, 33 | CPEX_DEST_CDECL] {
            let convention = if encoded & CPEX_DEST_CDECL == 0 {
                Win32ThunkTargetConvention::Stdcall
            } else {
                Win32ThunkTargetConvention::Cdecl
            };
            let frame = legacy_frame(
                0x0001_0000,
                encoded,
                33,
                convention,
                Win16GenericThunkDisposition::ReturnZero,
                Vec::new(),
                u32::MAX,
            );
            assert_documented_zero(&frame);
        }
    }

    #[test]
    fn call_proc32w_cdecl_flag_stays_a_gap() {
        let parameters = vec![0x1111_2222, 0x3333_4444];
        let frame = legacy_frame(
            0x0040_0000,
            2 | CPEX_DEST_CDECL,
            2,
            Win32ThunkTargetConvention::Cdecl,
            Win16GenericThunkDisposition::Invoke,
            parameters.clone(),
            0,
        );
        let error = validate_generic_thunk_target(&frame, &parameters).unwrap_err();
        assert_eq!(error.kind(), DiagnosticKind::CompatibilityGap);
        assert!(error.to_string().contains("not established"));
    }

    #[test]
    fn call_proc32w_count_at_limit_keeps_guest_dwords() {
        let parameters = vec![0x20_u32; 32];
        let frame = legacy_frame(
            0x0040_1000,
            32,
            32,
            Win32ThunkTargetConvention::Stdcall,
            Win16GenericThunkDisposition::Invoke,
            parameters.clone(),
            0x0000_0001,
        );
        let Pe32GenericThunkTarget::Invoke {
            procedure,
            convention,
            arguments,
        } = validate_generic_thunk_target(&frame, &parameters).unwrap()
        else {
            panic!("in-range CallProc32W returned zero");
        };
        assert_eq!(procedure, 0x0040_1000);
        assert_eq!(convention, Pe32CallConvention::Stdcall);
        assert_eq!(arguments, parameters.as_slice());
    }
}
