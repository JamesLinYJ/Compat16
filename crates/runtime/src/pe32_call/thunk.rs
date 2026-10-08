use win16_abi::generic_thunk::{
    CPEX_DEST_CDECL, GENERIC_THUNK_MAX_PARAMETERS, Win16GenericThunkApi,
    Win16GenericThunkDisposition, Win16GenericThunkFrame, Win32ThunkTargetConvention,
};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::frame::Pe32CallConvention;

/// Validated target portion of a decoded generic-thunk invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Pe32GenericThunkTarget<'a> {
    /// CallProcEx32W documents zero for a NULL target or a count above 32.
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
/// Source-specific pointer ordering comes from the decoded frame. Legacy
/// target flags and early-return cleanup remain separate from CallProcEx32W.
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
    if frame.encoded_parameter_count > GENERIC_THUNK_MAX_PARAMETERS
        || frame.target_convention != Win32ThunkTargetConvention::Stdcall
        || frame.target_procedure == 0
        || frame.disposition != Win16GenericThunkDisposition::Invoke
    {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "CallProc32W flags, null-target, or rejection contract is not established",
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
