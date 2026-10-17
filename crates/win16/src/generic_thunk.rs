//! Checked decoding for the Win16-to-32-bit generic-thunk call frames.
//!
//! The two call entrypoints have different *source* conventions and therefore
//! different layouts around their variadic DWORD arguments. This module only
//! decodes those guest frames. It deliberately keeps the procedure token and
//! pointer mask as guest values; it neither creates a host pointer nor calls a
//! host procedure. The mask numbering is convention-specific: the Pascal
//! `CallProc32W` numbers from `paramN` downward, while CDECL `CallProcEx32W`
//! numbers from `param1` upward. A later invocation adapter must apply that
//! mapping only after validating the target argument list.
//!
//! ABI references: Microsoft's *Programmer's Guide to Microsoft Windows 95*,
//! Article 32, “16-bit WOW Functions” (the original PDF page was not directly
//! readable during this review); and Microsoft Learn, “CallProcEx32W”
//! (<https://learn.microsoft.com/en-us/previous-versions/aa383672(v=vs.85)>).

use crate::{
    ArgumentKind, StackCleanup, Win16Argument, Win16CallFrame, Win16CallingConvention,
    Win16Error, SelectorTable,
};
use guest_core::GuestMemory;

/// Maximum number of DWORD arguments accepted by the generic call thunks.
pub const GENERIC_THUNK_MAX_PARAMETERS: u32 = 32;

/// `nParams` flag selecting a cdecl target for a generic call thunk.
///
/// Microsoft Learn documents the flag for `CallProcEx32W`. A text-indexed
/// extract of Microsoft generic-thunk documentation also places these target
/// convention flags in `CallProc32W::nParams`; the original Windows 95 Guide
/// PDF page was not directly verified here. The raw encoded value is retained
/// in the frame so that interpretation can be revised without losing bits.
pub const CPEX_DEST_CDECL: u32 = 0x8000_0000;

const FIXED_DWORD_ARGUMENTS: &[ArgumentKind] = &[
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
];

/// Generic-thunk call entrypoint whose Win16-side frame is being decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16GenericThunkApi {
    /// `DWORD FAR PASCAL CallProc32W(param1..., proc, mask, nParams)`.
    CallProc32W,
    /// `DWORD FAR CDECL CallProcEx32W(nParams, mask, proc, param1...)`.
    CallProcEx32W,
}

impl Win16GenericThunkApi {
    /// Source-side Win16 convention of the generic-thunk entrypoint itself.
    pub const fn source_calling_convention(self) -> Win16CallingConvention {
        match self {
            Self::CallProc32W => Win16CallingConvention::Pascal,
            Self::CallProcEx32W => Win16CallingConvention::Cdecl,
        }
    }
}

/// Calling convention requested for the 32-bit target procedure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win32ThunkTargetConvention {
    /// Default target convention for generic thunks.
    Stdcall,
    /// Selected by `CPEX_DEST_CDECL` in the thunk's `nParams` value.
    Cdecl,
}

/// Whether the decoded frame may invoke its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16GenericThunkDisposition {
    Invoke,
    /// The documented generic-thunk result is zero for a null target or an
    /// argument count above 32. `parameters` is empty for either case; the
    /// caller can distinguish them from the retained target and count fields.
    ReturnZero,
}

/// Source-side cleanup facts known from the decoded generic-thunk frame.
///
/// A documented zero-result path can return before its variadic tail is
/// consumed. That tail is deliberately not decoded or assumed to exist. The
/// fixed prefix is known to have been present, but the total cleanup extent
/// may be unknown. `None` for a pop count means the failure-path cleanup rule
/// is not established by the sources used here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Win16GenericThunkStackCleanup {
    /// Bytes occupied by the three fixed DWORD arguments (the prefix was read).
    pub fixed_argument_bytes: u16,
    /// Bytes occupied by the variadic DWORD tail; `None` means it was not
    /// inspected and must not be treated as an absent tail.
    pub variadic_argument_bytes: Option<u16>,
    /// Exact callee-owned pop count, when established.
    pub callee_pop_bytes: Option<u16>,
    /// Exact caller-owned pop count, when established.
    pub caller_pop_bytes: Option<u16>,
}

/// Owned, checked representation of one Win16 generic-thunk stack frame.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Win16GenericThunkFrame {
    pub api: Win16GenericThunkApi,
    /// Opaque 32-bit procedure token returned by `GetProcAddress32W`.
    pub target_procedure: u32,
    /// Original conversion mask; its bit-order interpretation is API-specific.
    pub pointer_mask: u32,
    /// Raw `nParams` value, including any target-convention flag.
    pub encoded_parameter_count: u32,
    /// Number of DWORD parameters after removing the documented convention bit.
    pub parameter_count: u32,
    pub target_convention: Win32ThunkTargetConvention,
    /// Parameters in target prototype/source order when this frame is callable.
    /// Empty whenever the documented result is zero and no target is invoked.
    pub parameters: Vec<u32>,
    pub disposition: Win16GenericThunkDisposition,
    /// Cleanup facts for the Win16 source call. Callable counts have exact pop
    /// counts; early zero-result paths preserve unknown tail cleanup.
    pub stack_cleanup: Win16GenericThunkStackCleanup,
}

impl Win16GenericThunkFrame {
    /// Mask bit for an argument in target prototype order. Pascal callers
    /// number from the last argument; CDECL callers number from the first.
    /// Legacy ordering follows Microsoft KB Q104009; Ex ordering follows
    /// Microsoft Learn's CallProcEx32W fAddressConvert contract.
    pub fn parameter_pointer_bit(&self, index: usize) -> Option<u32> {
        let index = u32::try_from(index).ok()?;
        if self.parameter_count > GENERIC_THUNK_MAX_PARAMETERS || index >= self.parameter_count {
            return None;
        }
        let bit = match self.api {
            Win16GenericThunkApi::CallProc32W => self.parameter_count - 1 - index,
            Win16GenericThunkApi::CallProcEx32W => index,
        };
        Some(1_u32 << bit)
    }
}

/// Decode a `CallProc32W` or `CallProcEx32W` guest entry frame.
///
/// The fixed arguments reveal the parameter count. A second checked decode then
/// reads at most 32 target DWORDs through `Win16CallFrame`; no guest stack byte
/// is exposed as a host pointer. For an over-limit count, it returns the
/// documented zero-result disposition without validating or assuming that a
/// variadic tail exists.
pub fn decode_generic_thunk_frame(
    api: Win16GenericThunkApi,
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16GenericThunkFrame, Win16Error> {
    let source_convention = api.source_calling_convention();
    let fixed = frame.decode_arguments(
        selectors,
        memory,
        source_convention,
        FIXED_DWORD_ARGUMENTS,
    )?;

    let (target_procedure, pointer_mask, encoded_parameter_count) = match api {
        // Pascal pushes left-to-right, so the three trailing formal arguments
        // appear first in memory as nParams, mask, then procedure address.
        // decode_arguments returns them back in source declaration order.
        Win16GenericThunkApi::CallProc32W => (
            dword_argument(&fixed, 0)?,
            dword_argument(&fixed, 1)?,
            dword_argument(&fixed, 2)?,
        ),
        // CDECL pushes right-to-left, so the first three formal arguments are
        // already at the top of the argument area in declaration order.
        Win16GenericThunkApi::CallProcEx32W => (
            dword_argument(&fixed, 2)?,
            dword_argument(&fixed, 1)?,
            dword_argument(&fixed, 0)?,
        ),
    };

    let target_convention = if encoded_parameter_count & CPEX_DEST_CDECL != 0 {
        Win32ThunkTargetConvention::Cdecl
    } else {
        Win32ThunkTargetConvention::Stdcall
    };
    let parameter_count = encoded_parameter_count & !CPEX_DEST_CDECL;

    if parameter_count > GENERIC_THUNK_MAX_PARAMETERS
        || (target_procedure == 0 && api == Win16GenericThunkApi::CallProcEx32W)
    {
        return Ok(Win16GenericThunkFrame {
            api,
            target_procedure,
            pointer_mask,
            encoded_parameter_count,
            parameter_count,
            target_convention,
            parameters: Vec::new(),
            disposition: Win16GenericThunkDisposition::ReturnZero,
            stack_cleanup: unknown_tail_cleanup(api, parameter_count),
        });
    }

    let total_dwords = parameter_count
        .checked_add(FIXED_DWORD_ARGUMENTS.len() as u32)
        .ok_or(Win16Error::InvalidRange)?;
    let argument_bytes = total_dwords
        .checked_mul(4)
        .ok_or(Win16Error::InvalidRange)?;
    let stack_cleanup = exact_cleanup(
        frame.cleanup_argument_bytes(source_convention, argument_bytes)?,
        parameter_count,
    );

    if target_procedure == 0 {
        return Ok(Win16GenericThunkFrame {
            api,
            target_procedure,
            pointer_mask,
            encoded_parameter_count,
            parameter_count,
            target_convention,
            parameters: Vec::new(),
            disposition: Win16GenericThunkDisposition::ReturnZero,
            stack_cleanup,
        });
    }

    let parameter_count_usize = usize::try_from(parameter_count)
        .map_err(|_| Win16Error::InvalidRange)?;
    let signature_len = parameter_count_usize
        .checked_add(FIXED_DWORD_ARGUMENTS.len())
        .ok_or(Win16Error::InvalidRange)?;
    let mut signature = Vec::new();
    signature
        .try_reserve_exact(signature_len)
        .map_err(|_| Win16Error::OutOfMemory)?;
    signature.resize(signature_len, ArgumentKind::Dword);
    let decoded = frame.decode_arguments(selectors, memory, source_convention, &signature)?;

    let parameters = match api {
        Win16GenericThunkApi::CallProc32W => {
            let fixed_offset = parameter_count_usize;
            verify_fixed_arguments(
                &decoded,
                fixed_offset,
                [target_procedure, pointer_mask, encoded_parameter_count],
            )?;
            dword_arguments(&decoded[..parameter_count_usize])?
        }
        Win16GenericThunkApi::CallProcEx32W => {
            verify_fixed_arguments(
                &decoded,
                0,
                [encoded_parameter_count, pointer_mask, target_procedure],
            )?;
            dword_arguments(&decoded[FIXED_DWORD_ARGUMENTS.len()..])?
        }
    };

    Ok(Win16GenericThunkFrame {
        api,
        target_procedure,
        pointer_mask,
        encoded_parameter_count,
        parameter_count,
        target_convention,
        parameters,
        disposition: Win16GenericThunkDisposition::Invoke,
        stack_cleanup,
    })
}

fn dword_argument(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn exact_cleanup(cleanup: StackCleanup, parameter_count: u32) -> Win16GenericThunkStackCleanup {
    let variadic_argument_bytes = (parameter_count * 4) as u16;
    Win16GenericThunkStackCleanup {
        fixed_argument_bytes: (FIXED_DWORD_ARGUMENTS.len() * 4) as u16,
        variadic_argument_bytes: Some(variadic_argument_bytes),
        callee_pop_bytes: Some(cleanup.callee_pop_bytes),
        caller_pop_bytes: Some(cleanup.caller_pop_bytes),
    }
}

fn unknown_tail_cleanup(
    api: Win16GenericThunkApi,
    parameter_count: u32,
) -> Win16GenericThunkStackCleanup {
    // The variadic tail is not read. CallProc32W is still far Pascal, so the
    // callee pops the three fixed DWORDs plus one DWORD per declared parameter.
    // CallProcEx32W is cdecl: the callee pops nothing, and the caller's tail
    // extent stays unknown. A Pascal width that does not fit in a Win16 pop
    // count stays unknown rather than wrapping.
    let pascal_pop = parameter_count
        .checked_add(FIXED_DWORD_ARGUMENTS.len() as u32)
        .and_then(|dwords| dwords.checked_mul(4))
        .and_then(|bytes| u16::try_from(bytes).ok());
    Win16GenericThunkStackCleanup {
        fixed_argument_bytes: (FIXED_DWORD_ARGUMENTS.len() * 4) as u16,
        variadic_argument_bytes: None,
        callee_pop_bytes: match api {
            Win16GenericThunkApi::CallProcEx32W => Some(0),
            Win16GenericThunkApi::CallProc32W => pascal_pop,
        },
        caller_pop_bytes: match api {
            Win16GenericThunkApi::CallProc32W if pascal_pop.is_some() => Some(0),
            _ => None,
        },
    }
}

fn dword_arguments(arguments: &[Win16Argument]) -> Result<Vec<u32>, Win16Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(arguments.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    for (index, _) in arguments.iter().enumerate() {
        values.push(dword_argument(arguments, index)?);
    }
    Ok(values)
}

fn verify_fixed_arguments(
    arguments: &[Win16Argument],
    offset: usize,
    expected: [u32; 3],
) -> Result<(), Win16Error> {
    for (index, value) in expected.into_iter().enumerate() {
        if dword_argument(arguments, offset + index)? != value {
            return Err(Win16Error::InvalidRange);
        }
    }
    Ok(())
}

#[path = "generic_thunk_requests.rs"]
pub mod requests;

#[path = "generic_thunk_addresses.rs"]
mod addresses;

pub use addresses::{
    resolve_get_vdm_pointer32w, GetVDMPointer32WAddressError, ResolvedGuestAddress,
};

pub use requests::{
    decode_generic_thunk_export, Win16GenericThunkExport, Win16GenericThunkRequest,
};
