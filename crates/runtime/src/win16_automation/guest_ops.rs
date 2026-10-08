//! Guest-only OLE Automation allocation and ownership operations.
//!
//! These operations consume checked, owned Win16 call arguments and mutate
//! only the task's emulated global heap and guest memory. No guest FAR value
//! is converted to a native pointer.

use compat_services::automation::{
    AutomationAbiError, FADF_BSTR, FADF_DISPATCH, FADF_UNKNOWN, FADF_VARIANT, SafeArray16, VT_BSTR,
    VT_DISPATCH, VT_UNKNOWN, VT_VARIANT, decode_safe_array_bounds16, safe_array_element_width,
};
use guest_core::{OwnerId, memory::Memory};
use std::error::Error;
use std::fmt;
use win16_abi::{GlobalHeap, SelectorTable, Win16Ole2DispArgument as Arg, Win16Ole2DispCall};

use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError};

use super::{
    AllocationKind, MAX_AUTOMATION_ALLOCATION, Win16AutomationState,
};

mod bstr_calls;
mod convert_calls;
mod get_element;
mod safearray_calls;
mod teardown;
mod variant;
mod variant_calls;
mod variant_rollback;
pub(super) use teardown::{preflight_owner_array_contents, release_owner_array_contents};

const S_OK: u32 = 0;
const E_POINTER: u32 = 0x8000_4003;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_OUTOFMEMORY: u32 = 0x8007_000e;
const E_INVALIDARG: u32 = 0x8007_0057;
const DISP_E_BADVARTYPE: u32 = 0x8002_0008;
const DISP_E_ARRAYISLOCKED: u32 = 0x8002_000d;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AutomationInterfaceAction {
    AddRef,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16AutomationGuestResult {
    Void,
    Word(u16),
    Dword(u32),
    FarPointer(u32),
    HResult(u32),
}

/// A documented guest HRESULT versus a runtime memory/ownership failure.
#[derive(Debug)]
pub(super) enum AutomationFailure {
    HResult(u32),
    HResultRuntime { status: u32, source: RuntimeError },
    Runtime(RuntimeError),
}

impl From<RuntimeError> for AutomationFailure {
    fn from(error: RuntimeError) -> Self {
        match error.kind() {
            Kind::InvalidInput => Self::HResultRuntime {
                status: E_INVALIDARG,
                source: error,
            },
            Kind::ResourceExhausted => Self::HResultRuntime {
                status: E_OUTOFMEMORY,
                source: error,
            },
            Kind::CompatibilityGap => Self::HResultRuntime {
                status: E_NOTIMPL,
                source: error,
            },
            Kind::HostFailure
            | Kind::GuestFault
            | Kind::InternalInvariant
            | Kind::ExecutionLimit => Self::Runtime(error),
        }
    }
}

impl AutomationFailure {
    fn into_runtime(self) -> Result<u32, RuntimeError> {
        match self {
            Self::HResult(status) => Ok(status),
            Self::HResultRuntime { status, .. } => Ok(status),
            Self::Runtime(error) => Err(error),
        }
    }

    /// Once release has begun, an ordinary HRESULT could resume the guest
    /// with only part of the old Automation graph destroyed. Preserve storage
    /// failures, and make every other post-commit error a stopped invariant
    /// failure with its original typed cause attached.
    pub(super) fn after_destructive_commit(self, operation: &'static str) -> Self {
        match self {
            Self::Runtime(error) if error.kind() == Kind::HostFailure => Self::Runtime(error),
            Self::Runtime(error) => Self::Runtime(RuntimeError::with_source(
                Kind::InternalInvariant,
                operation,
                error,
            )),
            Self::HResult(status) => Self::Runtime(RuntimeError::with_source(
                Kind::InternalInvariant,
                operation,
                HResultCause(status),
            )),
            Self::HResultRuntime { status, source } => Self::Runtime(RuntimeError::with_source(
                Kind::InternalInvariant,
                operation,
                HResultRuntimeCause { status, source },
            )),
        }
    }

    /// Rollback is a cleanup boundary: failure means newly owned guest
    /// allocations may remain live but unpublished, so it must stop execution.
    pub(super) fn rollback_failure(self, operation: &'static str) -> Self {
        let error = match self {
            Self::Runtime(error) => {
                RuntimeError::with_source(Kind::InternalInvariant, operation, error)
            }
            Self::HResult(status) => {
                RuntimeError::with_source(Kind::InternalInvariant, operation, HResultCause(status))
            }
            Self::HResultRuntime { status, source } => RuntimeError::with_source(
                Kind::InternalInvariant,
                operation,
                HResultRuntimeCause { status, source },
            ),
        };
        Self::Runtime(error)
    }

    pub(super) fn cleanup_failed(primary: Self, cleanup: Self, operation: &'static str) -> Self {
        Self::Runtime(RuntimeError::with_source(
            Kind::InternalInvariant,
            operation,
            CombinedAutomationFailure {
                primary: AutomationFailureCause::from(primary),
                cleanup: AutomationFailureCause::from(cleanup),
            },
        ))
    }
}

#[derive(Debug)]
struct HResultCause(u32);

impl fmt::Display for HResultCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "guest Automation operation returned HRESULT 0x{:08X}",
            self.0
        )
    }
}

impl Error for HResultCause {}

#[derive(Debug)]
struct HResultRuntimeCause {
    status: u32,
    source: RuntimeError,
}

impl fmt::Display for HResultRuntimeCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HRESULT 0x{:08X} mapped from {}",
            self.status, self.source
        )
    }
}

impl Error for HResultRuntimeCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug)]
enum AutomationFailureCause {
    Runtime(RuntimeError),
    HResult(HResultCause),
    HResultRuntime(HResultRuntimeCause),
}

impl From<AutomationFailure> for AutomationFailureCause {
    fn from(failure: AutomationFailure) -> Self {
        match failure {
            AutomationFailure::Runtime(error) => Self::Runtime(error),
            AutomationFailure::HResult(status) => Self::HResult(HResultCause(status)),
            AutomationFailure::HResultRuntime { status, source } => {
                Self::HResultRuntime(HResultRuntimeCause { status, source })
            }
        }
    }
}

impl fmt::Display for AutomationFailureCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => fmt::Display::fmt(error, formatter),
            Self::HResult(status) => fmt::Display::fmt(status, formatter),
            Self::HResultRuntime(status) => fmt::Display::fmt(status, formatter),
        }
    }
}

impl Error for AutomationFailureCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::HResult(_) => None,
            Self::HResultRuntime(cause) => Some(cause),
        }
    }
}

#[derive(Debug)]
struct CombinedAutomationFailure {
    primary: AutomationFailureCause,
    cleanup: AutomationFailureCause,
}

impl fmt::Display for CombinedAutomationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "primary failure: {}; cleanup failure: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for CombinedAutomationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cleanup)
    }
}

impl Win16AutomationState {
    pub(crate) fn execute_guest_ole2disp_convert_call(
        &mut self,
        call: &win16_abi::Win16Ole2DispConvertCall,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        services: &mut impl crate::Win16AutomationConversionServices,
    ) -> Result<Win16AutomationGuestResult, RuntimeError> {
        convert_calls::execute(self, call, heap, selectors, memory, owner, services)
    }

    /// Execute one decoded guest-local OLE2DISP BSTR, VARIANT, or SAFEARRAY call.
    /// The decoder admits only these ordinals; native conversion, NLS,
    /// TYPELIB, and COM host operations use independent request paths.
    pub(crate) fn execute_guest_ole2disp_call(
        &mut self,
        call: &Win16Ole2DispCall,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        warn: &mut impl FnMut(Diagnostic),
    ) -> Result<Win16AutomationGuestResult, RuntimeError> {
        let mut interface_warning_emitted = false;
        let mut reject_interface = |_action: AutomationInterfaceAction,
                                    _guest_value: u32|
         -> Result<(), RuntimeError> {
            if !interface_warning_emitted {
                warn(Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 OLE2DISP COM interface values are unsupported by this guest-only path",
                ));
                interface_warning_emitted = true;
            }
            Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 OLE2DISP COM interface reference cannot be acquired or released",
            ))
        };

        match call.ordinal {
            2..=7 => bstr_calls::execute_bstr_call(
                self,
                call.ordinal,
                &call.arguments,
                heap,
                selectors,
                memory,
                owner,
            ),
            8..=11 => variant_calls::execute_variant_call(
                self,
                call.ordinal,
                &call.arguments,
                heap,
                selectors,
                memory,
                owner,
                &mut reject_interface,
            ),
            15..=25 | 27 | 38..=41 => safearray_calls::execute_safe_array_call(
                self,
                call.ordinal,
                &call.arguments,
                heap,
                selectors,
                memory,
                owner,
                &mut reject_interface,
            ),
            _ => Err(unsupported_ordinal()),
        }
    }
}

fn argument<'a>(arguments: &'a [Arg], index: usize) -> Result<&'a Arg, RuntimeError> {
    arguments.get(index).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP call is missing a decoded argument",
        )
    })
}

fn unsupported_ordinal() -> RuntimeError {
    RuntimeError::new(
        Kind::InvalidInput,
        "unsupported Win16 OLE2DISP guest ordinal",
    )
}

fn guest_address(arguments: &[Arg], index: usize) -> Result<u32, RuntimeError> {
    match argument(arguments, index)? {
        Arg::GuestAddress(value) => Ok(*value),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP argument is not a guest FAR address",
        )),
    }
}

fn word(arguments: &[Arg], index: usize) -> Result<u16, RuntimeError> {
    match argument(arguments, index)? {
        Arg::Word(value) => Ok(*value),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP argument is not a guest WORD",
        )),
    }
}

fn nullable_bytes(arguments: &[Arg], index: usize) -> Result<Option<&[u8]>, RuntimeError> {
    match argument(arguments, index)? {
        Arg::NullableAnsiString(value) => Ok(value.as_deref()),
        Arg::AnsiString(value) => Ok(Some(value)),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP argument is not a decoded ANSI string",
        )),
    }
}

fn counted_bstr(arguments: &[Arg], index: usize) -> Result<Option<&[u8]>, RuntimeError> {
    match argument(arguments, index)? {
        Arg::CountedBstrBytes(value) => Ok(value.as_deref()),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP argument is not a counted BSTR byte string",
        )),
    }
}

fn exact_bytes(arguments: &[Arg], index: usize) -> Result<Option<&[u8]>, RuntimeError> {
    match argument(arguments, index)? {
        Arg::ExactBytes(value) => Ok(value.as_deref()),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OLE2DISP argument is not an exact guest byte range",
        )),
    }
}

fn zeroed_bytes(length: usize) -> Result<Vec<u8>, RuntimeError> {
    if length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation zero-fill exceeds its bounded allocation size",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 Automation zero-fill",
            error,
        )
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn allocation_failure_pointer(error: RuntimeError) -> Result<u32, RuntimeError> {
    match error.kind() {
        Kind::InvalidInput | Kind::ResourceExhausted => Ok(0),
        _ => Err(error),
    }
}

fn hresult_from_runtime(error: RuntimeError) -> Result<u32, RuntimeError> {
    match error.kind() {
        Kind::InvalidInput => Ok(E_INVALIDARG),
        Kind::ResourceExhausted => Ok(E_OUTOFMEMORY),
        Kind::CompatibilityGap => Ok(E_NOTIMPL),
        Kind::HostFailure | Kind::GuestFault | Kind::InternalInvariant | Kind::ExecutionLimit => {
            Err(error)
        }
    }
}

fn read_u32(selectors: &SelectorTable, memory: &Memory, far: u32) -> Result<u32, RuntimeError> {
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let bytes = super::read_guest_far_bytes(selectors, memory, pointer, 4)?;
    Ok(u32::from_le_bytes(bytes.as_slice().try_into().map_err(
        |_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 Automation DWORD copy has an unexpected length",
            )
        },
    )?))
}

fn write_u32(
    selectors: &SelectorTable,
    memory: &mut Memory,
    far: u32,
    value: u32,
) -> Result<(), RuntimeError> {
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    super::write_guest_far_bytes(selectors, memory, pointer, &value.to_le_bytes())
}

fn validate_writable_range(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
    length: usize,
) -> Result<(), RuntimeError> {
    super::validate_guest_far_range(selectors, memory, far, length, win16_abi::Access::Write)
}
