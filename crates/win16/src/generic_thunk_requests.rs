//! Owned requests for the six KERNEL generic-thunk exports.
//!
//! Microsoft Learn documents the argument and result contracts for
//! [`LoadLibraryEx32W`](https://learn.microsoft.com/en-us/previous-versions/aa383716(v=vs.85)),
//! [`FreeLibrary32W`](https://learn.microsoft.com/en-us/previous-versions/aa383685(v=vs.85)),
//! [`GetProcAddress32W`](https://learn.microsoft.com/en-us/previous-versions/aa383696(v=vs.85)),
//! [`GetVDMPointer32W`](https://learn.microsoft.com/en-us/previous-versions/aa383698(v=vs.85)),
//! and [`CallProcEx32W`](https://learn.microsoft.com/en-us/previous-versions/aa383672(v=vs.85)).
//! The project-owned KERNEL declarations at
//! `abi/groups/kernel/thunks.toml` provide the Win16 stack widths and
//! source conventions. All frame reads and source cleanup calculations go
//! through `Win16CallFrame`; strings use the bounded shared ANSI-Z reader.

use guest_core::GuestMemory;

use crate::{
    ArgumentKind, SelectorTable, StackCleanup, Win16Argument, Win16CallFrame,
    Win16CallingConvention, Win16Error, MAX_WIN16_STRING_BYTES,
};

use super::{
    decode_generic_thunk_frame, Win16GenericThunkApi, Win16GenericThunkFrame,
};

const DWORD_ARGUMENT: &[ArgumentKind] = &[ArgumentKind::Dword];
const TWO_DWORD_ARGUMENTS: &[ArgumentKind] = &[ArgumentKind::Dword, ArgumentKind::Dword];
const THREE_DWORD_ARGUMENTS: &[ArgumentKind] = &[
    ArgumentKind::Dword,
    ArgumentKind::Dword,
    ArgumentKind::Dword,
];
const FAR_POINTER_AND_WORD_ARGUMENTS: &[ArgumentKind] =
    &[ArgumentKind::Dword, ArgumentKind::Word];

/// KERNEL export identities in the generic-thunk family.
///
/// Ordinal 518 is named `_CallProcEx32W` in the project-owned KERNEL spec and
/// `CallProcEx32W` in Microsoft's API documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Win16GenericThunkExport {
    LoadLibraryEx32W,
    FreeLibrary32W,
    GetProcAddress32W,
    GetVDMPointer32W,
    CallProc32W,
    CallProcEx32W,
}

impl Win16GenericThunkExport {
    /// Resolve one of the KERNEL.513–518 generic-thunk exports.
    pub const fn from_kernel_ordinal(ordinal: u16) -> Option<Self> {
        match ordinal {
            513 => Some(Self::LoadLibraryEx32W),
            514 => Some(Self::FreeLibrary32W),
            515 => Some(Self::GetProcAddress32W),
            516 => Some(Self::GetVDMPointer32W),
            517 => Some(Self::CallProc32W),
            518 => Some(Self::CallProcEx32W),
            _ => None,
        }
    }

    /// Return this export's ordinal in the project-owned KERNEL specification.
    pub const fn kernel_ordinal(self) -> u16 {
        match self {
            Self::LoadLibraryEx32W => 513,
            Self::FreeLibrary32W => 514,
            Self::GetProcAddress32W => 515,
            Self::GetVDMPointer32W => 516,
            Self::CallProc32W => 517,
            Self::CallProcEx32W => 518,
        }
    }
}

/// Checked, owned arguments for a Win16 generic-thunk export.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Win16GenericThunkRequest {
    /// Success returns a 32-bit module handle; failure returns NULL.
    LoadLibraryEx32W {
        /// Original guest FAR string address; it is never a host pointer.
        library_name_far: u32,
        /// Bounded owned copy of the null-terminated ANSI library name,
        /// excluding its terminator.
        library_name: Vec<u8>,
        /// Retained exactly, even though Microsoft documents this field as
        /// reserved and requiring NULL.
        reserved_hfile: u32,
        /// Retained exactly so the host adapter can apply the target OS rules.
        flags: u32,
        /// Exact source argument cleanup; excludes the return address.
        source_stack_cleanup: StackCleanup,
    },
    /// Success returns TRUE and failure returns FALSE.
    FreeLibrary32W {
        /// Opaque 32-bit module identity returned by `LoadLibraryEx32W`.
        module_handle: u32,
        /// Exact source argument cleanup; excludes the return address.
        source_stack_cleanup: StackCleanup,
    },
    /// Success returns an opaque 32-bit procedure token for `CallProcEx32W`.
    GetProcAddress32W {
        /// Opaque 32-bit module identity returned by `LoadLibraryEx32W`.
        module_handle: u32,
        /// Original guest FAR string address; it is never a host pointer.
        procedure_name_far: u32,
        /// Bounded owned copy of the null-terminated procedure name,
        /// excluding its terminator.
        procedure_name: Vec<u8>,
        /// Exact source argument cleanup; excludes the return address.
        source_stack_cleanup: StackCleanup,
    },
    /// Success returns a 32-bit linear address or NULL. A returned linear
    /// address can become invalid after guest global-memory movement.
    GetVDMPointer32W {
        /// Raw 16:16 guest address. It is not resolved to a host pointer here;
        /// it may be either a real-mode or protected-mode address.
        address_far: u32,
        /// Raw Win16 `UINT` value. Microsoft documents 0 for real mode and 1
        /// for protected mode; the decoder retains other values unchanged.
        mode: u16,
        /// Exact source argument cleanup; excludes the return address.
        source_stack_cleanup: StackCleanup,
    },
    /// The result and cleanup disposition are carried by the existing dynamic
    /// frame decoder; this layer does not invoke the target procedure.
    CallProc32W(Win16GenericThunkFrame),
    /// The result and cleanup disposition are carried by the existing dynamic
    /// frame decoder; this layer does not invoke the target procedure.
    CallProcEx32W(Win16GenericThunkFrame),
}

/// Decode one KERNEL.513–518 request from its checked Win16 entry frame.
///
/// `Ok(None)` means the ordinal is outside this family. Guest strings are
/// copied into owned bytes. Module handles, procedure tokens, raw flags, and
/// FAR addresses remain guest values; no host pointer or handle is created.
pub fn decode_generic_thunk_export(
    ordinal: u16,
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16GenericThunkRequest>, Win16Error> {
    let Some(export) = Win16GenericThunkExport::from_kernel_ordinal(ordinal) else {
        return Ok(None);
    };

    let request = match export {
        Win16GenericThunkExport::LoadLibraryEx32W => {
            let (arguments, source_stack_cleanup) = decode_fixed_frame(
                frame,
                selectors,
                memory,
                THREE_DWORD_ARGUMENTS,
            )?;
            let library_name_far = dword_argument(&arguments, 0)?;
            let library_name = crate::strings::read_ansi_z(
                selectors,
                memory,
                library_name_far,
                MAX_WIN16_STRING_BYTES,
            )?;
            Win16GenericThunkRequest::LoadLibraryEx32W {
                library_name_far,
                library_name,
                reserved_hfile: dword_argument(&arguments, 1)?,
                flags: dword_argument(&arguments, 2)?,
                source_stack_cleanup,
            }
        }
        Win16GenericThunkExport::FreeLibrary32W => {
            let (arguments, source_stack_cleanup) =
                decode_fixed_frame(frame, selectors, memory, DWORD_ARGUMENT)?;
            Win16GenericThunkRequest::FreeLibrary32W {
                module_handle: dword_argument(&arguments, 0)?,
                source_stack_cleanup,
            }
        }
        Win16GenericThunkExport::GetProcAddress32W => {
            let (arguments, source_stack_cleanup) = decode_fixed_frame(
                frame,
                selectors,
                memory,
                TWO_DWORD_ARGUMENTS,
            )?;
            let module_handle = dword_argument(&arguments, 0)?;
            let procedure_name_far = dword_argument(&arguments, 1)?;
            // The Microsoft 32W contract declares LPCSTR and explicitly calls
            // this a null-terminated function-name string. It does not define
            // the low-word ordinal convention used by other GetProcAddress
            // interfaces, so this decoder deliberately does not infer ordinals.
            let procedure_name = crate::strings::read_ansi_z(
                selectors,
                memory,
                procedure_name_far,
                MAX_WIN16_STRING_BYTES,
            )?;
            Win16GenericThunkRequest::GetProcAddress32W {
                module_handle,
                procedure_name_far,
                procedure_name,
                source_stack_cleanup,
            }
        }
        Win16GenericThunkExport::GetVDMPointer32W => {
            let (arguments, source_stack_cleanup) = decode_fixed_frame(
                frame,
                selectors,
                memory,
                FAR_POINTER_AND_WORD_ARGUMENTS,
            )?;
            Win16GenericThunkRequest::GetVDMPointer32W {
                address_far: dword_argument(&arguments, 0)?,
                mode: word_argument(&arguments, 1)?,
                source_stack_cleanup,
            }
        }
        Win16GenericThunkExport::CallProc32W => {
            Win16GenericThunkRequest::CallProc32W(decode_generic_thunk_frame(
                Win16GenericThunkApi::CallProc32W,
                frame,
                selectors,
                memory,
            )?)
        }
        Win16GenericThunkExport::CallProcEx32W => {
            Win16GenericThunkRequest::CallProcEx32W(decode_generic_thunk_frame(
                Win16GenericThunkApi::CallProcEx32W,
                frame,
                selectors,
                memory,
            )?)
        }
    };

    Ok(Some(request))
}

fn decode_fixed_frame(
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    signature: &[ArgumentKind],
) -> Result<(Vec<Win16Argument>, StackCleanup), Win16Error> {
    let arguments = frame.decode_arguments(
        selectors,
        memory,
        Win16CallingConvention::Pascal,
        signature,
    )?;
    let cleanup = frame.cleanup(
        Win16CallingConvention::Pascal,
        signature,
    )?;
    Ok((arguments, cleanup))
}

fn dword_argument(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn word_argument(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}
