//! Shared checked argument, string, and output-buffer decoders.

use super::super::{
    Win16AnsiCaseTarget, Win16AtomName, Win16ModuleReference, Win16OutputBuffer,
    Win16ProcReference, MAX_WIN16_STRING_BYTES,
};
use crate::{
    Access, SelectorTable, StackCleanup, Win16Argument, Win16CallFrame, Win16CallingConvention,
    Win16Error,
};
use guest_core::GuestMemory;

use super::super::{
    ExportCallingConvention, Win16ExportAbiKind, Win16ExportDescriptor, Win16ExportId,
    Win16ExportStackCleanup,
};

/// Validate a fixed export frame and decode its declared scalar arguments.
///
/// Keeping ABI frame checks here leaves the top-level dispatcher responsible
/// only for routing the resulting request to its family decoder.
pub(super) fn decode_fixed_stack_frame(
    descriptor: &Win16ExportDescriptor,
    frame: Win16CallFrame,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<(Vec<Win16Argument>, StackCleanup), Win16Error> {
    match descriptor.id {
        Win16ExportId::KernelLoadLibraryEx32W
        | Win16ExportId::KernelFreeLibrary32W
        | Win16ExportId::KernelGetProcAddress32W
        | Win16ExportId::KernelGetVDMPointer32W => {
            return Err(Win16Error::GenericThunkRequiresSpecialDecoder);
        }
        Win16ExportId::KernelCallProc32W | Win16ExportId::KernelCallProcEx32W => {
            return Err(Win16Error::VariableStackRequiresSpecialDecoder);
        }
        _ => {}
    }

    match descriptor.abi_kind {
        Win16ExportAbiKind::Stack => {}
        Win16ExportAbiKind::VariableStack => {
            return Err(Win16Error::VariableStackRequiresSpecialDecoder);
        }
        Win16ExportAbiKind::RegisterContext => return Err(Win16Error::RegisterContextRequired),
    }
    let stack_cleanup = match descriptor.stack_cleanup {
        Win16ExportStackCleanup::Fixed(cleanup) => cleanup,
        Win16ExportStackCleanup::Variable => {
            return Err(Win16Error::VariableStackRequiresSpecialDecoder);
        }
    };
    let calling_convention = match descriptor.calling_convention {
        ExportCallingConvention::Pascal => Win16CallingConvention::Pascal,
        ExportCallingConvention::Cdecl => Win16CallingConvention::Cdecl,
        ExportCallingConvention::Varargs => {
            return Err(Win16Error::VariableStackRequiresSpecialDecoder);
        }
        _ => return Err(Win16Error::UnsupportedCallingConvention),
    };
    let kinds: Vec<_> = descriptor
        .parameters
        .iter()
        .map(|parameter| parameter.kind)
        .collect();
    let arguments = frame.decode_arguments(selectors, memory, calling_convention, &kinds)?;
    Ok((arguments, stack_cleanup))
}

pub(in crate::exports) fn word_argument(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

pub(in crate::exports) fn dword_argument(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

pub(super) fn module_reference(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ModuleReference, Win16Error> {
    if raw >> 16 == 0 {
        Ok(module_handle_reference(raw as u16))
    } else {
        read_far_string(raw, selectors, memory).map(Win16ModuleReference::Name)
    }
}

pub(super) fn module_handle_reference(handle: u16) -> Win16ModuleReference {
    if handle == 0 {
        Win16ModuleReference::Current
    } else {
        Win16ModuleReference::Handle(handle)
    }
}

pub(super) fn procedure_reference(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ProcReference, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16ProcReference::Ordinal(raw as u16))
    } else {
        read_far_string(raw, selectors, memory).map(Win16ProcReference::Name)
    }
}

pub(super) fn ansi_case_target(
    pointer_or_char: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16AnsiCaseTarget, Win16Error> {
    if pointer_or_char >> 16 == 0 {
        Ok(Win16AnsiCaseTarget::Char(pointer_or_char as u16))
    } else {
        let bytes = read_far_string(pointer_or_char, selectors, memory)?;
        Ok(Win16AnsiCaseTarget::String {
            pointer: pointer_or_char,
            bytes,
        })
    }
}

pub(super) fn read_far_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    crate::strings::read_ansi_z(selectors, memory, far, MAX_WIN16_STRING_BYTES)
}

pub(in crate::exports) fn read_nullable_far_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    if far == 0 {
        Ok(None)
    } else {
        read_far_string(far, selectors, memory).map(Some)
    }
}

pub(super) fn read_atom_name(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16AtomName, Win16Error> {
    if far >> 16 == 0 {
        Ok(Win16AtomName::Integer(far as u16))
    } else {
        read_far_string(far, selectors, memory).map(Win16AtomName::String)
    }
}

pub(in crate::exports) fn checked_output_buffer(
    far: u32,
    capacity: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16OutputBuffer, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let mut pointer = start;
    let mut remaining = usize::from(capacity);
    if remaining == 0 {
        selectors.translate(pointer, Access::Write, 0, memory)?;
    }
    while remaining > 0 {
        let descriptor = selectors.describe(pointer.selector())?;
        let bytes_in_segment = descriptor
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = remaining.min(bytes_in_segment);
        if chunk == 0 {
            return Err(Win16Error::InvalidRange);
        }
        selectors.translate(pointer, Access::Write, chunk, memory)?;
        remaining -= chunk;
        if remaining > 0 {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(Win16OutputBuffer { pointer: start, capacity })
}
