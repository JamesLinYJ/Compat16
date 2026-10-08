//! Decode the documented KERNEL diagnostic APIs from checked Pascal frames.

use guest_core::GuestMemory;
use crate::{SelectorTable, Win16Argument, Win16Error, Win16ExportId, MAX_WIN16_STRING_BYTES};
use super::request::Win16KernelDiagnosticRequest;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16KernelDiagnosticRequest>, Win16Error> {
    let request = match (export, arguments) {
        (Win16ExportId::KernelOutputDebugString, [Win16Argument::Dword(pointer)]) => {
            Win16KernelDiagnosticRequest::OutputDebugString {
                message: read_ordinary_far_string(selectors, memory, *pointer)?,
            }
        }
        (Win16ExportId::KernelFatalAppExit,
            [Win16Argument::Word(action), Win16Argument::Dword(pointer)]) => {
            Win16KernelDiagnosticRequest::FatalAppExit {
                action: *action,
                message: read_ordinary_far_string(selectors, memory, *pointer)?,
            }
        }
        (Win16ExportId::KernelFatalExit, [Win16Argument::Word(error_code)]) => {
            Win16KernelDiagnosticRequest::FatalExit {
                error_code: *error_code as i16,
            }
        }
        (Win16ExportId::KernelDebugBreak, []) => Win16KernelDiagnosticRequest::DebugBreak,
        (Win16ExportId::KernelOutputDebugString
            | Win16ExportId::KernelFatalAppExit
            | Win16ExportId::KernelFatalExit
            | Win16ExportId::KernelDebugBreak, _) => return Err(Win16Error::InvalidRange),
        _ => return Ok(None),
    };
    Ok(Some(request))
}

/// LPCSTR is an ordinary FAR pointer: bound the copy by its current selector
/// instead of traversing adjacent descriptors in the same huge allocation.
fn read_ordinary_far_string(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    let remaining = descriptor.limit
        .checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let bound = remaining.min(MAX_WIN16_STRING_BYTES);
    let mut result = Vec::new();
    result.try_reserve(bound.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..bound {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(result);
        }
        result.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        result.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}
