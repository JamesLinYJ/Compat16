//! Inventory-driven decoder for known-signature multimedia-family exports.

use super::{
    lookup_export_metadata, ExportArchitecture, ExportArgumentType, ExportEntryKind,
    ExportSignatureKind, ExportLookupTarget, Win16ApiRequest, Win16MultimediaArgument,
    Win16MultimediaCall, MAX_WIN16_STRING_BYTES,
};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

/// Decode a declared Win16 multimedia call without guessing any ABI details.
/// The descriptor catalog can call this after it has decoded the stack frame.
/// Only known-signature functions in the assigned modules are accepted;
/// stubs, data, Win32-only records, varargs and unsupported widths remain
/// unresolved for their ordinary trap/diagnostic path.
pub fn decode_multimedia_export(
    module: &[u8],
    target: ExportLookupTarget<'_>,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    let Some(declaration) = lookup_export_metadata(module, target) else {
        return Ok(None);
    };
    if declaration.architecture != ExportArchitecture::Win16
        || declaration.kind != ExportEntryKind::Function
        || !is_assigned_module(declaration.module)
    {
        return Ok(None);
    }
    let Some(abi) = declaration.abi else { return Ok(None); };
    if abi.signature != ExportSignatureKind::Known
        || matches!(abi.calling_convention, Some(super::ExportCallingConvention::Varargs))
        || abi.arguments.len() != arguments.len()
    {
        return Ok(None);
    }

    let mut decoded = Vec::new();
    decoded.try_reserve_exact(arguments.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    for (kind, value) in abi.arguments.iter().copied().zip(arguments.iter().copied()) {
        let Some(value) = decode_argument(kind, value, selectors, memory)? else {
            // This is an ABI-width boundary, not a default value. The export
            // remains on its unresolved path until a complete decoder exists.
            return Ok(None);
        };
        decoded.push(value);
    }

    Ok(Some(Win16ApiRequest::Multimedia(Win16MultimediaCall {
        module: declaration.module,
        ordinal: declaration.ordinal,
        name: declaration.name,
        arguments: decoded,
    })))
}

fn is_assigned_module(module: &str) -> bool {
    ["MMSYSTEM", "MSACM", "MSVIDEO", "AVIFILE", "SOUND"]
        .iter()
        .any(|expected| module.eq_ignore_ascii_case(expected))
}

fn decode_argument(
    kind: ExportArgumentType,
    value: Win16Argument,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16MultimediaArgument>, Win16Error> {
    let decoded = match (kind, value) {
        (ExportArgumentType::Word, Win16Argument::Word(value)) => {
            Win16MultimediaArgument::Word(value)
        }
        (ExportArgumentType::SignedWord, Win16Argument::Word(value)) => {
            Win16MultimediaArgument::SignedWord(value as i16)
        }
        (ExportArgumentType::Long, Win16Argument::Dword(value)) => {
            Win16MultimediaArgument::Dword(value)
        }
        (ExportArgumentType::SegmentedPointer | ExportArgumentType::Pointer,
            Win16Argument::Dword(value)) => Win16MultimediaArgument::GuestFarPointer(value),
        (ExportArgumentType::SegmentedString | ExportArgumentType::String,
            Win16Argument::Dword(value)) => {
            let bytes = crate::strings::read_ansi_z(
                selectors,
                memory,
                value,
                MAX_WIN16_STRING_BYTES,
            )?;
            Win16MultimediaArgument::AnsiString(bytes)
        }
        // These types need a different guest-stack or encoding rule. Do not
        // coerce them to DWORDs merely because the native API uses pointers.
        (ExportArgumentType::Int64 | ExportArgumentType::Int128
            | ExportArgumentType::Float | ExportArgumentType::Double
            | ExportArgumentType::WideString | ExportArgumentType::Unknown, _) => {
            return Ok(None);
        }
        // The metadata says a scalar; a frame with a different width is an
        // inconsistent catalog binding, so let the normal unresolved path
        // report it rather than reinterpreting the bits.
        _ => return Ok(None),
    };
    Ok(Some(decoded))
}
