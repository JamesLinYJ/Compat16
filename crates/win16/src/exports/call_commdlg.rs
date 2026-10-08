//! Decoding for the known Win16 common-dialog exports.

use super::Win16ExportDescriptor;
use super::request::{Win16ApiRequest, Win16CommdlgRequest};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    if descriptor.id.module() != "COMMDLG" {
        return Err(Win16Error::InvalidRange);
    }
    let request = decode_commdlg_arguments(
        descriptor.ordinal(), arguments, selectors, memory,
    )?
    .ok_or(Win16Error::InvalidRange)?;
    Ok(Win16ApiRequest::Commdlg(request))
}

/// Decode only the nine public COMMDLG APIs represented in the formal catalog.
/// Procedure exports remain callback entries and are deliberately not treated
/// as ordinary guest-to-host API calls.
pub(super) fn decode_commdlg_arguments(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16CommdlgRequest>, Win16Error> {
    let request = match (ordinal, arguments) {
        (1, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::GetOpenFileName { structure: *structure }
        }
        (2, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::GetSaveFileName { structure: *structure }
        }
        (5, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::ChooseColor { structure: *structure }
        }
        (11, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::FindText { structure: *structure }
        }
        (12, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::ReplaceText { structure: *structure }
        }
        (15, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::ChooseFont { structure: *structure }
        }
        (20, [Win16Argument::Dword(structure)]) => {
            Win16CommdlgRequest::PrintDlg { structure: *structure }
        }
        (26, []) => Win16CommdlgRequest::ExtendedError,
        (27, [Win16Argument::Dword(file), Win16Argument::Dword(title),
            Win16Argument::Word(capacity)]) => {
            if *file == 0 {
                return Err(Win16Error::InvalidRange);
            }
            let file_name = crate::strings::read_ansi_z(
                selectors, memory, *file, super::MAX_WIN16_STRING_BYTES,
            )?;
            Win16CommdlgRequest::GetFileTitle {
                file_name,
                title: *title,
                capacity: *capacity,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}
