//! Stack argument decoding for USER global-atom exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{checked_output_buffer, dword_argument, read_atom_name, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::UserGlobalAddAtom => Win16ApiRequest::User(super::Win16UserRequest::Atoms(
            super::Win16UserAtomsRequest::GlobalAddAtom {
                name: read_atom_name(dword_argument(arguments, 0)?, selectors, memory)?,
            },
        )),
        Win16ExportId::UserGlobalDeleteAtom => Win16ApiRequest::User(
            super::Win16UserRequest::Atoms(super::Win16UserAtomsRequest::GlobalDeleteAtom {
                atom: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGlobalFindAtom => Win16ApiRequest::User(super::Win16UserRequest::Atoms(
            super::Win16UserAtomsRequest::GlobalFindAtom {
                name: read_atom_name(dword_argument(arguments, 0)?, selectors, memory)?,
            },
        )),
        Win16ExportId::UserGlobalGetAtomName => {
            let atom = word_argument(arguments, 0)?;
            let far_buffer = dword_argument(arguments, 1)?;
            let signed_capacity = word_argument(arguments, 2)? as i16;
            let output_buffer = if signed_capacity <= 0 {
                None
            } else {
                Some(checked_output_buffer(
                    far_buffer,
                    signed_capacity as u16,
                    selectors,
                    memory,
                )?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Atoms(
                super::Win16UserAtomsRequest::GlobalGetAtomName {
                    atom,
                    output_buffer,
                },
            ))
        }
        _ => return Err(Win16Error::InvalidRange),
    })
}
