//! Stack argument decoding for KERNEL local-atom exports.

use super::super::Win16ExportId;
use super::super::request::{Win16ApiRequest, Win16KernelAtomsRequest, Win16KernelRequest};
use super::call_helpers::{checked_output_buffer, dword_argument, read_atom_name, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::KernelInitAtomTable => Win16KernelAtomsRequest::InitAtomTable {
            buckets: word_argument(arguments, 0)? as i16,
        },
        Win16ExportId::KernelFindAtom => Win16KernelAtomsRequest::FindAtom {
            name: read_atom_name(dword_argument(arguments, 0)?, selectors, memory)?,
        },
        Win16ExportId::KernelAddAtom => Win16KernelAtomsRequest::AddAtom {
            name: read_atom_name(dword_argument(arguments, 0)?, selectors, memory)?,
        },
        Win16ExportId::KernelDeleteAtom => Win16KernelAtomsRequest::DeleteAtom {
            atom: word_argument(arguments, 0)?,
        },
        Win16ExportId::KernelGetAtomName => {
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
            Win16KernelAtomsRequest::GetAtomName { atom, output_buffer }
        }
        Win16ExportId::KernelGetAtomHandle => Win16KernelAtomsRequest::GetAtomHandle {
            atom: word_argument(arguments, 0)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::Kernel(Win16KernelRequest::Atoms(request)))
}

#[cfg(test)]
#[path = "call_kernel_atoms_tests.rs"]
mod tests;
