//! Stack argument decoding for KERNEL module and procedure lookup exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{
    checked_output_buffer, dword_argument, module_handle_reference, module_reference,
    procedure_reference, read_far_string, word_argument,
};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelGetModuleFileName => {
            let module = word_argument(arguments, 0)?;
            let far_output = dword_argument(arguments, 1)?;
            let signed_capacity = word_argument(arguments, 2)? as i16;
            let output = if signed_capacity <= 0 {
                None
            } else {
                Some(checked_output_buffer(
                    far_output,
                    signed_capacity as u16,
                    selectors,
                    memory,
                )?)
            };
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Modules(
                super::Win16KernelModulesRequest::GetModuleFileName { module, output },
            ))
        }
        Win16ExportId::KernelGetModuleHandle => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Modules(super::Win16KernelModulesRequest::GetModuleHandle {
                module: module_reference(dword_argument(arguments, 0)?, selectors, memory)?,
            }),
        ),
        Win16ExportId::KernelGetModuleUsage => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Modules(super::Win16KernelModulesRequest::GetModuleUsage {
                module: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelGetProcAddress => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Modules(super::Win16KernelModulesRequest::GetProcAddress {
                module: module_handle_reference(word_argument(arguments, 0)?),
                procedure: procedure_reference(dword_argument(arguments, 1)?, selectors, memory)?,
            }),
        ),
        Win16ExportId::KernelLoadLibrary => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Modules(super::Win16KernelModulesRequest::LoadLibrary {
                library_name: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            }),
        ),
        Win16ExportId::KernelFreeLibrary => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Modules(super::Win16KernelModulesRequest::FreeLibrary {
                module: word_argument(arguments, 0)?,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}
