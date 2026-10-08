//! Stack argument decoding for the Win16 KERNEL resource API family.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::{dword_argument, read_far_string, word_argument};
use crate::{SelectorTable, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::KernelFindResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::FindResource {
                    module: word_argument(arguments, 0)?,
                    name: resource_name(dword_argument(arguments, 1)?, selectors, memory)?,
                    resource_type: resource_name(dword_argument(arguments, 2)?, selectors, memory)?,
                },
            ))
        }
        Win16ExportId::KernelLoadResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::LoadResource {
                    module: word_argument(arguments, 0)?,
                    info: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelLockResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::LockResource {
                    data: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelFreeResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::FreeResource {
                    data: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelAccessResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::AccessResource {
                    module: word_argument(arguments, 0)?,
                    info: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelSizeofResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::SizeofResource {
                    module: word_argument(arguments, 0)?,
                    info: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelAllocResource => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::AllocResource {
                    module: word_argument(arguments, 0)?,
                    info: word_argument(arguments, 1)?,
                    size: dword_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::KernelSetResourceHandler => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::SetResourceHandler {
                    module: word_argument(arguments, 0)?,
                    type_name: resource_name(dword_argument(arguments, 1)?, selectors, memory)?,
                    handler: dword_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::KernelDefResourceHandler => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Resources(
                super::Win16KernelResourcesRequest::DefResourceHandler {
                    data: word_argument(arguments, 0)?,
                    module: word_argument(arguments, 1)?,
                    info: word_argument(arguments, 2)?,
                },
            ))
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn resource_name(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ResourceName, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16ResourceName::Id(raw as u16))
    } else {
        read_far_string(raw, selectors, memory).map(Win16ResourceName::Name)
    }
}
