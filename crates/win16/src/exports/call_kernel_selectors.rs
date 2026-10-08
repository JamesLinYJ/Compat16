//! Stack argument decoding for KERNEL selector alias and conversion exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{dword_argument, word_argument};
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelAllocSelector => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::AllocSelector {
                    source_selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelAllocCStoDSAlias => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::AllocCStoDSAlias {
                    source_selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelAllocDStoCSAlias => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::AllocDStoCSAlias {
                    source_selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelAllocAlias => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::AllocAlias {
                    source_selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelFreeSelector => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::FreeSelector {
                    selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelPrestoChangoSelector => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::PrestoChangoSelector {
                    source_selector: word_argument(arguments, 0)?,
                    destination_selector: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelGetSelectorBase => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::GetSelectorBase {
                    selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelSetSelectorBase => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::SetSelectorBase {
                    selector: word_argument(arguments, 0)?,
                    base: dword_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelGetSelectorLimit => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::GetSelectorLimit {
                    selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelSetSelectorLimit => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::SetSelectorLimit {
                    selector: word_argument(arguments, 0)?,
                    limit: dword_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelSelectorAccessRights => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::SelectorAccessRights {
                    selector: word_argument(arguments, 0)?,
                    operation: word_argument(arguments, 1)?,
                    access: word_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::KernelAllocSelectorArray => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::AllocSelectorArray {
                    count: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelLongPtrAdd => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::LongPtrAdd {
                    far_pointer: dword_argument(arguments, 0)?,
                    amount: dword_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelIsSharedSelector => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::IsSharedSelector {
                    selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelMapSL => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::MapSL {
                    far_pointer: dword_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelMapLS => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::MapLS {
                    guest_linear: dword_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelUnMapLS => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Selectors(
                super::Win16KernelSelectorsRequest::UnMapLS {
                    far_pointer: dword_argument(arguments, 0)?,
                },
            ))
        }
        _ => return Err(Win16Error::InvalidRange),
    })
}
