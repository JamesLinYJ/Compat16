//! Stack argument decoding for KERNEL global and local heap exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{dword_argument, word_argument};
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelGlobalAlloc => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalAlloc {
                    flags: word_argument(arguments, 0)?,
                    size: dword_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelGlobalFree => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalFree {
                    handle: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelGlobalLock => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalLock {
                    handle: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelGlobalUnlock => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalUnlock {
                    handle: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelGlobalSize => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalSize {
                    handle: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelGlobalHandle => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::GlobalMemory(
                super::Win16KernelGlobalMemoryRequest::GlobalHandle {
                    selector: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelLocalInit => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalInit {
                selector: word_argument(arguments, 0)?,
                start: word_argument(arguments, 1)?,
                end: word_argument(arguments, 2)?,
            }),
        ),
        Win16ExportId::KernelLocalAlloc => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalAlloc {
                flags: word_argument(arguments, 0)?,
                size: word_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::KernelLocalReAlloc => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::LocalHeap(
                super::Win16KernelLocalHeapRequest::LocalReAlloc {
                    handle: word_argument(arguments, 0)?,
                    size: word_argument(arguments, 1)?,
                    flags: word_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::KernelLocalFree => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalFree {
                handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalLock => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalLock {
                handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalUnlock => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalUnlock {
                handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalSize => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalSize {
                handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalHandle => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalHandle {
                offset: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalFlags => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalFlags {
                handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelLocalCompact => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::LocalHeap(
                super::Win16KernelLocalHeapRequest::LocalCompact {
                    minimum: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelLocalCountFree => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::LocalHeap(
                super::Win16KernelLocalHeapRequest::LocalCountFree,
            ))
        }
        Win16ExportId::KernelLocalHeapSize => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::LocalHeap(super::Win16KernelLocalHeapRequest::LocalHeapSize),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}
