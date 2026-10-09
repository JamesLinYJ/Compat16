//! Stack argument decoding for KERNEL file open, creation, seek, and count APIs.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{dword_argument, read_far_string, read_nullable_far_string, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelLclose => Win16ApiRequest::Kernel(super::Win16KernelRequest::Files(
            super::Win16KernelFilesRequest::CloseFile {
                file_handle: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::KernelLopen => Win16ApiRequest::Kernel(super::Win16KernelRequest::Files(
            super::Win16KernelFilesRequest::OpenFile {
                path: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
                mode: word_argument(arguments, 1)? as i16,
            },
        )),
        Win16ExportId::KernelOpenFile => Win16ApiRequest::Kernel(super::Win16KernelRequest::Files(
            super::Win16KernelFilesRequest::OpenStructuredFile {
                path: read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?
                    .unwrap_or_default(),
                ofstruct: dword_argument(arguments, 1)?,
                style: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::KernelLlseek => Win16ApiRequest::Kernel(super::Win16KernelRequest::Files(
            super::Win16KernelFilesRequest::SeekFile {
                file_handle: word_argument(arguments, 0)?,
                offset: dword_argument(arguments, 1)? as i32,
                origin: word_argument(arguments, 2)? as i16,
            },
        )),
        Win16ExportId::KernelLcreat => {
            let path = read_far_string(dword_argument(arguments, 0)?, selectors, memory)?;
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Files(
                super::Win16KernelFilesRequest::CreateFile {
                    path,
                    attributes: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelSetHandleCount => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::SetHandleCount {
                requested_count: word_argument(arguments, 0)?,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}
