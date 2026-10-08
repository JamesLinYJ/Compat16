//! Stack argument decoding for Win16 file and huge-memory operations.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::{dword_argument, word_argument};
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    match export {
        Win16ExportId::KernelLread => Ok(Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::ReadFile {
                file_handle: word_argument(arguments, 0)?,
                buffer: dword_argument(arguments, 1)?,
                count: i32::from(word_argument(arguments, 2)?),
            }),
        )),
        Win16ExportId::KernelHread => Ok(Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::ReadFile {
                file_handle: word_argument(arguments, 0)?,
                buffer: dword_argument(arguments, 1)?,
                count: dword_argument(arguments, 2)? as i32,
            }),
        )),
        Win16ExportId::KernelLwrite => Ok(Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::WriteFile {
                file_handle: word_argument(arguments, 0)?,
                buffer: dword_argument(arguments, 1)?,
                count: i32::from(word_argument(arguments, 2)?),
            }),
        )),
        Win16ExportId::KernelHwrite => Ok(Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::WriteFile {
                file_handle: word_argument(arguments, 0)?,
                buffer: dword_argument(arguments, 1)?,
                count: dword_argument(arguments, 2)? as i32,
            }),
        )),
        Win16ExportId::KernelHmemcpy => Ok(Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Files(super::Win16KernelFilesRequest::HugeMemoryCopy {
                destination: dword_argument(arguments, 0)?,
                source: dword_argument(arguments, 1)?,
                count: dword_argument(arguments, 2)? as i32,
            }),
        )),
        _ => Err(Win16Error::InvalidRange),
    }
}
