//! Stack argument decoding for KERNEL instance and code-segment queries.

use super::{Win16ExportId, Win16ApiRequest};
use super::call::call_helpers::{dword_argument, word_argument};
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::KernelGetInstanceData => {
            super::Win16KernelInstanceRequest::GetInstanceData {
                previous_instance: word_argument(arguments, 0)?,
                buffer_offset: word_argument(arguments, 1)?,
                byte_count: word_argument(arguments, 2)?,
            }
        }
        Win16ExportId::KernelGetCodeHandle => super::Win16KernelInstanceRequest::GetCodeHandle {
            procedure: dword_argument(arguments, 0)?,
        },
        Win16ExportId::KernelGetCodeInfo => super::Win16KernelInstanceRequest::GetCodeInfo {
            procedure_or_module_segment: dword_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::Kernel(
        super::Win16KernelRequest::Instance(request),
    ))
}
