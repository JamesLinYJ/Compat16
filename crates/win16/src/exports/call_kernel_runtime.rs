//! Stack argument decoding for KERNEL task and process runtime exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{dword_argument, word_argument};
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelYield => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::Yield),
        ),
        Win16ExportId::KernelGetVersion => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::GetVersion),
        ),
        Win16ExportId::KernelGetCurrentTask => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::GetCurrentTask),
        ),
        Win16ExportId::KernelGetDriveType => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::GetDriveType {
                drive: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelSetErrorMode => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::SetErrorMode {
                mode: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelWaitEvent => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::WaitEvent {
                task_handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelPostEvent => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::PostEvent {
                task_handle: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::KernelMakeProcInstance => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Runtime(
                super::Win16KernelRuntimeRequest::MakeProcInstance {
                    procedure: dword_argument(arguments, 0)?,
                    instance: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::KernelFreeProcInstance => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Runtime(
                super::Win16KernelRuntimeRequest::FreeProcInstance {
                    procedure: dword_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::KernelExitProcess => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Runtime(super::Win16KernelRuntimeRequest::ExitProcess {
                status: word_argument(arguments, 0)?,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}
