//! Typed KERNEL queries over the guest task registry.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16KernelTaskRequest {
    GetCurrentPDB,
    GetDOSEnvironment,
    GetNumTasks,
    GetTaskDS,
    IsTask { task: u16 },
}

pub fn decode_kernel_task(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16KernelTaskRequest>, Win16Error> {
    match ordinal {
        37 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetCurrentPDB)),
        37 => Err(Win16Error::InvalidRange),
        131 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetDOSEnvironment)),
        131 => Err(Win16Error::InvalidRange),
        155 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetTaskDS)),
        155 => Err(Win16Error::InvalidRange),
        152 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetNumTasks)),
        152 => Err(Win16Error::InvalidRange),
        320 => match arguments.first() {
            Some(Win16Argument::Word(task)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::IsTask { task: *task }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        _ => Ok(None),
    }
}
