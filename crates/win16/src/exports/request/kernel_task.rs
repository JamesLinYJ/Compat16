//! Typed KERNEL queries over the guest task registry.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16KernelTaskRequest {
    GetCurrentPDB,
    GetDOSEnvironment,
    GetNumTasks,
    GetTaskDS,
    IsTask { task: u16 },
    /// Signed priority adjustment. A zero task handle names the current task.
    SetPriority { task: u16, delta: i16 },
    /// Nonzero locks the current task; zero clears that lock.
    LockCurrentTask { lock: u16 },
    /// Guest queue word for a task. A zero task handle names the current task.
    SetTaskQueue { task: u16, queue: u16 },
    GetTaskQueue { task: u16 },
    OldYield,
    /// Queue of the task identified by the caller's DS or ES.
    GetTaskQueueDs,
    GetTaskQueueEs,
    IsTaskLocked,
    SetLastError { error: u32 },
    GetLastError,
    /// Far pointer to a caller-owned OSVERSIONINFO. Never a host pointer.
    GetVersionEx { version_info: u32 },
    /// Requested task handle. This runtime does not switch to it.
    DirectedYield { task: u16 },
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
        32 => match (arguments.first(), arguments.get(1)) {
            (Some(Win16Argument::Word(task)), Some(Win16Argument::Word(delta)))
                if arguments.len() == 2 =>
            {
                Ok(Some(Win16KernelTaskRequest::SetPriority {
                    task: *task,
                    delta: *delta as i16,
                }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        33 => match arguments.first() {
            Some(Win16Argument::Word(lock)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::LockCurrentTask { lock: *lock }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        34 => match (arguments.first(), arguments.get(1)) {
            (Some(Win16Argument::Word(task)), Some(Win16Argument::Word(queue)))
                if arguments.len() == 2 =>
            {
                Ok(Some(Win16KernelTaskRequest::SetTaskQueue {
                    task: *task,
                    queue: *queue,
                }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        35 => match arguments.first() {
            Some(Win16Argument::Word(task)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::GetTaskQueue { task: *task }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        117 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::OldYield)),
        117 => Err(Win16Error::InvalidRange),
        118 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetTaskQueueDs)),
        118 => Err(Win16Error::InvalidRange),
        119 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetTaskQueueEs)),
        119 => Err(Win16Error::InvalidRange),
        122 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::IsTaskLocked)),
        122 => Err(Win16Error::InvalidRange),
        147 => match arguments.first() {
            Some(Win16Argument::Dword(error)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::SetLastError { error: *error }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        148 if arguments.is_empty() => Ok(Some(Win16KernelTaskRequest::GetLastError)),
        148 => Err(Win16Error::InvalidRange),
        149 => match arguments.first() {
            Some(Win16Argument::Dword(version_info)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::GetVersionEx {
                    version_info: *version_info,
                }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        150 => match arguments.first() {
            Some(Win16Argument::Word(task)) if arguments.len() == 1 => {
                Ok(Some(Win16KernelTaskRequest::DirectedYield { task: *task }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        _ => Ok(None),
    }
}
