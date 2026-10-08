//! Typed KERNEL queries over loaded NE module metadata.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16KernelModuleRequest {
    GetModuleName { module: u16, output: u32, capacity: u16 },
    GetExePtr { handle: u16 },
    GetExeVersion,
    GetExpWinVer { module: u16 },
}

pub fn decode_kernel_module(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16KernelModuleRequest>, Win16Error> {
    match ordinal {
        27 => match arguments {
            [Win16Argument::Word(module), Win16Argument::Dword(output), Win16Argument::Word(capacity)] => {
                Ok(Some(Win16KernelModuleRequest::GetModuleName {
                    module: *module, output: *output, capacity: *capacity,
                }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        105 if arguments.is_empty() => Ok(Some(Win16KernelModuleRequest::GetExeVersion)),
        105 => Err(Win16Error::InvalidRange),
        133 => match arguments {
            [Win16Argument::Word(handle)] => {
                Ok(Some(Win16KernelModuleRequest::GetExePtr { handle: *handle }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        167 => match arguments {
            [Win16Argument::Word(module)] => {
                Ok(Some(Win16KernelModuleRequest::GetExpWinVer { module: *module }))
            }
            _ => Err(Win16Error::InvalidRange),
        },
        _ => Ok(None),
    }
}
