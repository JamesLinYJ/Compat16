//! Typed decoders for the implemented KERNEL, TOOLHELP, and SYSTEM services.

use guest_core::GuestMemory;

use super::super::request::*;
use super::{
    Win16ApiRequest, Win16ExportId,
    call_helpers::{
        ansi_case_target, checked_output_buffer, dword_argument, read_nullable_far_string,
        word_argument,
    },
};
use crate::{SelectorTable, Win16Argument, Win16Error};

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    let ordinal = export.ordinal();
    if export.module().eq_ignore_ascii_case("KERNEL") {
        if ordinal == 59 {
            return Ok(Some(Win16ApiRequest::Kernel(
                super::Win16KernelRequest::Profiles(
                    super::Win16KernelProfilesRequest::WritePrivateProfileString {
                        section: read_nullable_far_string(
                            dword_argument(arguments, 0)?,
                            selectors,
                            memory,
                        )?,
                        key: read_nullable_far_string(
                            dword_argument(arguments, 1)?,
                            selectors,
                            memory,
                        )?,
                        value: read_nullable_far_string(
                            dword_argument(arguments, 2)?,
                            selectors,
                            memory,
                        )?,
                        filename: None,
                    },
                ),
            )));
        }
        if ordinal == 142 {
            return Ok(Some(Win16ApiRequest::Kernel(
                super::Win16KernelRequest::Profiles(
                    super::Win16KernelProfilesRequest::GetProfileString {
                        section: None,
                        key: None,
                        default_value: None,
                        output_buffer: checked_output_buffer(
                            dword_argument(arguments, 0)?,
                            word_argument(arguments, 1)?,
                            selectors,
                            memory,
                        )?,
                    },
                ),
            )));
        }
        if ordinal == 143 {
            return Ok(Some(Win16ApiRequest::Kernel(
                super::Win16KernelRequest::Profiles(
                    super::Win16KernelProfilesRequest::GetPrivateProfileString {
                        section: None,
                        key: None,
                        default_value: None,
                        output_buffer: checked_output_buffer(
                            dword_argument(arguments, 0)?,
                            word_argument(arguments, 1)?,
                            selectors,
                            memory,
                        )?,
                        filename: read_nullable_far_string(
                            dword_argument(arguments, 2)?,
                            selectors,
                            memory,
                        )?,
                    },
                ),
            )));
        }
        if ordinal == 26 {
            return Ok(Some(Win16ApiRequest::KernelGlobalHeap(
                Win16KernelGlobalHeapRequest::GlobalFreeAll {
                    owner: word_argument(arguments, 0)?,
                },
            )));
        }
        if ordinal == 159 {
            return Ok(Some(Win16ApiRequest::Kernel(
                super::Win16KernelRequest::GlobalMemory(
                    super::Win16KernelGlobalMemoryRequest::GlobalHandle {
                        selector: word_argument(arguments, 0)?,
                    },
                ),
            )));
        }
        match export {
            Win16ExportId::KernelReserved1 => {
                return Ok(Some(Win16ApiRequest::User(super::Win16UserRequest::Ansi(
                    super::Win16UserAnsiRequest::AnsiNext {
                        pointer: dword_argument(arguments, 0)?,
                    },
                ))));
            }
            Win16ExportId::KernelReserved2 => {
                return Ok(Some(Win16ApiRequest::User(super::Win16UserRequest::Ansi(
                    super::Win16UserAnsiRequest::AnsiPrev {
                        start: dword_argument(arguments, 0)?,
                        current: dword_argument(arguments, 1)?,
                    },
                ))));
            }
            Win16ExportId::KernelReserved3 => {
                return Ok(Some(Win16ApiRequest::User(super::Win16UserRequest::Ansi(
                    super::Win16UserAnsiRequest::AnsiUpper {
                        target: ansi_case_target(dword_argument(arguments, 0)?, selectors, memory)?,
                    },
                ))));
            }
            Win16ExportId::KernelReserved4 => {
                return Ok(Some(Win16ApiRequest::User(super::Win16UserRequest::Ansi(
                    super::Win16UserAnsiRequest::AnsiLower {
                        target: ansi_case_target(dword_argument(arguments, 0)?, selectors, memory)?,
                    },
                ))));
            }
            _ => {}
        }
        if let Some(request) = decode_kernel_memory(ordinal, arguments)? {
            return Ok(Some(Win16ApiRequest::KernelMemory(request)));
        }
        if let Some(request) = decode_kernel_task(ordinal, arguments)? {
            return Ok(Some(Win16ApiRequest::KernelTask(request)));
        }
        if let Some(request) = decode_kernel_module(ordinal, arguments)? {
            return Ok(Some(Win16ApiRequest::KernelModule(request)));
        }
        if let Some(request) = decode_kernel_string(ordinal, arguments, selectors, memory)? {
            return Ok(Some(Win16ApiRequest::KernelString(request)));
        }
    } else if export.module().eq_ignore_ascii_case("TOOLHELP") {
        if let Some(request) = decode_toolhelp(ordinal, arguments, selectors, memory)? {
            return Ok(Some(Win16ApiRequest::Toolhelp(request)));
        }
    } else if export.module().eq_ignore_ascii_case("SYSTEM") {
        if let Some(request) = decode_system(ordinal, arguments)? {
            return Ok(Some(Win16ApiRequest::System(request)));
        }
    }
    Ok(None)
}
