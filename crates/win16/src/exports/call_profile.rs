//! Stack argument decoding for KERNEL profile string and integer exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{
    checked_output_buffer, dword_argument, read_nullable_far_string, word_argument,
};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::KernelGetPrivateProfileInt => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Profiles(
                super::Win16KernelProfilesRequest::GetPrivateProfileInt {
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
                    default_value: word_argument(arguments, 2)? as i16,
                    filename: read_nullable_far_string(
                        dword_argument(arguments, 3)?,
                        selectors,
                        memory,
                    )?,
                },
            ))
        }
        Win16ExportId::KernelGetPrivateProfileString => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Profiles(
                super::Win16KernelProfilesRequest::GetPrivateProfileString {
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
                    default_value: read_nullable_far_string(
                        dword_argument(arguments, 2)?,
                        selectors,
                        memory,
                    )?,
                    output_buffer: checked_output_buffer(
                        dword_argument(arguments, 3)?,
                        word_argument(arguments, 4)?,
                        selectors,
                        memory,
                    )?,
                    filename: read_nullable_far_string(
                        dword_argument(arguments, 5)?,
                        selectors,
                        memory,
                    )?,
                },
            ))
        }
        Win16ExportId::KernelGetProfileString => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Profiles(
                super::Win16KernelProfilesRequest::GetProfileString {
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
                    default_value: read_nullable_far_string(
                        dword_argument(arguments, 2)?,
                        selectors,
                        memory,
                    )?,
                    output_buffer: checked_output_buffer(
                        dword_argument(arguments, 3)?,
                        word_argument(arguments, 4)?,
                        selectors,
                        memory,
                    )?,
                },
            ))
        }
        Win16ExportId::KernelWritePrivateProfileString => {
            Win16ApiRequest::Kernel(super::Win16KernelRequest::Profiles(
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
                    filename: read_nullable_far_string(
                        dword_argument(arguments, 3)?,
                        selectors,
                        memory,
                    )?,
                },
            ))
        }
        Win16ExportId::KernelGetProfileInt => Win16ApiRequest::Kernel(
            super::Win16KernelRequest::Profiles(super::Win16KernelProfilesRequest::GetProfileInt {
                section: read_nullable_far_string(
                    dword_argument(arguments, 0)?,
                    selectors,
                    memory,
                )?,
                key: read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
                default_value: word_argument(arguments, 2)? as i16,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}
