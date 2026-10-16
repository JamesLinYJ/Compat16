//! Stack argument decoding for USER messages and loaded UI resources.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{
    checked_output_buffer, dword_argument, read_far_string, read_nullable_far_string, word_argument,
};
use crate::{SelectorTable, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::UserCopyIcon => Win16ApiRequest::User(super::Win16UserRequest::Resources(
            super::Win16UserResourcesRequest::CopyIcon {
                instance: word_argument(arguments, 0)?, icon: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserCopyCursor => Win16ApiRequest::User(super::Win16UserRequest::Resources(
            super::Win16UserResourcesRequest::CopyCursor {
                instance: word_argument(arguments, 0)?, cursor: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserCreateIcon => Win16ApiRequest::User(super::Win16UserRequest::Resources(
            super::Win16UserResourcesRequest::CreateIcon {
                instance: word_argument(arguments, 0)?, width: word_argument(arguments, 1)? as i16,
                height: word_argument(arguments, 2)? as i16,
                // SDK BYTE parameters occupy word-sized stack slots.
                planes: word_argument(arguments, 3)? as u8, bits_per_pixel: word_argument(arguments, 4)? as u8,
                and_mask: dword_argument(arguments, 5)?, xor_mask: dword_argument(arguments, 6)?,
            },
        )),
        Win16ExportId::UserCreateCursor => Win16ApiRequest::User(super::Win16UserRequest::Resources(
            super::Win16UserResourcesRequest::CreateCursor {
                instance: word_argument(arguments, 0)?, x_hotspot: word_argument(arguments, 1)? as i16,
                y_hotspot: word_argument(arguments, 2)? as i16, width: word_argument(arguments, 3)? as i16,
                height: word_argument(arguments, 4)? as i16,
                and_mask: dword_argument(arguments, 5)?, xor_mask: dword_argument(arguments, 6)?,
            },
        )),
        Win16ExportId::UserMessageBox => {
            let owner = word_argument(arguments, 0)?;
            let far_text = dword_argument(arguments, 1)?;
            let far_caption = dword_argument(arguments, 2)?;
            let style = word_argument(arguments, 3)?;
            Win16ApiRequest::User(super::Win16UserRequest::Text(
                super::Win16UserTextRequest::MessageBox {
                    owner,
                    text: read_nullable_far_string(far_text, selectors, memory)?,
                    caption: read_nullable_far_string(far_caption, selectors, memory)?,
                    style,
                },
            ))
        }
        Win16ExportId::UserInitApp => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::InitApp {
                instance: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserLoadString => {
            let instance = word_argument(arguments, 0)?;
            let string_id = word_argument(arguments, 1)?;
            let far_buffer = dword_argument(arguments, 2)?;
            let output_buffer = if far_buffer == 0 {
                None
            } else {
                let signed_capacity = word_argument(arguments, 3)? as i16;
                if signed_capacity < 0 {
                    return Err(Win16Error::InvalidRange);
                }
                Some(checked_output_buffer(
                    far_buffer,
                    signed_capacity as u16,
                    selectors,
                    memory,
                )?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Resources(
                super::Win16UserResourcesRequest::LoadString {
                    instance,
                    string_id,
                    output_buffer,
                },
            ))
        }
        Win16ExportId::UserLoadCursor | Win16ExportId::UserLoadIcon
        | Win16ExportId::UserLoadBitmap => {
            let instance = word_argument(arguments, 0)?;
            let far_name_or_id = dword_argument(arguments, 1)?;
            let name = if far_name_or_id >> 16 == 0 {
                Win16ResourceName::Id(far_name_or_id as u16)
            } else {
                Win16ResourceName::Name(read_far_string(far_name_or_id, selectors, memory)?)
            };
            if export == Win16ExportId::UserLoadBitmap {
                Win16ApiRequest::User(super::Win16UserRequest::Resources(
                    super::Win16UserResourcesRequest::LoadBitmap { instance, name },
                ))
            } else if export == Win16ExportId::UserLoadCursor {
                Win16ApiRequest::User(super::Win16UserRequest::Resources(
                    super::Win16UserResourcesRequest::LoadCursor { instance, name },
                ))
            } else {
                Win16ApiRequest::User(super::Win16UserRequest::Resources(
                    super::Win16UserResourcesRequest::LoadIcon { instance, name },
                ))
            }
        }
        _ => return Err(Win16Error::InvalidRange),
    })
}
