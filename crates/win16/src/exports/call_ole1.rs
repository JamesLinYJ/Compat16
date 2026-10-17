//! Checked decoder for the OLECLI/OLESVR OLE 1.0 APIs.

use guest_core::GuestMemory;

use super::call::call_helpers::{dword_argument, read_nullable_far_string, word_argument};
use super::request::Win16Ole1Request;
use crate::{SelectorTable, Win16Argument, Win16Error};

const OLE_ERROR_ADDRESS: u16 = 16;

/// Decode the OLE1 calls implemented by the guest callback bridge and the
/// client-document metadata table. Other exports retain their complete
/// catalog ABI for later object/server behavior.
pub fn decode_ole1(
    module: &str,
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16Ole1Request>, Win16Error> {
    if module.eq_ignore_ascii_case("OLESVR") {
        return match ordinal {
            2 if arguments.len() == 5 => Ok(Some(Win16Ole1Request::RegisterServer {
                class_name_far: dword_argument(arguments, 0)?,
                server_far: dword_argument(arguments, 1)?,
                output_far: dword_argument(arguments, 2)?,
                instance: word_argument(arguments, 3)?,
                use_mode: word_argument(arguments, 4)?,
            })),
            3 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::RevokeServer {
                server: dword_argument(arguments, 0)? as i32,
            })),
            4 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::BlockServer {
                server: dword_argument(arguments, 0)? as i32,
            })),
            5 if arguments.len() == 2 => Ok(Some(Win16Ole1Request::UnblockServer {
                server: dword_argument(arguments, 0)? as i32,
                blocked_output_far: dword_argument(arguments, 1)?,
            })),
            6 if arguments.len() == 4 => Ok(Some(Win16Ole1Request::RegisterServerDoc {
                server: dword_argument(arguments, 0)? as i32,
                document_name_far: dword_argument(arguments, 1)?,
                server_document_far: dword_argument(arguments, 2)?,
                output_far: dword_argument(arguments, 3)?,
            })),
            7 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::RevokeServerDoc {
                document: dword_argument(arguments, 0)? as i32,
            })),
            8 if arguments.len() == 2 => Ok(Some(Win16Ole1Request::RenameServerDoc {
                document: dword_argument(arguments, 0)? as i32,
                document_name_far: dword_argument(arguments, 1)?,
            })),
            9 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::RevertServerDoc {
                document: dword_argument(arguments, 0)? as i32,
            })),
            10 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::SavedServerDoc {
                document: dword_argument(arguments, 0)? as i32,
            })),
            11 if arguments.len() == 1 => Ok(Some(Win16Ole1Request::RevokeObject {
                client_far: dword_argument(arguments, 0)?,
            })),
            12 if arguments.is_empty() => Ok(Some(Win16Ole1Request::QueryServerVersion)),
            26 if arguments.len() == 3 => Ok(Some(Win16Ole1Request::ItemCallback {
                client_far: dword_argument(arguments, 0)?,
                notification: word_argument(arguments, 1)?,
                object_far: dword_argument(arguments, 2)?,
            })),
            2..=12 | 26 => Err(Win16Error::InvalidRange),
            _ => Ok(None),
        };
    }
    if !module.eq_ignore_ascii_case("OLECLI") {
        return Ok(None);
    }

    let request = match ordinal {
        4 if arguments.len() == 6 => {
            let stream = dword_argument(arguments, 0)?;
            let class_far = dword_argument(arguments, 1)?;
            let client = dword_argument(arguments, 2)?;
            let document = dword_argument(arguments, 3)? as i32;
            let item_far = dword_argument(arguments, 4)?;
            let object_output = dword_argument(arguments, 5)?;
            let Some(protocol) = required_string(class_far, selectors, memory) else {
                return Ok(Some(creation_address_error(object_output)));
            };
            let Some(item_name) = nullable_string(item_far, selectors, memory) else {
                return Ok(Some(creation_address_error(object_output)));
            };
            Win16Ole1Request::LoadFromStream {
                stream,
                protocol,
                client,
                document,
                item_name,
                object_output,
            }
        }
        3 if arguments.len() == 2 => Win16Ole1Request::SaveToStream {
            object: dword_argument(arguments, 0)?,
            stream: dword_argument(arguments, 1)?,
        },
        3 => return Err(Win16Error::InvalidRange),
        ordinal if is_object_method(ordinal) => {
            return decode_object_method(ordinal, arguments).map(Some);
        }
        41 if arguments.len() == 4 => {
            // Validate scalar widths/count before interpreting any pointer,
            // so a malformed frame is not converted into an OLE status.
            let class_name_far = dword_argument(arguments, 0)?;
            let document_name_far = dword_argument(arguments, 1)?;
            let reserved = dword_argument(arguments, 2)? as i32;
            let output = dword_argument(arguments, 3)?;
            let Some(class_name) = required_string(class_name_far, selectors, memory) else {
                return Ok(Some(register_address_error(output)));
            };
            let Some(document_name) = required_string(document_name_far, selectors, memory) else {
                return Ok(Some(register_address_error(output)));
            };
            Win16Ole1Request::RegisterClientDoc {
                class_name,
                document_name,
                reserved,
                output,
            }
        }
        42 if arguments.len() == 1 => Win16Ole1Request::RevokeClientDoc {
            document: dword_argument(arguments, 0)? as i32,
        },
        43 if arguments.len() == 2 => {
            let document = dword_argument(arguments, 0)? as i32;
            let document_name_far = dword_argument(arguments, 1)?;
            match required_string(document_name_far, selectors, memory) {
                Some(document_name) => Win16Ole1Request::RenameClientDoc {
                    document,
                    document_name,
                },
                None => Win16Ole1Request::RenameClientDocInvalidAddress {
                    document,
                    status: OLE_ERROR_ADDRESS,
                },
            }
        }
        44 if arguments.len() == 1 => Win16Ole1Request::RevertClientDoc {
            document: dword_argument(arguments, 0)? as i32,
        },
        45 if arguments.len() == 1 => Win16Ole1Request::SavedClientDoc {
            document: dword_argument(arguments, 0)? as i32,
        },
        47 if arguments.len() == 2 => Win16Ole1Request::EnumObjects {
            document: dword_argument(arguments, 0)? as i32,
            object_inout: dword_argument(arguments, 1)?,
        },
        33 | 34 if arguments.len() == 8 => {
            let class_far = dword_argument(arguments, 0)?;
            let client = dword_argument(arguments, 1)?;
            let third_far = dword_argument(arguments, 2)?;
            let document = dword_argument(arguments, 3)? as i32;
            let item_far = dword_argument(arguments, 4)?;
            let object_output = dword_argument(arguments, 5)?;
            let render_option = word_argument(arguments, 6)?;
            let clip_format = word_argument(arguments, 7)?;
            let Some(item_name) = nullable_string(item_far, selectors, memory) else {
                return Ok(Some(creation_address_error(object_output)));
            };
            if ordinal == 33 {
                let Some(class_name) = required_string(class_far, selectors, memory) else {
                    return Ok(Some(creation_address_error(object_output)));
                };
                let Some(template_name) = required_string(third_far, selectors, memory) else {
                    return Ok(Some(creation_address_error(object_output)));
                };
                Win16Ole1Request::CreateFromTemplate {
                    class_name,
                    template_name,
                    client,
                    document,
                    item_name,
                    object_output,
                    render_option,
                    clip_format,
                }
            } else {
                // Windows 3.1 SDK OleCreate order: protocol, client, class,
                // client document, object name, output, render, format.
                let Some(protocol) = required_string(class_far, selectors, memory) else {
                    return Ok(Some(creation_address_error(object_output)));
                };
                let Some(class_name) = required_string(third_far, selectors, memory) else {
                    return Ok(Some(creation_address_error(object_output)));
                };
                Win16Ole1Request::Create {
                    class_name,
                    client,
                    protocol,
                    document,
                    item_name,
                    object_output,
                    render_option,
                    clip_format,
                    activate: false,
                }
            }
        }
        38 if arguments.len() == 9 => {
            let class_far = dword_argument(arguments, 0)?;
            let client = dword_argument(arguments, 1)?;
            let file_far = dword_argument(arguments, 2)?;
            let native_type_far = dword_argument(arguments, 3)?;
            let document = dword_argument(arguments, 4)? as i32;
            let item_far = dword_argument(arguments, 5)?;
            let object_output = dword_argument(arguments, 6)?;
            let render_option = word_argument(arguments, 7)?;
            let clip_format = word_argument(arguments, 8)?;
            let (Some(class_name), Some(file_name), Some(native_type), Some(item_name)) = (
                required_string(class_far, selectors, memory),
                required_string(file_far, selectors, memory),
                required_string(native_type_far, selectors, memory),
                nullable_string(item_far, selectors, memory),
            ) else {
                return Ok(Some(creation_address_error(object_output)));
            };
            Win16Ole1Request::CreateFromFile {
                class_name,
                file_name,
                client,
                native_type,
                document,
                item_name,
                object_output,
                render_option,
                clip_format,
            }
        }
        39 if arguments.len() == 10 => {
            let class_far = dword_argument(arguments, 0)?;
            let client = dword_argument(arguments, 1)?;
            let file_far = dword_argument(arguments, 2)?;
            let native_type_far = dword_argument(arguments, 3)?;
            let link_source_far = dword_argument(arguments, 4)?;
            let document = dword_argument(arguments, 5)? as i32;
            let item_far = dword_argument(arguments, 6)?;
            let object_output = dword_argument(arguments, 7)?;
            let render_option = word_argument(arguments, 8)?;
            let clip_format = word_argument(arguments, 9)?;
            let (
                Some(class_name),
                Some(file_name),
                Some(native_type),
                Some(link_source),
                Some(item_name),
            ) = (
                required_string(class_far, selectors, memory),
                required_string(file_far, selectors, memory),
                required_string(native_type_far, selectors, memory),
                required_string(link_source_far, selectors, memory),
                nullable_string(item_far, selectors, memory),
            )
            else {
                return Ok(Some(creation_address_error(object_output)));
            };
            Win16Ole1Request::CreateLinkFromFile {
                file_name,
                class_name,
                client,
                native_type,
                link_source,
                item_name,
                document,
                object_output,
                render_option,
                clip_format,
            }
        }
        58 if arguments.len() == 9 => {
            let class_far = dword_argument(arguments, 0)?;
            let client = dword_argument(arguments, 1)?;
            let protocol_far = dword_argument(arguments, 2)?;
            let document = dword_argument(arguments, 3)? as i32;
            let item_far = dword_argument(arguments, 4)?;
            let object_output = dword_argument(arguments, 5)?;
            let render_option = word_argument(arguments, 6)?;
            let clip_format = word_argument(arguments, 7)?;
            let activate = word_argument(arguments, 8)? != 0;
            let (Some(class_name), Some(protocol), Some(item_name)) = (
                required_string(class_far, selectors, memory),
                required_string(protocol_far, selectors, memory),
                nullable_string(item_far, selectors, memory),
            ) else {
                return Ok(Some(creation_address_error(object_output)));
            };
            Win16Ole1Request::Create {
                class_name,
                client,
                protocol,
                document,
                item_name,
                object_output,
                render_option,
                clip_format,
                activate,
            }
        }
        59 if arguments.is_empty() => Win16Ole1Request::QueryClientVersion,
        60 if arguments.len() == 1 => Win16Ole1Request::IsDcMeta {
            dc: word_argument(arguments, 0)?,
        },
        4 | 33 | 34 | 38 | 39 | 58 | 41..=45 | 47 | 59..=60 => {
            return Err(Win16Error::InvalidRange);
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn is_object_method(ordinal: u16) -> bool {
    matches!(
        ordinal,
        2 | 6..=8
            | 13..=32
            | 35..=37
            | 40
            | 46
            | 48..=50
            | 56..=57
    )
}

fn decode_object_method(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16Ole1Request, Win16Error> {
    let trailing_count = match ordinal {
        2 | 13 | 20 | 22 | 23 | 27 | 31 | 35 | 36 | 37 | 40 => 0,
        8 | 14 | 16 | 17 | 18 | 24 | 25 | 26 | 30 | 46 | 49 | 50 | 56 => 1,
        15 => 2,
        6 => 4,
        19 => 4,
        7 | 32 | 21 => 5,
        28 | 29 | 48 | 57 => 2,
        _ => return Err(Win16Error::InvalidRange),
    };
    if arguments.len() != trailing_count + 1 {
        return Err(Win16Error::InvalidRange);
    }
    let object = dword_argument(arguments, 0)?;
    let forwarded = arguments[1..].iter().copied().map(raw_argument).collect();
    Ok(Win16Ole1Request::ObjectMethod {
        ordinal,
        object,
        arguments: forwarded,
    })
}

fn raw_argument(argument: Win16Argument) -> u32 {
    match argument {
        Win16Argument::Byte(value) => u32::from(value),
        Win16Argument::Word(value) => u32::from(value),
        Win16Argument::Dword(value) => value,
    }
}

fn register_address_error(output: u32) -> Win16Ole1Request {
    Win16Ole1Request::RegisterClientDocInvalidAddress {
        output,
        status: OLE_ERROR_ADDRESS,
    }
}

fn creation_address_error(output: u32) -> Win16Ole1Request {
    Win16Ole1Request::CreationInvalidAddress {
        object_output: output,
        status: OLE_ERROR_ADDRESS,
    }
}

fn required_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Option<Vec<u8>> {
    if far == 0 {
        return None;
    }
    read_nullable_far_string(far, selectors, memory)
        .ok()
        .flatten()
}

fn nullable_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Option<Option<Vec<u8>>> {
    if far == 0 {
        Some(None)
    } else {
        read_nullable_far_string(far, selectors, memory)
            .ok()
            .flatten()
            .map(Some)
    }
}
