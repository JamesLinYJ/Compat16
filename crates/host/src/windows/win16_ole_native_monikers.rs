//! Native moniker operations kept separate from the general OLE dispatcher.

use std::ptr;

use compat_services::com::{IID_IBIND_CTX, IID_IMONIKER};
use runtime::{
    DiagnosticKind, RuntimeError, Win16OleHostOperation as Win16OleNativeOperation,
    Win16OleHostReply as Win16OleNativeReply, Win16OleHostValue as Win16OleNativeValue,
};
use windows_sys::Win32::System::Com::{
    BindMoniker, CreateFileMoniker, CreateGenericComposite, CreateItemMoniker, MkParseDisplayName,
};

use super::support::{
    adopt_interface, decode_guest_text, native_guid, status, wide_z,
    with_required_interface, with_two_required_interfaces,
};
use super::{E_INVALIDARG, E_NOINTERFACE};
use super::super::win16_com_objects::Win16ComObjects;

pub(super) fn execute(
    objects: &Win16ComObjects,
    operation: Win16OleNativeOperation,
) -> Result<Win16OleNativeReply, RuntimeError> {
    let reply = match operation {
        Win16OleNativeOperation::CreateFileMoniker { path, code_page } => {
            let path = decode_guest_text(&path, code_page)?;
            let wide: Vec<_> = path.encode_utf16().collect();
            let Some(path) = wide_z(&wide) else {
                return Ok(status(E_INVALIDARG, Win16OleNativeValue::None));
            };
            let mut output = ptr::null_mut();
            // SAFETY: `path` is an owned, NUL-terminated UTF-16 string and
            // `output` is a writable native interface slot.
            let result = unsafe { CreateFileMoniker(path.as_ptr(), &mut output) };
            let (result, value) = adopt_interface(objects, result, output, IID_IMONIKER)?;
            status(result, value)
        }
        Win16OleNativeOperation::CreateItemMoniker {
            delimiter,
            item,
            code_page,
        } => {
            let delimiter = decode_guest_text(&delimiter, code_page)?;
            let item = decode_guest_text(&item, code_page)?;
            let delimiter_wide: Vec<_> = delimiter.encode_utf16().collect();
            let item_wide: Vec<_> = item.encode_utf16().collect();
            let (Some(delimiter), Some(item)) = (wide_z(&delimiter_wide), wide_z(&item_wide))
            else {
                return Ok(status(E_INVALIDARG, Win16OleNativeValue::None));
            };
            let mut output = ptr::null_mut();
            // SAFETY: both strings are owned NUL-terminated UTF-16 values and
            // `output` is a writable native interface slot.
            let result = unsafe {
                CreateItemMoniker(delimiter.as_ptr(), item.as_ptr(), &mut output)
            };
            let (result, value) = adopt_interface(objects, result, output, IID_IMONIKER)?;
            status(result, value)
        }
        Win16OleNativeOperation::CreateGenericComposite { first, rest } => {
            let Some((result, output)) = with_two_required_interfaces(
                objects,
                first,
                IID_IMONIKER,
                rest,
                IID_IMONIKER,
                |first, rest| {
                    let mut output = ptr::null_mut();
                    // SAFETY: both leased pointers are live IMoniker
                    // interfaces and `output` is writable.
                    let result = unsafe { CreateGenericComposite(first, rest, &mut output) };
                    (result, output)
                },
            )? else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let (result, value) = adopt_interface(objects, result, output, IID_IMONIKER)?;
            status(result, value)
        }
        Win16OleNativeOperation::BindMoniker {
            moniker,
            options,
            iid,
        } => {
            let native_iid = native_guid(iid);
            let Some((result, output)) =
                with_required_interface(objects, moniker, IID_IMONIKER, "IMoniker", |moniker| {
                    let mut output = ptr::null_mut();
                    // SAFETY: the moniker lease is live, `native_iid` is a
                    // local GUID, and `output` is writable.
                    let result = unsafe {
                        BindMoniker(moniker, options, &native_iid, &mut output)
                    };
                    (result, output)
                })?
            else {
                return Ok(status(E_NOINTERFACE, Win16OleNativeValue::None));
            };
            let (result, value) = adopt_interface(objects, result, output, iid)?;
            status(result, value)
        }
        Win16OleNativeOperation::ParseDisplayName {
            bind_context,
            display_name,
            code_page,
        } => {
            let display_name = decode_guest_text(&display_name, code_page)?;
            let wide: Vec<_> = display_name.encode_utf16().collect();
            let Some(display_name) = wide_z(&wide) else {
                return Ok(status(
                    E_INVALIDARG,
                    Win16OleNativeValue::ParsedDisplayName {
                        eaten: 0,
                        moniker: None,
                    },
                ));
            };
            let Some((result, eaten, output)) = with_required_interface(
                objects,
                bind_context,
                IID_IBIND_CTX,
                "IBindCtx",
                |bind_context| {
                    let mut eaten = 0;
                    let mut output = ptr::null_mut();
                    // SAFETY: the bind-context lease and owned display name
                    // remain live through the call; output slots are writable.
                    let result = unsafe {
                        MkParseDisplayName(
                            bind_context,
                            display_name.as_ptr(),
                            &mut eaten,
                            &mut output,
                        )
                    };
                    (result, eaten, output)
                },
            )?
            else {
                return Ok(status(
                    E_NOINTERFACE,
                    Win16OleNativeValue::ParsedDisplayName {
                        eaten: 0,
                        moniker: None,
                    },
                ));
            };
            let (result, value) = adopt_interface(objects, result, output, IID_IMONIKER)?;
            let moniker = match value {
                Win16OleNativeValue::Object(interface) => Some(interface),
                Win16OleNativeValue::None => None,
                _ => {
                    return Err(RuntimeError::new(
                        DiagnosticKind::InternalInvariant,
                        "display-name parser produced an unexpected COM value",
                    ));
                }
            };
            status(
                result,
                Win16OleNativeValue::ParsedDisplayName { eaten, moniker },
            )
        }
        _ => {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "moniker dispatcher received a non-moniker operation",
            ));
        }
    };
    Ok(reply)
}
