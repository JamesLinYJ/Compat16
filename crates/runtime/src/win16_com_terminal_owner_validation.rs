//! Validate exact native owner identities in retained COM terminal values.

use crate::{RuntimeError, Win16ComHostOwnerIdentity};
use super::invariant;

pub(super) fn validate_com_result_owner(
    owner: Win16ComHostOwnerIdentity,
    result: &crate::Win16ComHostResult,
) -> Result<(), RuntimeError> {
    match result {
        crate::Win16ComHostResult::Ole(reply) => validate_ole_value_owner(owner, &reply.value),
        crate::Win16ComHostResult::Storage(reply) => {
            if let Some(storage) = reply.storage {
                validate_com_interface_owner(owner, storage)?;
            }
            Ok(())
        }
        crate::Win16ComHostResult::MediumReleased { medium } => {
            if medium.owner == owner && medium.is_valid() {
                Ok(())
            } else {
                Err(invariant(
                    "COM terminal released a storage medium from another owner",
                ))
            }
        }
        crate::Win16ComHostResult::ObjectReferenceReleased {
            owner: released_owner,
            ..
        } if *released_owner == owner => Ok(()),
        crate::Win16ComHostResult::ObjectReferenceReleased { .. } => Err(invariant(
            "COM terminal released an interface from another owner",
        )),
    }
}

fn validate_ole_value_owner(
    owner: Win16ComHostOwnerIdentity,
    value: &crate::Win16OleHostValue,
) -> Result<(), RuntimeError> {
    match value {
        crate::Win16OleHostValue::Object(interface) => validate_com_interface_owner(owner, *interface),
        crate::Win16OleHostValue::CallbackInterfaces {
            client_site,
            advise_sink,
        } => {
            validate_com_interface_owner(owner, *client_site)?;
            validate_com_interface_owner(owner, *advise_sink)
        }
        crate::Win16OleHostValue::StorageMedium(
            crate::Win16ComHostStorageMedium::Stream(interface)
            | crate::Win16ComHostStorageMedium::Storage(interface),
        ) => validate_com_interface_owner(owner, *interface),
        crate::Win16OleHostValue::StorageMedium(
            crate::Win16ComHostStorageMedium::NativeResource { token, .. },
        ) if token.owner != owner || !token.is_valid() => Err(invariant(
            "COM terminal returned a native storage medium from another owner",
        )),
        crate::Win16OleHostValue::ParsedDisplayName {
            moniker: Some(interface),
            ..
        } => validate_com_interface_owner(owner, *interface),
        _ => Ok(()),
    }
}

fn validate_com_interface_owner(
    owner: Win16ComHostOwnerIdentity,
    interface: crate::Win16ComHostInterface,
) -> Result<(), RuntimeError> {
    if interface.owner == owner && interface.object.0 != 0 {
        Ok(())
    } else {
        Err(invariant(
            "COM terminal returned an interface from another owner incarnation",
        ))
    }
}
