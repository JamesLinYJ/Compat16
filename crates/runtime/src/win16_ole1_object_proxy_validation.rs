//! Selector, allocation, vtable and owned-host-identity checks for OLE1 proxies.

use guest_core::memory::Memory;
use win16_abi::Access;

use super::super::Win16State;
use super::{Win16Ole1NativeObjectProxyRecord, canonical_far};
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn validate(
    state: &Win16State,
    record: Win16Ole1NativeObjectProxyRecord,
    slot: u8,
    memory: &mut Memory,
) -> Result<bool, RuntimeError> {
    if record.id == 0
        || record.object.object.0 == 0
        || !record.object.owner.is_valid()
        || record.callback_route.0 == 0
        || record.object.iid != super::iid_ole_object()
        || record.object.disposition != compat_services::com::ReferenceDisposition::Owned
        || record.client_site.object.0 == 0
        || record.client_site.owner != record.object.owner
        || record.client_site.iid != compat_services::com::IID_IOLE_CLIENT_SITE
        || record.client_site.disposition != compat_services::com::ReferenceDisposition::Owned
        || record.advise_sink.object.0 == 0
        || record.advise_sink.owner != record.object.owner
        || record.advise_sink.iid != super::iid_iadvise_sink()
        || record.advise_sink.disposition != compat_services::com::ReferenceDisposition::Owned
        || record.storage.is_some_and(|storage| {
            storage.object.0 == 0
                || storage.owner != record.object.owner
                || storage.iid != compat_services::com::IID_ISTORAGE
                || storage.disposition != compat_services::com::ReferenceDisposition::Owned
        })
    {
        return Ok(false);
    }
    let info = match state.heap.info(record.allocation) {
        Ok(info) => info,
        Err(error) => {
            let runtime = crate::runtime_error(error);
            return match runtime.kind() {
                Kind::GuestFault | Kind::InvalidInput => Ok(false),
                _ => Err(runtime.with_context("validate owned OLE1 object proxy allocation")),
            };
        }
    };
    if info.owner != super::OLE1_OBJECT_PROXY_OWNER
        || info.size != super::OLE1_OBJECT_PROXY_BYTES
        || info.movable
        || info.discarded
        || info.executable
    {
        return Ok(false);
    }
    let expected_vtable_address = info
        .base
        .0
        .checked_add(super::OLE1_OBJECT_BYTES)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "owned OLE1 vtable physical address overflow",
            )
        })?;
    let object_address = match state.selectors.address_within(
        record.object_pointer,
        Access::Read,
        super::OLE1_OBJECT_BYTES as usize,
        memory.size_bytes(),
    ) {
        Ok(address) => address,
        Err(error) => {
            let runtime = crate::runtime_error(error);
            return match runtime.kind() {
                Kind::GuestFault | Kind::InvalidInput => Ok(false),
                _ => Err(runtime.with_context("validate OLE1 object allocation selector")),
            };
        }
    };
    let vtable_address = match state.selectors.address_within(
        record.vtable_pointer,
        Access::Read,
        super::OLE1_OBJECT_VTABLE_BYTES as usize,
        memory.size_bytes(),
    ) {
        Ok(address) => address,
        Err(error) => {
            let runtime = crate::runtime_error(error);
            return match runtime.kind() {
                Kind::GuestFault | Kind::InvalidInput => Ok(false),
                _ => Err(runtime.with_context("validate OLE1 vtable allocation selector")),
            };
        }
    };
    if object_address != info.base || vtable_address.0 != expected_vtable_address {
        return Ok(false);
    }
    let object_pointer = match state.selectors.pointer_from_far(record.object_far) {
        Ok(pointer) => pointer,
        Err(error) => {
            let runtime = crate::runtime_error(error);
            return match runtime.kind() {
                Kind::GuestFault | Kind::InvalidInput => Ok(false),
                _ => Err(runtime.with_context("resolve owned OLE1 object proxy FAR")),
            };
        }
    };
    if object_pointer != record.object_pointer {
        return Ok(false);
    }
    if let Err(error) = state.selectors.translate(
        object_pointer,
        Access::Read,
        super::OLE1_OBJECT_BYTES as usize,
        memory,
    ) {
        let runtime = crate::runtime_error(error);
        return match runtime.kind() {
            Kind::GuestFault | Kind::InvalidInput => Ok(false),
            _ => Err(runtime.with_context("validate OLE1 object proxy wire range")),
        };
    }
    let mut object_wire = [0_u8; 4];
    state
        .selectors
        .read(memory, object_pointer, &mut object_wire)
        .map_err(crate::runtime_error)?;
    if canonical_far(u32::from_le_bytes(object_wire)) != canonical_far(record.vtable_far) {
        return Ok(false);
    }
    let vtable_pointer = match state.selectors.pointer_from_far(record.vtable_far) {
        Ok(pointer) => pointer,
        Err(error) => {
            let runtime = crate::runtime_error(error);
            return match runtime.kind() {
                Kind::GuestFault | Kind::InvalidInput => Ok(false),
                _ => Err(runtime.with_context("resolve owned OLE1 vtable FAR")),
            };
        }
    };
    if vtable_pointer != record.vtable_pointer {
        return Ok(false);
    }
    if let Err(error) = state.selectors.translate(
        vtable_pointer,
        Access::Read,
        super::OLE1_OBJECT_VTABLE_BYTES as usize,
        memory,
    ) {
        let runtime = crate::runtime_error(error);
        return match runtime.kind() {
            Kind::GuestFault | Kind::InvalidInput => Ok(false),
            _ => Err(runtime.with_context("validate OLE1 object vtable wire range")),
        };
    }
    let mut method_wire = [0_u8; 4];
    let slot_pointer = state
        .selectors
        .add_bytes(vtable_pointer, u32::from(slot) * 4)
        .map_err(crate::runtime_error)?;
    state
        .selectors
        .read(memory, slot_pointer, &mut method_wire)
        .map_err(crate::runtime_error)?;
    let actual = u32::from_le_bytes(method_wire);
    let Some(expected) = state.ole1_object_method_gate_address(record.id, slot)
    else {
        return Ok(false);
    };
    Ok(canonical_far(actual) == canonical_far(expected))
}
