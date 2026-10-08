use std::collections::BTreeSet;

use super::super::super::read_safe_array_huge_bytes;
use super::*;

pub(in crate::win16_automation::guest_ops) fn preflight_variant_release(
    state: &Win16AutomationState,
    value: Variant16,
    selectors: &SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    visited_arrays: &mut BTreeSet<u32>,
    visited_bstrs: &mut BTreeSet<u32>,
    depth: usize,
    check_locks: bool,
) -> Result<(), AutomationFailure> {
    validate_vartype_bits(value.vt)?;
    let base = value.vt & VT_TYPEMASK;
    if value.vt & VT_BYREF != 0 {
        if !supported_vartype(base) {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        return Ok(());
    }
    if value.vt & VT_ARRAY != 0 {
        let far = value.guest_far();
        if far == 0 {
            return Ok(());
        }
        return preflight_safe_array_release(
            state,
            far,
            Some(base),
            selectors,
            memory,
            owner,
            reject_interface,
            visited_arrays,
            visited_bstrs,
            depth,
            check_locks,
        );
    }
    match base {
        VT_BSTR => {
            let far = value.guest_far();
            if far != 0 && visited_bstrs.insert(far) {
                state
                    .validate_owned_bstr(selectors, memory, owner, far)
                    .map_err(AutomationFailure::from)?;
            }
            Ok(())
        }
        VT_DISPATCH | VT_UNKNOWN => {
            let far = value.guest_far();
            if far != 0 {
                reject_interface(LeaseAction::Release, far).map_err(AutomationFailure::from)?;
            }
            Ok(())
        }
        VT_EMPTY | VT_NULL | VT_I1 | VT_UI1 | VT_I2 | VT_UI2 | VT_I4 | VT_UI4 | VT_I8 | VT_UI8
        | VT_INT | VT_UINT | VT_R4 | VT_R8 | VT_CY | VT_DATE | VT_ERROR | VT_BOOL => Ok(()),
        _ => Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    }
}

pub(in crate::win16_automation::guest_ops) fn preflight_safe_array_release(
    state: &Win16AutomationState,
    far: u32,
    expected_type: Option<u16>,
    selectors: &SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    visited_arrays: &mut BTreeSet<u32>,
    visited_bstrs: &mut BTreeSet<u32>,
    depth: usize,
    check_locks: bool,
) -> Result<(), AutomationFailure> {
    if !visited_arrays.insert(far) {
        // A duplicate reference can be an alias or a cycle. Do not recurse a
        // second time, but still verify this VARIANT's expected element type
        // so an alias cannot bypass descriptor/type validation.
        if let Some(expected) = expected_type {
            let (_, descriptor) = read_safe_array_descriptor(selectors, memory, far)
                .map_err(AutomationFailure::from)?;
            element_type_from_descriptor(&descriptor, Some(expected))?;
        }
        return Ok(());
    }
    let (_, descriptor) =
        read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
    require_safe_array_descriptor(state, owner, far).map_err(AutomationFailure::from)?;
    if check_locks && descriptor.locks != 0 {
        return Err(AutomationFailure::HResult(DISP_E_ARRAYISLOCKED));
    }
    if descriptor.data == 0 {
        if expected_type.is_some() && descriptor.element_size != 0 {
            element_type_from_descriptor(&descriptor, expected_type)?;
        }
        return Ok(());
    }
    let element_type = element_type_from_descriptor(&descriptor, expected_type)?;
    state
        .require_owned_allocation(owner, descriptor.data, AllocationKind::SafeArrayData)
        .map_err(AutomationFailure::from)?;
    let data_length = expected_array_data_length(&descriptor).map_err(AutomationFailure::from)?;
    if data_length > MAX_AUTOMATION_ALLOCATION {
        return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
    }
    let data_pointer = selectors
        .pointer_from_far(descriptor.data)
        .map_err(crate::runtime_error)
        .map_err(AutomationFailure::from)?;
    let data = read_safe_array_huge_bytes(selectors, memory, data_pointer, data_length)
        .map_err(AutomationFailure::from)?;

    match element_type {
        Some(VT_BSTR) => {
            for chunk in data.chunks_exact(4) {
                let bstr = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
                );
                if bstr != 0 && visited_bstrs.insert(bstr) {
                    state
                        .validate_owned_bstr(selectors, memory, owner, bstr)
                        .map_err(AutomationFailure::from)?;
                }
            }
        }
        Some(VT_DISPATCH) | Some(VT_UNKNOWN) => {
            for chunk in data.chunks_exact(4) {
                let interface = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
                );
                if interface != 0 {
                    reject_interface(LeaseAction::Release, interface)
                        .map_err(AutomationFailure::from)?;
                }
            }
        }
        Some(VT_VARIANT) => {
            if depth >= MAX_VARIANT_INDIRECTION {
                return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
            }
            for chunk in data.chunks_exact(16) {
                let value = Variant16::decode(chunk)
                    .map_err(|_| AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
                preflight_variant_release(
                    state,
                    value,
                    selectors,
                    memory,
                    owner,
                    reject_interface,
                    visited_arrays,
                    visited_bstrs,
                    depth + 1,
                    check_locks,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}
