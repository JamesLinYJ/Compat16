//! Release owned Automation values when a guest task exits.
//!
//! The visited sets protect teardown from guest-written SAFEARRAY aliases
//! and cycles. Unsupported guest COM proxies are diagnosed before cleanup.

use std::collections::BTreeSet;

use compat_services::automation::{
    VT_ARRAY, VT_BOOL, VT_BSTR, VT_BYREF, VT_CY, VT_DATE, VT_DISPATCH, VT_EMPTY, VT_ERROR, VT_I1,
    VT_I2, VT_I4, VT_I8, VT_INT, VT_NULL, VT_R4, VT_R8, VT_TYPEMASK, VT_UI1, VT_UI2, VT_UI4,
    VT_UI8, VT_UINT, VT_UNKNOWN, VT_VARIANT, Variant16,
};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use win16_abi::{GlobalHeap, SelectorTable};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::super::{
    AllocationKind, MAX_AUTOMATION_ALLOCATION, Win16AutomationState, read_safe_array_descriptor,
    read_safe_array_huge_bytes,
};
use super::variant::{
    element_type_from_descriptor, preflight_safe_array_release, validate_vartype_bits,
};
use super::{AutomationFailure, AutomationInterfaceAction as LeaseAction};

const MAX_TEARDOWN_VARIANT_DEPTH: usize = 64;

/// Preflight every top-level array before task cleanup releases any child
/// resource. The owner-wide allocator pass still reclaims tracked blocks if a
/// malformed guest value prevents semantic cleanup.
pub(in crate::win16_automation) fn preflight_owner_array_contents(
    state: &Win16AutomationState,
    selectors: &SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    arrays: &[u32],
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut visited_arrays = BTreeSet::new();
    let mut visited_bstrs = BTreeSet::new();
    for &far in arrays {
        if visited_arrays.contains(&far) {
            continue;
        }
        preflight_safe_array_release(
            state,
            far,
            None,
            selectors,
            memory,
            owner,
            reject_interface,
            &mut visited_arrays,
            &mut visited_bstrs,
            0,
            false,
        )
        .map_err(failure_to_runtime)?;
    }
    Ok(())
}

pub(in crate::win16_automation) fn release_owner_array_contents(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    far: u32,
    visited_arrays: &mut BTreeSet<u32>,
    visited_bstrs: &mut BTreeSet<u32>,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    release_array_contents(
        state,
        heap,
        selectors,
        memory,
        owner,
        far,
        None,
        visited_arrays,
        visited_bstrs,
        reject_interface,
        0,
    )
}

fn release_array_contents(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    far: u32,
    expected: Option<u16>,
    visited_arrays: &mut BTreeSet<u32>,
    visited_bstrs: &mut BTreeSet<u32>,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    depth: usize,
) -> Result<(), RuntimeError> {
    if !visited_arrays.insert(far) {
        return Ok(());
    }
    state.require_owned_allocation(owner, far, AllocationKind::SafeArrayDescriptor)?;
    let (_, descriptor) = read_safe_array_descriptor(selectors, memory, far)?;
    if descriptor.data == 0 {
        return Ok(());
    }
    let element_type =
        element_type_from_descriptor(&descriptor, expected).map_err(failure_to_runtime)?;
    let data_length = crate::win16_automation::expected_array_data_length(&descriptor)?;
    if data_length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 SAFEARRAY teardown data exceeds the bounded copy size",
        ));
    }
    let data_pointer = selectors
        .pointer_from_far(descriptor.data)
        .map_err(crate::runtime_error)?;
    let data = read_safe_array_huge_bytes(selectors, memory, data_pointer, data_length)?;
    let mut first_error = None;
    match element_type {
        Some(VT_BSTR) => {
            for chunk in data.chunks_exact(4) {
                let string = u32::from_le_bytes(chunk.try_into().map_err(|_| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 SAFEARRAY BSTR slot has an invalid width",
                    )
                })?);
                if string != 0 && visited_bstrs.insert(string) {
                    if let Err(error) = state.release_bstr(heap, selectors, owner, string) {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
        }
        Some(VT_DISPATCH) | Some(VT_UNKNOWN) => {
            for chunk in data.chunks_exact(4) {
                let interface = u32::from_le_bytes(chunk.try_into().map_err(|_| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 SAFEARRAY interface slot has an invalid width",
                    )
                })?);
                if interface != 0 {
                    if let Err(error) = reject_interface(LeaseAction::Release, interface) {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
        }
        Some(VT_VARIANT) => {
            for chunk in data.chunks_exact(16) {
                let value = match Variant16::decode(chunk) {
                    Ok(value) => value,
                    Err(_) => {
                        if first_error.is_none() {
                            first_error = Some(RuntimeError::new(
                                Kind::InvalidInput,
                                "Win16 SAFEARRAY contains an invalid VARIANT",
                            ));
                        }
                        continue;
                    }
                };
                if let Err(error) = release_variant_contents(
                    state,
                    heap,
                    selectors,
                    memory,
                    owner,
                    value,
                    visited_arrays,
                    visited_bstrs,
                    reject_interface,
                    depth + 1,
                ) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        _ => {}
    }
    first_error.map_or(Ok(()), Err)
}

fn release_variant_contents(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    value: Variant16,
    visited_arrays: &mut BTreeSet<u32>,
    visited_bstrs: &mut BTreeSet<u32>,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    depth: usize,
) -> Result<(), RuntimeError> {
    validate_vartype_bits(value.vt).map_err(failure_to_runtime)?;
    let base = value.vt & VT_TYPEMASK;
    if value.vt & VT_BYREF != 0 {
        return Ok(());
    }
    let far = value.guest_far();
    if value.vt & VT_ARRAY != 0 {
        if far == 0 {
            return Ok(());
        }
        if depth >= MAX_TEARDOWN_VARIANT_DEPTH {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY teardown nesting exceeds its bound",
            ));
        }
        return release_array_contents(
            state,
            heap,
            selectors,
            memory,
            owner,
            far,
            Some(base),
            visited_arrays,
            visited_bstrs,
            reject_interface,
            depth,
        );
    }
    match base {
        VT_BSTR => {
            if far != 0 && visited_bstrs.insert(far) {
                state.release_bstr(heap, selectors, owner, far)?;
            }
            Ok(())
        }
        VT_DISPATCH | VT_UNKNOWN => {
            if far != 0 {
                reject_interface(LeaseAction::Release, far)?;
            }
            Ok(())
        }
        VT_EMPTY | VT_NULL | VT_I1 | VT_UI1 | VT_I2 | VT_UI2 | VT_I4 | VT_UI4 | VT_I8 | VT_UI8
        | VT_INT | VT_UINT | VT_R4 | VT_R8 | VT_CY | VT_DATE | VT_ERROR | VT_BOOL => Ok(()),
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY contains an unsupported owned VARTYPE",
        )),
    }
}

fn failure_to_runtime(error: AutomationFailure) -> RuntimeError {
    match error {
        AutomationFailure::Runtime(error) => error,
        AutomationFailure::HResultRuntime { source, .. } => source,
        AutomationFailure::HResult(status) => RuntimeError::new(
            if status == 0x8000_4001 {
                Kind::CompatibilityGap
            } else {
                Kind::InvalidInput
            },
            format!("Win16 Automation teardown rejected HRESULT {status:#010x}"),
        ),
    }
}
