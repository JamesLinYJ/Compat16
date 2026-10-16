//! Checked OLE2DISP.26 replacement in tracked, current-owner SAFEARRAY storage.
//!
//! Win16 ABI: Open Watcom dispatch.mh:652, compobj.mh:16-20, scode.mh:15,
//! and w16api/lib/ole2disp.def:27 at commit
//! 08a5064dd9831edf10234844630e605e83606989 establish three FAR arguments,
//! FAR PASCAL and a four-byte HRESULT. The compiler's pragma.gml documents
//! 12-byte callee cleanup and the DX:AX FAR return convention.
//! https://github.com/open-watcom/open-watcom-v2/tree/08a5064dd9831edf10234844630e605e83606989/bld/w16api
//! Ownership contract:
//! https://learn.microsoft.com/en-us/previous-versions/ms865838(v=msdn.10)
//!
//! Untracked/static arrays and non-null COM references remain unsupported.
//! Ordinary pre-commit failures preserve the cell; failures after releasing
//! old ownership are fatal invariant failures rather than fictional rollback.

use std::collections::BTreeSet;

use compat_services::automation::{
    FADF_AUTO, FADF_EMBEDDED, FADF_STATIC, VT_BSTR, VT_DISPATCH, VT_UNKNOWN, VT_VARIANT,
    Variant16,
};
use guest_core::{OwnerId, memory::Memory};
use win16_abi::{Access, GlobalHeap, SelectorTable};

use super::super::{read_guest_far_bytes, read_safe_array_huge_bytes, write_safe_array_huge_bytes};
use super::variant::{clone_variant, element_type_from_descriptor, release_variant};
use super::variant_rollback::rollback_variant;
use super::{AutomationFailure, AutomationInterfaceAction, E_INVALIDARG, Win16AutomationState};
use crate::RuntimeError;

#[path = "put_element_ownership.rs"]
mod ownership;

pub(super) fn safe_array_put_element(
    state: &mut Win16AutomationState,
    array_far: u32,
    indices_far: u32,
    input_far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    if array_far == 0 || indices_far == 0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    let descriptor = state.read_safe_array_descriptor(selectors, memory, array_far)?;
    let element_type = element_type_from_descriptor(&descriptor, None)?;
    if input_far == 0 && matches!(element_type, None | Some(VT_VARIANT)) {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    if descriptor.features & (FADF_AUTO | FADF_STATIC | FADF_EMBEDDED) != 0 {
        return Err(ownership::unsupported_storage());
    }
    let protected = ownership::validate_destination(
        state, &descriptor, array_far, heap, selectors, memory, owner,
    )?;
    let width = usize::from(descriptor.element_size);
    let indices = read_guest_far_bytes(
        selectors, memory, selectors.pointer_from_far(indices_far).map_err(crate::runtime_error)?,
        usize::from(descriptor.dimensions) * 4,
    )?;
    let cell = super::get_element::array_cell_index(&descriptor, &indices)?;
    let offset = cell.checked_mul(width)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let data = selectors.pointer_from_far(descriptor.data).map_err(crate::runtime_error)?;
    let cell_pointer = selectors.add_bytes(data, offset).map_err(crate::runtime_error)?;
    let old_bytes = read_safe_array_huge_bytes(selectors, memory, cell_pointer, width)?;
    // Preflight the entire huge cell before cloning or releasing anything.
    super::super::checked_safe_array_huge_chunks(selectors, memory, cell_pointer, width, Access::Write)?;
    let old_value = owned_value(element_type, &old_bytes)?;

    // Enforce unsupported ownership even if an injected diagnostic callback
    // happens to return success. No host COM side effect is allowed here.
    let mut reject = |action, far| {
        reject_interface(action, far)?;
        Err(RuntimeError::new(crate::DiagnosticKind::CompatibilityGap,
            "Win16 SafeArrayPutElement cannot transfer a non-null COM reference"))
    };
    // Check ownership before staging allocations: a stale guest pointer must
    // not become valid merely because a new clone reuses its former address.
    if let Some(old) = old_value {
        ownership::preflight_replacement(
            state, old, &protected, heap, selectors, memory, owner, &mut reject,
        )?;
    }
    // Stage the complete input before lock writes: pv/indices can alias the
    // descriptor, cell or old owned value. BSTR/interface pv is already the
    // value, whereas scalar/VARIANT pv points to the input bytes.
    let mut staged_bytes = super::variant::zeroed(width)?;
    let staged = match element_type {
        None => {
            let source = selectors.pointer_from_far(input_far).map_err(crate::runtime_error)?;
            staged_bytes = read_guest_far_bytes(selectors, memory, source, width)?;
            None
        }
        Some(vt) => {
            let source = if vt == VT_VARIANT {
                let source = selectors.pointer_from_far(input_far).map_err(crate::runtime_error)?;
                let bytes = read_guest_far_bytes(selectors, memory, source, 16)?;
                Variant16::decode(&bytes)
                    .map_err(|_| AutomationFailure::HResult(super::DISP_E_BADVARTYPE))?
            } else {
                super::variant::with_guest_far(Variant16 { vt, ..Variant16::EMPTY }, input_far)
            };
            let copied = clone_variant(state, source, heap, selectors, memory, owner, &mut reject, 0)?;
            if vt == VT_VARIANT {
                staged_bytes.copy_from_slice(&copied.encode());
            } else {
                staged_bytes.copy_from_slice(&copied.guest_far().to_le_bytes());
            }
            Some(copied)
        }
    };
    if let Err(error) = state.safe_array_lock(selectors, memory, array_far) {
        let primary = AutomationFailure::from(error);
        return match rollback_staged(state, staged, heap, selectors, memory, owner, &mut reject) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(AutomationFailure::cleanup_failed(primary, cleanup,
                "Win16 SafeArrayPutElement lock and staged rollback both failed")),
        };
    }

    let result = (|| {
        if let Some(old) = old_value {
            ownership::preflight_replacement(
                state, old, &protected, heap, selectors, memory, owner, &mut reject,
            )?;
            release_variant(state, old, heap, selectors, memory, owner, &mut reject,
                &mut BTreeSet::new())
                .map_err(|error| error.after_destructive_commit(
                    "Win16 SafeArrayPutElement failed while releasing the preflighted old value"))?;
        }
        write_safe_array_huge_bytes(selectors, memory, cell_pointer, &staged_bytes)
            .map_err(AutomationFailure::from)
            .map_err(|error| error.after_destructive_commit(
                "Win16 SafeArrayPutElement failed to publish its staged element"))
    })();
    let result = match result {
        Ok(()) => Ok(()),
        Err(primary) => match rollback_staged(state, staged, heap, selectors, memory, owner, &mut reject) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(AutomationFailure::cleanup_failed(primary, cleanup,
                "Win16 SafeArrayPutElement replacement and staged rollback both failed")),
        },
    };
    let unlock = state.safe_array_unlock(selectors, memory, array_far)
        .map_err(AutomationFailure::from)
        .map_err(|error| error.rollback_failure("Win16 SafeArrayPutElement failed to restore its array lock"));
    match (result, unlock) {
        (Err(primary), Err(cleanup)) => Err(AutomationFailure::cleanup_failed(primary, cleanup,
            "Win16 SafeArrayPutElement replacement and unlock both failed")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn owned_value(element_type: Option<u16>, bytes: &[u8]) -> Result<Option<Variant16>, AutomationFailure> {
    match element_type {
        None => Ok(None),
        Some(VT_VARIANT) => Variant16::decode(bytes).map(Some)
            .map_err(|_| AutomationFailure::HResult(super::DISP_E_BADVARTYPE)),
        Some(vt @ (VT_BSTR | VT_DISPATCH | VT_UNKNOWN)) => {
            let far = u32::from_le_bytes(bytes.try_into()
                .map_err(|_| AutomationFailure::HResult(super::DISP_E_BADVARTYPE))?);
            Ok(Some(super::variant::with_guest_far(Variant16 { vt, ..Variant16::EMPTY }, far)))
        }
        Some(_) => Err(AutomationFailure::HResult(super::DISP_E_BADVARTYPE)),
    }
}

fn rollback_staged(
    state: &mut Win16AutomationState,
    staged: Option<Variant16>,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    match staged {
        Some(value) => rollback_variant(state, value, heap, selectors, memory, owner, reject),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "put_element_tests.rs"]
mod tests;
