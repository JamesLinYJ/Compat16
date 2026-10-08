//! Win16 VARIANT and SAFEARRAY ownership transitions.

use std::collections::BTreeSet;

use compat_services::automation::{
    FADF_AUTO, FADF_BSTR, FADF_DISPATCH, FADF_EMBEDDED, FADF_STATIC, FADF_UNKNOWN, FADF_VARIANT,
    SafeArray16, VT_ARRAY, VT_BOOL, VT_BSTR, VT_BYREF, VT_CY, VT_DATE, VT_DISPATCH, VT_EMPTY,
    VT_ERROR, VT_I1, VT_I2, VT_I4, VT_I8, VT_INT, VT_NULL, VT_R4, VT_R8, VT_TYPEMASK, VT_UI1,
    VT_UI2, VT_UI4, VT_UI8, VT_UINT, VT_UNKNOWN, VT_VARIANT, Variant16, safe_array_element_width,
};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use win16_abi::{GlobalHeap, SelectorTable};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::super::{
    AllocationKind, MAX_AUTOMATION_ALLOCATION, Win16AutomationState, array_abi_error,
    expected_array_data_length, read_guest_far_bytes, read_safe_array_descriptor,
    validate_array_data, write_guest_far_bytes,
};
use super::variant_rollback::{
    ClonedElement, rollback_array, rollback_cloned_elements, rollback_variant,
};
use super::{
    AutomationFailure, AutomationInterfaceAction as LeaseAction, DISP_E_ARRAYISLOCKED,
    DISP_E_BADVARTYPE, E_INVALIDARG, E_OUTOFMEMORY, E_POINTER,
};

const MAX_VARIANT_INDIRECTION: usize = 32;

#[path = "variant_array.rs"]
mod variant_array;
#[path = "variant_codec.rs"]
mod variant_codec;
#[path = "variant_preflight.rs"]
mod variant_preflight;

pub(super) use variant_array::{
    clone_safe_array, destroy_safe_array_with_type, element_type_from_descriptor,
    release_array_contents, require_safe_array_descriptor, supported_vartype,
    validate_vartype_bits,
};
pub(super) use variant_codec::{
    clone_raw_bytes, read_u32, read_variant, validate_writable_range, with_guest_far, write_u32,
    write_variant, zeroed,
};
pub(super) use variant_preflight::{preflight_safe_array_release, preflight_variant_release};

pub(super) fn variant_init(
    destination: u32,
    selectors: &SelectorTable,
    memory: &mut Memory,
) -> Result<(), RuntimeError> {
    write_variant(selectors, memory, destination, Variant16::EMPTY)
}

pub(super) fn variant_clear(
    state: &mut Win16AutomationState,
    far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    validate_writable_range(selectors, memory, far, 16).map_err(AutomationFailure::from)?;
    let value = read_variant(selectors, memory, far).map_err(AutomationFailure::from)?;
    preflight_variant_release(
        state,
        value,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        0,
        true,
    )?;
    let mut released = BTreeSet::new();
    release_variant(
        state,
        value,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut released,
    )
    .map_err(|error| {
        error.after_destructive_commit(
            "Win16 VariantClear failed after preflight began releasing the value",
        )
    })?;
    write_variant(selectors, memory, far, Variant16::EMPTY)
        .map_err(AutomationFailure::from)
        .map_err(|error| {
            error.after_destructive_commit(
                "Win16 VariantClear failed to publish VT_EMPTY after releasing the value",
            )
        })
}

pub(super) fn variant_copy(
    state: &mut Win16AutomationState,
    destination: u32,
    source: u32,
    indirect: bool,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    validate_writable_range(selectors, memory, destination, 16).map_err(AutomationFailure::from)?;
    if destination == source && !indirect {
        return Ok(());
    }
    let source_value = read_variant(selectors, memory, source).map_err(AutomationFailure::from)?;
    let destination_value =
        read_variant(selectors, memory, destination).map_err(AutomationFailure::from)?;
    preflight_variant_release(
        state,
        destination_value,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        0,
        true,
    )?;
    let copied = if indirect {
        indirect_variant(
            state,
            source_value,
            source,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            0,
        )?
    } else {
        clone_variant(
            state,
            source_value,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            0,
        )?
    };
    if let Err(error) = release_variant(
        state,
        destination_value,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
    ) {
        rollback_variant(
            state,
            copied,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
        )?;
        return Err(error.after_destructive_commit(
            "Win16 VariantCopy failed while releasing its preflighted destination",
        ));
    }
    if let Err(error) = write_variant(selectors, memory, destination, copied) {
        rollback_variant(
            state,
            copied,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
        )?;
        return Err(AutomationFailure::from(error).after_destructive_commit(
            "Win16 VariantCopy failed to publish the copied value after releasing its destination",
        ));
    }
    Ok(())
}

pub(super) fn safe_array_copy(
    state: &mut Win16AutomationState,
    source: u32,
    output: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    if output == 0 {
        return Err(AutomationFailure::HResult(E_POINTER));
    }
    validate_writable_range(selectors, memory, output, 4).map_err(AutomationFailure::from)?;
    write_u32(selectors, memory, output, 0).map_err(AutomationFailure::from)?;
    let (_, descriptor) =
        read_safe_array_descriptor(selectors, memory, source).map_err(AutomationFailure::from)?;
    let expected = element_type_from_descriptor(&descriptor, None)?;
    let array = clone_safe_array(
        state,
        source,
        expected,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
        0,
    )?;
    if let Err(error) = write_u32(selectors, memory, output, array) {
        rollback_array(
            state,
            array,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
        )?;
        return Err(AutomationFailure::from(error));
    }
    Ok(())
}

pub(super) fn safe_array_destroy(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    far: u32,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    preflight_safe_array_release(
        state,
        far,
        None,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        0,
        true,
    )?;
    let (_, descriptor) =
        read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
    if descriptor.data != 0 {
        let mut released = BTreeSet::new();
        released.insert(far);
        release_array_contents(
            state,
            &descriptor,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            &mut released,
        )
        .map_err(|error| {
            error.after_destructive_commit(
                "Win16 SAFEARRAY destroy failed after preflight began releasing elements",
            )
        })?;
    }
    state
        .release_safe_array(heap, selectors, memory, owner, far)
        .map_err(AutomationFailure::from)
        .map_err(|error| {
            error.after_destructive_commit(
                "Win16 SAFEARRAY destroy failed after releasing its elements",
            )
        })
}

pub(super) fn safe_array_destroy_descriptor(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    far: u32,
) -> Result<(), AutomationFailure> {
    let (_, descriptor) =
        read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
    require_safe_array_descriptor(state, owner, far).map_err(AutomationFailure::from)?;
    if descriptor.locks != 0 {
        return Err(AutomationFailure::HResult(DISP_E_ARRAYISLOCKED));
    }
    if descriptor.data != 0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    state
        .release_allocation(
            heap,
            selectors,
            owner,
            far,
            AllocationKind::SafeArrayDescriptor,
        )
        .map_err(AutomationFailure::from)
}

pub(super) fn safe_array_destroy_data(
    state: &mut Win16AutomationState,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    far: u32,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    let (pointer, descriptor) =
        read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
    require_safe_array_descriptor(state, owner, far).map_err(AutomationFailure::from)?;
    if descriptor.locks != 0 {
        return Err(AutomationFailure::HResult(DISP_E_ARRAYISLOCKED));
    }
    if descriptor.data == 0 {
        return Ok(());
    }
    let mut cleared_descriptor = descriptor.clone();
    cleared_descriptor.data = 0;
    let cleared_bytes = cleared_descriptor
        .encode()
        .map_err(array_abi_error)
        .map_err(AutomationFailure::from)?;
    validate_writable_range(selectors, memory, pointer.far_value(), cleared_bytes.len())
        .map_err(AutomationFailure::from)?;
    preflight_safe_array_release(
        state,
        far,
        None,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        0,
        true,
    )?;
    let mut released = BTreeSet::new();
    released.insert(far);
    release_array_contents(
        state,
        &descriptor,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut released,
    )
    .map_err(|error| {
        error.after_destructive_commit(
            "Win16 SafeArrayDestroyData failed after preflight began releasing elements",
        )
    })?;
    state
        .release_allocation(
            heap,
            selectors,
            owner,
            descriptor.data,
            AllocationKind::SafeArrayData,
        )
        .map_err(AutomationFailure::from)
        .map_err(|error| {
            error.after_destructive_commit(
                "Win16 SafeArrayDestroyData failed while releasing its data allocation",
            )
        })?;
    write_guest_far_bytes(selectors, memory, pointer, &cleared_bytes)
        .map_err(AutomationFailure::from)
        .map_err(|error| {
            error.after_destructive_commit(
                "Win16 SafeArrayDestroyData failed to clear the descriptor after freeing its data",
            )
        })
}

pub(super) fn clone_variant(
    state: &mut Win16AutomationState,
    source: Variant16,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    depth: usize,
) -> Result<Variant16, AutomationFailure> {
    validate_vartype_bits(source.vt)?;
    let base = source.vt & VT_TYPEMASK;
    if source.vt & VT_BYREF != 0 {
        if !supported_vartype(base) {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        return Ok(source);
    }
    if source.vt & VT_ARRAY != 0 {
        let source_array = source.guest_far();
        if source_array == 0 {
            return Ok(source);
        }
        if depth >= MAX_VARIANT_INDIRECTION {
            return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
        }
        let (_, descriptor) = read_safe_array_descriptor(selectors, memory, source_array)
            .map_err(AutomationFailure::from)?;
        let expected = element_type_from_descriptor(&descriptor, Some(base))?;
        let array = clone_safe_array(
            state,
            source_array,
            expected,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            depth + 1,
        )?;
        return Ok(with_guest_far(source, array));
    }
    match base {
        VT_BSTR => {
            let source_bstr = source.guest_far();
            if source_bstr == 0 {
                return Ok(source);
            }
            let bytes = state
                .read_bstr(selectors, memory, source_bstr)
                .map_err(AutomationFailure::from)?
                .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
            let copy = state
                .allocate_bstr(heap, selectors, memory, owner, &bytes)
                .map_err(AutomationFailure::from)?;
            Ok(with_guest_far(source, copy))
        }
        VT_DISPATCH | VT_UNKNOWN => {
            let interface = source.guest_far();
            if interface != 0 {
                reject_interface(LeaseAction::AddRef, interface)
                    .map_err(AutomationFailure::from)?;
            }
            Ok(source)
        }
        VT_EMPTY | VT_NULL | VT_I1 | VT_UI1 | VT_I2 | VT_UI2 | VT_I4 | VT_UI4 | VT_I8 | VT_UI8
        | VT_INT | VT_UINT | VT_R4 | VT_R8 | VT_CY | VT_DATE | VT_ERROR | VT_BOOL => Ok(source),
        _ => Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    }
}

fn indirect_variant(
    state: &mut Win16AutomationState,
    source: Variant16,
    _source_far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    depth: usize,
) -> Result<Variant16, AutomationFailure> {
    validate_vartype_bits(source.vt)?;
    if source.vt & VT_BYREF == 0 {
        return clone_variant(
            state,
            source,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            depth,
        );
    }
    if depth >= MAX_VARIANT_INDIRECTION {
        return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
    }
    let base = source.vt & VT_TYPEMASK;
    let source_pointer = source.guest_far();
    if source_pointer == 0 {
        return Err(AutomationFailure::HResult(E_POINTER));
    }
    if base == VT_VARIANT && source.vt & VT_ARRAY == 0 {
        let nested =
            read_variant(selectors, memory, source_pointer).map_err(AutomationFailure::from)?;
        return indirect_variant(
            state,
            nested,
            source_pointer,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            depth + 1,
        );
    }
    if source.vt & VT_ARRAY != 0 {
        let array_far =
            read_u32(selectors, memory, source_pointer).map_err(AutomationFailure::from)?;
        let mut output = source;
        output.vt &= !VT_BYREF;
        if array_far == 0 {
            return Ok(with_guest_far(output, 0));
        }
        if depth >= MAX_VARIANT_INDIRECTION {
            return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
        }
        let (_, descriptor) = read_safe_array_descriptor(selectors, memory, array_far)
            .map_err(AutomationFailure::from)?;
        let expected = element_type_from_descriptor(&descriptor, Some(base))?;
        let array = clone_safe_array(
            state,
            array_far,
            expected,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            depth + 1,
        )?;
        return Ok(with_guest_far(output, array));
    }
    let width = match base {
        VT_BSTR | VT_DISPATCH | VT_UNKNOWN | VT_I4 | VT_UI4 | VT_R4 | VT_ERROR | VT_INT
        | VT_UINT => 4,
        VT_I1 | VT_UI1 => 1,
        VT_I2 | VT_UI2 | VT_BOOL => 2,
        VT_R8 | VT_CY | VT_DATE | VT_I8 | VT_UI8 => 8,
        _ => return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    };
    let pointer = selectors
        .pointer_from_far(source_pointer)
        .map_err(crate::runtime_error)
        .map_err(AutomationFailure::from)?;
    let bytes =
        read_guest_far_bytes(selectors, memory, pointer, width).map_err(AutomationFailure::from)?;
    let mut output = Variant16 {
        vt: source.vt & !VT_BYREF,
        reserved: [0; 3],
        payload: [0; 8],
    };
    output.payload[..width].copy_from_slice(&bytes);
    if matches!(base, VT_BSTR | VT_DISPATCH | VT_UNKNOWN) {
        let far = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
        );
        if base == VT_BSTR && far != 0 {
            let string = state
                .read_bstr(selectors, memory, far)
                .map_err(AutomationFailure::from)?
                .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
            let copy = state
                .allocate_bstr(heap, selectors, memory, owner, &string)
                .map_err(AutomationFailure::from)?;
            return Ok(with_guest_far(output, copy));
        }
        if matches!(base, VT_DISPATCH | VT_UNKNOWN) && far != 0 {
            reject_interface(LeaseAction::AddRef, far).map_err(AutomationFailure::from)?;
        }
    }
    Ok(output)
}

pub(super) fn release_variant(
    state: &mut Win16AutomationState,
    value: Variant16,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    released: &mut BTreeSet<u32>,
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
        // Aliased guest VARIANTs can refer to one owned SAFEARRAY. The
        // preflight has already validated the descriptor graph; skip a second
        // release before reading guest memory that the first release retired.
        if released.contains(&far) {
            return Ok(());
        }
        let (_, descriptor) =
            read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
        let expected = element_type_from_descriptor(&descriptor, Some(base))?;
        return destroy_safe_array_with_type(
            state,
            far,
            expected,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            released,
        );
    }
    match base {
        VT_BSTR => {
            let far = value.guest_far();
            if far != 0 && released.insert(far) {
                state
                    .release_bstr(heap, selectors, owner, far)
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
