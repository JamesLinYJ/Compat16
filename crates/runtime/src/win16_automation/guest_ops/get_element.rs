//! Checked SafeArrayGetElement copy with guest ownership preservation.

use compat_services::automation::{VT_BSTR, VT_DISPATCH, VT_UNKNOWN, VT_VARIANT, Variant16};
use guest_core::OwnerId;
use guest_core::memory::Memory;
use win16_abi::{GlobalHeap, SelectorTable};

use crate::RuntimeError;

use super::super::{read_guest_far_bytes, write_guest_far_bytes};
use super::variant::{clone_variant, element_type_from_descriptor, validate_writable_range};
use super::variant_rollback::rollback_variant;
use super::{
    AutomationFailure, AutomationInterfaceAction as LeaseAction, DISP_E_BADVARTYPE,
    Win16AutomationState,
};

const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOTIMPL: u32 = 0x8000_4001;
const DISP_E_BADINDEX: u32 = 0x8002_000b;

pub(super) fn safe_array_get_element(
    state: &mut Win16AutomationState,
    array_far: u32,
    indices_far: u32,
    output_far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    if array_far == 0 || indices_far == 0 || output_far == 0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    let (descriptor, data) = state
        .read_safe_array(selectors, memory, array_far)
        .map_err(AutomationFailure::from)?;
    let element_type = element_type_from_descriptor(&descriptor, None)?;
    let width = usize::from(descriptor.element_size);
    validate_writable_range(selectors, memory, output_far, width)
        .map_err(AutomationFailure::from)?;
    let output_pointer = selectors
        .pointer_from_far(output_far)
        .map_err(crate::runtime_error)
        .map_err(AutomationFailure::from)?;

    let indices_length = usize::from(descriptor.dimensions)
        .checked_mul(4)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let indices_pointer = selectors
        .pointer_from_far(indices_far)
        .map_err(crate::runtime_error)
        .map_err(AutomationFailure::from)?;
    let indices = read_guest_far_bytes(selectors, memory, indices_pointer, indices_length)
        .map_err(AutomationFailure::from)?;
    let cell = array_cell_index(&descriptor, &indices)?;
    let byte_offset = cell
        .checked_mul(width)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let byte_end = byte_offset
        .checked_add(width)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let source_bytes = data
        .get(byte_offset..byte_end)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;

    state
        .safe_array_lock(selectors, memory, array_far)
        .map_err(AutomationFailure::from)?;
    let result = copy_element(
        state,
        element_type,
        source_bytes,
        output_pointer,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
    );
    let unlock = state
        .safe_array_unlock(selectors, memory, array_far)
        .map_err(AutomationFailure::from)
        .map_err(|error| {
            error.rollback_failure("Win16 SafeArrayGetElement failed to unlock its source array")
        });
    match (result, unlock) {
        (Err(primary), Err(cleanup)) => Err(AutomationFailure::cleanup_failed(
            primary,
            cleanup,
            "Win16 SafeArrayGetElement copy and unlock both failed",
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn copy_element(
    state: &mut Win16AutomationState,
    element_type: Option<u16>,
    source: &[u8],
    output_pointer: win16_abi::SegmentedPointer,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    match element_type {
        Some(VT_BSTR) => {
            let source_far = read_far(source)?;
            let copied_far = if source_far == 0 {
                0
            } else {
                let bytes = state
                    .read_bstr(selectors, memory, source_far)
                    .map_err(AutomationFailure::from)?
                    .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
                state
                    .allocate_bstr(heap, selectors, memory, owner, &bytes)
                    .map_err(AutomationFailure::from)?
            };
            if let Err(error) =
                write_guest_far_bytes(selectors, memory, output_pointer, &copied_far.to_le_bytes())
            {
                if copied_far != 0 {
                    state
                        .release_bstr(heap, selectors, owner, copied_far)
                        .map_err(AutomationFailure::from)?;
                }
                return Err(AutomationFailure::from(error));
            }
            Ok(())
        }
        Some(VT_DISPATCH) | Some(VT_UNKNOWN) => {
            let interface = read_far(source)?;
            if interface != 0 {
                return match reject_interface(LeaseAction::AddRef, interface)
                    .map_err(AutomationFailure::from)
                {
                    Err(error) => Err(error),
                    Ok(()) => Err(AutomationFailure::HResult(E_NOTIMPL)),
                };
            }
            write_guest_far_bytes(selectors, memory, output_pointer, &0_u32.to_le_bytes())
                .map_err(AutomationFailure::from)?;
            Ok(())
        }
        Some(VT_VARIANT) => {
            let source = Variant16::decode(source)
                .map_err(|_| AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
            let copied = clone_variant(
                state,
                source,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
                0,
            )?;
            if let Err(error) =
                write_guest_far_bytes(selectors, memory, output_pointer, &copied.encode())
            {
                rollback_variant(
                    state,
                    copied,
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
        None => write_guest_far_bytes(selectors, memory, output_pointer, source)
            .map_err(AutomationFailure::from),
        Some(_) => Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    }
}

fn array_cell_index(
    descriptor: &compat_services::automation::SafeArray16,
    raw_indices: &[u8],
) -> Result<usize, AutomationFailure> {
    let expected = usize::from(descriptor.dimensions)
        .checked_mul(4)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    if raw_indices.len() != expected
        || descriptor.bounds.len() != usize::from(descriptor.dimensions)
    {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    let mut cell = 0_usize;
    let mut stride = 1_usize;
    for dimension in 0..usize::from(descriptor.dimensions) {
        let offset = dimension
            .checked_mul(4)
            .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
        let index = i32::from_le_bytes(
            raw_indices[offset..offset + 4]
                .try_into()
                .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
        );
        let bound_index = descriptor.bounds.len() - 1 - dimension;
        let bound = descriptor.bounds[bound_index];
        let relative = i64::from(index) - i64::from(bound.lower_bound);
        if relative < 0 || relative >= i64::from(bound.elements) {
            return Err(AutomationFailure::HResult(DISP_E_BADINDEX));
        }
        let relative =
            usize::try_from(relative).map_err(|_| AutomationFailure::HResult(DISP_E_BADINDEX))?;
        cell = cell
            .checked_add(
                relative
                    .checked_mul(stride)
                    .ok_or(AutomationFailure::HResult(E_INVALIDARG))?,
            )
            .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
        stride = stride
            .checked_mul(
                usize::try_from(bound.elements)
                    .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
            )
            .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    }
    Ok(cell)
}

fn read_far(bytes: &[u8]) -> Result<u32, AutomationFailure> {
    if bytes.len() != 4 {
        return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
    }
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        AutomationFailure::HResult(DISP_E_BADVARTYPE)
    })?))
}
