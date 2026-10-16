//! Checked OLE2DISP.109 pointer lookup into guest-owned SAFEARRAY data.
//!
//! `ole2disp.spec` supplies the Win16 FAR/FAR/FAR Pascal frame and DWORD
//! HRESULT. The operation follows Microsoft's Automation contract:
//! https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayptrofindex
//! The caller owns the array lock; lookup neither acquires nor releases it.

use guest_core::memory::Memory;
use win16_abi::{Access, SelectorTable};

use super::{AutomationFailure, E_INVALIDARG, Win16AutomationState};
use super::super::{
    checked_safe_array_huge_chunks, expected_array_data_length, read_guest_far_bytes,
};

pub(super) fn safe_array_ptr_of_index(
    state: &Win16AutomationState,
    array_far: u32,
    indices_far: u32,
    output_far: u32,
    selectors: &SelectorTable,
    memory: &mut Memory,
) -> Result<(), AutomationFailure> {
    if array_far == 0 || indices_far == 0 || output_far == 0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    // Preflight the four-byte FAR-pointer output before reading inputs; commit
    // only after all descriptor, index and data-range checks have succeeded.
    super::validate_writable_range(selectors, memory, output_far, 4)?;
    let descriptor = state.read_safe_array_descriptor(selectors, memory, array_far)?;
    if descriptor.data == 0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    let data_length = expected_array_data_length(&descriptor)?;
    let indices_length = usize::from(descriptor.dimensions)
        .checked_mul(4)
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let indices_pointer = selectors.pointer_from_far(indices_far)
        .map_err(crate::runtime_error)?;
    let indices = read_guest_far_bytes(selectors, memory, indices_pointer, indices_length)?;
    let cell = super::get_element::array_cell_index(&descriptor, &indices)?;
    let byte_offset = cell.checked_mul(usize::from(descriptor.element_size))
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
    let data_pointer = selectors.pointer_from_far(descriptor.data)
        .map_err(crate::runtime_error)?;
    // SAFEARRAY pvData uses the existing checked huge-span contract. Do not
    // copy array contents or wrap a 16-bit offset across unrelated selectors.
    checked_safe_array_huge_chunks(selectors, memory, data_pointer, data_length, Access::Read)?;
    let element = selectors.add_bytes(data_pointer, byte_offset)
        .map_err(crate::runtime_error)?;
    super::write_u32(selectors, memory, output_far, element.far_value())?;
    Ok(())
}

#[cfg(test)]
#[path = "ptr_of_index_tests.rs"]
mod ptr_of_index_tests;
