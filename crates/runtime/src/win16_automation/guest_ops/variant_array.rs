use std::collections::BTreeSet;

use super::super::super::read_safe_array_huge_bytes;
use super::super::E_NOTIMPL;
use super::*;

pub(in crate::win16_automation::guest_ops) fn clone_safe_array(
    state: &mut Win16AutomationState,
    source_far: u32,
    expected: Option<u16>,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    depth: usize,
) -> Result<u32, AutomationFailure> {
    let (source_descriptor, data) = state
        .read_safe_array(selectors, memory, source_far)
        .map_err(AutomationFailure::from)?;
    let element_type = element_type_from_descriptor(&source_descriptor, expected)?;
    validate_array_data(&source_descriptor, data.len()).map_err(AutomationFailure::from)?;
    let mut cloned_elements = Vec::new();
    let cloned_data = match element_type {
        Some(VT_BSTR) => {
            let mut output = zeroed(data.len())?;
            cloned_elements
                .try_reserve_exact(data.len() / 4)
                .map_err(|_| AutomationFailure::HResult(E_OUTOFMEMORY))?;
            for (index, chunk) in data.chunks_exact(4).enumerate() {
                let input_far = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
                );
                if input_far == 0 {
                    continue;
                }
                let bytes = match state.read_bstr(selectors, memory, input_far) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => continue,
                    Err(error) => {
                        rollback_cloned_elements(
                            state,
                            &mut cloned_elements,
                            heap,
                            selectors,
                            memory,
                            owner,
                            reject_interface,
                        )?;
                        return Err(AutomationFailure::from(error));
                    }
                };
                let new_far = match state.allocate_bstr(heap, selectors, memory, owner, &bytes) {
                    Ok(far) => far,
                    Err(error) => {
                        rollback_cloned_elements(
                            state,
                            &mut cloned_elements,
                            heap,
                            selectors,
                            memory,
                            owner,
                            reject_interface,
                        )?;
                        return Err(AutomationFailure::from(error));
                    }
                };
                cloned_elements.push(ClonedElement::Bstr(new_far));
                let offset = index * 4;
                output[offset..offset + 4].copy_from_slice(&new_far.to_le_bytes());
            }
            output
        }
        Some(VT_DISPATCH) | Some(VT_UNKNOWN) => {
            let output = zeroed(data.len())?;
            for chunk in data.chunks_exact(4) {
                let interface = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
                );
                if interface == 0 {
                    continue;
                }
                let failure = reject_interface(LeaseAction::AddRef, interface)
                    .map_err(AutomationFailure::from);
                rollback_cloned_elements(
                    state,
                    &mut cloned_elements,
                    heap,
                    selectors,
                    memory,
                    owner,
                    reject_interface,
                )?;
                return match failure {
                    Err(error) => Err(error),
                    Ok(()) => Err(AutomationFailure::HResult(E_NOTIMPL)),
                };
            }
            output
        }
        Some(VT_VARIANT) => {
            let mut output = zeroed(data.len())?;
            cloned_elements
                .try_reserve_exact(data.len() / 16)
                .map_err(|_| AutomationFailure::HResult(E_OUTOFMEMORY))?;
            for (index, chunk) in data.chunks_exact(16).enumerate() {
                let source = Variant16::decode(chunk).map_err(|error| {
                    AutomationFailure::HResult(
                        if matches!(
                            error,
                            compat_services::automation::AutomationAbiError::WrongSize { .. }
                        ) {
                            E_INVALIDARG
                        } else {
                            DISP_E_BADVARTYPE
                        },
                    )
                })?;
                let copied = match clone_variant(
                    state,
                    source,
                    heap,
                    selectors,
                    memory,
                    owner,
                    reject_interface,
                    depth,
                ) {
                    Ok(copied) => copied,
                    Err(error) => {
                        rollback_cloned_elements(
                            state,
                            &mut cloned_elements,
                            heap,
                            selectors,
                            memory,
                            owner,
                            reject_interface,
                        )?;
                        return Err(error);
                    }
                };
                cloned_elements.push(ClonedElement::Variant(copied));
                let offset = index * 16;
                output[offset..offset + 16].copy_from_slice(&copied.encode());
            }
            output
        }
        _ => clone_raw_bytes(&data)?,
    };
    let mut descriptor = source_descriptor;
    descriptor.locks = 0;
    descriptor.handle = 0;
    descriptor.data = 0;
    descriptor.features &= !(FADF_AUTO | FADF_STATIC | FADF_EMBEDDED);
    match state.allocate_safe_array(heap, selectors, memory, owner, descriptor, &cloned_data) {
        Ok(far) => Ok(far),
        Err(error) => {
            rollback_cloned_elements(
                state,
                &mut cloned_elements,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
            )?;
            Err(AutomationFailure::from(error))
        }
    }
}

pub(in crate::win16_automation::guest_ops) fn destroy_safe_array_with_type(
    state: &mut Win16AutomationState,
    far: u32,
    expected_type: Option<u16>,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    released: &mut BTreeSet<u32>,
) -> Result<(), AutomationFailure> {
    if !released.insert(far) {
        return Ok(());
    }
    let (_, descriptor) =
        read_safe_array_descriptor(selectors, memory, far).map_err(AutomationFailure::from)?;
    require_safe_array_descriptor(state, owner, far).map_err(AutomationFailure::from)?;
    if descriptor.locks != 0 {
        return Err(AutomationFailure::HResult(DISP_E_ARRAYISLOCKED));
    }
    if descriptor.data != 0 {
        if let Some(expected) = expected_type {
            element_type_from_descriptor(&descriptor, Some(expected))?;
        }
        release_array_contents(
            state,
            &descriptor,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
            released,
        )?;
    }
    state
        .release_safe_array(heap, selectors, memory, owner, far)
        .map_err(AutomationFailure::from)
}

pub(in crate::win16_automation::guest_ops) fn release_array_contents(
    state: &mut Win16AutomationState,
    descriptor: &SafeArray16,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
    released: &mut BTreeSet<u32>,
) -> Result<(), AutomationFailure> {
    if descriptor.data == 0 {
        return Ok(());
    }
    let data_length = expected_array_data_length(descriptor).map_err(AutomationFailure::from)?;
    if data_length > MAX_AUTOMATION_ALLOCATION {
        return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
    }
    let data_pointer = selectors
        .pointer_from_far(descriptor.data)
        .map_err(crate::runtime_error)
        .map_err(AutomationFailure::from)?;
    let data = read_safe_array_huge_bytes(selectors, memory, data_pointer, data_length)
        .map_err(AutomationFailure::from)?;
    match element_type_from_descriptor(descriptor, None)? {
        Some(VT_BSTR) => {
            for chunk in data.chunks_exact(4) {
                let far = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?,
                );
                if far != 0 && released.insert(far) {
                    state
                        .release_bstr(heap, selectors, owner, far)
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
            for chunk in data.chunks_exact(16) {
                let value = Variant16::decode(chunk)
                    .map_err(|_| AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
                release_variant(
                    state,
                    value,
                    heap,
                    selectors,
                    memory,
                    owner,
                    reject_interface,
                    released,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(in crate::win16_automation::guest_ops) fn element_type_from_descriptor(
    descriptor: &SafeArray16,
    expected: Option<u16>,
) -> Result<Option<u16>, AutomationFailure> {
    let special = descriptor.features & (FADF_BSTR | FADF_DISPATCH | FADF_UNKNOWN | FADF_VARIANT);
    let inferred = match special {
        0 => None,
        FADF_BSTR => Some(VT_BSTR),
        FADF_DISPATCH => Some(VT_DISPATCH),
        FADF_UNKNOWN => Some(VT_UNKNOWN),
        FADF_VARIANT => Some(VT_VARIANT),
        _ => return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE)),
    };
    if let Some(expected) = expected {
        let width = safe_array_element_width(expected)
            .ok_or(AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
        if width != descriptor.element_size {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        if let Some(inferred) = inferred {
            if inferred != expected {
                return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
            }
        } else if matches!(expected, VT_BSTR | VT_DISPATCH | VT_UNKNOWN | VT_VARIANT) {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        return Ok(Some(expected));
    }
    if let Some(inferred) = inferred {
        if safe_array_element_width(inferred) != Some(descriptor.element_size) {
            return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
        }
        return Ok(Some(inferred));
    }
    if descriptor.element_size == 0 {
        return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
    }
    Ok(None)
}

pub(in crate::win16_automation::guest_ops) fn validate_vartype_bits(
    vartype: u16,
) -> Result<(), AutomationFailure> {
    let allowed = VT_TYPEMASK | VT_ARRAY | VT_BYREF;
    if vartype & !allowed != 0 {
        return Err(AutomationFailure::HResult(DISP_E_BADVARTYPE));
    }
    Ok(())
}

pub(in crate::win16_automation::guest_ops) fn supported_vartype(vartype: u16) -> bool {
    matches!(
        vartype,
        VT_EMPTY
            | VT_NULL
            | VT_BSTR
            | VT_DISPATCH
            | VT_UNKNOWN
            | VT_VARIANT
            | VT_I1
            | VT_UI1
            | VT_I2
            | VT_UI2
            | VT_I4
            | VT_UI4
            | VT_I8
            | VT_UI8
            | VT_INT
            | VT_UINT
            | VT_R4
            | VT_R8
            | VT_CY
            | VT_DATE
            | VT_ERROR
            | VT_BOOL
    )
}

pub(in crate::win16_automation::guest_ops) fn require_safe_array_descriptor(
    state: &Win16AutomationState,
    owner: OwnerId,
    far: u32,
) -> Result<(), RuntimeError> {
    state
        .require_owned_allocation(owner, far, AllocationKind::SafeArrayDescriptor)
        .map(|_| ())
}
