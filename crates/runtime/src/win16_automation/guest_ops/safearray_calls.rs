use super::*;

pub(super) fn execute_safe_array_call(
    state: &mut Win16AutomationState,
    ordinal: u16,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match ordinal {
        15 => execute_safe_array_create(state, arguments, heap, selectors, memory, owner),
        17..=24 => execute_safe_array_query(state, ordinal, arguments, selectors, memory),
        109 => {
            let result = super::ptr_of_index::safe_array_ptr_of_index(
                state,
                guest_address(arguments, 0)?,
                guest_address(arguments, 1)?,
                guest_address(arguments, 2)?,
                selectors,
                memory,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        _ => execute_safe_array_lifecycle(
            state,
            ordinal,
            arguments,
            heap,
            selectors,
            memory,
            owner,
            reject_interface,
        ),
    }
}

fn execute_safe_array_create(
    state: &mut Win16AutomationState,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    let vartype = word(arguments, 0)?;
    let dimensions = word(arguments, 1)?;
    let raw_bounds = exact_bytes(arguments, 2)?;
    let far = match state.create_safe_array(
        vartype, dimensions, raw_bounds, heap, selectors, memory, owner,
    ) {
        Ok(far) => far,
        Err(AutomationFailure::HResult(_) | AutomationFailure::HResultRuntime { .. }) => 0,
        Err(AutomationFailure::Runtime(error)) => allocation_failure_pointer(error)?,
    };
    Ok(Win16AutomationGuestResult::FarPointer(far))
}

fn execute_safe_array_query(
    state: &mut Win16AutomationState,
    ordinal: u16,
    arguments: &[Arg],
    selectors: &mut SelectorTable,
    memory: &mut Memory,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match ordinal {
        17 => {
            let far = guest_address(arguments, 0)?;
            let value = match state.safe_array_dimensions(selectors, memory, far) {
                Ok(value) => value,
                Err(error) => {
                    let _ = hresult_from_runtime(error)?;
                    0
                }
            };
            Ok(Win16AutomationGuestResult::Word(value))
        }
        18 => {
            let far = guest_address(arguments, 0)?;
            let value = match state.safe_array_element_size(selectors, memory, far) {
                Ok(value) => value,
                Err(error) => {
                    let _ = hresult_from_runtime(error)?;
                    0
                }
            };
            Ok(Win16AutomationGuestResult::Word(value))
        }
        19 | 20 => {
            let far = guest_address(arguments, 0)?;
            let dimension = word(arguments, 1)?;
            let output = guest_address(arguments, 2)?;
            let result = state
                .safe_array_bound(selectors, memory, far, dimension)
                .and_then(|(lower, upper)| {
                    validate_writable_range(selectors, memory, output, 4)?;
                    let value = if ordinal == 20 { lower } else { upper };
                    write_u32(selectors, memory, output, value as u32)
                });
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => hresult_from_runtime(error)?,
            }))
        }
        21 | 22 | 24 => {
            let far = guest_address(arguments, 0)?;
            let result = match ordinal {
                21 => state.safe_array_lock(selectors, memory, far),
                22 | 24 => state.safe_array_unlock(selectors, memory, far),
                _ => unreachable!(),
            };
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => hresult_from_runtime(error)?,
            }))
        }
        23 => {
            let far = guest_address(arguments, 0)?;
            let output = guest_address(arguments, 1)?;
            let result = validate_writable_range(selectors, memory, output, 4)
                .and_then(|()| state.safe_array_access_data(selectors, memory, far))
                .and_then(|data| write_u32(selectors, memory, output, data));
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => hresult_from_runtime(error)?,
            }))
        }
        _ => Err(unsupported_ordinal()),
    }
}

fn execute_safe_array_lifecycle(
    state: &mut Win16AutomationState,
    ordinal: u16,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match ordinal {
        16 => {
            let far = guest_address(arguments, 0)?;
            let result = variant::safe_array_destroy(
                state,
                heap,
                selectors,
                memory,
                owner,
                far,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        25 => {
            let array = guest_address(arguments, 0)?;
            let indices = guest_address(arguments, 1)?;
            let output = guest_address(arguments, 2)?;
            let result = get_element::safe_array_get_element(
                state,
                array,
                indices,
                output,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        27 => {
            let source = guest_address(arguments, 0)?;
            let output = guest_address(arguments, 1)?;
            let result = variant::safe_array_copy(
                state,
                source,
                output,
                heap,
                selectors,
                memory,
                owner,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        38 => allocate_descriptor_call(state, arguments, heap, selectors, memory, owner),
        39 => {
            let far = guest_address(arguments, 0)?;
            let result = state.safe_array_alloc_data(heap, selectors, memory, owner, far);
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => hresult_from_runtime(error)?,
            }))
        }
        40 => {
            let far = guest_address(arguments, 0)?;
            let result =
                variant::safe_array_destroy_descriptor(state, heap, selectors, memory, owner, far);
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        41 => {
            let far = guest_address(arguments, 0)?;
            let result = variant::safe_array_destroy_data(
                state,
                heap,
                selectors,
                memory,
                owner,
                far,
                reject_interface,
            );
            Ok(Win16AutomationGuestResult::HResult(match result {
                Ok(()) => S_OK,
                Err(error) => error.into_runtime()?,
            }))
        }
        _ => Err(unsupported_ordinal()),
    }
}

fn allocate_descriptor_call(
    state: &mut Win16AutomationState,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    let dimensions = word(arguments, 0)?;
    let output = guest_address(arguments, 1)?;
    if output == 0 {
        return Ok(Win16AutomationGuestResult::HResult(E_POINTER));
    }
    validate_writable_range(selectors, memory, output, 4)?;
    let result = state.safe_array_alloc_descriptor(heap, selectors, memory, owner, dimensions);
    let status = match result {
        Ok(far) => {
            if let Err(error) = write_u32(selectors, memory, output, far) {
                state.release_allocation(
                    heap,
                    selectors,
                    owner,
                    far,
                    AllocationKind::SafeArrayDescriptor,
                )?;
                return Err(error);
            }
            S_OK
        }
        Err(error) => hresult_from_runtime(error)?,
    };
    Ok(Win16AutomationGuestResult::HResult(status))
}

impl Win16AutomationState {
    fn create_safe_array(
        &mut self,
        vartype: u16,
        dimensions: u16,
        raw_bounds: Option<&[u8]>,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
    ) -> Result<u32, AutomationFailure> {
        let element_size = safe_array_element_width(vartype)
            .ok_or(AutomationFailure::HResult(DISP_E_BADVARTYPE))?;
        let raw_bounds = raw_bounds.ok_or(AutomationFailure::HResult(E_INVALIDARG))?;
        if dimensions == 0 {
            return Err(AutomationFailure::HResult(E_INVALIDARG));
        }
        let mut bounds = decode_safe_array_bounds16(raw_bounds, dimensions).map_err(|error| {
            AutomationFailure::HResult(match error {
                AutomationAbiError::AllocationFailed | AutomationAbiError::LengthOverflow => {
                    E_OUTOFMEMORY
                }
                _ => E_INVALIDARG,
            })
        })?;
        bounds.reverse();
        let features = match vartype {
            VT_BSTR => FADF_BSTR,
            VT_DISPATCH => FADF_DISPATCH,
            VT_UNKNOWN => FADF_UNKNOWN,
            VT_VARIANT => FADF_VARIANT,
            _ => 0,
        };
        let descriptor = SafeArray16 {
            dimensions,
            features,
            element_size,
            locks: 0,
            handle: 0,
            data: 0,
            bounds,
        };
        let length = super::super::expected_array_data_length(&descriptor)
            .map_err(AutomationFailure::from)?;
        if length > MAX_AUTOMATION_ALLOCATION {
            return Err(AutomationFailure::HResult(E_OUTOFMEMORY));
        }
        let data = zeroed_bytes(length).map_err(AutomationFailure::from)?;
        self.allocate_safe_array(heap, selectors, memory, owner, descriptor, &data)
            .map_err(AutomationFailure::from)
    }
}
