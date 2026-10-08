use std::borrow::Cow;

use super::*;

pub(super) fn execute_bstr_call(
    state: &mut Win16AutomationState,
    ordinal: u16,
    arguments: &[Arg],
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
) -> Result<Win16AutomationGuestResult, RuntimeError> {
    match ordinal {
        2 => {
            let value = nullable_bytes(arguments, 0)?;
            let far = match value {
                None => 0,
                Some(value) => match state.allocate_bstr(heap, selectors, memory, owner, value) {
                    Ok(far) => far,
                    Err(error) => allocation_failure_pointer(error)?,
                },
            };
            Ok(Win16AutomationGuestResult::FarPointer(far))
        }
        3 => {
            let output = guest_address(arguments, 0)?;
            let value = nullable_bytes(arguments, 1)?;
            let succeeded = state.reallocate_bstr(output, value, heap, selectors, memory, owner)?;
            Ok(Win16AutomationGuestResult::Dword(u32::from(succeeded)))
        }
        4 => {
            let source = counted_bstr(arguments, 0)?;
            let count = usize::from(word(arguments, 1)?);
            let value = match source {
                Some(bytes) => Cow::Borrowed(bytes),
                None => match zeroed_bytes(count) {
                    Ok(bytes) => Cow::Owned(bytes),
                    Err(error) if error.kind() == Kind::ResourceExhausted => {
                        return Ok(Win16AutomationGuestResult::FarPointer(0));
                    }
                    Err(error) => return Err(error),
                },
            };
            if value.len() != count {
                return Ok(Win16AutomationGuestResult::FarPointer(0));
            }
            let far = match state.allocate_bstr(heap, selectors, memory, owner, value.as_ref()) {
                Ok(far) => far,
                Err(error) => allocation_failure_pointer(error)?,
            };
            Ok(Win16AutomationGuestResult::FarPointer(far))
        }
        5 => {
            let output = guest_address(arguments, 0)?;
            let source = counted_bstr(arguments, 1)?;
            let count = usize::from(word(arguments, 2)?);
            let value = match source {
                Some(bytes) => Cow::Borrowed(bytes),
                None => match zeroed_bytes(count) {
                    Ok(bytes) => Cow::Owned(bytes),
                    Err(error) if error.kind() == Kind::ResourceExhausted => {
                        return Ok(Win16AutomationGuestResult::Word(0));
                    }
                    Err(error) => return Err(error),
                },
            };
            if value.len() != count {
                return Ok(Win16AutomationGuestResult::Word(0));
            }
            let succeeded = state.reallocate_bstr(
                output,
                Some(value.as_ref()),
                heap,
                selectors,
                memory,
                owner,
            )?;
            Ok(Win16AutomationGuestResult::Dword(u32::from(succeeded)))
        }
        6 => {
            let far = guest_address(arguments, 0)?;
            state.release_bstr(heap, selectors, owner, far)?;
            Ok(Win16AutomationGuestResult::Void)
        }
        7 => {
            let far = guest_address(arguments, 0)?;
            let length = state
                .read_bstr(selectors, memory, far)?
                .map_or(0, |bytes| bytes.len() as u32);
            Ok(Win16AutomationGuestResult::Dword(length))
        }
        _ => Err(unsupported_ordinal()),
    }
}

impl Win16AutomationState {
    fn reallocate_bstr(
        &mut self,
        output_far: u32,
        value: Option<&[u8]>,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
    ) -> Result<bool, RuntimeError> {
        if output_far == 0 {
            return Ok(false);
        }
        validate_writable_range(selectors, memory, output_far, 4)?;
        let old_far = read_u32(selectors, memory, output_far)?;
        if old_far != 0 {
            if let Err(error) = self.require_owned_allocation(owner, old_far, AllocationKind::Bstr)
            {
                if error.kind() == Kind::InvalidInput {
                    return Ok(false);
                }
                return Err(error);
            }
        }
        let new_far = match value {
            Some(value) => match self.allocate_bstr(heap, selectors, memory, owner, value) {
                Ok(far) => far,
                Err(error)
                    if matches!(error.kind(), Kind::InvalidInput | Kind::ResourceExhausted) =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            },
            None => 0,
        };
        if old_far != 0 {
            if let Err(error) = self.release_bstr(heap, selectors, owner, old_far) {
                if new_far != 0 {
                    self.release_bstr(heap, selectors, owner, new_far)
                        .map_err(|cleanup| {
                            RuntimeError::with_source(
                                Kind::InternalInvariant,
                                format!("BSTR reallocation could not release its new value after old-value release failed ({error})"),
                                cleanup,
                            )
                        })?;
                }
                if matches!(error.kind(), Kind::InvalidInput | Kind::ResourceExhausted) {
                    return Ok(false);
                }
                return Err(error);
            }
        }
        if let Err(error) = write_u32(selectors, memory, output_far, new_far) {
            if new_far != 0 {
                self.release_bstr(heap, selectors, owner, new_far)
                    .map_err(|cleanup| {
                        RuntimeError::with_source(
                            Kind::InternalInvariant,
                            format!("BSTR reallocation output write failed ({error}) and its new allocation rollback failed"),
                            cleanup,
                        )
                    })?;
            }
            if error.kind() == Kind::HostFailure {
                return Err(error);
            }
            return Err(RuntimeError::with_source(
                Kind::InternalInvariant,
                "BSTR reallocation could not publish after releasing the old value",
                error,
            ));
        }
        Ok(true)
    }
}
