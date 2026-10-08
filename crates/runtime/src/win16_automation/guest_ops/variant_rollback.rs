//! Roll back owned Automation values created during a failed copy.

use std::collections::BTreeSet;

use guest_core::OwnerId;
use guest_core::memory::Memory;
use win16_abi::{GlobalHeap, SelectorTable};

use crate::RuntimeError;

use super::variant::{release_variant, safe_array_destroy};
use super::{AutomationFailure, AutomationInterfaceAction as LeaseAction, Win16AutomationState};

#[derive(Clone, Copy)]
pub(super) enum ClonedElement {
    Bstr(u32),
    Variant(compat_services::automation::Variant16),
}

pub(super) fn rollback_cloned_elements(
    state: &mut Win16AutomationState,
    elements: &mut Vec<ClonedElement>,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    let mut first_error = None;
    while let Some(element) = elements.pop() {
        let result = match element {
            ClonedElement::Bstr(far) => state
                .release_bstr(heap, selectors, owner, far)
                .map_err(AutomationFailure::from)
                .map_err(|error| {
                    error.rollback_failure("rollback failed while releasing a cloned BSTR")
                }),
            ClonedElement::Variant(value) => {
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
                    error.rollback_failure("rollback failed while releasing a cloned VARIANT")
                })
            }
        };
        if let Err(error) = result {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(super) fn rollback_variant(
    state: &mut Win16AutomationState,
    value: compat_services::automation::Variant16,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    release_variant(
        state,
        value,
        heap,
        selectors,
        memory,
        owner,
        reject_interface,
        &mut BTreeSet::new(),
    )
    .map_err(|error| error.rollback_failure("rollback failed while releasing a cloned VARIANT"))
}

pub(super) fn rollback_array(
    state: &mut Win16AutomationState,
    far: u32,
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    reject_interface: &mut impl FnMut(LeaseAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    safe_array_destroy(state, heap, selectors, memory, owner, far, reject_interface).map_err(
        |error| error.rollback_failure("rollback failed while destroying a cloned SAFEARRAY"),
    )
}
