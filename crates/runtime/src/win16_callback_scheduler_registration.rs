//! Registration-time and entry-time binding for guest callback code identity.

use guest_core::memory::Memory;
use win16_abi::{Access, SelectorTable};

use super::callback_entry::Win16GuestCallbackAbi;
use super::callback_scheduler::Win16GuestCallbackRegistration;
use super::far_callback::{Win16FarCallbackConvention, Win16FarCallbackReturn};
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, Win16GuestCallbackToken};

impl Win16State {
    /// Capture the exact selector generation and descriptor behind this FAR
    /// procedure before publishing its opaque producer token.
    pub(super) fn register_guest_callback(
        &mut self,
        memory: &Memory,
        procedure: u32,
        convention: Win16FarCallbackConvention,
        return_kind: Win16FarCallbackReturn,
    ) -> Result<Win16GuestCallbackToken, RuntimeError> {
        self.register_guest_callback_abi(
            memory,
            procedure,
            Win16GuestCallbackAbi::FarCall { convention, return_kind },
        )
    }

    fn register_guest_callback_abi(
        &mut self,
        memory: &Memory,
        procedure: u32,
        abi: Win16GuestCallbackAbi,
    ) -> Result<Win16GuestCallbackToken, RuntimeError> {
        let pointer = self.selectors.pointer_from_far(procedure).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        let procedure_selector = pointer.selector();
        let procedure_descriptor = self.selectors.describe(procedure_selector)
            .map_err(crate::runtime_error)?;
        self.callback_scheduler.register(
            procedure, procedure_selector, procedure_descriptor, abi,
        )
    }
}

pub(super) fn validate_guest_callback_registration(
    selectors: &SelectorTable,
    memory: &Memory,
    registration: Win16GuestCallbackRegistration,
) -> Result<(), RuntimeError> {
    let pointer = selectors.pointer_from_far(registration.procedure)
        .map_err(crate::runtime_error)?;
    if pointer.selector() != registration.procedure_selector {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "registered Win16 callback selector generation changed before guest entry",
        ));
    }
    let descriptor = selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
    if descriptor != registration.procedure_descriptor {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "registered Win16 callback descriptor changed before guest entry",
        ));
    }
    selectors
        .translate(pointer, Access::Execute, 1, memory)
        .map_err(crate::runtime_error)?;
    Ok(())
}
