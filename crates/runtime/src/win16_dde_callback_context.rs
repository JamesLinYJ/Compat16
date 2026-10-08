//! Temporary Win16 CONVCONTEXT16 allocation for DDE callbacks.

use guest_core::{OwnerId, memory::Memory};
use win16_abi::{AllocationFlags, GlobalHandle};
use compat_services::win16_dde::DdeConvContext16;

use super::Win16State;
use crate::RuntimeError;

const DDE_CONTEXT_OWNER: OwnerId = OwnerId(1);

impl Win16State {
    pub(super) fn allocate_dde_context(
        &mut self,
        callback_id: super::CallbackFrameId,
        memory: &mut Memory,
        context: crate::Win16HostDdeContext,
    ) -> Result<(GlobalHandle, u32), RuntimeError> {
        self.reserve_dde_guest_block_retirement()?;
        if !self.dde_callbacks.last().is_some_and(|frame| {
            frame.callback_id == callback_id
                && frame.callback_kind_active
                && frame.context_allocation.is_none()
        }) || self.require_callback_top(super::CallbackKind::Dde)? != callback_id
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "DDE CONVCONTEXT allocation requires its exact published callback owner",
            ));
        }
        let allocation = self
            .heap
            .alloc(
                memory,
                DDE_CONTEXT_OWNER,
                DdeConvContext16::SIZE as u32,
                AllocationFlags::fixed().with_zero_init(),
            )
            .map_err(crate::runtime_error)?;
        let frame = self.dde_callbacks.last_mut().expect("exact DDE owner checked");
        frame.context_allocation = Some(allocation);
        frame.context_allocation_locked = false;
        let pointer = self
            .heap
            .lock(allocation, &mut self.selectors, memory)
            .map_err(crate::runtime_error)?;
        let frame = self.dde_callbacks.last_mut().expect("exact DDE owner retained");
        frame.context_allocation_locked = true;
        let encoded = DdeConvContext16 {
            flags: context.flags,
            country_id: context.country_id,
            code_page: context.code_page,
            language_id: context.language_id,
            security: context.security,
        }
        .encode();
        if let Err(error) = self.selectors.write(memory, pointer, &encoded) {
            return Err(crate::runtime_error(error));
        }
        Ok((allocation, pointer.far_value()))
    }
}

