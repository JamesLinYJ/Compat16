//! Whole-state adapters for DDE owners that do not hold an in-place window frame borrow.

use super::{DdeCompletionAccess, Win16State};
use crate::{RuntimeError, RuntimeHost, Win16HostDdeOperation, Win16HostDdeStep};

impl Win16State {
    /// Retry retirement of a DDE native Complete already cached on its exact
    /// exact top operation frame. This never searches past a child, begins or
    /// replays native work, and keeps the continuation in place on failure.
    pub(in crate::win16_runtime) fn retire_cached_dde_completion_source(
        &mut self,
        operation: Win16HostDdeOperation,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostDdeStep, RuntimeError> {
        use super::super::super::global_teardown::GlobalMemoryTeardownAccess;
        let Win16State {
            window_operations,
            heap,
            selectors,
            selector_backing_leases,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
            modules,
            ..
        } = self;
        let frame = window_operations.last_mut().ok_or_else(|| RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "cached DDE completion has no exact top operation frame",
        ))?;
        let Some(super::super::WindowReturn::Dde(continuation)) = frame.result.as_mut() else {
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "cached DDE completion reached a non-DDE top operation frame"));
        };
        if continuation.host_operation() != Some(operation) {
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "cached DDE completion does not match the exact top operation frame"));
        }
        let memory = GlobalMemoryTeardownAccess::from_parts(
            heap,
            selectors,
            selector_backing_leases,
            &mut modules.records,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
        );
        let mut access = DdeCompletionAccess::from_parts(
            memory,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
        );
        access.retire_cached_normal_source(continuation, operation, host)
    }

    pub(in crate::win16_runtime) fn reserve_dde_guest_block_retirement(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.with_dde_completion_access(|access| access.reserve_dde_guest_block_retirement())
    }

    pub(in crate::win16_runtime) fn reserve_dde_guest_block_retirements(
        &mut self,
        count: usize,
    ) -> Result<(), RuntimeError> {
        self.with_dde_completion_access(|access| {
            access.reserve_dde_guest_block_retirements(count)
        })
    }

    pub(in crate::win16_runtime) fn queue_removed_dde_guest_blocks(
        &mut self,
        blocks: Vec<crate::win16_dde::Win16DdeAccessBlock>,
    ) -> Result<(), RuntimeError> {
        self.with_dde_completion_access(|access| access.queue_removed_dde_guest_blocks(blocks))
    }

    pub(in crate::win16_runtime) fn drain_dde_guest_block_retirements(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.with_dde_completion_access(|access| access.drain_dde_guest_block_retirements())
    }

    pub(in crate::win16_runtime) fn unregister_retired_dde_callbacks(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.with_dde_completion_access(|access| access.unregister_retired_dde_callbacks())
    }

}
