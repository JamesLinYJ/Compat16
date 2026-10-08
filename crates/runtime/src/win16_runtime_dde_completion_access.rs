//! Disjoint owner borrows for DDE completion while its window frame stays in place.

use super::super::super::{
    CallbackKind,
    CallbackFrameId,
    Win16State,
    callback_scheduler::Win16CallbackScheduler,
    dde_callback::Win16DdeCallbackFrame,
    global_teardown::GlobalMemoryTeardownAccess,
};
use crate::{Win16GuestCallbackToken, win16_dde::{Win16DdeRetiredGuestBlock, Win16DdeState}};

pub(in crate::win16_runtime) struct DdeCompletionAccess<'a> {
    pub(in crate::win16_runtime) memory: GlobalMemoryTeardownAccess<'a>,
    pub(in crate::win16_runtime) dde: &'a mut Win16DdeState,
    pub(in crate::win16_runtime) dde_callbacks: &'a mut Vec<Win16DdeCallbackFrame>,
    pub(in crate::win16_runtime) dde_retired_callback_tokens: &'a mut Vec<Win16GuestCallbackToken>,
    pub(in crate::win16_runtime) dde_retired_guest_blocks: &'a mut Vec<Win16DdeRetiredGuestBlock>,
    pub(in crate::win16_runtime) callback_kinds: &'a mut Vec<CallbackKind>,
    pub(in crate::win16_runtime) callback_frame_ids: &'a mut Vec<CallbackFrameId>,
    pub(in crate::win16_runtime) callback_scheduler: &'a mut Win16CallbackScheduler,
}

impl<'a> DdeCompletionAccess<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::win16_runtime) fn from_parts(
        memory: GlobalMemoryTeardownAccess<'a>,
        dde: &'a mut Win16DdeState,
        dde_callbacks: &'a mut Vec<Win16DdeCallbackFrame>,
        dde_retired_callback_tokens: &'a mut Vec<Win16GuestCallbackToken>,
        dde_retired_guest_blocks: &'a mut Vec<Win16DdeRetiredGuestBlock>,
        callback_kinds: &'a mut Vec<CallbackKind>,
        callback_frame_ids: &'a mut Vec<CallbackFrameId>,
        callback_scheduler: &'a mut Win16CallbackScheduler,
    ) -> Self {
        Self {
            memory,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
        }
    }

    pub(in crate::win16_runtime) fn selectors(&self) -> &win16_abi::SelectorTable {
        self.memory.selectors()
    }

}

impl Win16State {
    /// Build the same disjoint DDE completion view for owners that do not
    /// already hold a continuation inside `window_operations`.
    pub(in crate::win16_runtime) fn with_dde_completion_access<R>(
        &mut self,
        use_access: impl FnOnce(&mut DdeCompletionAccess<'_>) -> R,
    ) -> R {
        let Win16State {
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
        use_access(&mut access)
    }
}
