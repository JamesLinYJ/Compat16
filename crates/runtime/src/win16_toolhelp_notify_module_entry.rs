//! Module-entry notifications owned by one exact synchronous load scope.

use std::collections::VecDeque;

use win16_abi::SelectorRef;

use super::{Win16ToolhelpNotifyEvent, Win16ToolhelpNotifyRegistry};
use crate::{DiagnosticKind as Kind, RuntimeError};

/// A DLL's required pre-LibMain notifications belong to the exact synchronous
/// module incarnation and, when one exists, the ToolHelp callback that
/// initiated the load. `None` means the load had no ToolHelp callback parent;
/// task, module-header generation, and entry-selector generation still identify
/// the exact synchronous entry boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::win16_runtime) struct Win16ToolhelpModuleEntryScope {
    pub(in crate::win16_runtime) task: u16,
    pub(in crate::win16_runtime) module_handle: u16,
    pub(in crate::win16_runtime) module_generation: SelectorRef,
    pub(in crate::win16_runtime) entry_selector_generation: SelectorRef,
    pub(in crate::win16_runtime) parent_notification_callback: Option<u64>,
}

/// Exact Module continuation that owned a scoped notification at the
/// pre-LibMain boundary. This identity is carried through publication so the
/// child ToolHelp callback can validate its immediate parent after the central
/// callback stack top changes from Module to ToolHelpNotify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16ToolhelpModuleEntryParent {
    pub(in crate::win16_runtime) scope: Win16ToolhelpModuleEntryScope,
    pub(in crate::win16_runtime) module_callback_id: super::super::CallbackFrameId,
}

impl Win16ToolhelpNotifyRegistry {
    pub(super) fn enqueue_module_entry_batch(
        &mut self,
        scope: Win16ToolhelpModuleEntryScope,
        events: Vec<Win16ToolhelpNotifyEvent>,
    ) -> Result<usize, RuntimeError> {
        self.enqueue_batch_to(events, Some(scope))
    }

    pub(super) fn enqueue_module_entry_event(
        &mut self,
        scope: Win16ToolhelpModuleEntryScope,
        event: Win16ToolhelpNotifyEvent,
    ) -> Result<bool, RuntimeError> {
        let mut events = Vec::new();
        events.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve one scoped Win16 ToolHelp module-entry event",
            error,
        ))?;
        events.push(event);
        Ok(self.enqueue_module_entry_batch(scope, events)? != 0)
    }

    pub(super) fn pop_module_entry_event(
        &mut self,
        scope: Win16ToolhelpModuleEntryScope,
    ) -> Option<Win16ToolhelpNotifyEvent> {
        self.module_entry_pending.get_mut(&scope)?.pop_front()
    }

    pub(super) fn push_module_entry_front(
        &mut self,
        scope: Win16ToolhelpModuleEntryScope,
        event: Win16ToolhelpNotifyEvent,
    ) {
        if let Some(queue) = self.module_entry_pending.get_mut(&scope) {
            queue.push_front(event);
        } else {
            let mut queue = VecDeque::new();
            queue.push_front(event);
            self.module_entry_pending.insert(scope, queue);
        }
    }

    pub(super) fn remove_empty_module_entry_queue(
        &mut self,
        scope: Win16ToolhelpModuleEntryScope,
    ) {
        if self.module_entry_pending.get(&scope).is_some_and(VecDeque::is_empty) {
            self.module_entry_pending.remove(&scope);
        }
    }

    pub(super) fn has_module_entry_event(
        &self,
        scope: Win16ToolhelpModuleEntryScope,
    ) -> Result<bool, RuntimeError> {
        if self.module_entry_pending.iter().any(|(pending, queue)| {
            *pending != scope
                && !queue.is_empty()
                && pending.module_handle == scope.module_handle
                && pending.module_generation == scope.module_generation
        }) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-entry callback parent changed before its exact LibMain boundary"));
        }
        Ok(self.module_entry_pending.get(&scope).is_some_and(|queue| !queue.is_empty()))
    }

    pub(super) fn pop_any_module_entry_event(
        &mut self,
    ) -> Option<Win16ToolhelpNotifyEvent> {
        let scope = self.module_entry_pending.iter()
            .find_map(|(scope, queue)| (!queue.is_empty()).then_some(*scope))?;
        self.pop_module_entry_event(scope)
    }

    pub(super) fn drain_module_entry_events_for_task(
        &mut self,
        task: u16,
        retired: &mut Vec<Win16ToolhelpNotifyEvent>,
    ) {
        for queue in self.module_entry_pending.values_mut() {
            let queued = queue.len();
            for _ in 0..queued {
                let Some(event) = queue.pop_front() else { break; };
                if event.task == task {
                    retired.push(event);
                } else {
                    // The queue never grows beyond its pre-drain length, so
                    // this preserves its existing allocation during the
                    // already-preflighted task retirement.
                    queue.push_back(event);
                }
            }
        }
        self.module_entry_pending.retain(|_, queue| !queue.is_empty());
    }

    pub(super) fn cancel_module_entry_events(
        &mut self,
        module_handle: u16,
        module_generation: SelectorRef,
    ) {
        self.module_entry_pending.retain(|scope, _| {
            scope.module_handle != module_handle || scope.module_generation != module_generation
        });
    }
}
