//! Reconcile native reparenting before a suspended callback can destroy a tree.

use std::collections::{BTreeMap, BTreeSet};

use super::{Win16State, windows::{WindowOperationLifecycle, WindowReturn}};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostWindowParentObservation, Win16NativeWindowOperationState};

impl Win16State {
    pub(super) fn has_pending_window_parent_mutation(&self) -> bool {
        self.window_operations.iter().any(|frame| {
            frame.lifecycle == WindowOperationLifecycle::Started
                && frame.native_state == Some(Win16NativeWindowOperationState::Active)
                && matches!(frame.result.as_ref(), Some(WindowReturn::WindowData(data))
                    if data.parent_mutation)
        })
    }

    /// Query each still-active setter target, including outer operations when
    /// an unrelated nested operation delivers this callback. The native call
    /// may callback before or after changing ancestry; its requested parent
    /// is never evidence that the move actually happened.
    pub(super) fn refresh_pending_window_parents(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let targets: BTreeMap<_, _> = self.window_operations.iter().filter_map(|frame| {
            if frame.lifecycle != WindowOperationLifecycle::Started
                || frame.native_state != Some(Win16NativeWindowOperationState::Active)
            {
                return None;
            }
            let Some(WindowReturn::WindowData(data)) = frame.result.as_ref() else {
                return None;
            };
            (data.parent_mutation
                && self.window_handles.get(&data.window) == Some(&data.native_window))
                .then_some((data.native_window, data.window))
        }).collect();
        let mut observed = BTreeMap::new();
        for (native, child) in targets {
            match host.win16_host_window_parent(native)? {
                Win16HostWindowParentObservation::Live { child_parent } => {
                    observed.insert(child, (native, child_parent));
                }
                // Retirement is not a live observation of a desktop move.
                // Existing exact destruction cleanup owns the dead HWND.
                Win16HostWindowParentObservation::Retired => {}
            }
        }
        let mut edges = BTreeMap::new();
        for (&child, &(_, native_parent)) in &observed {
            let parent = native_parent.map(|native| self.map_window_handle(native, false))
                .transpose()?;
            edges.insert(child, parent);
        }
        // Validate the entire observed graph before changing any edge. Nested
        // moves can reverse old ancestry, so validating one replacement at a
        // time against other stale edges would reject a valid native forest.
        for &child in edges.keys() {
            let mut current = Some(child);
            let mut visited = BTreeSet::new();
            while let Some(window) = current {
                if !visited.insert(window) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native Win16 parent observations would create a guest HWND cycle"));
                }
                current = edges.get(&window).copied()
                    .unwrap_or_else(|| self.window_parents.get(&window).copied());
            }
        }
        if observed.iter().any(|(child, (native, _))|
            self.window_handles.get(child) != Some(native))
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 parent observation changed its exact guest HWND incarnation"));
        }
        for (child, parent) in edges {
            let (native, native_parent) = observed[&child];
            if let Some(parent) = parent {
                self.window_parents.insert(child, parent);
            } else {
                self.window_parents.remove(&child);
            }
            self.window_parent_observations.insert(native, native_parent);
            self.note_pending_create_parent_update(child);
        }
        Ok(())
    }
}
