//! Disjoint state borrowed by projected USER completions.

use std::collections::{BTreeMap, BTreeSet};
use guest_core::OwnerId;
use win16_abi::SelectorTable;

use super::super::{
    classes::GuestWindowClasses,
    gdi::GuestGdiHandles,
    menu::GuestMenus,
    message_calls::Win16TimerRegistrations,
    user_cursor_accelerator::GuestAcceleratorHandles,
    images::GuestImageHandles,
    kernel_diagnostics::Win16KernelDiagnosticEffect,
    user_services_controls::GuestClipboardState,
};
use super::operation_frame::WindowOperationFrame;
use crate::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowInputMessage};

pub(in crate::win16_runtime) struct WindowProjectionAccess<'a> {
    pub(in crate::win16_runtime) selectors: &'a SelectorTable,
    pub(in crate::win16_runtime) guest_gdi: &'a mut GuestGdiHandles,
    pub(in crate::win16_runtime) guest_menus: &'a mut GuestMenus,
    pub(in crate::win16_runtime) timers: &'a mut Win16TimerRegistrations,
    pub(in crate::win16_runtime) clipboard_state: &'a mut GuestClipboardState,
    pub(in crate::win16_runtime) window_handles: &'a mut BTreeMap<u16, Win16HostWindow>,
    pub(in crate::win16_runtime) window_parents: &'a mut BTreeMap<u16, u16>,
    pub(in crate::win16_runtime) window_parent_observations:
        &'a mut BTreeMap<Win16HostWindow, Option<Win16HostWindow>>,
    pub(in crate::win16_runtime) prior_operations: &'a mut [WindowOperationFrame],
    pub(in crate::win16_runtime) owned_window_handles: &'a mut BTreeSet<u16>,
    pub(in crate::win16_runtime) window_system_classes: &'a BTreeMap<u16, crate::Win16HostSystemClass>,
    pub(in crate::win16_runtime) mdi_children: &'a BTreeSet<u16>,
    pub(in crate::win16_runtime) next_window_handle: &'a mut u16,
    pub(in crate::win16_runtime) guest_images: &'a mut GuestImageHandles,
    pub(in crate::win16_runtime) guest_accelerators: &'a mut GuestAcceleratorHandles,
    pub(in crate::win16_runtime) window_classes: &'a GuestWindowClasses,
    pub(in crate::win16_runtime) window_procedures: &'a BTreeMap<u16, super::WindowProcedure>,
    pub(in crate::win16_runtime) dialog_procedures: &'a BTreeMap<u16, (u32, u16)>,
    pub(in crate::win16_runtime) user_task_queue: Option<(OwnerId, u16, u64, crate::Win16HostTaskQueue)>,
    pub(in crate::win16_runtime) current_task_owner: Option<OwnerId>,
    pub(in crate::win16_runtime) task_handles: &'a BTreeMap<OwnerId, u16>,
    pub(in crate::win16_runtime) kernel_diagnostic_effects: &'a mut Vec<Win16KernelDiagnosticEffect>,
}

impl WindowProjectionAccess<'_> {
    pub(in crate::win16_runtime) fn activation_task_for_queue(
        &self,
        queue: Option<crate::Win16HostTaskQueue>,
    ) -> Result<u16, RuntimeError> {
        super::super::window_payload_input::checked_activation_task_for_queue(
            queue, self.user_task_queue, self.current_task_owner,
            self.task_handles, self.selectors,
        )
    }

    pub(in crate::win16_runtime) fn map_window_handle(
        &mut self,
        native: Win16HostWindow,
        owned: bool,
    ) -> Result<u16, RuntimeError> {
        if let Some((&guest, _)) = self.window_handles.iter()
            .find(|(_, existing)| **existing == native)
        {
            if owned {
                self.owned_window_handles.insert(guest);
            }
            return Ok(guest);
        }

        for _ in 0..u16::MAX {
            let guest = *self.next_window_handle;
            *self.next_window_handle = if guest >= 0xfffd { 2 } else { guest + 1 };
            // HWND_BOTTOM and the TOPMOST pseudo handles are valid USER
            // arguments, so keep them out of the ordinary token namespace.
            if matches!(guest, 0 | 1 | 0xfffe | u16::MAX)
                || self.window_handles.contains_key(&guest)
            {
                continue;
            }
            self.window_handles.insert(guest, native);
            if owned {
                self.owned_window_handles.insert(guest);
            } else {
                self.owned_window_handles.remove(&guest);
            }
            return Ok(guest);
        }

        Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 window handle table is full",
        ))
    }

    pub(in crate::win16_runtime) fn set_window_parent_from_host(
        &mut self,
        child: u16,
        parent: u16,
    ) -> Result<(), RuntimeError> {
        if child == 0 || child == parent { return Ok(()) }
        if parent == 0 {
            self.window_parents.remove(&child);
            self.observe_window_parent_from_guest(child, parent);
            self.mark_created_parent_updated(child);
            return Ok(())
        }
        let mut current = parent;
        let mut visited = BTreeSet::new();
        loop {
            if current == child {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native Win16 parent metadata would create a guest HWND cycle"));
            }
            if !visited.insert(current) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 window parent table already contains a cycle"));
            }
            let Some(next) = self.window_parents.get(&current).copied() else { break };
            current = next;
        }
        self.window_parents.insert(child, parent);
        self.observe_window_parent_from_guest(child, parent);
        self.mark_created_parent_updated(child);
        Ok(())
    }

    fn observe_window_parent_from_guest(&mut self, child: u16, parent: u16) {
        let Some(native_child) = self.window_handles.get(&child).copied() else {
            return;
        };
        let native_parent = if parent == 0 {
            Some(None)
        } else {
            self.window_handles.get(&parent).copied().map(Some)
        };
        if let Some(native_parent) = native_parent {
            self.window_parent_observations
                .insert(native_child, native_parent);
        }
    }

    fn mark_created_parent_updated(&mut self, child: u16) {
        for frame in self.prior_operations.iter_mut() {
            let Some(continuation) = frame.continuation_mut() else { continue };
            if let super::WindowReturn::Create {
                window: Some(created), parent_was_updated, ..
            } = continuation {
                if *created == child { *parent_was_updated = true; }
            }
        }
    }

    pub(in crate::win16_runtime) fn refresh_child_parent_from_host(
        &mut self,
        child: u16,
        expected_native_window: Win16HostWindow,
        native_parent: Option<Win16HostWindow>,
    ) -> Result<(), RuntimeError> {
        if self.window_handles.get(&child) != Some(&expected_native_window) {
            return Ok(())
        }
        self.window_parent_observations
            .insert(expected_native_window, native_parent);
        if !self.window_handles.contains_key(&child) { return Ok(()) }
        let Some(native_parent) = native_parent else {
            self.window_parents.remove(&child);
            self.mark_created_parent_updated(child);
            return Ok(())
        };
        let parent = self.map_window_handle(native_parent, false)?;
        if parent != child { self.set_window_parent_from_host(child, parent)?; }
        self.mark_created_parent_updated(child);
        Ok(())
    }

    pub(in crate::win16_runtime) fn window_input_to_guest(
        &mut self,
        input: Win16WindowInputMessage,
    ) -> Result<(u16, u16, u32), RuntimeError> {
        let guest_window = |access: &mut Self, native: Option<Win16HostWindow>|
            -> Result<u16, RuntimeError> {
            match native {
                Some(native) => access.map_window_handle(native, false),
                None => Ok(0),
            }
        };
        let (w_param, l_param) = match input {
            Win16WindowInputMessage::Activate { state, minimized, other } => {
                let other = guest_window(self, other)?;
                (state, u32::from(other) | (u32::from(minimized) << 16))
            }
            Win16WindowInputMessage::NonClientActivate { active, minimized, other } => {
                let other = guest_window(self, other)?;
                (active, u32::from(other) | (u32::from(minimized) << 16))
            }
            Win16WindowInputMessage::Focus { other, .. } => (guest_window(self, other)?, 0),
            Win16WindowInputMessage::SetCursor { target, hit_test, mouse_message } => {
                let target = guest_window(self, target)?;
                (target, u32::from(hit_test) | (u32::from(mouse_message) << 16))
            }
            Win16WindowInputMessage::MouseActivate { parent, hit_test, mouse_message } => {
                let parent = guest_window(self, parent)?;
                (parent, u32::from(hit_test) | (u32::from(mouse_message) << 16))
            }
        };
        Ok((input.message_id(), w_param, l_param))
    }
}
