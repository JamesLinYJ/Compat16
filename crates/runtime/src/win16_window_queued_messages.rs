//! Checked conversion of native queued MSG records into Win16 guest memory.

use guest_core::memory::Memory;
use win16_abi::{Msg16, SegmentedPointer};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostQueuedMessage, Win16MessageParam,
    Win16MessageSource,
};

const WM_TIMER: u16 = 0x0113;

impl Win16State {
    pub(in crate::win16_runtime) fn write_queued_message(
        &mut self,
        output: SegmentedPointer,
        message: Option<Win16HostQueuedMessage>,
        get: bool,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let Some(message) = message else { return Ok(0); };
        if !matches!(message.source, Win16MessageSource::NativeQueue
            | Win16MessageSource::GuestNotification)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native USER queue returned a guest-origin MSG"));
        }
        let notification_target = match (message.source, message.l_param) {
            (Win16MessageSource::GuestNotification,
                Win16MessageParam::GuestNotification { provenance, .. }) => {
                if provenance.source.id == 0 || provenance.source.generation == 0
                    || provenance.source.sequence == 0
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "owned notification MSG has a zero source identity or sequence"));
                }
                Some(provenance.target)
            }
            (Win16MessageSource::GuestNotification, _) => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "guest notification queue record lost its owned provenance")),
            (_, Win16MessageParam::GuestNotification { .. }) => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native queue message acquired guest notification provenance")),
            _ => None,
        };
        let mut w_param = message.w_param;
        let mut output_message_id = message.message;
        let timer_registration = match &message.l_param {
            Win16MessageParam::TimerHostId(host_id) => {
                if message.message != WM_TIMER {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native USER queue returned a timer identity for a non-WM_TIMER message"));
                }
                Some(self.timers.registration_for_host(*host_id).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "native USER queue returned an unknown timer generation"))?)
            }
            _ => None,
        };
        let (mdi_receiver_guest, mdi_projection) = match message.l_param {
            Win16MessageParam::Mdi(queued) => {
                if message.source != Win16MessageSource::NativeQueue {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed MDI queue payload came from a non-native message source"));
                }
                let Some(native) = message.window else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed MDI queue payload has no exact native receiving HWND"));
                };
                if queued.native_message_id() != u32::from(message.message) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed MDI queue payload does not match the captured native message id"));
                }
                let mut guest_receiver = None;
                for (&guest, &mapped_native) in &self.window_handles {
                    if mapped_native != native {
                        continue;
                    }
                    if guest_receiver.replace(guest).is_some() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "typed MDI receiving HWND has multiple live Win16 aliases"));
                    }
                }
                let guest_receiver = guest_receiver.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "typed MDI receiving HWND has no existing Win16 alias",
                ))?;
                self.validate_mdi_endpoint(guest_receiver, native, queued.endpoint)?;
                let projected = self.project_queued_mdi_message(queued)?;
                output_message_id = projected.message;
                w_param = projected.w_param;
                (Some(guest_receiver), Some(projected))
            }
            _ => (None, None),
        };
        let window = match (notification_target, timer_registration) {
            (Some(crate::Win16GuestNotificationTarget::Window { window, guest_hwnd }), _) => {
                if message.window != Some(window)
                    || self.window_handles.get(&guest_hwnd) != Some(&window)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "owned notification window alias no longer maps to its exact native token"));
                }
                guest_hwnd
            }
            (Some(crate::Win16GuestNotificationTarget::Task { owner, guest_htask,
                task_selector_generation, queue }), _) => {
                if message.window.is_some()
                    || self.user_task_queue != Some((owner, guest_htask,
                        task_selector_generation, queue))
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "owned notification task receipt no longer matches its exact queue binding"));
                }
                0
            }
            // Resolve a retained timer before looking up a live HWND. A
            // queued generation must not allocate a new guest window token.
            (None, Some((owner, _, _))) => owner,
            (None, None) if mdi_receiver_guest.is_some() => mdi_receiver_guest.unwrap(),
            (None, None) => match message.window {
                Some(native) => self.map_window_handle(native, false)?,
                None => 0,
            },
        };
        let l_param = match message.l_param {
            Win16MessageParam::ActivationApp(input) => {
                if message.source != Win16MessageSource::NativeQueue
                    || message.message != 0x001c
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed WM_ACTIVATEAPP payload has different source or message id"));
                }
                w_param = u16::from(input.active != 0);
                u32::from(self.activation_task_for_queue(input.other_task_queue)?)
            }
            Win16MessageParam::ParentNotification(input) => {
                if message.source != Win16MessageSource::NativeQueue
                    || message.message != 0x0210
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed WM_PARENTNOTIFY payload has different source or message id"));
                }
                w_param = input.event;
                match input.data {
                    crate::Win16HostParentNotificationData::Child { child, id }
                        if matches!(input.event, 0x0001 | 0x0002) => {
                        let child = match child {
                            Some(native) => self.map_window_handle(native, false)?,
                            None => 0,
                        };
                        u32::from(child) | (u32::from(id) << 16)
                    }
                    crate::Win16HostParentNotificationData::Mouse { coordinates }
                        if matches!(input.event, 0x0201 | 0x0204 | 0x0207) => coordinates,
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed WM_PARENTNOTIFY event has a different parameter layout")),
                }
            }
            Win16MessageParam::ControlColor(_) => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "callback-scoped control-color HDC was queued beyond its native callback",
            )),
            Win16MessageParam::WindowInput(input) => {
                if input.message_id() != message.message {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native USER queue returned a window-input payload for a different message"));
                }
                let (_, guest_w, guest_l) = self.window_input_to_guest(input)?;
                w_param = guest_w;
                guest_l
            }
            Win16MessageParam::Scalar(value) => value,
            Win16MessageParam::GuestNotification { provenance, l_param } => {
                if message.source != Win16MessageSource::GuestNotification
                    || Some(provenance.target) != notification_target
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "owned notification parameter does not match its queue receipt"));
                }
                l_param
            }
            // The host emits GuestBits only for worker-owned sidecars (thread
            // posts and guest WM_TIMER posts) or an explicitly registered
            // guest WndProc/DLGPROC's private message range. Native USER
            // pointers are never exposed through this case.
            Win16MessageParam::GuestBits(value)
                if message.window.is_none() || message.message == WM_TIMER => value,
            Win16MessageParam::GuestBits(value)
                if message.message >= 0x0400
                    && (self.window_procedures.contains_key(&window)
                        || self.dialog_procedures.contains_key(&window)) => value,
            Win16MessageParam::GuestBits(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "native USER queue exposed guest LPARAM bits without guest-procedure provenance")),
            Win16MessageParam::Command { control, notify, control_parent } => {
                let guest_control = match control {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                if let (Some(native_child), Some(native_parent)) = (control, control_parent) {
                    let child = self.map_window_handle(native_child, false)?;
                    if child != guest_control {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "queued Win16 WM_COMMAND control mapping changed during conversion"));
                    }
                    let parent = self.map_window_handle(native_parent, false)?;
                    self.set_window_parent_from_host(child, parent)?;
                }
                (u32::from(notify) << 16) | u32::from(guest_control)
            }
            Win16MessageParam::ClipboardChainChange { removed, next } => {
                let removed = match removed {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                let next = match next {
                    Some(native) => self.map_window_handle(native, false)?,
                    None => 0,
                };
                w_param = removed;
                u32::from(next)
            }
            Win16MessageParam::TimerHostId(_) => {
                let (_, timer_id, registration) = timer_registration.ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "native timer message lost its checked registration"))?;
                w_param = timer_id;
                registration.callback.unwrap_or(0)
            }
            Win16MessageParam::Mdi(_) => mdi_projection.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "typed MDI message lost its validated guest projection",
            ))?.l_param,
        };
        let output_message = Msg16 {
            hwnd: window,
            message: output_message_id,
            w_param,
            l_param,
            time: message.time,
            pt: win16_abi::Point16 {
                x: message.point.x as i16,
                y: message.point.y as i16,
            },
        };
        output_message.write_to(&self.selectors, memory, output)
            .map_err(crate::runtime_error)?;
        if get {
            Ok(u32::from(message.message != 0x0012))
        } else {
            Ok(1)
        }
    }
}
