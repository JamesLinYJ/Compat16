//! Checked conversion of native queued MSG records into Win16 guest memory.

use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{Msg16, SegmentedPointer};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostQueuedMessage, Win16MessageParam,
    Win16MessageSource,
};

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
                if !crate::Win16ScalarMessage::is_timer_message(message.message) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "native USER queue returned a timer identity for a non-timer message"));
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
        if let Some((_, _, registration)) = timer_registration {
            output_message_id = registration.guest_message();
        }
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
                if message.window.is_none()
                    || crate::Win16ScalarMessage::is_timer_message(message.message) => value,
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
            pt: guest_msg_point(&self.selectors, memory, output, message.point)?,
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

/// Win16 `MSG.pt` is a `POINT` of signed 16-bit coordinates. A host point
/// inside `-32768..=32767` is stored exactly. A coordinate outside that range
/// is not truncated: the previous guest point bytes are copied back, and the
/// rest of the message is still delivered.
pub(in crate::win16_runtime) fn guest_msg_point(
    selectors: &win16_abi::SelectorTable,
    memory: &Memory,
    output: SegmentedPointer,
    point: crate::Win16HostPoint,
) -> Result<win16_abi::Point16, RuntimeError> {
    if let (Ok(x), Ok(y)) = (i16::try_from(point.x), i16::try_from(point.y)) {
        return Ok(win16_abi::Point16 { x, y });
    }
    let point_pointer = selectors
        .add_bytes(output, win16_abi::msg16_offsets::PT_X as u32)
        .map_err(crate::runtime_error)?;
    let address = selectors
        .translate(point_pointer, win16_abi::Access::Write, win16_abi::Point16::SIZE, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = [0u8; win16_abi::Point16::SIZE];
    memory.read(address, &mut bytes).map_err(crate::runtime_error)?;
    Ok(win16_abi::Point16::decode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::super::super::test_support::tiny_ne_executable;
    use crate::{
        Runtime, Win16HostPoint, Win16HostQueuedMessage, Win16MessageParam, Win16MessageSource,
    };

    fn loaded() -> Runtime {
        Runtime::load(&tiny_ne_executable(), &[], br"C:\MSG.NE").unwrap()
    }

    fn output_pointer(runtime: &Runtime) -> win16_abi::SegmentedPointer {
        let far = (u32::from(runtime.cpu.regs.ds) << 16) | 0x20;
        runtime.win16.as_ref().unwrap().selectors.pointer_from_far(far).unwrap()
    }

    fn poison(runtime: &mut Runtime) {
        let pointer = output_pointer(runtime);
        let state = runtime.win16.as_ref().unwrap();
        state.selectors.write(&mut runtime.memory, pointer, &[0xA5; 18]).unwrap();
    }

    fn read_msg(runtime: &Runtime) -> [u8; 18] {
        let pointer = output_pointer(runtime);
        let state = runtime.win16.as_ref().unwrap();
        let mut bytes = [0u8; 18];
        state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
        bytes
    }

    fn queued(point: Win16HostPoint, message: u16) -> Win16HostQueuedMessage {
        Win16HostQueuedMessage {
            source: Win16MessageSource::NativeQueue,
            window: None,
            message,
            w_param: 0x1111,
            l_param: Win16MessageParam::Scalar(0x2222_3333),
            time: 0x4444_5555,
            point,
        }
    }

    fn write(runtime: &mut Runtime, message: Win16HostQueuedMessage) -> u32 {
        let pointer = output_pointer(runtime);
        let mut state = runtime.win16.take().unwrap();
        let value = state
            .write_queued_message(pointer, Some(message), true, &mut runtime.memory)
            .unwrap();
        runtime.win16 = Some(state);
        value
    }

    #[test]
    fn fitting_msg_point_is_stored_exactly_and_the_message_is_kept() {
        for (x, y) in [
            (0, 0),
            (-1, -1),
            (i32::from(i16::MIN), i32::from(i16::MAX)),
            (1, -32768),
            (32767, -2),
        ] {
            let mut runtime = loaded();
            poison(&mut runtime);
            let value = write(&mut runtime, queued(Win16HostPoint { x, y }, 1));
            assert_eq!(value, 1);
            let decoded = win16_abi::Msg16::decode(&read_msg(&runtime));
            assert_eq!(decoded.hwnd, 0);
            assert_eq!(decoded.message, 1);
            assert_eq!(decoded.w_param, 0x1111);
            assert_eq!(decoded.l_param, 0x2222_3333);
            assert_eq!(decoded.time, 0x4444_5555);
            assert_eq!(decoded.pt.x, i16::try_from(x).unwrap());
            assert_eq!(decoded.pt.y, i16::try_from(y).unwrap());
        }
    }

    #[test]
    fn out_of_range_msg_point_is_not_truncated_and_the_message_is_kept() {
        for point in [
            Win16HostPoint { x: 32768, y: 1 },
            Win16HostPoint { x: -32769, y: -1 },
            Win16HostPoint { x: 1, y: 32768 },
            Win16HostPoint { x: i32::MIN, y: i32::MAX },
        ] {
            let mut runtime = loaded();
            poison(&mut runtime);
            let value = write(&mut runtime, queued(point, 0x0012));
            assert_eq!(value, 0);
            let bytes = read_msg(&runtime);
            assert_eq!(&bytes[14..18], &[0xA5; 4]);
            assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x0012);
            assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 0x1111);
            assert_eq!(u32::from_le_bytes(bytes[6..10].try_into().unwrap()), 0x2222_3333);
            assert_eq!(u32::from_le_bytes(bytes[10..14].try_into().unwrap()), 0x4444_5555);
        }
    }
}
