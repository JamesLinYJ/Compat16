//! Exact output and owner projection for window-owned API returns.

use super::*;
use crate::Win16WindowCallResult;
use super::completion_access::WindowProjectionAccess;
use super::operation_frame::{
    CursorAcceleratorProjection, CursorAcceleratorProjectionPhase,
    MessageCallProjectionPhase,
    MessageProjection, MessageProjectionPhase,
    QueuedMessageProjection, QueuedMessageProjectionPhase,
    WindowCallProjection, WindowCallProjectionPhase, WindowDataProjection,
    WindowDataProjectionPhase, WindowPropertyProjection,
    WindowPropertyProjectionPhase,
};

pub(super) fn finish_dialog_item_miss(
    phase: &mut super::operation_frame::DialogItemMessageProjectionPhase,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::DialogItemMessageProjectionPhase as Phase;
    if *phase == Phase::Complete {
        return Ok((0, Win16ReturnKind::Dword));
    }
    if *phase != Phase::Ready {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "SendDlgItemMessage miss has an unexpected retained follow-up phase"));
    }
    *phase = Phase::Complete;
    Ok((0, Win16ReturnKind::Dword))
}

pub(super) fn finish_clipboard_projection(
    completion: &super::super::user_services_controls::clipboard::ClipboardCompletion,
    result: &crate::Win16HostClipboardResult,
    owner: &mut super::operation_frame::UserFamilyProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
    return_kind: Win16ReturnKind,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::user_services_controls::clipboard::ClipboardCompletion as Completion;
    use super::operation_frame::UserFamilyProjectionPhase as Phase;
    use crate::Win16HostClipboardResult as ResultValue;

    if owner.phase == Phase::Complete {
        return owner.value.map(|value| (value, return_kind)).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "completed clipboard projection lost its cached return"));
    }
    let ResultValue::Sequenced { sequence, result } = result else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native clipboard completion lost its worker sequence receipt"));
    };
    if !owner.clipboard_sequence_observed {
        access.clipboard_state.observe_native_sequence(*sequence);
        owner.clipboard_sequence_observed = true;
    }

    let value = match (completion, result.as_ref()) {
        (Completion::Plain, ResultValue::Bool(value)) => u32::from(*value),
        (Completion::Plain, ResultValue::Window(window)) => window.map_or(Ok(0), |native|
            access.map_window_handle(native, false).map(u32::from))?,
        (Completion::Plain, ResultValue::Count(value)) => u32::from(*value),
        (Completion::Plain, ResultValue::Format(value)) => u32::from(*value),
        (Completion::Plain, ResultValue::PriorityFormat(value)) => *value as u16 as u32,
        (Completion::FormatName { range, capacity },
            ResultValue::FormatName { copied, bytes }) => {
            if *copied <= 0 {
                0
            } else {
                if bytes.len() > usize::from(*capacity)
                    || bytes.len() > range.length()
                    || usize::try_from(*copied).ok().and_then(|count| count.checked_add(1))
                        != Some(bytes.len())
                    || bytes.last() != Some(&0)
                    || bytes[..bytes.len().saturating_sub(1)].contains(&0)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "GetClipboardFormatName result does not match its captured range"));
                }
                if owner.phase == Phase::Ready {
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, bytes,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
                u32::from(*copied as u16)
            }
        }
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
            "clipboard result does not match its retained owner or host sequence")),
    };
    owner.value = Some(value);
    if owner.phase == Phase::Ready || owner.phase == Phase::GuestOutputCommitted {
        owner.phase = Phase::ReturnReady;
    }
    if owner.phase == Phase::ReturnReady { owner.phase = Phase::Complete; }
    Ok((value, return_kind))
}

pub(super) fn finish_window_message(
    output: &super::super::messages::MessageOutput,
    result: Option<&crate::Win16HostMessageResult>,
    owner: &mut MessageProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::messages::MessageOutput as Output;
    use crate::Win16HostMessageOutput as HostOutput;
    use MessageProjectionPhase as Phase;

    if owner.phase == Phase::Complete {
        return owner.value.map(|value| (value, Win16ReturnKind::Dword)).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "window-message projection lost its completed return"));
    }
    let Some(result) = result else {
        owner.value = Some(0);
        owner.phase = Phase::Complete;
        return Ok((0, Win16ReturnKind::Dword));
    };
    if owner.phase == Phase::Ready { owner.phase = Phase::InputsValidated; }
    let output_committed = owner.phase == Phase::GuestOutputCommitted;
    let mut return_value = result.value;
    match (output, &result.output) {
        (Output::Control(plan), HostOutput::Control(output)) => {
            let bytes = plan.encode(output, result.value)?;
            if !output_committed {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, &plan.range, &bytes,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::ControlColor, HostOutput::ControlColor(brush)) => {
            if result.dialog_result.is_some() || result.value != 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 control-color result carried an unrelated scalar or dialog result"));
            }
            return_value = super::super::messages::control_color_brush_guest_handle(
                access.guest_gdi, *brush,
            )?;
        }
        (Output::Control(_), HostOutput::None) if result.value >= u32::MAX - 1 => {}
        (Output::OwnerDrawMeasure(range), HostOutput::OwnerDrawMeasure { width, height }) => {
            let bytes = super::super::owner_draw_payloads::measure_output_bytes(*width, *height);
            if !output_committed {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, range, &bytes,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::Text(Some(output)), HostOutput::Text(bytes)) => {
            if bytes.len() > usize::from(output.buffer.capacity)
                || bytes.len() > output.range.length()
                || bytes.last() != Some(&0)
                || usize::try_from(result.value).ok().and_then(|value| value.checked_add(1))
                    != Some(bytes.len())
                || bytes[..bytes.len().saturating_sub(1)].contains(&0)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native WM_GETTEXT output exceeds its captured guest range"));
            }
            if !output_committed {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, &output.range, bytes,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::Text(Some(_) | None), HostOutput::None)
            if result.value == 0 || result.value == u32::MAX => {}
        (Output::Text(None), HostOutput::Text(bytes)) if bytes.is_empty() => {}
        (Output::MinMaxInfo(range), HostOutput::MinMaxInfo(info)) => {
            let bytes = super::super::geometry::guest_minmax_info(*info).encode();
            if !output_committed {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, range, &bytes,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::WindowPosition(output), HostOutput::WindowPosition(position)) => {
            let wire = super::super::window_payloads::window_position_payloads::
                guest_wire_position_with(*position, |window|
                    access.map_window_handle(window, false))?.encode();
            if !output_committed {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, &output.range, &wire,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::WindowPosition(_), HostOutput::None) => {}
        (Output::None, HostOutput::None) => {}
        (Output::NonClientCalcSize(output), HostOutput::NonClientCalcSize(data)) => {
            if !output_committed {
                super::super::window_payloads::nonclient_payloads::write_guest_result_with_selectors(
                    output.clone(), *data, access.selectors, memory,
                    |window| access.map_window_handle(window, false),
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
        }
        (Output::NonClientCalcSize(_), _) | (Output::WindowPosition(_), _) => return Err(
            RuntimeError::new(Kind::InternalInvariant,
                "native window-message result does not match its captured output")),
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
            "native window-message output does not match its retained guest destination")),
    }
    owner.value = Some(return_value);
    owner.phase = Phase::ReturnReady;
    owner.phase = Phase::Complete;
    owner.value.map(|value| (value, Win16ReturnKind::Dword)).ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant,
            "window-message projection lost its completed value"))
}

pub(super) fn finish_queued_message(
    output: &super::super::guest_ranges::GuestOutputRange,
    message: Option<crate::Win16HostQueuedMessage>,
    get: bool,
    owner: &mut QueuedMessageProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use crate::{Win16MessageParam as Param, Win16MessageSource as Source};
    use QueuedMessageProjectionPhase as Phase;

    if owner.phase == Phase::Complete {
        return owner.value.map(|value| (value, Win16ReturnKind::Word)).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "completed queued-message projection lost its result"));
    }
    let Some(message) = message else {
        if get {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetMessage completed without a message or native API error"));
        }
        owner.value = Some(0);
        owner.phase = Phase::Complete;
        return Ok((0, Win16ReturnKind::Word));
    };

    let notification_target = match (message.source, message.l_param) {
        (Source::GuestNotification, Param::GuestNotification { provenance, .. }) => {
            if provenance.source.id == 0 || provenance.source.generation == 0
                || provenance.source.sequence == 0
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "owned notification MSG has a zero source identity or sequence"));
            }
            Some(provenance.target)
        }
        (Source::GuestNotification, _) => return Err(RuntimeError::new(
            Kind::InternalInvariant, "owned notification MSG lost its source provenance")),
        (_, Param::GuestNotification { .. }) => return Err(RuntimeError::new(
            Kind::InternalInvariant, "native queue message acquired guest notification provenance")),
        (Source::NativeQueue, _) => None,
        (Source::GuestMessage, _) => return Err(RuntimeError::new(
            Kind::InternalInvariant, "native USER queue returned a guest-origin MSG")),
    };
    if owner.phase == Phase::Ready { owner.phase = Phase::QueueOwnerValidated; }

    if owner.projected_message.is_none() {

    let mut w_param = message.w_param;
    let mut output_message_id = message.message;
    let (mdi_receiver_guest, mdi_projection) = match message.l_param {
        Param::Mdi(queued) => {
            if message.source != Source::NativeQueue
                || queued.native_message_id() != u32::from(message.message)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "typed MDI queue result does not match its native queue source and message id"));
            }
            let native = message.window.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "typed MDI queue result has no native receiving HWND",
            ))?;
            let mut guest_receiver = None;
            for (&guest, &mapped_native) in access.window_handles.iter() {
                if mapped_native != native {
                    continue;
                }
                if guest_receiver.replace(guest).is_some() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "typed MDI receiver has multiple live Win16 HWND aliases"));
                }
            }
            let guest_receiver = guest_receiver.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "typed MDI receiver has no existing Win16 HWND alias",
            ))?;
            let projected = {
                let super::completion_access::WindowProjectionAccess {
                    window_handles,
                    window_parents,
                    window_system_classes,
                    mdi_children,
                    guest_menus,
                    ..
                } = access;
                super::super::messages_mdi::validate_mdi_endpoint_maps(
                    guest_receiver,
                    native,
                    queued.endpoint,
                    window_handles,
                    window_parents,
                    window_system_classes,
                    mdi_children,
                )?;
                super::super::messages_mdi::validate_mdi_queued_children_maps(
                    queued,
                    window_handles,
                    window_parents,
                    window_system_classes,
                    mdi_children,
                )?;
                let mut map_window = |native| {
                    let mut guest = None;
                    for (&candidate, &mapped_native) in window_handles.iter() {
                        if mapped_native != native {
                            continue;
                        }
                        if guest.replace(candidate).is_some() {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "typed MDI child has multiple live Win16 HWND aliases"));
                        }
                    }
                    guest.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "typed MDI child has no existing Win16 HWND alias"))
                };
                let mut map_menu = |native| guest_menus.intern(native).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 guest HMENU namespace is full for a queued MDI message"));
                super::super::messages_mdi::project_queued_mdi_message_with(
                    queued, &mut map_window, &mut map_menu,
                )?
            };
            output_message_id = projected.message;
            w_param = projected.w_param;
            (Some(guest_receiver), Some(projected))
        }
        _ => (None, None),
    };
    let timer_registration = match message.l_param {
        Param::TimerHostId(host_id) => {
            if !crate::Win16ScalarMessage::is_timer_message(message.message) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native USER queue returned a timer identity for a non-timer message"));
            }
            Some(access.timers.registration_for_host(host_id).ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "native USER queue returned an unknown timer generation"))?)
        }
        _ => None,
    };
    if let Some((_, _, registration)) = timer_registration {
        output_message_id = registration.guest_message();
    }
    let window = match (notification_target, timer_registration) {
        (Some(crate::Win16GuestNotificationTarget::Window { window, guest_hwnd }), _) => {
            if message.window != Some(window)
                || access.window_handles.get(&guest_hwnd) != Some(&window)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "owned notification window alias no longer maps to its exact native token"));
            }
            guest_hwnd
        }
        (Some(crate::Win16GuestNotificationTarget::Task {
            owner, guest_htask, task_selector_generation, queue,
        }), _) => {
            if message.window.is_some()
                || access.user_task_queue != Some((owner, guest_htask, task_selector_generation, queue))
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "owned notification task receipt no longer matches its queue binding"));
            }
            0
        }
        (None, Some((timer_window, _, _))) => timer_window,
        (None, None) if mdi_receiver_guest.is_some() => mdi_receiver_guest.unwrap(),
        (None, None) => match message.window {
            Some(native) => access.map_window_handle(native, false)?,
            None => 0,
        },
    };
    let l_param = match message.l_param {
        Param::ActivationApp(input) => {
            if message.source != Source::NativeQueue || message.message != 0x001c {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "typed WM_ACTIVATEAPP payload has different source or message id"));
            }
            w_param = u16::from(input.active != 0);
            u32::from(access.activation_task_for_queue(input.other_task_queue)?)
        }
        Param::ParentNotification(input) => {
            if message.source != Source::NativeQueue || message.message != 0x0210 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "typed WM_PARENTNOTIFY payload has different source or message id"));
            }
            w_param = input.event;
            match input.data {
                crate::Win16HostParentNotificationData::Child { child, id }
                    if matches!(input.event, 0x0001 | 0x0002) => {
                    let child = match child {
                        Some(native) => access.map_window_handle(native, false)?,
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
        Param::ControlColor(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
            "callback-scoped control-color HDC was queued beyond its native callback")),
        Param::WindowInput(input) => {
            if input.message_id() != message.message {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native USER queue returned window-input data for another message"));
            }
            let (_, guest_w, guest_l) = access.window_input_to_guest(input)?;
            w_param = guest_w;
            guest_l
        }
        Param::Scalar(value) => value,
        Param::GuestNotification { provenance, l_param } => {
            if message.source != Source::GuestNotification
                || Some(provenance.target) != notification_target
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "owned notification parameter does not match its queue receipt"));
            }
            l_param
        }
        Param::GuestBits(value) if message.window.is_none()
            || crate::Win16ScalarMessage::is_timer_message(message.message) => value,
        Param::GuestBits(value) if message.message >= 0x0400
            && (access.window_procedures.contains_key(&window)
                || access.dialog_procedures.contains_key(&window)) => value,
        Param::GuestBits(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
            "native queue exposed guest LPARAM bits without guest-procedure provenance")),
        Param::Command { control, notify, control_parent } => {
            let guest_control = match control {
                Some(native) => access.map_window_handle(native, false)?,
                None => 0,
            };
            if let (Some(native_child), Some(native_parent)) = (control, control_parent) {
                let child = access.map_window_handle(native_child, false)?;
                if child != guest_control {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "queued WM_COMMAND child mapping changed during conversion"));
                }
                let parent = access.map_window_handle(native_parent, false)?;
                owner.parent_update = Some((child, parent));
            }
            (u32::from(notify) << 16) | u32::from(guest_control)
        }
        Param::ClipboardChainChange { removed, next } => {
            let removed = match removed {
                Some(native) => access.map_window_handle(native, false)?,
                None => 0,
            };
            let next = match next {
                Some(native) => access.map_window_handle(native, false)?,
                None => 0,
            };
            w_param = removed;
            u32::from(next)
        }
        Param::TimerHostId(_) => {
            let (_, timer_id, registration) = timer_registration.ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "native timer message lost its checked registration"))?;
            w_param = timer_id;
            registration.callback.unwrap_or(0)
        }
        Param::Mdi(_) => mdi_projection.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "typed MDI queue result lost its validated guest projection",
        ))?.l_param,
    };
        owner.projected_message = Some(win16_abi::Msg16 {
            hwnd: window,
            message: output_message_id,
            w_param,
            l_param,
            time: message.time,
            pt: win16_abi::Point16 { x: message.point.x as i16, y: message.point.y as i16 },
        });
        owner.phase = Phase::GuestHandlesMapped;
    }
    if owner.phase != Phase::OutputCommitted
        && owner.phase != Phase::ReturnReady
        && owner.phase != Phase::Complete
    {
        let output_message = owner.projected_message.as_ref().ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "queued-message projection lost its cached guest MSG"))?;
        super::super::guest_ranges::commit_guest_output_with_selectors(
            access.selectors, memory, output, &output_message.encode(),
        )?;
        owner.phase = Phase::OutputCommitted;
    }
    if !owner.owner_bookkeeping_committed {
        if let Some((child, parent)) = owner.parent_update {
            access.set_window_parent_from_host(child, parent)?;
        }
        owner.owner_bookkeeping_committed = true;
    }
    let message_id = owner.projected_message.as_ref().ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant,
            "queued-message projection lost its cached guest MSG"))?.message;
    let value = u32::from(if get { message_id != 0x0012 } else { true });
    owner.value = Some(value);
    owner.phase = Phase::ReturnReady;
    owner.phase = Phase::Complete;
    Ok((value, Win16ReturnKind::Word))
}

pub(super) fn finish_message_call(
    continuation: &crate::win16_host_message_calls::Win16MessageCallContinuation,
    result: &crate::Win16MessageCallResult,
    phase: &mut MessageCallProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use crate::win16_host_message_calls::Win16MessageCallContinuation as Call;
    use crate::Win16MessageCallResult as ResultValue;
    use MessageCallProjectionPhase as Phase;

    if let Some(cached) = *value {
        if *phase == Phase::Complete { return Ok(cached); }
    }
    if *phase == Phase::Ready {
        let projected = match (continuation, result) {
            (Call::Yield, ResultValue::Yielded) => (0, Win16ReturnKind::Void),
            (Call::Boolean { return_kind } | Call::WaitMessage { return_kind },
                ResultValue::Boolean(result)) => (u32::from(*result), *return_kind),
            (Call::Window { return_kind }, ResultValue::Window(window)) => {
                let handle = window.map_or(Ok(0), |native| access.map_window_handle(native, false))?;
                (u32::from(handle), *return_kind)
            }
            (Call::Dword { return_kind }, ResultValue::Dword(result)) => (*result, *return_kind),
            (Call::Dword { return_kind }, ResultValue::Long(result)) => (*result as u32, *return_kind),
            (Call::SetTimer { guest_window, host_window, guest_timer_id, callback, system },
                ResultValue::Timer(Some(host_id))) => {
                access.timers.insert(*guest_window, *guest_timer_id,
                    super::super::message_calls::Win16TimerRegistration {
                        host_id: *host_id, host_window: *host_window, callback: *callback,
                        system: *system,
                    });
                (u32::from(*guest_timer_id), Win16ReturnKind::Word)
            }
            (Call::SetTimer { .. }, ResultValue::Timer(None)) => (0, Win16ReturnKind::Word),
            (Call::KillTimer { guest_window, guest_timer_id, system },
                ResultValue::Boolean(succeeded)) => {
                if *succeeded { access.timers.remove(*guest_window, *guest_timer_id, *system); }
                (u32::from(*succeeded), Win16ReturnKind::Word)
            }
            (Call::GetKeyboardState { output_range, .. },
                ResultValue::KeyboardState { succeeded, state }) => {
                if *succeeded {
                    let range = output_range.as_ref().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "GetKeyboardState lost its entry-captured guest output range",
                    ))?;
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, state,
                    )?;
                    *phase = Phase::OutputCommitted;
                }
                // The native BOOL only gates the output copy; Win16 returns void.
                (0, Win16ReturnKind::Void)
            }
            (Call::SetKeyboardState, ResultValue::Boolean(_succeeded)) =>
                (0, Win16ReturnKind::Void),
            (Call::QuerySendMessage { output, window, message, w_param, l_param },
                ResultValue::QuerySend { in_send, time, x, y }) => {
                if *in_send {
                    if let (Some(range), Some(hwnd)) = (output, *window) {
                        let bytes = win16_abi::Msg16 {
                            hwnd,
                            message: *message,
                            w_param: *w_param,
                            l_param: *l_param,
                            time: *time,
                            pt: win16_abi::Point16 { x: *x, y: *y },
                        }.encode();
                        super::super::guest_ranges::commit_guest_output_with_selectors(
                            access.selectors, memory, range, &bytes,
                        )?;
                        *phase = Phase::OutputCommitted;
                    }
                }
                (u32::from(*in_send), Win16ReturnKind::Word)
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER message result does not match its retained call owner")),
        };
        *value = Some(projected);
        if *phase == Phase::Ready { *phase = Phase::OwnerBookkeepingCommitted; }
    }
    if *phase == Phase::OwnerBookkeepingCommitted || *phase == Phase::OutputCommitted {
        *phase = Phase::Complete;
    }
    value.as_ref().copied().ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
        "USER message-call projection lost its cached result"))
}

pub(super) fn finish_window_properties(
    pending: &super::super::window_properties::WindowPropertyReturn,
    result: &crate::Win16WindowCallResult,
    owner: &mut WindowPropertyProjection,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    if owner.phase == WindowPropertyProjectionPhase::Ready {
        let value = match (pending, result) {
            (super::super::window_properties::WindowPropertyReturn::Set,
                Win16WindowCallResult::PropertySet(value)) => u32::from(*value),
            (super::super::window_properties::WindowPropertyReturn::Get
                | super::super::window_properties::WindowPropertyReturn::Remove,
                Win16WindowCallResult::PropertyValue(value)) =>
                    u32::from(value.unwrap_or(0)),
            (super::super::window_properties::WindowPropertyReturn::Enum { .. },
                Win16WindowCallResult::PropertyEnumeration(value)) =>
                    u32::from(*value as u16),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "native property result does not match its exact continuation")),
        };
        owner.value = Some(value);
        owner.phase = WindowPropertyProjectionPhase::ReturnReady;
    }
    if owner.phase == WindowPropertyProjectionPhase::ReturnReady {
        owner.phase = WindowPropertyProjectionPhase::Complete;
    }
    owner.value.map(|value| (value, Win16ReturnKind::Word))
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "window-property projection lost its cached result"))
}

pub(super) fn finish_window_data(
    continuation: &super::super::window_data::Win16WindowDataContinuation,
    result: &crate::Win16WindowDataResult,
    owner: &mut WindowDataProjection,
    access: &mut WindowProjectionAccess<'_>,
    host: &mut impl RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use WindowDataProjectionPhase as Phase;
    use crate::Win16WindowDataResult as ResultValue;
    if owner.phase == Phase::Ready {
        match result {
            ResultValue::Value(value) if !continuation.parent_result => {
                owner.value = Some(value.unwrap_or(0) & continuation.return_mask);
                owner.phase = Phase::ReturnValueMapped;
            }
            ResultValue::Parent { .. }
                if continuation.parent_result && !continuation.parent_mutation => {
                owner.phase = Phase::ParentGraphRefreshing;
            }
            ResultValue::ParentMutation { attempted, succeeded, .. }
                if continuation.parent_result && continuation.parent_mutation => {
                if *succeeded && !*attempted {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "unattempted window-parent mutation cannot succeed"));
                }
                owner.phase = if *attempted { Phase::ParentObserving }
                    else { Phase::ParentGraphRefreshed };
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "native Win16 window-data result does not match its exact owner")),
        }
    }
    if owner.phase == Phase::ParentObserving {
        // Native mutation already returned. A failed query retains this phase
        // and the immutable native outcome; retry only the observation.
        owner.parent_observation = Some(host.win16_host_window_parent(continuation.native_window)?);
        owner.phase = Phase::ParentGraphRefreshing;
    }
    if owner.phase == Phase::ParentGraphRefreshing {
        match result {
            ResultValue::Parent { succeeded: true, child_parent, .. } => {
                access.refresh_child_parent_from_host(
                    continuation.window, continuation.native_window, *child_parent,
                )?;
            }
            ResultValue::Parent { succeeded: false, .. } => {}
            ResultValue::ParentMutation { .. } => {
                let observation = owner.parent_observation.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "window-parent projection lost its exact observation"))?;
                if let crate::Win16HostWindowParentObservation::Live { child_parent } = observation {
                    // A failing outer native call can still contain a nested
                    // successful move. Apply the actual observation regardless
                    // of the outer success bit, and only to the original token.
                    access.refresh_child_parent_from_host(
                        continuation.window, continuation.native_window, child_parent,
                    )?;
                }
                // A retired child is not a live null-parent observation.
                // Exact destruction receipts own its guest retirement.
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "window-parent journal no longer owns a parent result")),
        }
        owner.phase = Phase::ParentGraphRefreshed;
    }
    if owner.phase == Phase::ParentGraphRefreshed {
        let (succeeded, previous, check_liveness) = match result {
            ResultValue::Parent { succeeded, previous, .. } => (*succeeded, *previous, false),
            ResultValue::ParentMutation { succeeded, previous, .. } => (*succeeded, *previous, true),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "window-parent value stage no longer owns a parent result")),
        };
        let old = if succeeded {
            match previous {
                Some(previous) => {
                    let live = !check_liveness || matches!(host.win16_host_window_liveness(previous)?,
                        crate::Win16HostWindowLiveness::Live);
                    if live { access.map_window_handle(previous, false)? } else { 0 }
                }
                None => 0,
            }
        } else { 0 };
        owner.value = Some(u32::from(old) & continuation.return_mask);
        owner.phase = Phase::ReturnValueMapped;
    }
    if owner.phase == Phase::ReturnValueMapped { owner.phase = Phase::ReturnReady; }
    if owner.phase == Phase::ReturnReady { owner.phase = Phase::Complete; }
    owner.value.map(|value| (value, continuation.return_kind))
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "window-data projection lost its cached return"))
}

pub(super) fn finish_cursor_accelerator(
    continuation: &super::super::user_cursor_accelerator::Win16UserCursorAcceleratorContinuation,
    result: &crate::Win16HostUserCursorAcceleratorResult,
    owner: &mut CursorAcceleratorProjection,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::user_cursor_accelerator::Win16UserCursorAcceleratorContinuation as Call;
    use crate::Win16HostUserCursorAcceleratorResult as ResultValue;
    if owner.phase == CursorAcceleratorProjectionPhase::Ready {
        let value = match (continuation, result) {
            (Call::SetCursor, ResultValue::SetCursor(Some(cursor)))
            | (Call::GetCursor, ResultValue::GetCursor(Some(cursor))) =>
                access.guest_images.allocate_cursor(*cursor).ok_or_else(||
                    RuntimeError::new(Kind::ResourceExhausted,
                        "Win16 cursor handle table is full"))?,
            (Call::SetCursor, ResultValue::SetCursor(None))
            | (Call::GetCursor, ResultValue::GetCursor(None)) => 0,
            (Call::ShowCursor, ResultValue::ShowCursor(count)) => *count as u16,
            (Call::WinHelp, ResultValue::WinHelp(succeeded)) => u16::from(*succeeded),
            (Call::LoadAccelerators { guest_handle, owner_module, resource_id },
                ResultValue::LoadAccelerators(Some(table))) => {
                access.guest_accelerators.insert_reserved(
                    *guest_handle, *owner_module, resource_id.clone(), *table,
                );
                *guest_handle
            }
            (Call::LoadAccelerators { .. }, ResultValue::LoadAccelerators(None)) => 0,
            (Call::TranslateAccelerator { lease }, ResultValue::TranslateAccelerator(value)) => {
                let _owner_kept_live = lease.owner_module();
                *value as u16
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 cursor/accelerator result does not match its exact continuation")),
        };
        owner.value = Some(value);
        owner.phase = if matches!(continuation, Call::LoadAccelerators { .. })
            && matches!(result, ResultValue::LoadAccelerators(Some(_)))
        { CursorAcceleratorProjectionPhase::HandleAllocated }
        else { CursorAcceleratorProjectionPhase::ReturnReady };
    }
    if owner.phase == CursorAcceleratorProjectionPhase::HandleAllocated {
        owner.phase = CursorAcceleratorProjectionPhase::ReturnReady;
    }
    if owner.phase == CursorAcceleratorProjectionPhase::ReturnReady {
        owner.phase = CursorAcceleratorProjectionPhase::Complete;
    }
    owner.value.map(|value| (u32::from(value), Win16ReturnKind::Word))
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "cursor/accelerator projection lost its cached return"))
}

pub(super) fn finish_window_call(
    call: &crate::win16_host_window_ops::Win16WindowCallContinuation,
    result: &crate::Win16WindowCallResult,
    owner: &mut WindowCallProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
    host: &mut impl crate::RuntimeHost,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use crate::Win16WindowCallOutput as Output;
    use crate::Win16WindowCallResult as ResultValue;
    use WindowCallProjectionPhase as Phase;
    if !owner.geometry_result_observed {
        if let (
            Output::WindowRect { api, guest_window, .. },
            ResultValue::Rect(Some(rect)),
        ) = (&call.output, result)
        {
            host.observe_win16_io(&crate::Win16IoEvent::WindowRectResult {
                api,
                window: *guest_window,
                rect: *rect,
            });
            owner.geometry_result_observed = true;
        }
    }
    if owner.phase == Phase::Ready {
        let value = match (&call.output, result) {
            (Output::None | Output::Boolean, ResultValue::Boolean(value)) => Some(u32::from(*value)),
            (Output::None | Output::Integer, ResultValue::Integer(value)) => Some(u32::from(*value as u16)),
            (Output::None, ResultValue::Window(None)) => Some(0),
            (Output::None, ResultValue::Window(Some(native))) =>
                Some(u32::from(access.map_window_handle(*native, false)?)),
            (Output::Rect(range) | Output::WindowRect { range, .. }, ResultValue::Rect(rect)) => {
                if let Some(rect) = rect {
                    let output = win16_abi::Rect16 {
                        left: rect.left as i16, top: rect.top as i16,
                        right: rect.right as i16, bottom: rect.bottom as i16,
                    }.encode();
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &output,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
                Some(0)
            }
            (Output::Point(range), ResultValue::Point(point)) => {
                if let Some(point) = point {
                    let output = win16_abi::Point16 {
                        x: point.x as i16, y: point.y as i16,
                    }.encode();
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &output,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
                Some(0)
            }
            (Output::Points { range, count }, ResultValue::Points(points)) => {
                if let Some(points) = points {
                    if points.len() != usize::from(*count)
                        || points.len().checked_mul(win16_abi::Point16::SIZE) != Some(range.length())
                    {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "native MapWindowPoints result does not match its captured array"));
                    }
                    let mut output = Vec::new();
                    output.try_reserve_exact(range.length()).map_err(|error|
                        RuntimeError::with_source(Kind::ResourceExhausted,
                            "retain Win16 MapWindowPoints output", error))?;
                    for point in points {
                        // POINT16 retains the low signed 16-bit coordinate,
                        // matching the other Win16 coordinate conversions.
                        output.extend_from_slice(&win16_abi::Point16 {
                            x: point.x as i16, y: point.y as i16,
                        }.encode());
                    }
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &output,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
                Some(0)
            }
            (Output::Placement(range), ResultValue::Placement(placement)) => {
                if let Some(placement) = placement {
                    use win16_abi::user_abi::WindowPlacement16;
                    let point = |p: crate::Win16HostPoint| win16_abi::Point16 {
                        x: p.x as i16, y: p.y as i16,
                    };
                    let output = WindowPlacement16 {
                        length: WindowPlacement16::SIZE as u16,
                        flags: placement.flags as u16, show_command: placement.show_command as u16,
                        minimum: point(placement.minimum), maximum: point(placement.maximum),
                        normal: win16_abi::Rect16 {
                            left: placement.normal.left as i16, top: placement.normal.top as i16,
                            right: placement.normal.right as i16, bottom: placement.normal.bottom as i16,
                        },
                    }.encode();
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &output,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
                Some(u32::from(placement.is_some()))
            }
            (Output::ClassName { range, capacity }, ResultValue::ClassName {
                count, bytes, registered_class,
            }) => {
                let (count, output) = if let Some(class) = registered_class {
                    access.window_classes.class_name_for_host_class(*class)
                        .map(|name| bounded_class_name(name, *capacity))
                        .transpose()?
                        .unwrap_or((0, Vec::new()))
                } else {
                    if *count < 0 || bytes.len() > usize::from(*capacity)
                        || bytes.len() > range.length()
                    {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "native GetClassName output exceeds its captured guest capacity"));
                    }
                    (*count, copy_output_bytes(bytes)?)
                };
                if !output.is_empty() {
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &output,
                    )?;
                }
                owner.phase = Phase::GuestOutputCommitted;
                Some(count as u32)
            }
            _ => None,
        };
        let Some(value) = value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native window-call result does not match its exact captured output owner"));
        };
        owner.value = Some(value);
        owner.phase = Phase::OwnerBookkeepingCommitted;
    }
    if owner.phase == Phase::OwnerBookkeepingCommitted {
        owner.phase = Phase::ReturnReady;
    }
    if owner.phase == Phase::ReturnReady { owner.phase = Phase::Complete; }
    owner.value.map(|value| (value, call.return_kind))
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "window-call projection lost its cached result"))
}

fn bounded_class_name(name: &[u8], capacity: u16) -> Result<(i32, Vec<u8>), RuntimeError> {
    let count = name.len().min(usize::from(capacity).saturating_sub(1));
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(count.saturating_add(1)).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "retain Win16 GetClassName output", error))?;
    bytes.extend_from_slice(&name[..count]);
    bytes.push(0);
    Ok((count as i32, bytes))
}

fn copy_output_bytes(bytes: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "retain native Win16 class-name output", error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(super) fn user_family_projection_pending(
    continuation: &super::super::user_services_controls::Win16UserFamilyContinuation,
) -> RuntimeError {
    use super::super::user_services_controls::clipboard::ClipboardCompletion as Clipboard;
    use super::super::user_services_controls::FamilyCompletion;
    match &continuation.completion {
        FamilyCompletion::Clipboard(Clipboard::Plain) => RuntimeError::new(Kind::CompatibilityGap,
            "clipboard scalar result needs exact native-sequence and window-token projection phases"),
        FamilyCompletion::Clipboard(Clipboard::Empty { .. }) => RuntimeError::new(Kind::CompatibilityGap,
            "EmptyClipboard needs a retained per-format global-handle retirement journal"),
        FamilyCompletion::Clipboard(Clipboard::FormatAvailable { .. }) =>
            RuntimeError::new(Kind::CompatibilityGap,
                "IsClipboardFormatAvailable needs a retained stale-format retirement phase"),
        FamilyCompletion::Clipboard(Clipboard::FormatName { .. }) =>
            RuntimeError::new(Kind::CompatibilityGap,
                "GetClipboardFormatName needs an entry-captured selector-generation output range"),
        FamilyCompletion::Clipboard(Clipboard::SetData { .. }) => RuntimeError::new(
            Kind::CompatibilityGap,
            "SetClipboardData needs an exact guest GlobalHandle transfer and old-format retirement journal",
        ),
        FamilyCompletion::Clipboard(Clipboard::GetData { .. }) => RuntimeError::new(
            Kind::CompatibilityGap,
            "GetClipboardData needs staged guest GlobalHandle allocation and clipboard-sequence ownership",
        ),
        _ => RuntimeError::new(Kind::InternalInvariant,
            "USER-family pending projection has no matching deferred owner"),
    }
}
