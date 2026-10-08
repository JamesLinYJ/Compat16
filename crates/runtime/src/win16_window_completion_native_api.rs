//! Borrowed, retryable projection for USER menu, update-region and scroll-bar calls.

use super::*;
use super::completion_access::WindowProjectionAccess;
use super::operation_frame::{GuestOutputProjectionPhase, MenuProjectionPhase};
use super::super::menu_calls::{MenuCall, MenuCallKind};
use super::super::user_services_update_region::Win16UpdateContinuation;
use super::super::scroll_bar::Win16ScrollBarContinuation;
use super::super::commctrl::{Win16CommonControlsContinuation, Win16CommonControlsOutput};

#[path = "win16_window_completion_user_owned.rs"]
mod user_owned;
pub(in crate::win16_runtime::windows) use user_owned::{
    finish_user_family_owned_projection, Win16UserOwnedProjection,
};

pub(super) fn finish_user_family_simple(
    continuation: &super::super::user_services_controls::Win16UserFamilyContinuation,
    result: &crate::Win16HostUserServiceResult,
    owner: &mut super::operation_frame::UserFamilyProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::user_services_controls::{
        clipboard::ClipboardCompletion as Clipboard, FamilyCompletion,
    };
    use super::operation_frame::UserFamilyProjectionPhase as Phase;
    use crate::Win16HostDialogResult as Dialog;

    if owner.phase == Phase::Complete {
        return owner.value.map(|value| (value, continuation.return_kind)).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "completed USER-family projection lost its retained caller value"));
    }
    let projected = match (&continuation.completion, result) {
        (FamilyCompletion::DialogDefaultProcedure { output },
            crate::Win16HostUserServiceResult::Dialog(Dialog::DefaultResult(result))) =>
                finish_user_default_procedure(
                    output, result.as_ref(), owner, access, memory,
                ),
        (FamilyCompletion::DialogEnd,
            crate::Win16HostUserServiceResult::Dialog(Dialog::Ended(value))) =>
                Ok(u32::from(*value)),
        (FamilyCompletion::DialogIsMessage,
            crate::Win16HostUserServiceResult::Dialog(Dialog::MessageHandled(value))) =>
                Ok(u32::from(*value)),
        (FamilyCompletion::Control { output },
            crate::Win16HostUserServiceResult::DialogControl(control)) =>
                finish_user_control(output.as_ref(), control, owner, access, memory),
        (FamilyCompletion::DialogCreate { modal: true, .. },
            crate::Win16HostUserServiceResult::Dialog(Dialog::ModalResult(_))) =>
                Err(RuntimeError::new(Kind::CompatibilityGap,
                    "DialogBox result requires the exact modal-window lease and retired-work receipt")),
        (FamilyCompletion::DialogCreate { modal: false, .. },
            crate::Win16HostUserServiceResult::Dialog(Dialog::Created { .. })) =>
                Err(RuntimeError::new(Kind::CompatibilityGap,
                    "CreateDialog result requires staged HWND, creation observation, and dialog-procedure publication")),
        (FamilyCompletion::Clipboard(completion @ (Clipboard::Plain
            | Clipboard::FormatName { .. })),
            crate::Win16HostUserServiceResult::Clipboard(result)) =>
                return super::completion_api::finish_clipboard_projection(
                    completion, result, owner, access, memory, continuation.return_kind,
                ),
        (FamilyCompletion::Clipboard(_),
            crate::Win16HostUserServiceResult::Clipboard(_)) =>
                Err(super::completion_api::user_family_projection_pending(continuation)),
        (FamilyCompletion::SystemParameters(spi),
            crate::Win16HostUserServiceResult::SystemParameters(result)) => {
                let (value, bytes) = spi.project_output(result)?;
                if let Some(bytes) = bytes {
                    match owner.phase {
                        Phase::Ready => {
                            spi.commit_output(access.selectors, memory, &bytes)?;
                            owner.phase = Phase::GuestOutputCommitted;
                        }
                        Phase::GuestOutputCommitted | Phase::ValueCaptured => {}
                        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                            "SystemParametersInfo output reached an invalid retained phase")),
                    }
                }
                Ok(value)
            }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "USER-family result does not match its exact retained completion variant")),
    };
    match projected {
        Ok(value) => {
            if owner.value.is_none() { owner.value = Some(value); }
            if matches!(owner.phase, Phase::Ready | Phase::GuestOutputCommitted
                | Phase::ValueCaptured | Phase::ControlParentLinked)
            {
                owner.phase = Phase::ReturnReady;
            }
            owner.phase = Phase::Complete;
            Ok((owner.value.unwrap_or(value), continuation.return_kind))
        }
        Err(error) => Err(error),
    }
}

fn finish_user_control(
    output: Option<&super::super::user_services_controls::ControlWriteBack>,
    result: &crate::Win16HostDialogControlResult,
    owner: &mut super::operation_frame::UserFamilyProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<u32, RuntimeError> {
    use super::operation_frame::UserFamilyProjectionPhase as Phase;
    use super::super::user_services_controls::ControlWriteBack as Output;
    use crate::Win16HostDialogControlResult as ResultValue;

    if let Some(value) = owner.value {
        if owner.phase == Phase::Complete || owner.phase == Phase::ReturnReady {
            return Ok(value);
        }
    }
    match (output, result) {
        (Some(Output::Window { parent, native_parent }),
            ResultValue::Item(window) | ResultValue::NextItem(window)) => {
            if owner.phase == Phase::Ready {
                let guest = match window {
                    Some(native) if access.window_handles.get(parent) == Some(native_parent) =>
                        access.map_window_handle(*native, false)?,
                    Some(_) | None => 0,
                };
                owner.value = Some(u32::from(guest));
                owner.phase = if guest == 0 { Phase::ReturnReady }
                    else { Phase::ControlWindowMapped };
            }
            if owner.phase == Phase::ControlWindowMapped {
                let guest = u16::try_from(owner.value.ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "dialog child mapping lost its guest HWND"))?)
                    .map_err(|_| RuntimeError::new(Kind::InternalInvariant,
                        "dialog child mapping exceeded Win16 handle width"))?;
                let native_child = window.as_ref().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "dialog child mapping lost its native identity"))?;
                if access.window_handles.get(&guest) != Some(native_child)
                    || access.window_handles.get(parent) != Some(native_parent)
                {
                    return Err(RuntimeError::new(Kind::CompatibilityGap,
                        "dialog child or parent HWND incarnation changed before relationship commit"));
                }
                access.set_window_parent_from_host(guest, *parent)?;
                owner.phase = Phase::ControlParentLinked;
            }
            owner.value.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "dialog child completion lost its cached return"))
        }
        (None, ResultValue::Item(window) | ResultValue::NextItem(window)) => {
            if owner.phase == Phase::Ready {
                let guest = match window {
                    Some(native) => access.map_window_handle(*native, false)?,
                    None => 0,
                };
                owner.value = Some(u32::from(guest));
                owner.phase = Phase::ValueCaptured;
            }
            owner.value.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "dialog item completion lost its cached guest handle"))
        }
        (None, ResultValue::ControlId(value)) => Ok(u32::from(*value)),
        (None, ResultValue::Integer { value, .. }) => Ok(u32::from(*value)),
        (Some(Output::IntegerTranslated { range: None }),
            ResultValue::Integer { value, .. }) => Ok(u32::from(*value)),
        (Some(Output::IntegerTranslated { range: Some(range) }),
            ResultValue::Integer { value, translated, .. }) => {
            if range.length() != 2 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "GetDlgItemInt lost its exact two-byte translated output range"));
            }
            if owner.phase == Phase::Ready {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, range,
                    &(if *translated { 1_u16 } else { 0 }).to_le_bytes(),
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
            Ok(u32::from(*value))
        }
        (None, ResultValue::ButtonState(value)) => Ok(u32::from(*value)),
        (None, ResultValue::Succeeded(value)) => Ok(u32::from(*value)),
        (Some(Output::Text { range, capacity }), ResultValue::Text { value, bytes }) => {
            if range.length() != usize::from(*capacity) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "GetDlgItemText lost its exact captured capacity"));
            }
            validate_dialog_control_text(*capacity, *value, bytes)?;
            if owner.phase == Phase::Ready && !bytes.is_empty() {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, range, bytes,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
            Ok(*value)
        }
        (None, ResultValue::Text { value, bytes }) => {
            if !bytes.is_empty() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "GetDlgItemText returned bytes without its captured output owner"));
            }
            Ok(*value)
        }
        (Some(Output::DirectoryPath { range, capacity }),
            ResultValue::DirectoryList { selected, path_spec }) => {
            if let Some(bytes) = path_spec {
                if bytes.len() > usize::from(*capacity)
                    || range.as_ref().is_none_or(|range| bytes.len() > range.length())
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "DlgDirList output exceeded its captured guest path range"));
                }
                if !bytes.is_empty() && owner.phase == Phase::Ready {
                    let range = range.as_ref().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant,
                        "DlgDirList returned path bytes without a captured output range"))?;
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, bytes,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
            }
            Ok(*selected as u16 as u32)
        }
        (Some(Output::DirectoryPath { .. }), ResultValue::Succeeded(value)) =>
            Ok(u32::from(*value)),
        (Some(Output::DirectorySelection { range, capacity }),
            ResultValue::DirectorySelect { selected, text }) => {
            if text.len() > usize::from(*capacity) || text.len() > range.length() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DlgDirSelect output exceeded its captured guest path range"));
            }
            if !text.is_empty() && owner.phase == Phase::Ready {
                super::super::guest_ranges::commit_guest_output_with_selectors(
                    access.selectors, memory, range, text,
                )?;
                owner.phase = Phase::GuestOutputCommitted;
            }
            Ok(u32::from(*selected))
        }
        (Some(Output::Rect { range }), ResultValue::Rect(rect)) => {
            if range.length() != win16_abi::Rect16::SIZE {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "dialog RECT result lost its exact eight-byte guest range"));
            }
            if let Some(rect) = rect {
                let bytes = win16_abi::Rect16 {
                    left: rect.left as i16,
                    top: rect.top as i16,
                    right: rect.right as i16,
                    bottom: rect.bottom as i16,
                }.encode();
                if owner.phase == Phase::Ready {
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, &bytes,
                    )?;
                    owner.phase = Phase::GuestOutputCommitted;
                }
            }
            Ok(u32::from(rect.is_some()))
        }
        _ => Err(RuntimeError::new(Kind::InternalInvariant,
            "dialog-control native result does not match its captured USER output contract")),
    }
}

fn finish_user_default_procedure(
    output: &super::super::messages::MessageOutput,
    result: Option<&crate::Win16HostMessageResult>,
    owner: &mut super::operation_frame::UserFamilyProjection,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<u32, RuntimeError> {
    use super::operation_frame::{MessageProjection, MessageProjectionPhase, UserFamilyProjectionPhase};

    if owner.phase == UserFamilyProjectionPhase::Complete {
        return owner.value.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "completed dialog default-procedure projection lost its cached return",
        ));
    }
    if owner.phase != UserFamilyProjectionPhase::Ready {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "dialog default-procedure projection reached an unexpected retained phase",
        ));
    }

    // Reuse the ordinary WM_* output contract, including exact HWND mapping,
    // selector-generation checks, and byte-layout validation. This small
    // adapter keeps the USER-family journal as the durable retry owner.
    let mut message_owner = MessageProjection {
        phase: MessageProjectionPhase::Ready,
        value: None,
    };
    let (value, _) = super::completion_api::finish_window_message(
        output, result, &mut message_owner, access, memory,
    )?;
    owner.value = Some(value);
    owner.phase = UserFamilyProjectionPhase::Complete;
    Ok(value)
}

fn validate_dialog_control_text(
    capacity: u16,
    value: u32,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if value == u32::MAX {
        if !bytes.is_empty() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetDlgItemText sentinel result contains output bytes"));
        }
    } else if !bytes.is_empty() {
        let count = value as usize;
        if count >= usize::from(capacity) || bytes.len() != count + 1
            || bytes[count] != 0 || bytes[..count].contains(&0)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "GetDlgItemText count does not match its terminated native prefix"));
        }
    } else if value != 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "GetDlgItemText count has no returned output prefix"));
    }
    Ok(())
}

pub(super) fn finish_common_controls_simple(
    continuation: &Win16CommonControlsContinuation,
    result: &crate::Win16HostCommonControlsResult,
    phase: &mut super::operation_frame::CommonControlsProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::CommonControlsProjectionPhase as Phase;
    use crate::Win16HostCommonControlsResult as ResultValue;

    if matches!(
        (&continuation.output, result),
        (Win16CommonControlsOutput::Window, ResultValue::CreatedWindow { .. })
    ) {
        return finish_common_control_window(continuation, result, phase, value, access);
    }
    if matches!(
        (&continuation.output, result),
        (Win16CommonControlsOutput::MenuHelpResolve { .. },
            ResultValue::MenuHelp(crate::Win16HostMenuHelpResolution::NoChange))
    ) {
        if *phase == Phase::Complete {
            return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "MenuHelp no-change result lost its cached return"));
        }
        let returned = (0, continuation.return_kind);
        *value = Some(returned);
        *phase = Phase::Complete;
        return Ok(returned);
    }

    if *phase == Phase::Complete {
        return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "common-control projection lost its cached return"));
    }
    if let Some(value) = value.as_ref().copied() {
        return Ok(value);
    }

    let projected = match (&continuation.output, result) {
        (Win16CommonControlsOutput::Neutral, ResultValue::Initialized) => 0,
        (Win16CommonControlsOutput::Boolean, ResultValue::Bool(value)) => u32::from(*value),
        (Win16CommonControlsOutput::MenuHelpApplied, ResultValue::MenuHelpApplied) => 0,
        (Win16CommonControlsOutput::Rect(_), ResultValue::Rect(None)) => 0,
        (Win16CommonControlsOutput::Rect(output), ResultValue::Rect(Some(rect))) => {
            if output.length() != win16_abi::Rect16::SIZE {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "common-control RECT output lost its exact 8-byte captured range"));
            }
            let bytes = win16_abi::Rect16 {
                left: rect.left as i16,
                top: rect.top as i16,
                right: rect.right as i16,
                bottom: rect.bottom as i16,
            }.encode();
            super::super::guest_ranges::commit_guest_output_with_selectors(
                access.selectors, memory, output, &bytes,
            )?;
            *phase = Phase::GuestOutputCommitted;
            0
        }
        (Win16CommonControlsOutput::Profile { output },
            ResultValue::ProfileData { succeeded, data }) => {
            if *succeeded {
                if let Some((range, capacity)) = output {
                    if data.len() > *capacity || data.len() > range.length() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "GetPrivateProfileStruct output exceeded its captured capacity"));
                    }
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, range, data,
                    )?;
                    *phase = Phase::GuestOutputCommitted;
                } else if !data.is_empty() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "GetPrivateProfileStruct returned bytes without a guest output range"));
                }
            }
            u32::from(*succeeded)
        }
        (Win16CommonControlsOutput::Window, ResultValue::CreatedWindow { .. }) =>
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "common-control window result bypassed its exact HWND phase owner")),
        (Win16CommonControlsOutput::MenuHelpResolve { .. }, ResultValue::MenuHelp(
            crate::Win16HostMenuHelpResolution::Close)) =>
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "MenuHelp close requires a retained same-frame MenuHelpApply operation stage")),
        (Win16CommonControlsOutput::MenuHelpResolve { .. }, ResultValue::MenuHelp(
            crate::Win16HostMenuHelpResolution::String(_))) =>
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "MenuHelp string requires a retained resource lookup and MenuHelpApply stage")),
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
            "common-control result does not match its retained request")),
    };
    let returned = (projected, continuation.return_kind);
    value.replace(returned);
    *phase = Phase::Complete;
    Ok(returned)
}

fn finish_common_control_window(
    continuation: &Win16CommonControlsContinuation,
    result: &crate::Win16HostCommonControlsResult,
    phase: &mut super::operation_frame::CommonControlsProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::operation_frame::CommonControlsProjectionPhase as Phase;
    use crate::Win16HostCommonControlsResult as ResultValue;

    let ResultValue::CreatedWindow { window, parent } = result else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "common-control HWND continuation received a non-window result"));
    };
    if *phase == Phase::Complete {
        return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "common-control HWND completion lost its cached return"));
    }

    if *phase == Phase::Ready {
        let guest = match window {
            Some(native) => access.map_window_handle(*native, true)?,
            None => 0,
        };
        *value = Some((u32::from(guest), continuation.return_kind));
        *phase = if window.is_some() { Phase::WindowMapped } else { Phase::ReturnReady };
    }

    if *phase == Phase::WindowMapped {
        let native = window.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "mapped common-control HWND lost its native identity"))?;
        let (guest, _) = value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "mapped common-control HWND lost its guest identity"))?;
        let guest = u16::try_from(guest).map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "common-control guest HWND exceeds Win16 width"))?;
        if access.window_handles.get(&guest) != Some(&native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "common-control guest HWND no longer names its captured native window"));
        }
        match parent {
            Some(native_parent) => {
                let guest_parent = access.map_window_handle(*native_parent, false)?;
                access.set_window_parent_from_host(guest, guest_parent)?;
            }
            None => access.set_window_parent_from_host(guest, 0)?,
        }
        *phase = Phase::ParentLinked;
    }

    if *phase == Phase::ParentLinked {
        *phase = Phase::ReturnReady;
    }
    if *phase == Phase::ReturnReady {
        *phase = Phase::Complete;
    }
    value.as_ref().copied().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "common-control HWND completion lost its cached return"))
}

pub(super) fn finish_kernel_diagnostic(
    continuation: &super::super::kernel_diagnostics::Win16KernelDiagnosticContinuation,
    result: &crate::Win16WindowResult,
    phase: &mut super::operation_frame::KernelDiagnosticProjectionPhase,
    retained_effect: &mut Option<super::super::kernel_diagnostics::Win16KernelDiagnosticEffect>,
    access: &mut WindowProjectionAccess<'_>,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::kernel_diagnostics::{
        Win16KernelDiagnosticEffect as Effect,
        Win16KernelDiagnosticContinuation as Continuation,
    };
    use super::operation_frame::KernelDiagnosticProjectionPhase as Phase;

    if *phase == Phase::EffectQueued {
        return Ok((0, Win16ReturnKind::Void));
    }
    if *phase == Phase::Ready {
        let effect = match (continuation, result) {
            (Continuation::FatalAppExit { exit_status },
                crate::Win16WindowResult::UserService(crate::Win16HostUserServiceResult::Dialog(
                    crate::Win16HostDialogResult::FatalAppExitAcknowledged,
                ))) => Some(Effect::FinishTask { status: *exit_status }),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "KERNEL diagnostic result does not match its exact modal continuation")),
        };
        if let Some(effect) = effect {
            access.kernel_diagnostic_effects.try_reserve(1).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve one retained KERNEL diagnostic effect", error))?;
            if retained_effect.is_some_and(|existing| existing != effect) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "KERNEL diagnostic effect changed after its exact result was retained"));
            }
            *retained_effect = Some(effect);
        }
        *phase = Phase::EffectReserved;
    }
    if *phase == Phase::EffectReserved {
        return Ok((0, Win16ReturnKind::Void));
    }
    Err(RuntimeError::new(Kind::InternalInvariant,
        "KERNEL diagnostic projection has an unknown retained phase"))
}

pub(super) fn finish_menu_call(
    call: &MenuCall,
    result: &crate::Win16MenuResult,
    phase: &mut MenuProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &mut WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use crate::Win16MenuResult as ResultValue;
    use MenuCallKind as CallKind;

    if matches!(*phase, MenuProjectionPhase::ReturnReady | MenuProjectionPhase::Complete) {
        return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "completed menu projection lost its cached value"));
    }

    if *phase == MenuProjectionPhase::Ready {
        let invalidated = match (call.kind, result) {
            (CallKind::Handle, ResultValue::Menu { invalidated, .. })
            | (CallKind::Boolean, ResultValue::Boolean { invalidated, .. })
            | (CallKind::Popup, ResultValue::Popup { invalidated, .. }) =>
                Some(invalidated.as_slice()),
            _ => None,
        };
        if let Some(invalidated) = invalidated {
            access.guest_menus.invalidate(invalidated);
            *phase = MenuProjectionPhase::Invalidated;
        }
    }

    if value.is_none() {
        let projected = match (call.kind, result) {
            (CallKind::Handle, ResultValue::Created(menu))
            | (CallKind::Handle, ResultValue::Menu { menu, .. }) => {
                let guest = match *menu {
                    Some(menu) => access.guest_menus.intern(menu).ok_or_else(||
                        RuntimeError::new(Kind::ResourceExhausted,
                            "Win16 HMENU table filled during native menu creation"))?,
                    None => 0,
                };
                u32::from(guest)
            }
            (CallKind::Boolean, ResultValue::Boolean { succeeded, .. }) => u32::from(*succeeded),
            (CallKind::ItemFlags, ResultValue::ItemFlags(flags)) => u32::from(*flags),
            (CallKind::ItemId, ResultValue::ItemId(item)) => u32::from(*item),
            (CallKind::ItemCount, ResultValue::ItemCount(count)) => u32::from(*count as u16),
            (CallKind::ContextHelpId, ResultValue::ContextHelpId(help_id)) =>
                u32::from(*help_id as u16),
            (CallKind::CheckMarkDimensions, ResultValue::CheckMarkDimensions(value)) => *value,
            (CallKind::MenuRect, ResultValue::MenuRect { succeeded, rect }) => {
                if *succeeded {
                    let rect = rect.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "native GetMenuItemRect succeeded without an output rectangle"))?;
                    let output = call.output.as_ref().ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant, "GetMenuItemRect lost its captured RECT16"))?;
                    if output.length() != 8 {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "GetMenuItemRect output is not one captured 8-byte RECT16 range"));
                    }
                    let mut bytes = [0_u8; 8];
                    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom]
                        .into_iter().enumerate()
                    {
                        bytes[index * 2..index * 2 + 2]
                            .copy_from_slice(&(value as i16).to_le_bytes());
                    }
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, output, &bytes,
                    )?;
                    *phase = MenuProjectionPhase::OutputCommitted;
                }
                u32::from(*succeeded)
            }
            (CallKind::MenuString, ResultValue::MenuString { count, buffer }) => {
                if *count >= 0 {
                    if let Some(output) = call.output.as_ref() {
                        let length = usize::try_from(*count).ok().and_then(|count|
                            count.checked_add(1)).ok_or_else(|| RuntimeError::new(
                                Kind::InternalInvariant,
                                "GetMenuString count cannot be represented as a byte length"))?;
                        if length > output.length() || buffer.len() != length
                            || buffer.last() != Some(&0)
                            || buffer[..buffer.len().saturating_sub(1)].contains(&0)
                        {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "native GetMenuString result is not an exact captured NUL prefix"));
                        }
                        super::super::guest_ranges::commit_guest_output_with_selectors(
                            access.selectors, memory, output, buffer,
                        )?;
                        *phase = MenuProjectionPhase::OutputCommitted;
                    } else if !buffer.is_empty() {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "GetMenuString returned bytes without a guest destination"));
                    }
                } else if !buffer.is_empty() {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "GetMenuString returned bytes with a failure count"));
                }
                u32::from(*count as u16)
            }
            (CallKind::Void, ResultValue::Drawn) => 0,
            (CallKind::Popup, ResultValue::Popup { value, .. }) => u32::from(*value),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "native menu result does not match its retained continuation")),
        };
        value.replace((projected, call.return_kind));
        if *phase != MenuProjectionPhase::OutputCommitted {
            *phase = MenuProjectionPhase::ReturnReady;
        }
    }
    *phase = MenuProjectionPhase::Complete;
    value.as_ref().copied().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "menu projection lost its cached return"))
}

pub(super) fn finish_update_region(
    continuation: &Win16UpdateContinuation,
    result: &crate::Win16HostUpdateResult,
    phase: &mut GuestOutputProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    if *phase == GuestOutputProjectionPhase::Complete {
        return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "update-region projection lost its cached return"));
    }
    if *phase == GuestOutputProjectionPhase::Ready {
        let result_value = match (continuation.result_kind, result) {
            (super::super::user_services_update_region::UpdateResultKind::Void,
                crate::Win16HostUpdateResult::Void { .. }) => 0,
            (super::super::user_services_update_region::UpdateResultKind::Word,
                crate::Win16HostUpdateResult::Word(value)) => u32::from(*value),
            (super::super::user_services_update_region::UpdateResultKind::Rect,
                crate::Win16HostUpdateResult::Rect { value, rect }) => {
                if let (Some(output), Some(rect)) = (continuation.rect_output.as_ref(), rect) {
                    let wire = win16_abi::Rect16 {
                        left: super::super::user_services_paint::guest_coordinate(rect.left),
                        top: super::super::user_services_paint::guest_coordinate(rect.top),
                        right: super::super::user_services_paint::guest_coordinate(rect.right),
                        bottom: super::super::user_services_paint::guest_coordinate(rect.bottom),
                    }.encode();
                    super::super::guest_ranges::commit_guest_output_with_selectors(
                        access.selectors, memory, output, &wire,
                    )?;
                    *phase = GuestOutputProjectionPhase::OutputCommitted;
                }
                u32::from(*value)
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER update result does not match its exact request")),
        };
        value.replace((result_value, continuation.return_kind));
        if *phase == GuestOutputProjectionPhase::Ready {
            *phase = GuestOutputProjectionPhase::OutputCommitted;
        }
    }
    *phase = GuestOutputProjectionPhase::Complete;
    value.as_ref().copied().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "update-region projection lost its return"))
}

pub(super) fn finish_scroll_bar(
    continuation: &Win16ScrollBarContinuation,
    result: &crate::Win16HostScrollBarResult,
    phase: &mut GuestOutputProjectionPhase,
    value: &mut Option<(u32, Win16ReturnKind)>,
    access: &WindowProjectionAccess<'_>,
    memory: &mut Memory,
) -> Result<(u32, Win16ReturnKind), RuntimeError> {
    use super::super::scroll_bar::ScrollBarResultKind as Request;
    use crate::Win16HostScrollBarResult as ResultValue;

    if *phase == GuestOutputProjectionPhase::Complete {
        return value.as_ref().copied().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "scroll-bar projection lost its cached return"));
    }
    if *phase == GuestOutputProjectionPhase::Ready {
        let projected = match (continuation.result_kind, result) {
            (Request::Position, ResultValue::Position(position)) =>
                u32::from(*position as i16 as u16),
            (Request::Range, ResultValue::Range(Some((minimum, maximum)))) => {
                let minimum_range = continuation.minimum_output.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "GetScrollRange lost its captured minimum output"))?;
                let maximum_range = continuation.maximum_output.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "GetScrollRange lost its captured maximum output"))?;
                let mut writes = Vec::new();
                writes.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted, "retain GetScrollRange output transaction", error))?;
                writes.push((minimum_range.clone(), (*minimum as i16).to_le_bytes().to_vec()));
                writes.push((maximum_range.clone(), (*maximum as i16).to_le_bytes().to_vec()));
                match super::super::guest_ranges::commit_guest_writes_with_selectors(
                    access.selectors, memory, writes,
                ) {
                    Ok(()) => *phase = GuestOutputProjectionPhase::OutputCommitted,
                    Err(error) if matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput) => {
                        *phase = GuestOutputProjectionPhase::OutputCommitted;
                        value.replace((0, continuation.return_kind));
                        return Ok((0, continuation.return_kind));
                    }
                    Err(error) => return Err(error),
                }
                0
            }
            (Request::Range, ResultValue::Range(None))
            | (Request::Void, ResultValue::Void)
            | (_, ResultValue::Unavailable) => 0,
            (Request::Enabled, ResultValue::Enabled(enabled)) => u32::from(*enabled),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "scroll-bar result does not match its exact USER request")),
        };
        value.replace((projected, continuation.return_kind));
        if *phase == GuestOutputProjectionPhase::Ready {
            *phase = GuestOutputProjectionPhase::OutputCommitted;
        }
    }
    *phase = GuestOutputProjectionPhase::Complete;
    value.as_ref().copied().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "scroll-bar projection lost its return"))
}
