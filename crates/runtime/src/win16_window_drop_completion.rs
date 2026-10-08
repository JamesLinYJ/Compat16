//! Exact native queue lease projection for Windows 3.1 WM_DROPFILES.

use super::*;
use crate::Win16WindowResult;

pub(super) fn prepare_queued_drop_delivery(
    state: &mut Win16State,
    frame_id: u64,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let delivery = state.window_operations.last()
        .filter(|frame| frame.id == frame_id)
        .and_then(|frame| frame.completion.as_ref())
        .and_then(|completion| match &completion.result {
            Win16WindowResult::QueuedMessage(delivery) => Some(delivery.clone()),
            _ => None,
        });
    let Some(delivery) = delivery else { return Ok(()); };
    let Some(drop_files) = delivery.drop_files else {
        if let Some(message) = delivery.message.filter(|message|
            message.source == crate::Win16MessageSource::NativeQueue
                && message.message == 0x0233)
        {
            let handle = message.w_param;
            let allocation = state.global_handles.get(&handle).copied();
            if handle == 0
                || message.l_param != crate::Win16MessageParam::Scalar(0)
                || !allocation.is_some_and(|allocation|
                    state.queued_drop_files.iter().any(|entry|
                        Some(entry.window) == message.window
                            && entry.guest_handle == handle
                            && entry.allocation == allocation))
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "queued Win16 WM_DROPFILES HGLOBAL has no exact live host queue lease"));
            }
        }
        return Ok(());
    };
    let mut message = delivery.message.ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant,
        "native WM_DROPFILES lease has no queued MSG",
    ))?;
    let window = message.window.ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant,
        "native WM_DROPFILES queue lease has no exact mapped HWND",
    ))?;
    if message.source != crate::Win16MessageSource::NativeQueue
        || message.message != 0x0233
        || message.w_param != 0
        || message.l_param != crate::Win16MessageParam::Scalar(0)
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native WM_DROPFILES queue lease does not match its Win16 MSG"));
    }
    let handle = state.project_queued_drop_files_hglobal(
        &drop_files,
        window,
        memory,
        host,
    )?;
    if let Some(handle) = handle {
        // SHELLAPI.H and WINDOWSX.H pass HDROP in WPARAM; LPARAM is zero.
        message.w_param = handle;
    } else {
        // The guest finished this peeked lease before PM_REMOVE. Preserve the
        // successful GetMessage/PeekMessage queue result as a harmless
        // WM_NULL, and never publish the freed HGLOBAL WORD again.
        host.report_diagnostic(&crate::Diagnostic::warning(
            Kind::CompatibilityGap,
            "suppressed a removed WM_DROPFILES whose exact lease was already finished",
        ));
        message.message = 0;
        message.w_param = 0;
        message.l_param = crate::Win16MessageParam::Scalar(0);
    }
    let completion = state.window_operations.last_mut()
        .filter(|frame| frame.id == frame_id)
        .and_then(|frame| frame.completion.as_mut())
        .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "queued WM_DROPFILES completion disappeared after HGLOBAL projection"))?;
    let Win16WindowResult::QueuedMessage(current) = &mut completion.result else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "queued WM_DROPFILES completion changed result family during projection"));
    };
    if current.drop_files.as_ref() != Some(&drop_files)
        || current.message != delivery.message
    {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "queued WM_DROPFILES native queue lease changed during projection"));
    }
    current.message = Some(message);
    current.drop_files = None;
    Ok(())
}

pub(super) fn queued_delivery_message(
    delivery: &crate::Win16HostQueuedDelivery,
) -> Result<Option<crate::Win16HostQueuedMessage>, RuntimeError> {
    if delivery.drop_files.is_some() {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "queued WM_DROPFILES payload reached MSG16 projection before HGLOBAL allocation"));
    }
    Ok(delivery.message)
}
