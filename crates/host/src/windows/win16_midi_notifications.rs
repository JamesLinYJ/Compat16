//! Stable, non-destructive projection and exact ACK for native MIDI callbacks.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMidiDevice as DeviceToken,
    Win16HostMidiNotification, Win16HostMidiNotificationDisposition,
    Win16HostMidiNotificationId,
};
use windows_sys::Win32::Media::{
    MM_MIM_CLOSE, MM_MIM_DATA, MM_MIM_ERROR, MM_MIM_LONGDATA, MM_MIM_LONGERROR,
    MM_MIM_OPEN, MM_MOM_CLOSE, MM_MOM_DONE, MM_MOM_OPEN,
};

use super::{Win16MidiHost, device_pointer};

const HEADER_MESSAGES: [u32; 3] = [MM_MOM_DONE, MM_MIM_LONGDATA, MM_MIM_LONGERROR];

pub(super) fn peek(
    host: &mut Win16MidiHost,
) -> Result<Option<Win16HostMidiNotification>, RuntimeError> {
    if let Some(error) = super::callback::unknown_context_failure() {
        return Err(error);
    }
    for device in &host.devices {
        if let Some(error) = device.callback.take_failure() { return Err(error); }
    }
    let candidate = host.devices.iter().enumerate().filter(|(_, device)| !device.orphaned)
        .filter_map(|(index, device)| {
        let event = device.callback.peek()?;
        Some((event.sequence, index, event))
    }).min_by_key(|(sequence, _, _)| *sequence);
    let Some((_, index, raw)) = candidate else { return Ok(None); };
    if let Some(projected) = host.devices[index].projected.as_ref() {
        if projected.sequence == raw.sequence { return Ok(Some(projected.clone())); }
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MIDI callback projection no longer matches its native queue front"));
    }
    let device_token = host.devices[index].token;
    let native_handle = host.devices[index].native;
    if device_pointer(native_handle) != raw.native_device {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native MIDI callback handle did not match its owner generation"));
    }
    if !known_message(raw.message) {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            format!("native MIDI callback message {:#x} has no Win16 3.1 projection", raw.message)));
    }
    let (parameter1, parameter2) = if matches!(raw.message,
        MM_MIM_OPEN | MM_MIM_CLOSE | MM_MOM_OPEN | MM_MOM_CLOSE)
    {
        // Open/close callbacks reserve both parameters; native implementations
        // may put handle-sized values there, so they are never guest data.
        (0, 0)
    } else {
        let parameter1 = if HEADER_MESSAGES.contains(&raw.message) { 0 } else {
            u32::try_from(raw.parameter1).map_err(|error| RuntimeError::with_source(
                Kind::CompatibilityGap, "native MIDI callback parameter exceeds Win16 DWORD", error))?
        };
        let parameter2 = u32::try_from(raw.parameter2).map_err(|error| RuntimeError::with_source(
            Kind::CompatibilityGap, "native MIDI callback timestamp exceeds Win16 DWORD", error))?;
        (parameter1, parameter2)
    };
    let header = if HEADER_MESSAGES.contains(&raw.message) {
        let Some(state) = host.header_snapshot_for_callback(device_token, raw.parameter1,
            raw.message != MM_MOM_DONE)? else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native MIDI completion named an unknown owned MIDIHDR"));
        };
        Some(state)
    } else {
        None
    };
    let projected = Win16HostMidiNotification {
        sequence: raw.sequence,
        device: device_token,
        callback_instance: host.devices[index].guest_instance,
        message: raw.message,
        parameter1,
        parameter2,
        header,
    };
    host.devices[index].projected = Some(projected.clone());
    Ok(Some(projected))
}

pub(super) fn ack(
    host: &mut Win16MidiHost,
    device_token: DeviceToken,
    sequence: u64,
    disposition: Win16HostMidiNotificationDisposition,
) -> Result<(), RuntimeError> {
    let Some(index) = host.device_index(device_token) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MIDI callback ACK referenced a retired device token"));
    };
    let device = &host.devices[index];
    let projected = device.projected.as_ref().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "MIDI callback ACK had no stable projection"))?;
    if projected.sequence != sequence || projected.device != device_token {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MIDI callback ACK did not match exact device and sequence"));
    }
    let raw = device.callback.peek().ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant, "MIDI callback ACK has no native queue item"))?;
    if raw.sequence != sequence {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "MIDI callback ACK sequence changed before native retirement"));
    }
    let message = raw.message;
    let header = projected.header.clone();
    if HEADER_MESSAGES.contains(&message) {
        let state = header.as_ref().ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "MIDI header callback lost its owned header projection"))?;
        host.validate_completion_ack(device_token, state.header,
            state.completed_submission)?;
    }
    // A cancelled target retires this exact source without claiming that its
    // guest callback or window procedure ran.
    let _retirement_disposition = disposition;
    device.callback.acknowledge(sequence, disposition)?;
    host.devices[index].projected = None;
    if HEADER_MESSAGES.contains(&message) {
        let state = header.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "MIDI header callback lost its owned header projection"))?;
        // All failure conditions are checked before the callback queue is
        // mutated above, so this exact completion retirement is infallible
        // unless the native owner ledger itself is damaged.
        host.complete_submission(device_token, state.header, state.completed_submission)?;
    }
    if message == MM_MOM_CLOSE || message == MM_MIM_CLOSE {
        host.devices[index].close_seen = true;
    }
    Ok(())
}

fn known_message(message: u32) -> bool {
    matches!(message,
        MM_MIM_OPEN | MM_MIM_CLOSE | MM_MIM_DATA | MM_MIM_LONGDATA | MM_MIM_ERROR
            | MM_MIM_LONGERROR | MM_MOM_OPEN | MM_MOM_CLOSE | MM_MOM_DONE)
}

#[allow(dead_code)]
fn _exact_identity(device: DeviceToken, sequence: u64) -> Win16HostMidiNotificationId {
    Win16HostMidiNotificationId { device, sequence }
}
