//! MIDI and multimedia host service delegations.

use super::*;

pub(super) fn midi_call(
    host: &mut WindowsHost,
    call: runtime::Win16HostMidiCall,
) -> Result<runtime::Win16HostMidiResult, RuntimeError> {
    host.win16_midi.execute(call, host.win16_dcs.text_codec())
}

pub(super) fn midi_peek(
    host: &mut WindowsHost,
) -> Result<Option<runtime::Win16HostMidiNotification>, RuntimeError> {
    host.win16_midi.peek_notification()
}

pub(super) fn midi_ack(
    host: &mut WindowsHost,
    device: runtime::Win16HostMidiDevice,
    sequence: u64,
    disposition: runtime::Win16HostMidiNotificationDisposition,
) -> Result<(), RuntimeError> {
    host.win16_midi
        .ack_notification(device, sequence, disposition)
}

pub(super) fn midi_wait(
    host: &mut WindowsHost,
    timeout: std::time::Duration,
) -> Result<bool, RuntimeError> {
    Ok(host.win16_midi.wait_notification(timeout))
}

pub(super) fn midi_get_mixer_id(
    host: &mut WindowsHost,
    device: runtime::Win16HostMidiDevice,
    expected: runtime::Win16HostMidiDirection,
) -> Result<runtime::Win16HostMidiMixerId, RuntimeError> {
    Ok(host.win16_midi.get_mixer_id(device, expected))
}

pub(super) fn midi_close_all(
    host: &mut WindowsHost,
) -> Result<runtime::Win16HostMidiCloseAll, RuntimeError> {
    host.win16_midi.close_all()
}

pub(super) fn midi_finalize_closed_device(
    host: &mut WindowsHost,
    device: runtime::Win16HostMidiDevice,
) -> Result<bool, RuntimeError> {
    host.win16_midi.finalize_closed_device(device)
}

pub(super) fn media_time(
    host: &mut WindowsHost,
    operation: runtime::Win16HostMediaTimeOperation,
) -> Result<runtime::Win16HostMediaTimeResult, RuntimeError> {
    let sender = host.win16_callback_sender.clone();
    host.win16_media_services.execute_time(operation, &sender)
}

pub(super) fn media_io(
    host: &mut WindowsHost,
    operation: runtime::Win16HostMediaIoOperation,
) -> Result<runtime::Win16HostMediaIoResult, RuntimeError> {
    host.win16_media_services.execute_io(operation)
}
