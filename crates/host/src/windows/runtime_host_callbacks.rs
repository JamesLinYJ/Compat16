//! Runtime callback-channel projection for WindowsHost.

use super::*;

pub(super) fn take_guest_callback(
    host: &mut WindowsHost,
) -> Result<Option<runtime::Win16GuestCallbackEvent>, RuntimeError> {
    match host.win16_callback_receiver.try_recv() {
        Ok(event) => Ok(Some(event)),
        Err(runtime::Win16GuestCallbackPoll::Empty) => Ok(None),
        Err(runtime::Win16GuestCallbackPoll::Closed) => Err(RuntimeError::new(
            Kind::HostFailure,
            "Win16 native callback event channel closed",
        )),
    }
}
