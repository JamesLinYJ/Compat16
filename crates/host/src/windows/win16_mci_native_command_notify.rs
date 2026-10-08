use super::*;

// Attach the shared owner source before submission; MM_MCINOTIFY has no command ID.
pub(super) fn reserve_command_notification(
    context: &MciNativeContext,
    message: u16,
    native_id: u32,
    parameters: &P,
    notification_window: runtime::Win16HostWindow,
    open_source_id: Option<u64>,
) -> Result<runtime::Win16HostMciNotificationId, RuntimeError> {
    let device = if message != MCI_OPEN_VALUE { target_device(parameters, native_id, context) } else { None };
    let route_native = (message != MCI_OPEN_VALUE && native_id != MCI_ALL_DEVICE_ID).then_some(native_id);
    let source_id = match (message == MCI_OPEN_VALUE, device) {
        (true, _) => open_source_id,
        (false, Some(device)) => Some(context.state.notification_source_id(device)?),
        (false, None) => {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "MCI_NOTIFY on an all-device or unresolved native target has no exact source generation",
            ));
        }
    };
    reserve_notification(context, route_native, device, notification_window, message == MCI_OPEN_VALUE, source_id)
}
