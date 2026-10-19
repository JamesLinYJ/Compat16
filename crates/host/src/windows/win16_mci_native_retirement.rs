use super::super::ACTIVE_YIELDS;
use super::*;

pub(super) fn bind_open_notification(
    context: &MciNativeContext,
    notification: runtime::Win16HostMciNotificationId,
    native: u32,
    device: runtime::Win16HostMciDevice,
    source_id: Option<u64>,
) -> Result<(), RuntimeError> {
    let source_id = source_id.ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "MCI OPEN notification lost its pre-reserved shared source ID",
        )
    })?;
    context
        .state
        .notifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .bind_open_notification(notification, native, device, source_id)
}

// Pin device notification sources before native callbacks can outlive registry entries.
pub(super) fn reserve_device_notification(
    context: &MciNativeContext,
    native: u32,
    device: runtime::Win16HostMciDevice,
    target: runtime::Win16HostWindow,
) -> Result<runtime::Win16HostMciNotificationId, RuntimeError> {
    let source_id = context.state.notification_source_id(device)?;
    super::reserve_notification(
        context,
        Some(native),
        Some(device),
        target,
        false,
        Some(source_id),
    )
}

pub(super) fn string_notification_source_id(
    context: &MciNativeContext,
    notify: bool,
    allow_new_device: bool,
    open_source_id: Option<u64>,
    device: Option<runtime::Win16HostMciDevice>,
) -> Result<Option<u64>, RuntimeError> {
    if !notify || allow_new_device {
        return Ok(if notify { open_source_id } else { None });
    }
    let Some(device) = device else {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "MCI string NOTIFY has no exact native device generation and shared source owner",
        ));
    };
    Ok(Some(context.state.notification_source_id(device)?))
}

pub(super) fn disable_yield_sources_for_close(
    state: &WorkerThreadState,
    device: Option<runtime::Win16HostMciDevice>,
) -> Result<(), RuntimeError> {
    ensure_no_active_yields_for_close(state, device)?;
    let (registrations, devices) = {
        let registry = state
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut registrations = Vec::new();
        let mut devices = Vec::new();
        if let Some(device) = device {
            registrations.try_reserve_exact(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI close yield-source owner",
                    error,
                )
            })?;
            devices.try_reserve_exact(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI close device snapshot",
                    error,
                )
            })?;
            let Some((native_id, _)) = registry.resolve(device) else {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "MCI close yield-source preflight references an unknown device generation",
                ));
            };
            devices.push((device, native_id));
            if let Some(registration) = registry.current_yield_registration(device) {
                registrations.push(Win16HostMciYieldRegistration {
                    device,
                    registration,
                });
            }
        } else {
            registrations = registry.yield_registration_snapshot()?;
            devices = registry.snapshot()?;
        }
        (registrations, devices)
    };
    for (device, native_id) in &devices {
        if registrations.iter().any(|owner| owner.device == *device) {
            continue;
        }
        let mut native_data = 0_u32;
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        match unsafe { mciGetYieldProc(*native_id, &mut native_data) } {
            Some(proc) if proc as usize == mci_yield_proc as *const () as usize => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!(
                        "MCI device {}:{} has the runtime yield thunk without an exact registration generation",
                        device.token, device.generation
                    ),
                ));
            }
            _ => {}
        }
    }
    state.reserve_yield_source_evidence_batch(&registrations)?;
    for owner in registrations {
        match yield_source::disable_yield_registration(state, owner)? {
            Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                observed_installed: false,
                ..
            } => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    format!(
                        "MCI close cannot retire device {}:{} while its exact yield source remains installed",
                        owner.device.token, owner.device.generation
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub(in crate::windows::win16_mci_owner::worker) fn ensure_no_active_yields_for_close(
    _state: &WorkerThreadState,
    device: Option<runtime::Win16HostMciDevice>,
) -> Result<(), RuntimeError> {
    let active = ACTIVE_YIELDS.with(|entries| {
        entries.borrow().iter().rev().find_map(|entry| {
            entry
                .active_yield
                .filter(|owner| device.is_none_or(|device| owner.device == device))
        })
    });
    if let Some(owner) = active {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            format!(
                "MCI close retains device {}:{} while operation {} frame {} is awaiting its exact guest WORD and native resume ACK",
                owner.device.token, owner.device.generation, owner.operation.0, owner.frame.0
            ),
        ));
    }
    Ok(())
}

pub(super) fn device_lookup(
    context: &MciNativeContext,
    native: u32,
) -> Result<Win16HostMciResult, RuntimeError> {
    if native == u32::MAX {
        return Ok(Win16HostMciResult {
            return_value: 0,
            output: Win16HostMciOutput::All,
        });
    }
    if native == 0 {
        return Ok(Win16HostMciResult {
            return_value: 0,
            output: Win16HostMciOutput::None,
        });
    }
    let device_type = query_device_type(native);
    let device = context.state.register_device(native, device_type, None)?;
    Ok(Win16HostMciResult {
        return_value: 0,
        output: Win16HostMciOutput::Device {
            device,
            device_type,
        },
    })
}

pub(super) fn query_device_type(native: u32) -> Option<u32> {
    let mut parameters = MCI_GETDEVCAPS_PARMS {
        dwItem: MCI_GETDEVCAPS_DEVICE_TYPE as u32,
        ..Default::default()
    };
    // SAFETY: mciSendCommandW receives an integer device id. A null parameter pointer carries no record; a non-null record stays live for the call.
    let result = unsafe {
        mciSendCommandW(
            native,
            MCI_GETDEVCAPS,
            MCI_GETDEVCAPS_ITEM as usize,
            (&mut parameters as *mut MCI_GETDEVCAPS_PARMS).cast::<c_void>() as usize,
        )
    };
    (result == 0).then_some(parameters.dwReturn)
}
// Keep rollback classification aligned with the runtime's typed cleanup rule.
// Two ordinary failures do not become an invariant merely because both occur.
pub(in crate::windows) fn classify_mci_cleanup(primary: Kind, cleanup: Option<Kind>) -> Kind {
    match (primary, cleanup) {
        (Kind::InternalInvariant, _) | (_, Some(Kind::InternalInvariant)) => {
            Kind::InternalInvariant
        }
        (Kind::ExecutionLimit, Some(additional)) => additional,
        (primary, _) => primary,
    }
}
