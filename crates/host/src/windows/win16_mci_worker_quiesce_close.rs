use super::*;

pub(in crate::windows::win16_mci_owner::worker::worker_loop) fn close_all_devices(
    state: &WorkerThreadState,
) -> Result<(), RuntimeError> {
    native::ensure_no_active_yields_for_close(state, None)?;
    // Complete every fallible snapshot before the first native close. The
    // copied aliases and native IDs preserve retry ownership if later closes
    // return failures.
    let (identities, aliases, native_ids, registrations) = {
        let devices = state.devices.lock().unwrap_or_else(PoisonError::into_inner);
        (
            devices.snapshot()?,
            devices.orphan_alias_snapshot()?,
            devices.orphan_native_snapshot()?,
            devices.yield_registration_snapshot()?,
        )
    };
    let mut failures = Vec::new();
    failures
        .try_reserve_exact(
            identities
                .len()
                .saturating_add(aliases.len())
                .saturating_add(native_ids.len())
                .saturating_add(registrations.len()),
        )
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MCI shutdown close results",
                error,
            )
        })?;
    for owner in registrations {
        match native::disable_yield_registration(state, owner) {
            Ok(Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                observed_installed: false,
                ..
            }) => {}
            Ok(_) => failures.push(MciCloseFailure::Error(RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "MCI shutdown retains device {}:{} because its exact yield source remains installed",
                    owner.device.token, owner.device.generation
                ),
            ))),
            Err(error) => failures.push(MciCloseFailure::Error(error)),
        }
    }
    for (identity, native_id) in identities {
        if state.current_yield_registration(identity).is_some() {
            continue;
        }
        let result = native::close_native_device(native_id, state.sink);
        if result == 0 {
            state.retire_device(identity)?;
        } else {
            failures.push(MciCloseFailure::Device(identity, result));
        }
    }
    for alias in aliases {
        match native::close_string_alias(&alias, state.text_codec) {
            Ok(0) => state
                .devices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retire_orphan_alias(&alias),
            Ok(result) => failures.push(MciCloseFailure::Alias(alias, result)),
            Err(error) => failures.push(MciCloseFailure::Error(error)),
        }
    }
    for native_id in native_ids {
        let result = native::close_native_device(native_id, state.sink);
        if result == 0 {
            state
                .devices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retire_orphan_native_id(native_id);
        } else {
            failures.push(MciCloseFailure::NativeId(native_id, result));
        }
    }
    close_failure_result("close all retained MCI devices", failures)
}
