//! Process-owned fallback retirement for native WAVE handles.
//!
//! WinMM may retain WAVEHDR, sample, and callback-context addresses after a
//! failed reset, unprepare, or close. Each opened device reserves one registry
//! slot before WinMM can observe any of those addresses. The registry retries
//! cleanup only on the creating thread and keeps the full owner record while
//! native completion or callback quiescence is outstanding.

use super::*;
use std::error::Error;
use std::fmt;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

struct RetiredWaveDevice {
    device: WaveDevice,
    owner_thread: ThreadId,
    prior_failure: Option<RuntimeError>,
}

// SAFETY: native WinMM pointers are never dereferenced by a foreign thread.
// The mutex protects registry membership, each entry records its creating
// thread, and retry_current_thread removes matching entries before performing
// native calls on that thread. Callback code only uses its own synchronized
// owned context and never accesses this registry.
unsafe impl Send for RetiredWaveDevice {}

#[derive(Default)]
struct RetirementTable {
    devices: Vec<RetiredWaveDevice>,
    reservations: usize,
    retrying: usize,
}

static RETIRED: OnceLock<Mutex<RetirementTable>> = OnceLock::new();

pub(super) fn reserve_slot() -> Result<(), RuntimeError> {
    let mut table = lock_table();
    let current_len = table.devices.len();
    let required = current_len
        .checked_add(table.reservations)
        .and_then(|value| value.checked_add(table.retrying))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| wave_invariant("WAVE retirement owner count overflow"))?;
    if required > table.devices.capacity() {
        table
            .devices
            .try_reserve_exact(required - current_len)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve process-owned WAVE retirement slot",
                    error,
                )
            })?;
    }
    table.reservations = table
        .reservations
        .checked_add(1)
        .ok_or_else(|| wave_invariant("WAVE retirement reservation count overflow"))?;
    Ok(())
}

pub(super) fn release_reservation() -> Result<(), RuntimeError> {
    let mut table = lock_table();
    table.reservations = table
        .reservations
        .checked_sub(1)
        .ok_or_else(|| wave_invariant("WAVE retirement reservation was released twice"))?;
    Ok(())
}

pub(super) fn release_device_reservation(device: &mut WaveDevice) -> Result<(), RuntimeError> {
    if !device.retirement_slot_reserved {
        return Err(wave_invariant(
            "WAVE device lost its retirement reservation before close",
        ));
    }
    release_reservation()?;
    device.retirement_slot_reserved = false;
    Ok(())
}

pub(super) fn dispose_or_retain(device: WaveDevice) -> Result<(), RuntimeError> {
    let owner_thread = device.owner_thread.clone();
    retain(device, owner_thread, None);
    retry_current_thread()
}

pub(super) fn retain(
    mut device: WaveDevice,
    owner_thread: ThreadId,
    prior_failure: Option<RuntimeError>,
) {
    debug_assert!(device.retirement_slot_reserved);
    device.retirement_slot_reserved = false;
    let mut table = lock_table();
    debug_assert!(table.reservations != 0);
    table.reservations -= 1;
    // Capacity was reserved before OPEN; moving this device into the table
    // cannot allocate while preserving pointers WinMM may still hold.
    table.devices.push(RetiredWaveDevice {
        device,
        owner_thread,
        prior_failure,
    });
}

pub(super) fn retry_current_thread() -> Result<(), RuntimeError> {
    let current_thread = thread::current().id();
    let (mut work, mut retained, mut failures, count) = {
        let mut table = lock_table();
        let count = table
            .devices
            .iter()
            .filter(|entry| entry.owner_thread == current_thread)
            .count();
        if count == 0 {
            return Ok(());
        }
        let retrying = table
            .retrying
            .checked_add(count)
            .ok_or_else(|| wave_invariant("WAVE retirement retry count overflow"))?;
        let mut work = Vec::new();
        work.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE retirement retry snapshot",
                error,
            )
        })?;
        let mut retained = Vec::new();
        retained.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE retirement retry results",
                error,
            )
        })?;
        let mut failures = Vec::new();
        let failure_capacity = count
            .checked_mul(2)
            .ok_or_else(|| wave_invariant("WAVE cleanup failure count overflow"))?;
        failures
            .try_reserve_exact(failure_capacity)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve typed WAVE cleanup causes",
                    error,
                )
            })?;
        let mut index = 0;
        while index < table.devices.len() {
            if table.devices[index].owner_thread == current_thread {
                work.push(table.devices.swap_remove(index));
            } else {
                index += 1;
            }
        }
        table.retrying = retrying;
        (work, retained, failures, count)
    };

    for mut entry in work.drain(..) {
        let previous_failure = entry.prior_failure.take();
        match attempt_cleanup(&mut entry.device) {
            Ok(true) => {
                if let Some(previous) = previous_failure {
                    failures.push(previous);
                }
            }
            Ok(false) => {
                if let Some(previous) = previous_failure {
                    failures.push(previous);
                }
                // A bounded wait is only a reaper poll. Preserve this owner
                // for a later retry without turning an ordinary pending
                // callback into a fatal task-cleanup result.
                retained.push(entry);
            }
            Err(error) => {
                if let Some(previous) = previous_failure {
                    failures.push(previous);
                }
                failures.push(error);
                retained.push(entry);
            }
        }
    }

    {
        let mut table = lock_table();
        debug_assert!(table.retrying >= count);
        table.retrying -= count;
        table.devices.extend(retained);
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(aggregate_failures(
            "one or more retained WAVE owners still require cleanup",
            failures,
        ))
    }
}

pub(super) fn barrier_current_thread() -> Result<(), RuntimeError> {
    let current_thread = thread::current().id();
    retry_current_thread()?;
    let table = lock_table();
    let remaining = table
        .devices
        .iter()
        .filter(|entry| entry.owner_thread == current_thread)
        .count();
    if remaining == 0 {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::HostFailure,
            format!(
                "current WAVE owner thread still has {remaining} process-retained native owner(s)",
            ),
        ))
    }
}

fn attempt_cleanup(device: &mut WaveDevice) -> Result<bool, RuntimeError> {
    if !device.native_closed {
        if let Some(callback) = device.callback.as_ref() {
            if callback.active_callbacks() != 0 {
                callback.wait_for_change(Duration::from_millis(25));
                if callback.active_callbacks() != 0 {
                    return Ok(false);
                }
            }
        }

        let result = unsafe { native::reset_native(device.direction, &device.native) };
        if result != MMSYSERR_NOERROR {
            return Err(wave_result_error("reset retained WAVE device", result));
        }
        for buffer in &mut device.buffers {
            if !buffer.prepared {
                continue;
            }
            let header = ptr::addr_of_mut!(buffer.storage.header);
            let result =
                unsafe { native::unprepare_native(device.direction, &device.native, header) };
            if result != MMSYSERR_NOERROR {
                return Err(wave_result_error("unprepare retained WAVE header", result));
            }
            buffer.prepared = false;
            buffer.in_flight = false;
        }
        let result = unsafe { native::close_native(&device.native) };
        if result != MMSYSERR_NOERROR {
            return Err(wave_result_error("close retained WAVE device", result));
        }
        device.native_closed = true;
        device.closing = true;
    }

    if device.buffers.iter().any(|buffer| buffer.prepared) {
        return Err(wave_invariant(
            "WinMM closed a WAVE device while a native header remained prepared",
        ));
    }
    if let Some(callback) = device.callback.as_ref() {
        if callback.active_callbacks() != 0 || !callback.close_seen() {
            callback.wait_for_change(Duration::from_millis(25));
            if callback.active_callbacks() != 0 || !callback.close_seen() {
                return Ok(false);
            }
        }
        for buffer in &device.buffers {
            callback.unregister_header(ptr::addr_of!(buffer.storage.header) as usize);
        }
    }
    Ok(true)
}

impl Win16WaveHost {
    pub(in crate::windows) fn retired_owner_barrier(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let current_thread = thread::current().id();
        let mut failures = Vec::new();
        failures.try_reserve_exact(3).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve WAVE/SOUND producer-barrier failures",
                error,
            )
        })?;
        if let Some(device) = self
            .devices
            .iter()
            .find(|device| device.owner_thread == current_thread)
        {
            failures.push(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "WAVE producer barrier still has live host owner {:?} on its creating thread",
                    device.token,
                ),
            ));
        }
        if let Err(error) = super::sound::producer_barrier(self) {
            failures.push(error.with_context("retire current-thread SOUND PlaySound owner"));
        }
        if let Err(error) = barrier_current_thread() {
            failures.push(error.with_context("retire current-thread WAVE process owners"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(aggregate_failures(
                "WAVE/SOUND producer owners remain at the teardown barrier",
                failures,
            ))
        }
    }
}

pub(super) fn aggregate_failures(
    message: &'static str,
    failures: Vec<RuntimeError>,
) -> RuntimeError {
    let kind = super::cleanup_failures_kind(&failures);
    RuntimeError::with_source(kind, message, WaveCleanupFailures(failures))
}

pub(super) fn wave_result_error(operation: &'static str, result: u32) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        format!("{operation} returned MMRESULT {result}"),
        WaveMmResult(result),
    )
}

pub(super) fn operation_and_cleanup_error(
    operation: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    let kind = super::cleanup_failure_kind(operation.kind(), cleanup.kind());
    RuntimeError::with_source(
        kind,
        "a native WAVE operation failed and its owner cleanup also failed",
        WaveOperationCleanupFailure { operation, cleanup },
    )
}

#[derive(Debug)]
struct WaveMmResult(u32);

impl fmt::Display for WaveMmResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Windows multimedia MMRESULT {}", self.0)
    }
}

impl Error for WaveMmResult {}

#[derive(Debug)]
struct WaveOperationCleanupFailure {
    operation: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for WaveOperationCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}; cleanup: {}", self.operation, self.cleanup)
    }
}

impl Error for WaveOperationCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.operation)
    }
}

#[derive(Debug)]
struct WaveCleanupFailures(Vec<RuntimeError>);

impl fmt::Display for WaveCleanupFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl Error for WaveCleanupFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.first().map(|error| error as &(dyn Error + 'static))
    }
}

fn lock_table() -> MutexGuard<'static, RetirementTable> {
    RETIRED
        .get_or_init(|| Mutex::new(RetirementTable::default()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn wave_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
