//! Reserved, non-executable Win16 identities for native shell operations.

use std::{error::Error, fmt};

use win16_abi::{SelectorRef, SelectorTable};

use super::{
    Win16State,
    module_registry::{ModuleRecord, ModuleState},
};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostProcess};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExternalApplicationKind {
    Activation,
    Association,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ExternalApplicationState {
    Pending(ExternalApplicationKind),
    ProcessStarted {
        process: Win16HostProcess,
    },
    /// Windows confirmed an activation but exposed no process identity.
    NativeActivationReceipt,
    /// FindExecutable resolved a file association; this is not an app process.
    AssociationIdentity {
        path: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub(super) struct ExternalApplicationRecord {
    pub(super) state: ExternalApplicationState,
    /// Unbacked descriptors reserve a unique WORD identity above Shell's
    /// error range. They carry no guest RAM and cannot be executed as code.
    pub(super) selector_reservations: Vec<ExternalSelectorReservation>,
}

/// Exact generation ledger. Successful frees are recorded immediately so a
/// retry never frees a reused selector or repeats a completed release.
#[derive(Clone, Copy, Debug)]
pub(super) struct ExternalSelectorReservation {
    reference: SelectorRef,
    released: bool,
}

// reserve_unbacked returns raw selectors as index << 3. ShellExecute errors
// occupy WORD values through 32, so at most four consecutive slots fall in
// that range; one additional slot is sufficient for a guest-success identity.
const SELECTOR_INDEX_SHIFT: u16 = 3;
const RAW_SELECTOR_STEP: u16 = 1 << SELECTOR_INDEX_SHIFT;
const SHELL_EXECUTE_ERROR_MAX: u16 = 32;
const SHELL_ERROR_SELECTOR_SLOTS: usize = (SHELL_EXECUTE_ERROR_MAX / RAW_SELECTOR_STEP) as usize;
const SHELL_IDENTITY_RESERVATION_CAPACITY: usize = SHELL_ERROR_SELECTOR_SLOTS + 1;

#[derive(Debug)]
struct SetupAndCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl fmt::Display for SetupAndCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; selector cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for SetupAndCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

impl ExternalApplicationRecord {
    pub(super) fn is_ready(&self) -> bool {
        !matches!(self.state, ExternalApplicationState::Pending(_))
    }

    pub(super) fn association_path(&self) -> Option<&[u8]> {
        match &self.state {
            ExternalApplicationState::AssociationIdentity { path } => Some(path),
            _ => None,
        }
    }
}

impl Win16State {
    /// Reserves a distinct >32 WORD identity and inserts its pending module
    /// record before a shell operation can cause native side effects.
    pub(super) fn reserve_external_application(
        &mut self,
        kind: ExternalApplicationKind,
    ) -> Result<u16, RuntimeError> {
        self.external_selector_cleanup
            .try_reserve(SHELL_IDENTITY_RESERVATION_CAPACITY)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve shell selector cleanup ledger",
                    error,
                )
            })?;
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(SHELL_IDENTITY_RESERVATION_CAPACITY)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 shell identity metadata",
                    error,
                )
            })?;
        let mut handle = None;
        for _ in 0..SHELL_IDENTITY_RESERVATION_CAPACITY {
            match self.selectors.reserve_unbacked() {
                Ok(reference) => {
                    let raw = reference.raw().0;
                    reservations.push(ExternalSelectorReservation {
                        reference,
                        released: false,
                    });
                    if raw > 32 {
                        handle = Some(raw);
                        break;
                    }
                }
                Err(error) => {
                    return Err(self.fail_external_reservation(
                        reservations,
                        None,
                        crate::runtime_error(error),
                    ));
                }
            }
        }
        let Some(handle) = handle else {
            return Err(self.fail_external_reservation(
                reservations,
                None,
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "no Win16 shell identity is available above the ShellExecute error range",
                ),
            ));
        };
        // The low selectors are temporary collision probes. Only the chosen
        // >32 selector belongs to the shell identity after reservation.
        if let Err(error) =
            release_selector_probes(&mut self.selectors, &mut reservations, Some(handle))
        {
            return Err(self.fail_external_reservation(reservations, Some(handle), error));
        }
        reservations.retain(|reservation| !reservation.released);
        if self.modules.records.contains_key(&handle) {
            return Err(self.fail_external_reservation(
                reservations,
                Some(handle),
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "reserved Win16 shell identity collides with a module record",
                ),
            ));
        }
        let record = ModuleRecord {
            handle,
            instance: handle,
            path: Vec::new(),
            name: Vec::new(),
            builtin: false,
            pinned: true,
            explicit_refs: 0,
            continuation_owner_refs: 0,
            state: ModuleState::Loading,
            deps: Vec::new(),
            definition: None,
            loaded: None,
            image: Vec::new(),
            allocations: Vec::new(),
            resources_retirement_deferred: false,
            builtin_data_selector: None,
            builtin_data_exports: None,
            wep_called: false,
            external_application: Some(ExternalApplicationRecord {
                state: ExternalApplicationState::Pending(kind),
                selector_reservations: reservations,
            }),
        };
        self.modules.records.insert(handle, record);
        Ok(handle)
    }

    pub(super) fn commit_external_application(
        &mut self,
        handle: u16,
        kind: ExternalApplicationKind,
        state: ExternalApplicationState,
    ) -> Result<(), RuntimeError> {
        if matches!(state, ExternalApplicationState::Pending(_)) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "cannot commit a pending Win16 shell identity",
            ));
        }
        let record = self.modules.records.get_mut(&handle).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "reserved Win16 shell module identity disappeared",
            )
        })?;
        let external = record.external_application.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "reserved Win16 shell identity lost its typed source",
            )
        })?;
        if external.state != ExternalApplicationState::Pending(kind) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 shell identity kind/state changed before commit",
            ));
        }
        if record.state != ModuleState::Loading {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 shell identity module changed state before commit",
            ));
        }
        let result_matches_kind = matches!(
            (&kind, &state),
            (
                ExternalApplicationKind::Activation,
                ExternalApplicationState::ProcessStarted { .. }
                    | ExternalApplicationState::NativeActivationReceipt
            ) | (
                ExternalApplicationKind::Association,
                ExternalApplicationState::AssociationIdentity { .. }
            )
        );
        if !result_matches_kind {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 shell identity result does not match its reserved operation kind",
            ));
        }
        external.state = state;
        record.state = ModuleState::Ready;
        Ok(())
    }

    pub(super) fn rollback_external_application(
        &mut self,
        handle: u16,
        kind: ExternalApplicationKind,
    ) -> Result<(), RuntimeError> {
        let record = self.modules.records.get(&handle).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "reserved Win16 shell identity disappeared before rollback",
            )
        })?;
        let Some(external) = record.external_application.as_ref() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "attempted to roll back a non-shell Win16 module",
            ));
        };
        if external.state != ExternalApplicationState::Pending(kind) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "attempted to roll back a shell identity with the wrong kind or state",
            ));
        }
        if record.state != ModuleState::Loading {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "attempted to roll back a shell identity outside its pending module state",
            ));
        }
        let (selectors, modules) = (&mut self.selectors, &mut self.modules);
        let external = modules
            .records
            .get_mut(&handle)
            .and_then(|record| record.external_application.as_mut())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "validated shell identity disappeared during rollback",
                )
            })?;
        release_selector_ledger(selectors, &mut external.selector_reservations, Some(handle))?;
        modules.records.remove(&handle).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "fully released Win16 shell identity disappeared",
            )
        })?;
        Ok(())
    }

    pub(super) fn external_application(&self, handle: u16) -> Option<&ExternalApplicationRecord> {
        self.modules
            .records
            .get(&handle)?
            .external_application
            .as_ref()
    }

    fn fail_external_reservation(
        &mut self,
        mut reservations: Vec<ExternalSelectorReservation>,
        keep_until_last: Option<u16>,
        primary: RuntimeError,
    ) -> RuntimeError {
        if let Err(cleanup) =
            release_selector_ledger(&mut self.selectors, &mut reservations, keep_until_last)
        {
            for reservation in reservations.into_iter().filter(|item| !item.released) {
                self.external_selector_cleanup.push(reservation);
            }
            RuntimeError::with_source(
                Kind::InternalInvariant,
                "Win16 shell identity setup failed and selector cleanup was incomplete",
                SetupAndCleanupFailure { primary, cleanup },
            )
        } else {
            primary
        }
    }
}

fn release_selector_ledger(
    selectors: &mut SelectorTable,
    reservations: &mut [ExternalSelectorReservation],
    keep_until_last: Option<u16>,
) -> Result<(), RuntimeError> {
    if let Some(identity) = keep_until_last {
        let identity_count = reservations
            .iter()
            .filter(|item| item.reference.raw().0 == identity && !item.released)
            .count();
        if identity_count != 1 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 shell selector ledger lost its unique live identity",
            ));
        }
    }
    release_selector_probes(selectors, reservations, keep_until_last)?;
    if let Some(identity) = keep_until_last {
        for reservation in reservations
            .iter_mut()
            .filter(|item| !item.released && item.reference.raw().0 == identity)
        {
            match selectors.free_selector(reservation.reference) {
                Ok(()) => reservation.released = true,
                Err(error) => {
                    return Err(RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "release Win16 shell identity selector",
                        error,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Release collision probes while retaining the selected alias selector.
/// This is distinct from rollback, which frees that identity last.
fn release_selector_probes(
    selectors: &mut SelectorTable,
    reservations: &mut [ExternalSelectorReservation],
    retained_identity: Option<u16>,
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    for reservation in reservations
        .iter_mut()
        .filter(|item| !item.released && Some(item.reference.raw().0) != retained_identity)
    {
        match selectors.free_selector(reservation.reference) {
            Ok(()) => reservation.released = true,
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "release reserved Win16 shell selector",
                        error,
                    ));
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(super) fn combine_rollback_failure(
    primary: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    RuntimeError::with_source(
        Kind::InternalInvariant,
        "Win16 shell result failed and reserved-identity rollback was incomplete",
        SetupAndCleanupFailure { primary, cleanup },
    )
}

pub(super) fn is_external_guest_identity(record: &ModuleRecord) -> bool {
    record
        .external_application
        .as_ref()
        .is_some_and(ExternalApplicationRecord::is_ready)
}

pub(super) fn report_external_identity_query(host: &mut impl RuntimeHost, api: &str, handle: u16) {
    host.report_diagnostic(&Diagnostic::warning(
        Kind::CompatibilityGap,
        format!(
            "Win16 {api} cannot resolve virtual native identity 0x{handle:04X} as a guest NE module"
        ),
    ));
}
