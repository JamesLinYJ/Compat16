//! Staging and commit helpers for a DLL whose LibMain returned FALSE.

use super::module_registry::ModuleState;
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone, Copy)]
pub(super) struct ModuleStateSnapshot {
    pub(super) handle: u16,
    pub(super) state: ModuleState,
    pub(super) wep_called: bool,
}

impl Win16State {
    pub(super) fn snapshot_module_states(
        &self,
        modules: &[u16],
    ) -> Result<Vec<ModuleStateSnapshot>, RuntimeError> {
        let mut snapshots = Vec::new();
        snapshots.try_reserve_exact(modules.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 module rollback state snapshot",
                error,
            )
        })?;
        for &handle in modules {
            let record = self.modules.records.get(&handle).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL initialization lost a created module",
                )
            })?;
            snapshots.push(ModuleStateSnapshot {
                handle,
                state: record.state,
                wep_called: record.wep_called,
            });
        }
        Ok(snapshots)
    }

    pub(super) fn stage_failed_load_retirement(
        &mut self,
        snapshots: &[ModuleStateSnapshot],
    ) -> Result<(), RuntimeError> {
        for snapshot in snapshots {
            if snapshot.state == ModuleState::Ready {
                continue;
            }
            let record = self.modules.records.get_mut(&snapshot.handle).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL initialization lost a staged module",
                )
            })?;
            record.state = ModuleState::Retired;
            record.wep_called = true;
        }
        Ok(())
    }

    pub(super) fn restore_module_states(
        &mut self,
        snapshots: &[ModuleStateSnapshot],
    ) -> Result<(), RuntimeError> {
        for snapshot in snapshots {
            let record = self.modules.records.get_mut(&snapshot.handle).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 module disappeared while rolling back staged retirement",
                )
            })?;
            record.state = snapshot.state;
            record.wep_called = snapshot.wep_called;
        }
        Ok(())
    }

    pub(super) fn restore_module_states_after_failure(
        &mut self,
        snapshots: &[ModuleStateSnapshot],
        failure: RuntimeError,
    ) -> RuntimeError {
        match self.restore_module_states(snapshots) {
            Ok(()) => failure,
            Err(restore) => failure.with_cleanup(
                "Win16 DLL rollback retained its primary failure and state restoration failure",
                restore,
            ),
        }
    }

    pub(super) fn commit_failed_load_retirement(
        &mut self,
        snapshots: &[ModuleStateSnapshot],
        unloading: &[u16],
    ) -> Result<(), RuntimeError> {
        for snapshot in snapshots {
            if !self.modules.records.contains_key(&snapshot.handle) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL initialization lost a staged module before commit",
                ));
            }
        }
        for &handle in unloading {
            if !self.modules.records.contains_key(&handle) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL rollback lost an unload candidate before commit",
                ));
            }
        }
        for snapshot in snapshots {
            if snapshot.state != ModuleState::Ready {
                let record = self.modules.records.get_mut(&snapshot.handle).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "failed Win16 DLL initialization lost a staged module during commit",
                    )
                })?;
                record.state = ModuleState::Retired;
                record.wep_called = true;
            }
        }
        for &handle in unloading {
            let record = self.modules.records.get_mut(&handle).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL rollback lost an unload candidate during commit",
                )
            })?;
            record.state = ModuleState::Unloading;
        }
        Ok(())
    }
}
