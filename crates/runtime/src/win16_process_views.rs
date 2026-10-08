//! Ownership of protected process metadata and its DOS-backed storage.

use dos_kernel::{DosBlockLease, DosKernel};
use guest_core::memory::Memory;
use win16_abi::{SelectorRef, SelectorTable};

use super::pdb::Win16Pdb;
use crate::win16_host_compat::Win16CompatState;
use crate::{DiagnosticKind as Kind, RuntimeError};

/// Loader-created real-mode addresses. None of these words is a selector.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Win16ProcessBootstrap {
    pub(crate) canonical_psp: u16,
    pub(crate) environment_segment: u16,
    pub(crate) environment_logical_bytes: usize,
}

#[derive(Debug)]
pub(super) struct Win16ProcessViews {
    pdb: Win16Pdb,
    environment_lease: Option<DosBlockLease>,
    canonical_psp: u16,
}

impl Win16ProcessViews {
    pub(super) fn create(
        dos: &mut DosKernel,
        selectors: &mut SelectorTable,
        bootstrap: Win16ProcessBootstrap,
        memory: &mut Memory,
    ) -> Result<(Self, Win16CompatState), RuntimeError> {
        let environment_lease = dos.pin_owned_block(
            memory, bootstrap.environment_segment, bootstrap.canonical_psp,
        ).map_err(crate::runtime_error)?.ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 process environment has no owned DOS allocation",
        ))?;
        let mut compat = match Win16CompatState::load(
            selectors, environment_lease.extent(), bootstrap.environment_logical_bytes, memory,
        ) {
            Ok(compat) => compat,
            Err(error) => {
                selectors.invalidate_all();
                return Err(rollback_error(error, dos.release_block_lease(
                    memory, &environment_lease, false,
                ).map_err(crate::runtime_error)));
            }
        };
        let pdb = match Win16Pdb::create(
            dos, selectors, bootstrap.canonical_psp, compat.environment_selector(), memory,
        ) {
            Ok(pdb) => pdb,
            Err(error) => {
                // No guest or host callback has seen this table yet. Retiring
                // every descriptor also covers aliases created during loading.
                selectors.invalidate_all();
                return Err(rollback_error(error, dos.release_block_lease(
                    memory, &environment_lease, false,
                ).map_err(crate::runtime_error)));
            }
        };
        compat.bind_pdb(pdb.selector());
        Ok((Self {
            pdb, environment_lease: Some(environment_lease),
            canonical_psp: bootstrap.canonical_psp,
        }, compat))
    }

    pub(super) fn selector(&self) -> SelectorRef { self.pdb.selector() }

    /// End the guest address space after all native windows and callbacks have
    /// closed. Explicit release needs the shared GuestMemory bus; a Drop impl
    /// cannot safely mutate that separately owned storage.
    pub(super) fn release(
        &mut self,
        dos: &mut DosKernel,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        selectors.invalidate_all();
        self.pdb.release_after_selector_teardown(dos, memory)?;
        if let Some(lease) = self.environment_lease.as_ref() {
            dos.release_block_lease(memory, lease, false).map_err(crate::runtime_error)?;
            self.environment_lease = None;
        }
        dos.free_process_blocks(memory, self.canonical_psp).map_err(crate::runtime_error)
    }
}

pub(super) fn rollback_error(
    operation: RuntimeError,
    cleanup: Result<(), RuntimeError>,
) -> RuntimeError {
    match cleanup {
        Ok(()) => operation,
        Err(cleanup) => RuntimeError::with_source(Kind::InternalInvariant,
            "Win16 process-view rollback failed", ProcessViewRollback { operation, cleanup }),
    }
}

#[derive(Debug)]
struct ProcessViewRollback { operation: RuntimeError, cleanup: RuntimeError }

impl std::fmt::Display for ProcessViewRollback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup failed: {}", self.operation, self.cleanup)
    }
}

impl std::error::Error for ProcessViewRollback {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.operation) }
}
