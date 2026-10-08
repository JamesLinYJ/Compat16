//! Process-view cleanup after runtime-owned guest producers are quiescent.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(super) fn release_process_views(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if !self.com_owner_guest_state_retired() {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::HostFailure,
                "Win16 process-view retirement is blocked by an unretired exact COM owner",
            ));
        }
        if !self.legacy_cpu_frames.is_empty() {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "Win16 process-view retirement is blocked by live legacy CPU frame owners",
            ));
        }
        // An active frame may still execute through an arena selector-map
        // identity. Refuse before alias cleanup can invalidate any view.
        self.runtime_arena_backing.ensure_no_frame_leases()?;
        // Process exit ends runtime-owned selector views. Retire those exact
        // generations before releasing their DOS primary blocks; unknown or
        // externally retained views still make GlobalDOSFree return busy.
        self.release_all_selector_backing(dos, memory)?;
        self.retry_retained_callback_buffers()?;
        // OLE proxy rollback handles use a subsystem owner rather than a task
        // owner. Retry exact handles only after selector aliases and callback
        // buffers retire, and keep process selectors alive if any remain pinned.
        self.retry_native_object_proxy_retirements()?;
        self.retry_pending_ole1_proxy_retirements()?;

        let mut dos_handles = Vec::new();
        dos_handles.try_reserve_exact(self.dos_global_blocks.len()).map_err(|error| {
            RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve Win16 process DOS-block teardown snapshot",
                error,
            )
        })?;
        dos_handles.extend(self.dos_global_blocks.keys().copied());
        for handle in dos_handles {
            if self.kernel_global_dos_free(handle, dos, memory)? != 0 {
                return Err(RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                    "Win16 process teardown is deferred while a GlobalDOSAlloc view remains busy"));
            }
        }
        // Failed GlobalDOSAlloc rollback leases belong to real MCB extents.
        // Release each token before ProcessViews frees the process arena, and
        // keep it in the owner vector until the release is confirmed.
        let orphan_index = 0;
        while orphan_index < self.orphaned_dos_leases.len() {
            let release = dos.release_block_lease(
                memory, &self.orphaned_dos_leases[orphan_index], false,
            );
            match release {
                Ok(()) => { self.orphaned_dos_leases.remove(orphan_index); }
                Err(error) => return Err(crate::runtime_error(error)
                    .with_context("releasing a retained DOS rollback lease before process MCB teardown")),
            }
        }
        // Retire exact registered chunks only after alias, DOS, and frame
        // owners are clear; the physical reservation remains in Runtime.
        self.runtime_arena_backing.retire_before_selector_teardown(
            &self.selectors, memory,
        )?;
        let result = self.process_views.release(dos, &mut self.selectors, memory);
        // ProcessViews::release invalidates the complete selector table before
        // releasing any DOS backing. These runtime-owned identities share that
        // address-space lifetime and must not retain stale generations.
        self.runtime_selector_aliases.retire();
        self.allocated_selector_aliases.clear();
        self.api_allocated_selectors.clear();
        self.mapls_selectors.clear();
        self.mapls_bases.clear();
        result?;
        Ok(())
    }
}
