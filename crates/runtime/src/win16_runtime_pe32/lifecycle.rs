//! Guest call entry, unload order and retained rollback recovery.

use std::{error::Error, fmt};

use guest_core::memory::Memory;
use x86_cpu::Cpu;

use crate::pe32_call::begin_pe32_call;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win32HostImportCall, Win32HostImportValue,
    pe32::{Pe32CallCompletion, Pe32CallLease, Pe32LoadRecovery},
};

use super::lifecycle_errors::cancel_prepared;
use super::{Pe32ThunkDispatcher, aggregate_errors, environment};

#[path = "lifecycle/call_execution.rs"]
mod call_execution;
#[path = "lifecycle/free_library.rs"]
mod free_library;
#[path = "lifecycle/group_retirement.rs"]
mod group_retirement;
#[path = "lifecycle/import_cleanup.rs"]
mod import_cleanup;

impl Pe32ThunkDispatcher {
    pub(super) fn execute_lease(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        lease: Pe32CallLease,
        step_limit: u64,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let budget_owner = match self.begin_budget(step_limit) {
            Ok(owner) => owner,
            Err(primary) => return Err(cancel_prepared(&mut self.registry, &lease, primary)),
        };
        let result = self.execute_lease_inner(cpu, memory, imports, host, lease, step_limit);
        self.finish_budget(budget_owner);
        result
    }

    fn execute_lease_inner(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        lease: Pe32CallLease,
        step_limit: u64,
    ) -> Result<Pe32CallCompletion, RuntimeError> {
        let module_owner = lease.module();
        if !self.retained_frames.is_empty() {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 dispatcher has an unfinished CPU-context restoration",
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        if self
            .active
            .last()
            .is_some_and(|active| !active.paused_at_service)
        {
            let primary = RuntimeError::new(
                Kind::CompatibilityGap,
                "PE32 nested guest entry lacks an owned paused service boundary",
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        if self.active.len() >= super::MAX_PE32_NESTED_CALL_DEPTH {
            let primary = RuntimeError::new(
                Kind::ExecutionLimit,
                "PE32 nested service call depth limit was reached",
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        if step_limit == 0
            || self
                .active_budget
                .is_some_and(|budget| budget.used >= budget.limit)
        {
            let primary = RuntimeError::new(
                Kind::ExecutionLimit,
                "PE32 call has no remaining CPU boundary budget",
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        if let Err(error) = self.active.try_reserve(1) {
            let primary = RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve nested PE32 call frame",
                error,
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        if let Err(error) = self
            .retained_frames
            .try_reserve(self.active.len().saturating_add(1))
        {
            let primary = RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 context-retention capacity",
                error,
            );
            return Err(cancel_prepared(&mut self.registry, &lease, primary));
        }
        let stack_top = match self.next_stack_top(cpu) {
            Ok(top) => top,
            Err(primary) => return Err(cancel_prepared(&mut self.registry, &lease, primary)),
        };
        let environment =
            match environment::for_call(self, imports, memory, stack_top, module_owner) {
                Ok(environment) => environment,
                Err(primary) => return Err(cancel_prepared(&mut self.registry, &lease, primary)),
            };
        let frame = begin_pe32_call(&mut self.registry, cpu, memory, lease, environment)?;
        self.execute_frame(cpu, memory, imports, host, frame, stack_top, module_owner)
    }

    pub(super) fn drain_retiring(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        step_limit: u64,
        dispatch_start: u64,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        let mut blocked_detach = None;
        let _ = self.registry.collect_retiring();
        loop {
            let remaining = self.remaining_steps(dispatch_start, step_limit);
            let next_detach = match self.registry.next_process_detach() {
                Ok(Some(lease)) => Some(lease),
                Ok(None) => match self.next_group_process_detach() {
                    Ok(lease) => lease,
                    Err(error) => {
                        keep_first(&mut first_error, error);
                        break;
                    }
                },
                Err(error) => {
                    keep_first(&mut first_error, error);
                    break;
                }
            };
            if let Some(lease) = next_detach {
                let module = lease.module().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "PE32 detach lease has no module identity",
                    )
                })?;
                if blocked_detach == Some(module) {
                    if let Err(error) = self.registry.cancel_prepared_call(&lease) {
                        keep_first(&mut first_error, error);
                    }
                    break;
                }
                let lease_id = lease.id();
                match self.execute_lease(cpu, memory, imports, host, lease, remaining) {
                    Err(error) => {
                        // A returned guest fault still runs frame
                        // finalization; retain the image only when the
                        // registry says execution is unfinished.
                        if self.registry.lease_state(lease_id)
                            != Some(crate::pe32::Pe32CallLeaseState::Retired)
                            && let Some(index) = self.module_index(module)
                        {
                            self.modules[index].quarantined = true;
                        }
                        blocked_detach = Some(module);
                        keep_first(&mut first_error, error);
                    }
                    Ok(Pe32CallCompletion::ProcessDetached) => {
                        if let Some(index) = self.module_index(module) {
                            self.modules[index].quarantined = false;
                        }
                    }
                    Ok(_) => {
                        keep_first(
                            &mut first_error,
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "PE32 detach lease returned a non-detach completion",
                            ),
                        );
                        if let Some(index) = self.module_index(module) {
                            self.modules[index].quarantined = true;
                        }
                    }
                }
                if self.registry.lease_state(lease_id)
                    == Some(crate::pe32::Pe32CallLeaseState::Prepared)
                {
                    break;
                }
                continue;
            }

            // A cycle is safe to break only after every member's required
            // detach returned; then recompute release receipts from the graph.
            let mut progressed = match self.clear_retired_load_group_edges() {
                Ok(cleared) => cleared,
                Err(error) => {
                    keep_first(&mut first_error, error);
                    false
                }
            };
            let ready = self.registry.collect_retiring();
            for receipt in ready {
                if self.modules.iter().any(|module| {
                    module.transaction.module() == receipt.module() && module.quarantined
                }) {
                    continue;
                }
                if let Some(index) = self.module_index(receipt.module()) {
                    let handle = self.modules[index].handle;
                    let result = if handle.is_some() {
                        self.modules[index].transaction.complete_unload(
                            &mut self.registry,
                            &mut self.arena,
                            receipt,
                        )
                    } else {
                        self.modules[index]
                            .transaction
                            .abort_unpublished(&mut self.registry, &mut self.arena)
                    };
                    match result {
                        Ok(()) => {
                            self.modules[index].image_released = true;
                            progressed = true;
                            if let Err(error) = self.finish_module_retirement(index, imports, host)
                            {
                                keep_first(&mut first_error, error);
                            }
                        }
                        Err(error) => {
                            self.modules[index].pending_retirement = Some(receipt);
                            keep_first(&mut first_error, error);
                        }
                    }
                    continue;
                }
                if let Some(index) = self.recovery_module_index(receipt.module()) {
                    let recovery = self.recoveries.swap_remove(index);
                    let Pe32LoadRecovery::Module(mut transaction) = recovery else {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "PE32 recovery owner changed variant",
                        ));
                    };
                    match transaction.abort_unpublished(&mut self.registry, &mut self.arena) {
                        Ok(()) => {
                            self.remove_group_identity(receipt.module());
                            progressed = true;
                        }
                        Err(error) => {
                            self.recoveries.push(Pe32LoadRecovery::Module(transaction));
                            keep_first(&mut first_error, error);
                        }
                    }
                }
            }

            if !progressed {
                break;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn retry_pending_releases(
        &mut self,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        let mut index = 0;
        while index < self.modules.len() {
            if self.modules[index].image_released {
                match self.finish_module_retirement(index, imports, host) {
                    Ok(true) => {}
                    Ok(false) => index += 1,
                    Err(error) => {
                        keep_first(&mut first_error, error);
                        index += 1;
                    }
                }
                continue;
            }
            let Some(receipt) = self.modules[index].pending_retirement else {
                if self.modules[index].handle.is_none() {
                    let result = self.modules[index]
                        .transaction
                        .abort_unpublished(&mut self.registry, &mut self.arena);
                    match result {
                        Ok(()) => {
                            self.modules[index].image_released = true;
                            if let Err(error) = self.finish_module_retirement(index, imports, host)
                            {
                                keep_first(&mut first_error, error);
                                index += 1;
                            }
                        }
                        Err(error) => {
                            keep_first(&mut first_error, error);
                            index += 1;
                        }
                    }
                } else {
                    index += 1;
                }
                continue;
            };
            match self.modules[index].transaction.complete_unload(
                &mut self.registry,
                &mut self.arena,
                receipt,
            ) {
                Ok(()) => {
                    self.modules[index].image_released = true;
                    if let Err(error) = self.finish_module_retirement(index, imports, host) {
                        keep_first(&mut first_error, error);
                        index += 1;
                    }
                }
                Err(error) => {
                    keep_first(&mut first_error, error);
                    index += 1;
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn retire_all(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
        step_limit: u64,
    ) -> Result<(), RuntimeError> {
        if self.has_active_call() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 teardown began with an active guest call",
            ));
        }
        if !self.retired {
            self.registry.begin_teardown()?;
            self.retired = true;
        }
        let start = self.budget_position();
        let mut first_error = None;
        if let Err(error) = self.drain_retiring(cpu, memory, imports, host, step_limit, start) {
            keep_first(&mut first_error, error);
        }
        if let Err(error) = self.retry_pending_releases(imports, host) {
            keep_first(&mut first_error, error);
        }
        if let Err(error) = self.retire_recoveries() {
            keep_first(&mut first_error, error);
        }
        if let Err(error) = self.retry_load_group_provider_releases(imports, host) {
            keep_first(&mut first_error, error);
        }
        if self
            .active_load_group
            .as_ref()
            .is_some_and(|group| group.members.is_empty() && group.temporary_providers.is_empty())
        {
            self.active_load_group = None;
        }
        if self.modules.is_empty() && self.recoveries.is_empty() && self.active_load_group.is_none()
        {
            if let Err(error) = self.retire_import_resources(imports, host) {
                keep_first(&mut first_error, error);
            }
            if !self.support_released {
                if let Err(error) = self.arena.release_unbound(&self.support) {
                    keep_first(&mut first_error, error);
                } else {
                    self.support_released = true;
                }
            }
        } else {
            keep_first(
                &mut first_error,
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "PE32 task teardown retained a module, group provider, or recovery lease",
                ),
            );
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn retire_recoveries(&mut self) -> Result<(), RuntimeError> {
        let mut first_error = None;
        // Work backward over the initial set. Failed owners are appended to
        // the retained tail and must not be retried in this same cleanup pass.
        let mut remaining = self.recoveries.len();
        while remaining != 0 {
            remaining -= 1;
            let index = remaining;
            let recovery = self.recoveries.swap_remove(index);
            let result = match recovery {
                Pe32LoadRecovery::Unbound(lease) => match self.arena.release_unbound(&lease) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        self.recoveries.push(Pe32LoadRecovery::Unbound(lease));
                        Err(error)
                    }
                },
                Pe32LoadRecovery::Module(mut transaction) => {
                    let identity = transaction.module();
                    match transaction.abort_unpublished(&mut self.registry, &mut self.arena) {
                        Ok(()) => {
                            self.remove_group_identity(identity);
                            Ok(())
                        }
                        Err(error) => {
                            self.recoveries.push(Pe32LoadRecovery::Module(transaction));
                            Err(error)
                        }
                    }
                }
            };
            if let Err(error) = result {
                keep_first(&mut first_error, error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn recovery_module_index(&self, module: crate::pe32::Pe32ModuleIdentity) -> Option<usize> {
        self.recoveries.iter().position(|recovery| match recovery {
            Pe32LoadRecovery::Module(transaction) => transaction.module() == module,
            Pe32LoadRecovery::Unbound(_) => false,
        })
    }

    pub(super) fn finish_module_retirement(
        &mut self,
        index: usize,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.modules[index].image_released {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 module dependencies cannot retire before its image",
            ));
        }
        self.retire_module_dependencies(index, imports, host)?;
        if !self.modules[index].system_dependencies.is_empty() {
            return Ok(false);
        }
        self.remove_module(index);
        Ok(true)
    }

    fn retire_module_dependencies(
        &mut self,
        index: usize,
        imports: &mut crate::win32_import_state::Win32ImportState,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owner = self.modules[index].transaction.module();
        while let Some(provider) = self.modules[index].system_dependencies.last().copied() {
            let host_owner = imports.host_owner(provider)?;
            let Some(native) = imports.unpin_dependency(provider, owner)? else {
                self.modules[index].system_dependencies.pop();
                continue;
            };
            let result = host.win32_import(Win32HostImportCall::FreeSystemModule {
                module: native,
                owner: host_owner,
            });
            match result {
                Ok(response) => {
                    let last_error = response.last_error;
                    let released = match response.value {
                        Win32HostImportValue::Bool(released) => released,
                        value => {
                            let primary = native_cleanup_failure(
                                "FreeLibrary for PE32 import provider",
                                value,
                                last_error,
                            );
                            return Err(finish_provider_release(imports, provider, false, primary));
                        }
                    };
                    if released {
                        imports.finish_release_module(provider, true)?;
                        self.modules[index].system_dependencies.pop();
                    } else {
                        let primary = native_cleanup_failure(
                            "FreeLibrary for PE32 import provider",
                            Win32HostImportValue::Bool(false),
                            last_error,
                        );
                        return match imports.finish_release_module(provider, false) {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(aggregate_errors(
                                "native provider release and runtime owner restoration failed",
                                primary,
                                cleanup,
                            )),
                        };
                    }
                }
                Err(primary) => {
                    return Err(finish_provider_release(imports, provider, false, primary));
                }
            }
        }
        Ok(())
    }

    pub(super) fn remove_module(&mut self, index: usize) {
        let identity = self.modules[index].transaction.module();
        debug_assert!(self.modules[index].image_released);
        debug_assert!(self.modules[index].system_dependencies.is_empty());
        self.procedures.retain(|entry| entry.module != identity);
        self.remove_group_identity(identity);
        self.modules.swap_remove(index);
    }
}

fn finish_provider_release(
    state: &mut crate::win32_import_state::Win32ImportState,
    identity: crate::win32_import_state::Win32SystemModuleIdentity,
    released: bool,
    primary: RuntimeError,
) -> RuntimeError {
    match state.finish_release_module(identity, released) {
        Ok(()) => primary,
        Err(cleanup) => aggregate_errors(
            "PE32 provider release failed and its state could not be restored",
            primary,
            cleanup,
        ),
    }
}

fn native_cleanup_failure(
    operation: &'static str,
    value: Win32HostImportValue,
    last_error: Option<u32>,
) -> RuntimeError {
    let kind = if matches!(&value, Win32HostImportValue::Bool(false)) {
        Kind::HostFailure
    } else {
        Kind::InternalInvariant
    };
    RuntimeError::with_source(kind, operation, NativeCleanupOutcome { value, last_error })
}

#[derive(Debug)]
struct NativeCleanupOutcome {
    value: Win32HostImportValue,
    last_error: Option<u32>,
}

impl fmt::Display for NativeCleanupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Win32HostImportValue::Bool(false) => formatter.write_str("Windows returned FALSE")?,
            _ => formatter.write_str("native cleanup returned an unexpected result shape")?,
        }
        match self.last_error {
            Some(code) => write!(formatter, " with Windows error {code}")?,
            None => formatter.write_str("; Windows last-error unavailable")?,
        }
        Ok(())
    }
}

impl Error for NativeCleanupOutcome {}

fn keep_first(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    let Some(primary) = slot.take() else {
        *slot = Some(error);
        return;
    };
    *slot = Some(aggregate_errors(
        "multiple PE32 cleanup operations failed",
        primary,
        error,
    ));
}
