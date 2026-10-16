//! Checked DLL returns, cached completion and exact owner retirement.
use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn finish_module_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.preflight_module_cpu_owners(cpu)?;
        let frame = self.module_callbacks.last().ok_or_else(|| {
            RuntimeError::new(Kind::GuestFault, "Win16 DLL return has no active entry")
        })?;
        let Some(handle) = frame.active else {
            return self.advance_module_calls(cpu, dos, memory, host);
        };
        if frame.phase != ModuleCallPhase::AwaitCallbackReturn
            || frame.queue.front().copied() != Some(handle)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLL callback return lost its queued module owner",
            ));
        }
        let returned = self.finish_module_cpu_callback(cpu, dos, memory)?;
        let frame = self
            .module_callbacks
            .last()
            .expect("checked DLL callback source remains");
        let loading = matches!(frame.action, ModuleAction::Load { .. });
        if loading && returned == 0 {
            self.detach_failed_startup_dependencies();
            let (return_address, created, initialized) = {
                let frame = self.module_callbacks.last().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "failed Win16 DLL load lost its continuation frame",
                    )
                })?;
                let ModuleAction::Load { created, .. } = &frame.action else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "failed Win16 DLL initialization changed its action before rollback",
                    ));
                };
                let created =
                    copy_module_handles(created, "reserve Win16 DLL rollback module owners")?;
                let mut initialized = copy_module_handles(
                    &frame.initialized,
                    "reserve initialized Win16 DLL rollback owners",
                )?;
                initialized.reverse();
                (
                    guest_code_reference(frame.return_to.0, frame.return_to.1),
                    created,
                    initialized,
                )
            };
            let snapshots = self.snapshot_module_states(&created)?;
            let mut unloading = Vec::new();
            unloading
                .try_reserve_exact(created.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve failed-load Win16 DLL retirement plan",
                        error,
                    )
                })?;
            let mut queue = VecDeque::new();
            queue
                .try_reserve_exact(initialized.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve failed-load Win16 DLL WEP retry queue",
                        error,
                    )
                })?;

            if let Err(error) = self.stage_failed_load_retirement(&snapshots) {
                return Err(self.restore_module_states_after_failure(&snapshots, error));
            }
            let candidates = self.modules.unreachable(&[]);
            if let Err(error) = self.release_module_classes(&candidates, host) {
                return Err(self.restore_module_states_after_failure(&snapshots, error));
            }
            let roots = match self.module_code_roots_after_callback_return(return_address) {
                Ok(roots) => roots,
                Err(error) => {
                    return Err(self.restore_module_states_after_failure(&snapshots, error));
                }
            };
            let unused = self.modules.unreachable(&roots);
            self.restore_module_states(&snapshots)?;

            for &module in &created {
                if unused.contains(&module) {
                    unloading.push(module);
                }
            }
            for &module in &initialized {
                if unloading.contains(&module) {
                    queue.push_back(module);
                }
            }
            self.commit_failed_load_retirement(&snapshots, &unloading)?;
            let frame = self.module_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "failed Win16 DLL commit lost its continuation frame",
                )
            })?;
            frame.action = ModuleAction::Unload {
                modules: unloading,
                failed_load: true,
                resume: false,
            };
            frame.queue = queue;
            frame.cpu.active_call = None;
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 library initialization returned FALSE; rolling back LoadLibrary",
            ));
        } else if loading {
            let frame = self.module_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "initialized DLL lost its continuation frame",
                )
            })?;
            let record = self.modules.records.get_mut(&handle).ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "initialized DLL is missing")
            })?;
            if frame.phase != ModuleCallPhase::AwaitCallbackReturn
                || frame.active != Some(handle)
                || frame.queue.front().copied() != Some(handle)
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "initialized DLL callback changed its continuation owner before commit",
                ));
            }
            frame.initialized.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve initialized Win16 DLL continuation owner",
                    error,
                )
            })?;
            let _ = frame.queue.pop_front();
            record.state = ModuleState::Ready;
            frame.initialized.push(handle);
            frame.cpu.active_call = None;
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
        } else {
            let frame = self.module_callbacks.last_mut().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "WEP return lost its continuation frame",
                )
            })?;
            let _ = frame.queue.pop_front();
            frame.cpu.active_call = None;
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
        }
        self.advance_module_calls(cpu, dos, memory, host)
    }

    fn prepare_module_completion(&self) -> Result<ModuleCompletionPlan, RuntimeError> {
        let frame = self
            .module_callbacks
            .last()
            .expect("checked DLL completion source");
        match &frame.action {
            ModuleAction::Load { root, .. } => {
                let record = self.modules.records.get(root).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "initialized DLL disappeared before caller return",
                    )
                })?;
                let explicit_refs = record.explicit_refs.checked_add(u16::from(!frame.startup)).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "Win16 module reference count overflow",
                    )
                })?;
                Ok(ModuleCompletionPlan::Load {
                    root: *root,
                    previous_refs: record.explicit_refs,
                    explicit_refs,
                    value: u32::from(record.instance),
                })
            }
            ModuleAction::LoadFailure { code, created } => Ok(ModuleCompletionPlan::LoadFailure {
                code: *code,
                modules: copy_module_handles(created, "retain failed DLL discovery plan")?,
            }),
            ModuleAction::Unload {
                modules,
                failed_load,
                resume,
            } => Ok(ModuleCompletionPlan::Unload {
                modules: copy_module_handles(modules, "retain DLL unload completion plan")?,
                failed_load: *failed_load,
                resume: *resume,
            }),
            ModuleAction::TaskExit { modules, scope } => Ok(ModuleCompletionPlan::TaskExit {
                modules: copy_module_handles(modules, "retain task-exit DLL completion owners")?,
                scope: *scope,
            }),
            ModuleAction::Discover { .. } => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL discovery has no completed load result",
            )),
        }
    }

    pub(super) fn complete_module_calls(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Module)?;
        let frame = self
            .module_callbacks
            .last()
            .filter(|frame| frame.callback_id == id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL completion lost its exact shared callback owner",
                )
            })?;
        if frame.phase == ModuleCallPhase::Returned {
            return self.retire_completed_module_call(dos, memory);
        }
        if frame.phase != ModuleCallPhase::Complete
            || frame.active.is_some()
            || !frame.queue.is_empty()
            || frame.cpu.active_call.is_some()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL completion precedes exact callback queue retirement",
            ));
        }
        let plan = match self
            .module_callbacks
            .last_mut()
            .expect("DLL completion source")
            .completion
            .take()
        {
            Some(plan) => plan,
            None => self.prepare_module_completion()?,
        };
        let result = self.commit_module_completion(cpu, dos, memory, &plan);
        self.module_callbacks
            .last_mut()
            .expect("DLL source remains through CPU commit")
            .completion = Some(plan);
        result?;
        self.retire_completed_module_call(dos, memory)
    }

    fn commit_module_completion(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        plan: &ModuleCompletionPlan,
    ) -> Result<(), RuntimeError> {
        let (mut resume, value, mut kind) = match plan {
            ModuleCompletionPlan::Load {
                root,
                previous_refs,
                value,
                ..
            } => {
                if self
                    .modules
                    .records
                    .get(root)
                    .is_none_or(|record| record.explicit_refs != *previous_refs)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "cached DLL completion reference count changed before return",
                    ));
                }
                (false, *value, Win16ReturnKind::Word)
            }
            ModuleCompletionPlan::LoadFailure { code, modules } => {
                self.rollback_modules(modules)?;
                (false, u32::from(*code), Win16ReturnKind::Word)
            }
            ModuleCompletionPlan::TaskExit { modules, scope } => {
                let callback = self.module_callbacks.last().expect("DLL completion source").callback_id;
                self.toolhelp_task_exit.validate_module_cleanup_return(*scope, callback)?;
                if modules.iter().any(|handle| !self.modules.records.contains_key(handle)) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "task-exit DLL completion lost a retained module"));
                }
                (true, 0, Win16ReturnKind::Void)
            }
            ModuleCompletionPlan::Unload {
                modules,
                failed_load,
                resume,
            } => {
                for handle in modules {
                    if let Some(record) = self.modules.records.get_mut(handle) {
                        record.state = ModuleState::Retired;
                        record.wep_called = true;
                    }
                }
                let frame = self.module_callbacks.last().expect("DLL completion source");
                let unload_result = frame.unload_result;
                let mut roots = self.module_code_roots(guest_code_reference(
                    frame.return_to.0,
                    frame.return_to.1,
                ))?;
                let locked = self.module_segment_lock_roots()?;
                roots.try_reserve(locked.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "retain post-WEP segment lock roots",
                        error,
                    )
                })?;
                roots.extend(locked);
                let unused = self.modules.unreachable(&roots);
                for &handle in modules {
                    if unused.contains(&handle) {
                        match self.remove_module(handle)? {
                            ModuleRemoval::Removed | ModuleRemoval::DeferredByGuestLock => {}
                        }
                    }
                }
                self.module_reap_pending = self.has_reapable_unreachable_modules()?;
                (
                    *resume,
                    if *failed_load { 0 } else { unload_result.unwrap_or(0) }.into(),
                    if *failed_load {
                        Win16ReturnKind::Word
                    } else if unload_result.is_some() {
                        Win16ReturnKind::Word
                    } else {
                        Win16ReturnKind::Void
                    },
                )
            }
        };
        let startup = self.module_callbacks.last().expect("DLL completion source").startup;
        let startup_result = if startup {
            Some(match plan {
                ModuleCompletionPlan::Load { .. } => ModuleStartupState::Ready,
                ModuleCompletionPlan::LoadFailure { code, .. } => ModuleStartupState::Failed(*code),
                ModuleCompletionPlan::Unload { failed_load: true, .. } => ModuleStartupState::Failed(0),
                ModuleCompletionPlan::Unload { .. } => return Err(RuntimeError::new(
                    Kind::InternalInvariant, "startup completed with an unrelated unload action")),
                ModuleCompletionPlan::TaskExit { .. } => return Err(RuntimeError::new(
                    Kind::InternalInvariant, "startup completed with a task-exit DLL action")),
            })
        } else { None };
        if startup {
            // An executable entry has no API caller or callee-pop stack frame.
            resume = true;
            kind = Win16ReturnKind::Void;
        }
        self.return_module_cpu_caller(cpu, dos, memory, resume, value, kind)?;
        // No guest or host callback can run between the checked CPU commit and
        // this infallible metadata commit. Owner-release retries use Returned.
        if let ModuleCompletionPlan::Load {
            root,
            explicit_refs,
            ..
        } = plan
        {
            self.modules
                .records
                .get_mut(root)
                .expect("validated DLL completion record remains")
                .explicit_refs = *explicit_refs;
        }
        if let Some(result) = startup_result { self.module_startup = result; }
        if let ModuleCompletionPlan::TaskExit { modules, scope } = plan {
            // WEP has returned, but older window/CPU/native callback roots
            // can still refer to these segments. Leave physical ownership
            // with ordinary process teardown after guest execution ends.
            for handle in modules {
                let record = self.modules.records.get_mut(handle).expect("retained exit DLL");
                record.state = ModuleState::Retired;
                record.wep_called = true;
            }
            let callback = self.module_callbacks.last().expect("DLL completion source").callback_id;
            self.toolhelp_task_exit.module_cleanup_returned(*scope, callback)?;
        }
        self.module_callbacks
            .last_mut()
            .expect("returned DLL completion source")
            .phase = ModuleCallPhase::Returned;
        Ok(())
    }
}
