//! Publish loader ownership before CPU capture, discovery or guest entry.
use super::*;

impl Win16State {
    pub(super) fn publish_module_call(
        &mut self,
        cpu: &Cpu,
        action: ModuleAction,
        queue: VecDeque<u16>,
        return_to: (u16, u16, u32),
    ) -> Result<(), RuntimeError> {
        let callback_id = self.reserve_callback_frame_id()?;
        self.module_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 DLL continuation owner",
                error,
            )
        })?;
        self.push_callback_kind(CallbackKind::Module, callback_id)?;
        self.module_callbacks.push(ModuleCallFrame {
            callback_id,
            saved: cpu.regs.clone(),
            return_to,
            action,
            cpu: ModuleCpuOwners::default(),
            completion: None,
            prepared: false,
            terminal: false,
            phase: ModuleCallPhase::EnterNext,
            queue,
            active: None,
            initialized: Vec::new(),
            startup: false,
            unload_result: None,
        });
        Ok(())
    }

    pub(in crate::win16_runtime) fn begin_load_library(
        &mut self,
        name: &[u8],
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_load_library_image(name, None, cpu, dos, memory, host, return_to)
    }

    pub(super) fn begin_load_library_image(
        &mut self, name: &[u8], image: Option<crate::Win16ModuleImage>,
        cpu: &mut Cpu, dos: &mut DosKernel, memory: &mut Memory,
        host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.publish_module_call(
            cpu,
            ModuleAction::Discover {
                created: Vec::new(),
            },
            VecDeque::new(),
            return_to,
        )?;
        self.capture_module_cpu_owners(cpu, dos, memory, true)?;
        let mut created = Vec::new();
        let result = match self.discover_library_image(name, image, memory, host, &mut created, 0) {
            Ok(Ok(root)) => self
                .relocate_libraries(&created, memory, host)
                .map(|result| result.map(|()| root)),
            Ok(Err(code)) => Ok(Err(code)),
            Err(error) => Err(error),
        };
        match result {
            Ok(Ok(root)) => {
                let queue = self.module_initialization_order(root, &created).into();
                for &handle in &created {
                    self.modules
                        .records
                        .get_mut(&handle)
                        .expect("discovered DLL")
                        .state = ModuleState::Initializing;
                }
                let frame = self
                    .module_callbacks
                    .last_mut()
                    .expect("published DLL load owner");
                frame.action = ModuleAction::Load { root, created };
                frame.queue = queue;
                frame.prepared = true;
            }
            Ok(Err(code)) => {
                let frame = self
                    .module_callbacks
                    .last_mut()
                    .expect("published DLL load owner");
                frame.action = ModuleAction::LoadFailure { code, created };
                frame.phase = ModuleCallPhase::Complete;
                frame.prepared = true;
            }
            Err(error) => {
                // A host/loader failure keeps its created modules on the exact
                // family owner. Terminal rollback cannot lose a partial graph.
                self.module_callbacks
                    .last_mut()
                    .expect("published DLL discovery owner")
                    .action = ModuleAction::Discover { created };
                return Err(error);
            }
        }
        self.advance_module_calls(cpu, dos, memory, host)?;
        Ok(None)
    }

    pub(in crate::win16_runtime) fn begin_free_library(
        &mut self,
        input: u16,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_release_module(input, false, cpu, dos, memory, host, return_to)
    }

    pub(in crate::win16_runtime) fn begin_free_module(
        &mut self, input: u16, cpu: &mut Cpu, dos: &mut DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if let Some(handle) = self.modules.by_handle(input)
            && let Some(record) = self.modules.records.get(&handle)
            && record.state == ModuleState::Ready && record.explicit_refs == 1
        {
            let process = match record.external_application.as_ref().map(|external| &external.state) {
                Some(super::super::external_application::ExternalApplicationState::ProcessStarted { process }) => Some(Some(*process)),
                Some(super::super::external_application::ExternalApplicationState::NativeActivationReceipt) => Some(None),
                _ => None,
            };
            if let Some(process) = process {
                return self.dispatch_owned_window_call(cpu, dos, memory, host, |state, cpu, memory, host| {
                    state.begin_external_module_release(handle, process, &mut cpu.regs, memory, host, return_to)
                });
            }
        }
        self.begin_release_module(input, true, cpu, dos, memory, host, return_to)
    }

    fn begin_release_module(
        &mut self, input: u16, boolean_result: bool, cpu: &mut Cpu, dos: &mut DosKernel,
        memory: &mut Memory, host: &mut impl RuntimeHost, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.publish_module_call(
            cpu,
            ModuleAction::Unload {
                modules: Vec::new(),
                failed_load: false,
                resume: false,
            },
            VecDeque::new(),
            return_to,
        )?;
        let mut released = false;
        if let Some(handle) = self.modules.by_handle(input) {
            if let Some(record) = self.modules.records.get_mut(&handle) {
                // Pinning is a physical-lifetime root, not an exemption from
                // balancing successful LoadModule/LoadLibrary references.
                let baseline = u16::from(handle == self.modules.main);
                if record.external_application.is_none() && record.explicit_refs > baseline {
                    record.explicit_refs -= 1;
                    released = true;
                }
            }
        }
        if boolean_result {
            self.module_callbacks.last_mut().expect("published module release owner")
                .unload_result = Some(u16::from(released));
        }
        self.module_reap_pending = true;
        let candidates = self.modules.unreachable(&[]);
        self.release_module_classes(&candidates, host)?;
        let roots = self.module_code_roots(guest_code_reference(return_to.0, return_to.1))?;
        let modules = self.modules.unreachable(&roots);
        let order = self.module_unload_order(&modules);
        self.module_callbacks
            .last_mut()
            .expect("published DLL unload owner")
            .action = ModuleAction::Unload {
            modules,
            failed_load: false,
            resume: false,
        };
        // Choose logical unloads before transient caller leases are captured.
        // Those leases may delay physical release, but must not suppress WEP.
        self.capture_module_cpu_owners(cpu, dos, memory, true)?;
        self.prepare_module_unload(order)?;
        self.advance_module_calls(cpu, dos, memory, host)?;
        Ok(None)
    }

    pub(super) fn module_unload_order(&self, modules: &[u16]) -> VecDeque<u16> {
        let mut order = Vec::new();
        for &handle in modules {
            for next in self.module_initialization_order(handle, modules) {
                if !order.contains(&next) {
                    order.push(next);
                }
            }
        }
        order.reverse();
        order.into()
    }

    pub(super) fn prepare_module_unload(&mut self, order: VecDeque<u16>) -> Result<(), RuntimeError> {
        let frame = self.module_callbacks.last_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DLL unload preparation lost its source owner",
            )
        })?;
        let modules = match &frame.action {
            ModuleAction::Unload { modules, .. } | ModuleAction::TaskExit { modules, .. } => modules,
            _ => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL unload preparation has a different loader action",
            )),
        };
        for handle in modules {
            let record = self.modules.records.get_mut(handle).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL unload preparation lost a retained module",
                )
            })?;
            if record.state != ModuleState::Retired {
                record.state = ModuleState::Unloading;
            }
        }
        frame.queue = order;
        frame.prepared = true;
        Ok(())
    }

    pub(in crate::win16_runtime) fn reap_modules(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !self.module_reap_pending
            || !self.module_callbacks.is_empty()
            || self.toolhelp_task_exit.pending_id().is_some()
            || cpu.interrupt_shadow_active()
        {
            return Ok(());
        }
        let candidates = self.modules.unreachable(&[]);
        self.release_module_classes(&candidates, host)?;
        let roots = self.module_code_roots(guest_code_reference(cpu.regs.cs, cpu.regs.ip()))?;
        let modules = self.modules.unreachable(&roots);
        if modules.is_empty() {
            self.module_reap_pending = self.has_reapable_unreachable_modules()?;
            return Ok(());
        }
        let order = self.module_unload_order(&modules);
        let return_to = (cpu.regs.cs, cpu.regs.ip(), u32::from(cpu.regs.sp()));
        self.publish_module_call(
            cpu,
            ModuleAction::Unload {
                modules,
                failed_load: false,
                resume: true,
            },
            VecDeque::new(),
            return_to,
        )?;
        self.capture_module_cpu_owners(cpu, dos, memory, false)?;
        self.prepare_module_unload(order)?;
        self.advance_module_calls(cpu, dos, memory, host)
    }
}
