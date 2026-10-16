//! Eager NE executable imports use the same resumable LibMain/WEP owners as
//! LoadLibrary. The executable entry remains parked until the graph is ready.

use super::*;

#[path = "startup/image.rs"]
mod image;

impl Win16State {
    pub(in crate::win16_runtime) fn report_program_load(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.program_load_reported { return Ok(()); }
        let result = match self.module_startup {
            ModuleStartupState::Ready if self.module_callbacks.iter().any(|frame| frame.startup) => {
                return Ok(());
            }
            ModuleStartupState::Ready => Ok(()),
            ModuleStartupState::Failed(code) => Err(code),
            _ => return Ok(()),
        };
        host.win16_program_load_result(result)?;
        self.program_load_reported = true;
        Ok(())
    }

    pub(in crate::win16_runtime) fn begin_program_modules(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.module_startup != ModuleStartupState::Pending {
            return self.check_program_modules();
        }
        let root = self.modules.main;
        if self
            .modules
            .records
            .get(&root)
            .is_none_or(|record| !record.deps.is_empty())
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 executable imports were published before startup discovery",
            ));
        }
        let return_to = (cpu.regs.cs, cpu.regs.ip(), u32::from(cpu.regs.sp()));
        self.publish_module_call(
            cpu,
            ModuleAction::Discover {
                created: Vec::new(),
            },
            VecDeque::new(),
            return_to,
        )?;
        self.module_callbacks
            .last_mut()
            .expect("published startup owner")
            .startup = true;
        self.module_startup = ModuleStartupState::Loading;
        self.capture_module_cpu_owners(cpu, dos, memory, false)?;

        let mut created = Vec::new();
        let result = self.prepare_program_modules(root, &mut created, memory, host);
        match result {
            Ok(Ok(dependencies)) => {
                // Publish the real static edges before LibMain: initialized
                // siblings must survive nested FreeLibrary/reaper calls, and
                // GetModuleUsage must see the executable's dependency edges.
                self.modules
                    .records
                    .get_mut(&root)
                    .expect("startup executable")
                    .deps = dependencies;
                let queue = self.module_initialization_order(root, &created).into();
                for handle in &created {
                    self.modules
                        .records
                        .get_mut(handle)
                        .expect("startup DLL")
                        .state = ModuleState::Initializing;
                }
                let frame = self
                    .module_callbacks
                    .last_mut()
                    .expect("published startup owner");
                frame.action = ModuleAction::Load { root, created };
                frame.queue = queue;
                frame.prepared = true;
            }
            Ok(Err(code)) => {
                let frame = self
                    .module_callbacks
                    .last_mut()
                    .expect("published startup owner");
                frame.action = ModuleAction::LoadFailure { code, created };
                frame.phase = ModuleCallPhase::Complete;
                frame.prepared = true;
            }
            Err(error) => {
                self.module_callbacks
                    .last_mut()
                    .expect("published startup owner")
                    .action = ModuleAction::Discover { created };
                return Err(error);
            }
        }
        self.advance_module_calls(cpu, dos, memory, host)?;
        self.check_program_modules()
    }

    fn prepare_program_modules(
        &mut self,
        root: u16,
        created: &mut Vec<u16>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<Vec<u16>, u16>, RuntimeError> {
        let definition = self.modules.records[&root]
            .definition
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "startup executable has no NE definition",
                )
            })?
            .clone();
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(definition.imported_modules.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve executable NE dependency edges",
                    error,
                )
            })?;
        // KERNEL31's LMImports loads every module-table entry before starting
        // the executable, including a DLL whose imported procedure is unused.
        for imported in &definition.imported_modules {
            let dependency =
                match self.discover_library(&imported.name, memory, host, created, 0)? {
                    Ok(handle) => handle,
                    Err(code) => return Ok(Err(code)),
                };
            if !dependencies.contains(&dependency) {
                dependencies.push(dependency);
            }
        }
        if let Err(code) = self.relocate_libraries(created, memory, host)? {
            return Ok(Err(code));
        }
        self.relocate_startup_program(&definition, memory, host)
            .map(|result| result.map(|()| dependencies))
    }

    pub(super) fn detach_failed_startup_dependencies(&mut self) {
        if self
            .module_callbacks
            .last()
            .is_some_and(|frame| frame.startup)
        {
            // The entry will never execute after this loader failure. Drop
            // only its provisional static roots before the ordinary rollback
            // computes WEP/unreachable modules. Retrying cleanup is harmless.
            if let Some(main) = self.modules.records.get_mut(&self.modules.main) {
                main.deps.clear();
            }
        }
    }

    pub(in crate::win16_runtime) fn check_program_modules(&self) -> Result<(), RuntimeError> {
        match self.module_startup {
            ModuleStartupState::Failed(code) => Err(RuntimeError::new(
                Kind::InvalidInput,
                if code == 0 {
                    "Win16 executable DLL initialization returned FALSE".to_owned()
                } else {
                    format!("Win16 executable dependency load failed with KERNEL error {code}")
                },
            )),
            ModuleStartupState::Ready => Ok(()),
            ModuleStartupState::Loading
                if self
                    .module_callbacks
                    .iter()
                    .filter(|frame| frame.startup && frame.prepared && !frame.terminal)
                    .count()
                    == 1 =>
            {
                Ok(())
            }
            ModuleStartupState::Loading => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 startup has no exact executable dependency continuation",
            )),
            ModuleStartupState::Pending => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 executable image has not completed startup linking",
            )),
        }
    }
}
