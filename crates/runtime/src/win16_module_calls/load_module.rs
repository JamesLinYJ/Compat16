//! LoadModule selects a guest library or an owned executable startup.

use super::*;
use crate::{Win16HostProgramLoadInput, Win16HostShellExecutionOperation};
use win16_abi::{Win16ModuleReference, load_module::LoadModuleParameters};

impl Win16State {
    pub(in crate::win16_runtime) fn begin_load_module(
        &mut self,
        module: &Win16ModuleReference,
        parameters: u32,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let existing = self.module_handle(module);
        let name = match module {
            Win16ModuleReference::Name(name) => name.clone(),
            Win16ModuleReference::Handle(_) => {
                match existing.and_then(|handle| self.modules.records.get(&handle)) {
                    Some(record) => match record.external_application.as_ref() {
                        Some(external) => match external.program_path.as_ref() {
                            Some(path) => path.clone(),
                            None => {
                                return self.complete_return(
                                    &mut cpu.regs,
                                    return_to.0,
                                    return_to.1,
                                    return_to.2,
                                    2,
                                    Win16ReturnKind::Word,
                                );
                            }
                        },
                        None => record.path.clone(),
                    },
                    _ => {
                        return self.complete_return(
                            &mut cpu.regs,
                            return_to.0,
                            return_to.1,
                            return_to.2,
                            2,
                            Win16ReturnKind::Word,
                        );
                    }
                }
            }
            Win16ModuleReference::Current => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    2,
                    Win16ReturnKind::Word,
                );
            }
        };
        // LoadLibrary uses FFFF:FFFF. A DLL does not consume a task parameter
        // block, including the conventional NULL form used by LoadModule.
        if matches!(parameters, 0 | u32::MAX)
            || existing.is_some_and(|handle| {
                let record = &self.modules.records[&handle];
                record.builtin
                    || record
                        .definition
                        .as_ref()
                        .is_some_and(|definition| definition.header.flags & 0x8000 != 0)
            })
        {
            return self.begin_load_library(&name, cpu, dos, memory, host, return_to);
        }
        let owner = self.current_task_owner()?;
        let input = Win16HostProgramLoadInput {
            name,
            directory: self
                .kernel_file_system
                .current_directory_canonical(owner)?
                .clone(),
            application_path: self.module_path.clone(),
            environment: self
                .compat
                .environment_list_bytes(&self.selectors, memory)?,
            owner,
        };
        let image = match host.win16_read_program_image(&input)? {
            Ok(image) => image,
            Err(code) => {
                return self.complete_return(
                    &mut cpu.regs,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    u32::from(code),
                    Win16ReturnKind::Word,
                );
            }
        };
        if let Ok(definition) = formats::parse_ne(&image.image)
            && definition.header.flags & 0x8000 != 0
        {
            let path = image.path.clone();
            return self.begin_load_library_image(
                &path,
                Some(image),
                cpu,
                dos,
                memory,
                host,
                return_to,
            );
        }
        let parameters = LoadModuleParameters::read(parameters, &self.selectors, memory)
            .map_err(crate::runtime_error)?;
        let operation = Win16HostShellExecutionOperation::LoadModule {
            environment: parameters
                .environment
                .unwrap_or_else(|| input.environment.clone()),
            input,
            image: std::sync::Arc::new(image),
            command_tail: parameters.command_tail,
            show: parameters.show,
        };
        self.dispatch_owned_window_call(cpu, dos, memory, host, |state, cpu, memory, host| {
            state.begin_module_program(operation, &mut cpu.regs, memory, host, return_to)
        })
    }
}
