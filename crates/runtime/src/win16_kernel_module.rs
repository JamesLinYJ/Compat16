//! KERNEL queries over loaded guest NE module metadata.

use guest_core::memory::Memory;
use win16_abi::{Access, Win16ModuleReference, Win16OutputBuffer};

use super::{module_registry::ModuleState, Win16State};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn kernel_get_module_name(
        &self,
        module: u16,
        output: u32,
        capacity: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let reference = Win16ModuleReference::Handle(module);
        let Some(handle) = self.module_handle(&reference) else { return Ok(0); };
        let Some(record) = self.modules.records.get(&handle) else { return Ok(0); };
        if record.external_application.is_some() {
            super::external_application::report_external_identity_query(
                host, "GetModuleName", handle,
            );
            return Ok(0);
        }
        let capacity = i16::from_le_bytes(capacity.to_le_bytes());
        if capacity <= 0 { return Ok(1); }
        let name: &[u8] = if record.name.is_empty() {
            basename(&record.path)
        } else {
            record.name.as_slice()
        };
        let capacity = capacity as u16;
        let copy = name.len().min(usize::from(capacity.saturating_sub(1)));
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(copy + 1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 module-name output", error,
        ))?;
        bytes.extend_from_slice(&name[..copy]);
        bytes.push(0);

        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        let output_buffer = Win16OutputBuffer { pointer, capacity };
        self.validate_module_name_output(output_buffer, bytes.len(), memory)?;
        self.write_output(memory, output_buffer, &bytes)?;
        Ok(1)
    }

    fn validate_module_name_output(
        &self, output: Win16OutputBuffer, length: usize, memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let mut pointer = output.pointer;
        let mut remaining = length;
        while remaining != 0 {
            let descriptor = self.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
            let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| usize::try_from(bytes).ok())
                .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                    "Win16 module-name output exceeds its selector"))?;
            let chunk = remaining.min(available);
            if chunk == 0 {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "Win16 module-name output has no writable selector range"));
            }
            self.selectors.translate(pointer, Access::Write, chunk, memory)
                .map_err(crate::runtime_error)?;
            remaining -= chunk;
            if remaining != 0 {
                pointer = self.selectors.add_bytes(pointer, chunk as u32)
                    .map_err(crate::runtime_error)?;
            }
        }
        Ok(())
    }

    pub(super) fn kernel_get_exe_ptr(
        &self, input: u16, host: &mut impl RuntimeHost,
    ) -> u16 {
        let Some(handle) = self.modules.by_handle(input) else { return 0; };
        if self.external_application(handle).is_some() {
            super::external_application::report_external_identity_query(
                host, "GetExePtr", handle,
            );
            return 0;
        }
        handle
    }

    pub(super) fn kernel_get_exe_version(&self) -> u16 {
        self.modules.records.get(&self.modules.main)
            .filter(|record| !matches!(record.state, ModuleState::Retired | ModuleState::Unloading))
            .and_then(|record| record.definition.as_ref())
            .map_or(0, |module| module.header.expected_windows_version)
    }

    pub(super) fn kernel_get_exp_win_ver(
        &self, input: u16, host: &mut impl RuntimeHost,
    ) -> u32 {
        let handle = if input == 0 { self.modules.main } else {
            let Some(handle) = self.modules.by_handle(input) else { return 0; };
            handle
        };
        if self.external_application(handle).is_some() {
            super::external_application::report_external_identity_query(
                host, "GetExpWinVer", handle,
            );
            return 0;
        }
        let Some(module) = self.modules.records.get(&handle)
            .filter(|record| !matches!(record.state, ModuleState::Retired | ModuleState::Unloading))
            .and_then(|record| record.definition.as_ref()) else { return 0; };

        // KERNEL's loaded NE header keeps NEWINPROT in ne_flags at runtime.
        // LDHEADER derives that private bit from NEINFONT in the high byte
        // of its exetype word, parsed here as the `other_flags` byte.
        const NEINFONT: u8 = 0x02;
        const NEWINPROT: u16 = 0x2000;
        let proportional_font_flag = if module.header.other_flags & NEINFONT != 0 {
            NEWINPROT
        } else {
            0
        };
        (u32::from(proportional_font_flag) << 16)
            | u32::from(module.header.expected_windows_version)
    }
}

fn basename(path: &[u8]) -> &[u8] {
    let start = path.iter().rposition(|byte| *byte == b'/' || *byte == b'\\')
        .map_or(0, |separator| separator + 1);
    &path[start..]
}
