//! Guest module identity and filename services.

use guest_core::memory::Memory;
use win16_abi::{Win16OutputBuffer, Win16ModuleReference, Win16ProcReference};

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcedureLookup {
    Address(u32),
    Missing,
    UnsupportedDataExport,
}

impl Win16State {
    pub(super) fn module_memory_info(&self, input: u16) -> Option<(u16, u32)> {
        let owner = self.modules.by_handle(input)?;
        let record = self.modules.records.get(&owner)?;
        if input == record.handle {
            let allocation = record.allocations.first()?;
            return self.heap.info(allocation.handle).ok().map(|info|
                (allocation.selector.raw().0, info.size));
        }
        if let (Some(selector), Some(data)) = (record.builtin_data_selector,
            record.builtin_data_exports.as_ref()) {
            if selector.raw().0 == input {
                return Some((input, u32::try_from(data.bytes.len()).ok()?));
            }
        }
        let loaded = record.loaded.as_ref()?;
        loaded.segments.iter().find(|segment| segment.selector.0 == input
            || self.loaded_segment_handles.get(&segment.selector.0) == Some(&input))
            .map(|segment| (segment.selector.0, segment.memory_size))
    }

    pub(super) fn module_handle(&self, module: &Win16ModuleReference) -> Option<u16> {
        let handle = match module {
            Win16ModuleReference::Current => Some(self.modules.main),
            // KB Q81496: a zero high word carries an instance handle, not an HTASK.
            // The task database selector is a different object from the module
            // and from the instance's automatic data segment.
            Win16ModuleReference::Handle(handle) => self.modules.by_handle(*handle),
            Win16ModuleReference::Name(name) => self.modules.by_name(name),
        }?;
        (self.modules.records.get(&handle)?.state != super::module_registry::ModuleState::Retired)
            .then_some(handle)
    }

    /// Failure is NULL in both words. The catalog return is a dword, so a
    /// miss must not leave the first module handle in DX. A hit keeps that
    /// high word and returns the module handle in the low word.
    pub(super) fn kernel_get_module_handle(&self, module: &Win16ModuleReference) -> u32 {
        let Some(handle) = self.module_handle(module) else { return 0 };
        u32::from(handle) | (u32::from(self.modules.first) << 16)
    }

    pub(super) fn get_proc_address(&mut self, module: &Win16ModuleReference,
        procedure: &Win16ProcReference, host: &mut impl RuntimeHost,
    ) -> Result<ProcedureLookup, RuntimeError> {
        let Some(handle) = self.module_handle(module) else { return Ok(ProcedureLookup::Missing); };
        if self.external_application(handle).is_some() {
            super::external_application::report_external_identity_query(
                host, "GetProcAddress", handle,
            );
            return Ok(ProcedureLookup::Missing);
        }
        let name = {
            let record = &self.modules.records[&handle];
            record.name.clone()
        };
        let lookup = match procedure {
            Win16ProcReference::Ordinal(ordinal) => win16_abi::ExportLookupTarget::Ordinal(*ordinal),
            Win16ProcReference::Name(name) => win16_abi::ExportLookupTarget::Name(name),
        };
        if win16_abi::exports::lookup_export_metadata(&name, lookup)
            .is_some_and(|declaration| win16_abi::exports::lookup_data_export_source(declaration).is_some()
                || matches!(declaration.kind,
                    win16_abi::exports::ExportEntryKind::Extern
                        | win16_abi::exports::ExportEntryKind::Forward
                        | win16_abi::exports::ExportEntryKind::Unknown)) {
            return Ok(ProcedureLookup::UnsupportedDataExport);
        }
        match self.module_import_value(handle, procedure, false).map_err(crate::runtime_error)? {
            Some(formats::NeImportValue::Address(address)) => Ok(ProcedureLookup::Address(
                (u32::from(address.selector.0) << 16) | u32::from(address.offset),
            )),
            Some(formats::NeImportValue::Selector(_)
                | formats::NeImportValue::Constant(_)) => {
                Ok(ProcedureLookup::UnsupportedDataExport)
            }
            None => Ok(ProcedureLookup::Missing),
        }
    }

    pub(super) fn get_module_file_name(
        &self,
        module: u16,
        output: Option<Win16OutputBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(output) = output else { return Ok(0); };
        let reference = if module == 0 { Win16ModuleReference::Current }
            else { Win16ModuleReference::Handle(module) };
        let Some(handle) = self.module_handle(&reference) else { return Ok(0); };
        let record = &self.modules.records[&handle];
        let path = if let Some(external) = record.external_application.as_ref() {
            if let Some(path) = external.program_path.as_deref().or_else(|| external.association_path()) {
                path
            } else {
                super::external_application::report_external_identity_query(
                    host, "GetModuleFileName", handle,
                );
                return Ok(0);
            }
        } else {
            record.path.as_slice()
        };
        let copy = path.len().min(usize::from(output.capacity.saturating_sub(1)));
        host.observe_win16_io(&crate::Win16IoEvent::ModuleFileName { path, copied: copy });
        let mut bytes = Vec::with_capacity(copy + 1);
        bytes.extend_from_slice(&path[..copy]);
        bytes.push(0);
        self.write_output(memory, output, &bytes)?;
        Ok(copy as u16)
    }

}
