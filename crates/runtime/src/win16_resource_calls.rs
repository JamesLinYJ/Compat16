//! Win16 resource-loader callbacks and file access through native services.

use formats::NeImportTarget;
use guest_core::{memory::Memory, Registers};
use win16_abi::{Win16ResourceName, Win16ReturnKind};
use dos_kernel::DosKernel;
use x86_cpu::Cpu;

use super::{CallbackKind, Win16State, INVALID_GUEST_HFILE};
use super::resources::{ResourceKey, ResourceMetadata};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[path = "win16_resource_calls/entry.rs"]
mod entry;
#[path = "win16_resource_calls/completion.rs"]
mod completion;
#[path = "win16_resource_calls/cpu.rs"]
mod cpu;
const OF_READ: u16 = 0;
const SEEK_SET: u16 = 0;

#[derive(Clone, Copy)]
enum ResourceReturn { Load, Lock }

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceCallPhase { Preparing, AwaitHandler, Complete, Returned }

enum ResourceCompletion {
    Commit { data: u16, operation: &'static str },
    Lock { data: u16, operation: &'static str },
    Ready { value: u32, kind: Win16ReturnKind, operation: Option<&'static str>, reported: bool },
}

pub(super) struct ResourceCallFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    key: Option<ResourceKey>,
    procedure: Option<u32>,
    result: ResourceReturn,
    caller: Option<u64>,
    parked: Option<u64>,
    callback: Option<super::far_callback::Win16FarCallbackFrame>,
    phase: ResourceCallPhase,
    completion: Option<ResourceCompletion>,
    terminal: bool,
}

impl Win16State {
    pub(super) fn access_resource(&mut self, module: u16, info: u16,
        host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        let result = self.access_resource_checked(module, info, host);
        if let Ok(file) = &result {
            host.observe_win16_io(&crate::Win16IoEvent::ResourceResult {
                operation: "resource-access-complete", module, resource: info,
                value: u32::from(*file),
            });
        }
        result
    }

    fn access_resource_checked(&mut self, module: u16, info: u16,
        host: &mut impl RuntimeHost) -> Result<u16, RuntimeError> {
        if module == 0 { return Ok(INVALID_GUEST_HFILE); }
        let Some(metadata) = self.resource_metadata(module, info) else {
            return Ok(INVALID_GUEST_HFILE);
        };
        host.observe_win16_io(&crate::Win16IoEvent::Resource {
            operation: "resource-access", module: metadata.key.module, resource: metadata.key.info,
            offset: metadata.offset, length: metadata.length, data: 0,
        });
        let Ok(offset) = i32::try_from(metadata.offset) else {
            return Ok(INVALID_GUEST_HFILE);
        };
        let path = self.modules.records[&metadata.key.module].path.clone();
        let number = self.open_legacy_file(&path, OF_READ, false, host)?;
        if !self.files.contains_key(&number) {
            return Ok(INVALID_GUEST_HFILE);
        }
        let seek = self.seek_file(number, offset, SEEK_SET, host);
        if !matches!(&seek, Ok(position) if *position == offset as u32) {
            self.close_legacy_file(number, host)?;
            return seek.map(|_| INVALID_GUEST_HFILE);
        }
        Ok(number)
    }

    fn default_resource_procedure(&mut self) -> Result<u32, RuntimeError> {
        let entry = self.bind_builtin(b"KERNEL",
            &NeImportTarget::Name(b"DefResourceHandler".to_vec()), false)
            .map_err(crate::runtime_error)?.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "default Win16 resource handler has no ABI entry"))?;
        Ok((u32::from(entry.selector.0) << 16) | u32::from(entry.offset))
    }

    pub(super) fn set_resource_handler(&mut self, module: u16,
        resource_type: &Win16ResourceName, handler: u32, host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if module == 0 { return Ok(0); }
        let types = self.matching_resource_types(module, resource_type, host)?;
        if types.is_empty() { return Ok(0); }
        let default = self.default_resource_procedure()?;
        let mut previous = default;
        for identity in types {
            previous = self.resource_handlers.get(&identity).copied().unwrap_or(default);
            // A NULL handler disables loading for this resource type. Only
            // the actual default procedure restores the built-in loader.
            if handler == default {
                self.resource_handlers.remove(&identity);
            } else {
                self.resource_handlers.insert(identity, handler);
            }
        }
        Ok(previous)
    }

    pub(super) fn resource_code_references(&self) -> Vec<u32> {
        self.resource_callbacks.iter().flat_map(|frame| {
            frame.procedure.into_iter()
                .chain(frame.key.map(|key| u32::from(key.module) << 16))
                .chain([u32::from(frame.saved.cs) << 16,
                    u32::from(frame.return_to.0) << 16])
        }).collect()
    }

    /// Installed handlers form module dependency edges. A callback keeps its
    /// code live only while the module whose resources it serves is reachable.
    pub(super) fn retain_resource_handler_modules(&self, roots: &mut Vec<u16>) {
        loop {
            let unreachable = self.modules.unreachable(roots);
            let mut added = false;
            for (&(owner, _), &procedure) in &self.resource_handlers {
                if unreachable.contains(&owner) { continue; }
                if let Some(code) = self.modules.retained_owner((procedure >> 16) as u16, &self.selectors) {
                    if !roots.contains(&code) { roots.push(code); added = true; }
                }
            }
            if !added { break; }
        }
    }
}
