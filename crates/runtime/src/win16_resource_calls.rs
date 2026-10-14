//! Win16 resource-loader callbacks and file access through native services.

use formats::NeImportTarget;
use guest_core::{memory::Memory, Registers, Selector};
use win16_abi::{Access, Win16ResourceName, Win16ReturnKind};

use super::{CallbackKind, Win16State, INVALID_GUEST_HFILE};
use super::resources::{ResourceKey, ResourceMetadata};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

// A FAR return followed by three WORDs in reverse Pascal argument order.
const LOADPROC_STACK_BYTES: u16 = 10;
const OF_READ: u16 = 0;
const SEEK_SET: u16 = 0;

#[derive(Clone, Copy)]
enum ResourceReturn { Load, Lock }

pub(super) struct ResourceCallFrame {
    callback_id: super::CallbackFrameId,
    saved: Registers,
    return_to: (u16, u16, u32),
    key: ResourceKey,
    procedure: u32,
    result: ResourceReturn,
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

    pub(super) fn begin_load_resource(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, module: u16, info: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(metadata) = self.resource_metadata(module, info) else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::Word);
        };
        if let Some(data) = self.retain_loaded_resource(metadata.key)? {
            host.observe_win16_io(&crate::Win16IoEvent::ResourceResult {
                operation: "resource-load-cached", module: metadata.key.module,
                resource: metadata.key.info, value: u32::from(data),
            });
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, u32::from(data), Win16ReturnKind::Word);
        }
        let data = self.prior_resource_handle(metadata.key);
        self.begin_resource_loader(registers, memory, host, metadata, data,
            ResourceReturn::Load, return_to)
    }

    pub(super) fn begin_lock_resource(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, data: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let pointer = self.global_lock(data, memory)?;
        // Failed locking alone does not mean the resource was discarded: the
        // heap may have exhausted locks or selectors. Reload only discarded data.
        if pointer != 0 || !self.discarded_handles.contains(&data) {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, pointer, Win16ReturnKind::FarPointer);
        }
        let metadata = self.resource_key_for_data(data)
            .and_then(|key| self.resource_metadata(key.module, key.info));
        let Some(metadata) = metadata else {
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, Win16ReturnKind::FarPointer);
        };
        self.begin_resource_loader(registers, memory, host, metadata, data,
            ResourceReturn::Lock, return_to)
    }

    fn begin_resource_loader(&mut self, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, metadata: ResourceMetadata,
        data: u16, result: ResourceReturn, return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let procedure = self.resource_handlers.get(&(metadata.key.module, metadata.type_index))
            .copied();
        let Some(procedure) = procedure else {
            let loaded = self.default_resource_load(data, metadata.key, memory, host)?;
            let (value, kind) = self.finish_resource_result(metadata.key, loaded, result, memory)?;
            host.observe_win16_io(&crate::Win16IoEvent::ResourceResult {
                operation: "resource-default-complete", module: metadata.key.module,
                resource: metadata.key.info, value,
            });
            return self.complete_return(registers, return_to.0, return_to.1, return_to.2, value, kind);
        };
        if procedure == 0 {
            let kind = match result {
                ResourceReturn::Load => Win16ReturnKind::Word,
                ResourceReturn::Lock => Win16ReturnKind::FarPointer,
            };
            return self.complete_return(registers, return_to.0, return_to.1,
                return_to.2, 0, kind);
        }
        let target = self.selectors.pointer_from_far(procedure).map_err(crate::runtime_error)?;
        self.selectors.translate(target, Access::Execute, 1, memory).map_err(crate::runtime_error)?;
        let sp = registers.sp().checked_sub(LOADPROC_STACK_BYTES).ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "Win16 resource callback stack underflow"))?;
        let stack = self.selectors.pointer_from_raw(Selector(registers.ss), sp)
            .map_err(crate::runtime_error)?;
        let instance = self.modules.records[&metadata.key.module].instance;
        let mut arguments = [0_u8; LOADPROC_STACK_BYTES as usize];
        arguments[2..4].copy_from_slice(&self.callback_gate_selector.0.to_le_bytes());
        arguments[4..6].copy_from_slice(&metadata.key.info.to_le_bytes());
        arguments[6..8].copy_from_slice(&instance.to_le_bytes());
        arguments[8..10].copy_from_slice(&data.to_le_bytes());
        let callback_id = self.reserve_callback_frame_id()?;
        self.resource_callbacks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 resource callback frame",
                error,
            )
        })?;
        // Stack writes can fail. Complete that fallible guest-memory work
        // before publishing the shared callback binding or family owner.
        self.selectors.write(memory, stack, &arguments).map_err(crate::runtime_error)?;
        self.push_callback_kind(CallbackKind::Resource, callback_id)?;
        self.resource_callbacks.push(ResourceCallFrame {
            callback_id, saved: registers.clone(), return_to, key: metadata.key, procedure, result,
        });
        // Win16 enters a resource handler with both data segments pointing
        // at the caller's stack. The saved frame restores them on return.
        registers.ds = registers.ss;
        registers.es = registers.ss;
        registers.set_sp(sp);
        registers.cs = (procedure >> 16) as u16;
        registers.set_ip(procedure as u16);
        Ok(None)
    }

    fn finish_resource_result(&mut self, key: ResourceKey, data: u16,
        result: ResourceReturn, memory: &Memory) -> Result<(u32, Win16ReturnKind), RuntimeError> {
        match result {
            ResourceReturn::Load => Ok((u32::from(self.commit_loaded_resource(key, data)?),
                Win16ReturnKind::Word)),
            ResourceReturn::Lock => {
                let data = self.commit_reloaded_resource(key, data)?;
                Ok((if data == 0 { 0 } else { self.global_lock(data, memory)? },
                    Win16ReturnKind::FarPointer))
            }
        }
    }

    pub(super) fn finish_resource_callback(&mut self, registers: &mut Registers,
        memory: &Memory, host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Resource)?;
        let frame = self.resource_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 resource callback has no saved frame"))?;
        if frame.callback_id != callback_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 resource callback differs from the exact shared LIFO identity"));
        }
        if registers.ip() != 0 || registers.ss != frame.saved.ss || registers.sp() != frame.saved.sp() {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 resource callback returned with an unexpected stack or gate"));
        }
        let (key, result, saved, return_to) = {
            let frame = self.resource_callbacks.last().expect("checked resource callback");
            (frame.key, frame.result, frame.saved.clone(), frame.return_to)
        };
        let (value, kind) = self.finish_resource_result(key, registers.ax(), result, memory)?;
        host.observe_win16_io(&crate::Win16IoEvent::ResourceResult {
            operation: "resource-callback-complete", module: key.module,
            resource: key.info, value,
        });
        let mut completed = saved;
        self.complete_return(&mut completed, return_to.0, return_to.1,
            return_to.2, value, kind)?;
        self.retire_callback_binding(CallbackKind::Resource, callback_id)?;
        self.resource_callbacks.pop().expect("resource callback frame checked before retirement");
        *registers = completed;
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_resource_callback_for_teardown(
        &mut self,
        _ended: &super::execute::Win16TaskExecutionEnded,
        _cpu: &mut x86_cpu::Cpu,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Resource)?;
        if self.resource_callbacks.last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 resource callback is not the exact retained LIFO frame"));
        }
        Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 resource callback has no checked full-CPU continuation for terminal cancellation; its exact frame remains retained"))
    }

    pub(super) fn resource_code_references(&self) -> Vec<u32> {
        self.resource_callbacks.iter().flat_map(|frame| [frame.procedure,
            u32::from(frame.key.module) << 16,
            u32::from(frame.saved.cs) << 16,
            u32::from(frame.return_to.0) << 16]).collect()
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
