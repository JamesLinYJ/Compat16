//! Guest CPU continuations for DLL initialization and WEP teardown.

use std::collections::VecDeque;
use win16_abi::{Access, Win16ProcReference, Win16ReturnKind};
use super::*;
use super::module_registry::ModuleState;
use super::module_loading::ModuleRemoval;

enum ModuleAction {
    Load { root: u16, created: Vec<u16> },
    Unload { modules: Vec<u16>, failed_load: bool, resume: bool },
}

enum ModuleCompletionPlan {
    Load {
        root: u16,
        explicit_refs: u16,
        value: u32,
    },
    Unload {
        modules: Vec<u16>,
        failed_load: bool,
        resume: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModuleCallPhase {
    EnterNext,
    AwaitCallbackReturn,
    Complete,
}

enum ModuleExecution<'a> {
    Registers(&'a mut Registers),
    Cpu(&'a mut x86_cpu::Cpu),
}

impl ModuleExecution<'_> {
    fn cpu(&self) -> Option<&x86_cpu::Cpu> {
        match self {
            Self::Registers(_) => None,
            Self::Cpu(cpu) => Some(&**cpu),
        }
    }

    fn registers(&mut self) -> &mut Registers {
        match self {
            Self::Registers(registers) => registers,
            Self::Cpu(cpu) => &mut cpu.regs,
        }
    }

    fn restore_context(
        &mut self,
        context: &x86_cpu::CpuContext,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Cpu(cpu) => {
                cpu.restore_context(context)?;
                Ok(())
            }
            Self::Registers(_) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "automatic DLL teardown lost its CPU owner before context restore",
            )),
        }
    }
}

fn guest_code_reference(selector: u16, offset: u16) -> u32 {
    (u32::from(selector) << 16) | u32::from(offset)
}

fn copy_module_handles(
    handles: &[u16],
    context: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(handles.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, context, error)
    })?;
    copy.extend_from_slice(handles);
    Ok(copy)
}

pub(super) struct ModuleCallFrame {
    callback_id: CallbackFrameId,
    saved: Registers,
    resume_context: Option<x86_cpu::CpuContext>,
    return_to: (u16, u16, u32),
    action: ModuleAction,
    phase: ModuleCallPhase,
    queue: VecDeque<u16>,
    active: Option<u16>,
    expected_sp: u16,
    initialized: Vec<u16>,
}

impl Win16State {
    fn toolhelp_module_entry_target_at(
        &self,
        code_segment: u16,
        instruction_pointer: u16,
    ) -> Option<(&ModuleCallFrame, u16, Selector)> {
        let frame = self.module_callbacks.last()?;
        if frame.phase != ModuleCallPhase::AwaitCallbackReturn
            || frame.active != frame.queue.front().copied()
            || !matches!(&frame.action, ModuleAction::Load { .. })
        {
            return None;
        }
        let module = frame.active?;
        let record = self.modules.records.get(&module)?;
        if record.state != ModuleState::Initializing { return None; }
        let entry = record.loaded.as_ref()?.code_entry?;
        if entry.selector.0 != code_segment || entry.offset != instruction_pointer {
            return None;
        }
        Some((frame, module, entry.selector))
    }

    pub(super) fn toolhelp_notify_module_entry_boundary(
        &self,
        code_segment: u16,
        instruction_pointer: u16,
    ) -> bool {
        let Some((frame, module, entry_selector)) = self.toolhelp_module_entry_target_at(
            code_segment, instruction_pointer,
        ) else { return false; };
        self.callback_kinds.len() == self.callback_frame_ids.len()
            && self.callback_kinds.last() == Some(&CallbackKind::Module)
            && self.callback_frame_ids.last() == Some(&frame.callback_id)
            && self.selectors.reference(Selector(module)).is_ok()
            && self.selectors.reference(entry_selector).is_ok()
    }

    pub(super) fn toolhelp_notify_module_entry_matches(
        &self,
        module: u16,
        code_segment: u16,
        instruction_pointer: u16,
    ) -> bool {
        self.module_callbacks.last().is_some_and(|frame| frame.active == Some(module))
            && self.toolhelp_notify_module_entry_boundary(code_segment, instruction_pointer)
    }

    pub(super) fn toolhelp_notify_module_entry_scope_at(
        &self,
        code_segment: u16,
        instruction_pointer: u16,
    ) -> Result<Option<super::toolhelp_notify::Win16ToolhelpModuleEntryScope>, RuntimeError> {
        let Some((frame, module, _entry_selector)) = self.toolhelp_module_entry_target_at(
            code_segment, instruction_pointer,
        ) else {
            return Ok(None);
        };
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 callback kind and identity stacks differ at a DLL entry boundary"));
        }
        match (self.callback_kinds.last(), self.callback_frame_ids.last()) {
            (Some(kind), Some(callback_id))
                if *kind == CallbackKind::Module && *callback_id == frame.callback_id => {}
            (Some(kind), Some(_)) if *kind != CallbackKind::Module => {
                // A nested guest callback may happen to share LibMain's
                // address. It is not the module-entry continuation boundary.
                return Ok(None);
            }
            (Some(kind), Some(_)) if *kind == CallbackKind::Module => {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DLL entry address is owned by a different Module callback frame"));
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "DLL entry continuation has no exact central Module callback binding")),
        }
        self.toolhelp_notify_module_entry_scope(module)
    }

    pub(super) fn capture_toolhelp_module_entry_parent(
        &self,
        scope: super::toolhelp_notify::Win16ToolhelpModuleEntryScope,
        event: &super::toolhelp_notify::Win16ToolhelpNotifyEvent,
        cpu: &x86_cpu::Cpu,
    ) -> Result<super::toolhelp_notify::Win16ToolhelpModuleEntryParent, RuntimeError> {
        let (module, module_generation, notification) = match &event.data {
            super::toolhelp_notify::Win16ToolhelpNotifyData::LoadSegment {
                module_handle, module_generation, ..
            } => (*module_handle, *module_generation,
                super::toolhelp_notify::NFY_LOADSEG),
            super::toolhelp_notify::Win16ToolhelpNotifyData::StartDll {
                module, module_generation, code_segment, instruction_pointer,
            } => {
                if cpu.regs.cs != *code_segment || cpu.regs.ip() != *instruction_pointer {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "STARTDLL publication left its exact LibMain instruction boundary"));
                }
                (*module, *module_generation, super::toolhelp_notify::NFY_STARTDLL)
            }
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "non-loader event entered a scoped DLL notification queue")),
        };
        if event.task != scope.task
            || event.notification != notification
            || event.termination_id.is_some()
            || event.module_root.is_some()
            || module != scope.module_handle
            || module_generation != scope.module_generation
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "scoped ToolHelp event does not match its exact module-entry owner"));
        }
        if self.toolhelp_notify_module_entry_scope_at(cpu.regs.cs, cpu.regs.ip())?
            != Some(scope)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "scoped ToolHelp event lost its exact pre-LibMain Module parent"));
        }
        let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "scoped ToolHelp event has no active Module continuation",
        ))?;
        Ok(super::toolhelp_notify::Win16ToolhelpModuleEntryParent {
            scope,
            module_callback_id: frame.callback_id,
        })
    }

    pub(super) fn validate_published_toolhelp_module_entry_parent(
        &self,
        child_callback_id: CallbackFrameId,
        parent: super::toolhelp_notify::Win16ToolhelpModuleEntryParent,
        event_task: u16,
    ) -> Result<(), RuntimeError> {
        let scope = parent.scope;
        let depth = self.callback_kinds.len();
        if depth != self.callback_frame_ids.len() || depth < 2 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child has no well-formed Module callback parent"));
        }
        if self.callback_kinds[depth - 1] != CallbackKind::ToolhelpNotify
            || self.callback_frame_ids[depth - 1] != child_callback_id
            || self.callback_kinds[depth - 2] != CallbackKind::Module
            || self.callback_frame_ids[depth - 2] != parent.module_callback_id
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child is not above its exact Module callback parent"));
        }
        let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "published ToolHelp child lost its retained Module continuation",
        ))?;
        if frame.callback_id != parent.module_callback_id
            || frame.phase != ModuleCallPhase::AwaitCallbackReturn
            || frame.active != Some(scope.module_handle)
            || frame.active != frame.queue.front().copied()
            || !matches!(&frame.action, ModuleAction::Load { .. })
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child no longer has its exact active Module frame"));
        }
        let record = self.modules.records.get(&scope.module_handle).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child lost its exact module record")
        })?;
        if event_task != scope.task
            || self.current_task_handle()? != scope.task
            || record.state != ModuleState::Initializing
            || record.external_application.is_some()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child changed task or module lifetime"));
        }
        let module_generation = self.selectors.reference(Selector(scope.module_handle))
            .map_err(crate::runtime_error)?;
        if module_generation != scope.module_generation {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child module selector generation changed"));
        }
        let entry = record.loaded.as_ref().and_then(|loaded| loaded.code_entry)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child lost the exact LibMain entry"))?;
        let entry_generation = self.selectors.reference(entry.selector)
            .map_err(crate::runtime_error)?;
        if entry_generation != scope.entry_selector_generation
            || self.toolhelp_notify_frames.last().map(|frame| frame.callback_id.0)
                != scope.parent_notification_callback
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "published ToolHelp child lost its exact entry generation or parent notification"));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_module_callback_for_teardown(
        &mut self,
        _ended: &super::execute::Win16TaskExecutionEnded,
        _cpu: &mut x86_cpu::Cpu,
    ) -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Module)?;
        if self.module_callbacks.last()
            .is_none_or(|frame| frame.callback_id != callback_id)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 module callback is not the exact retained LIFO frame"));
        }
        Err(RuntimeError::new(Kind::CompatibilityGap,
            "Win16 module callback has no checked full-CPU continuation for terminal cancellation; its exact frame remains retained"))
    }

    fn return_failed_load_attempt<T>(
        &mut self,
        created: &[u16],
        result: Result<Result<T, u16>, RuntimeError>,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let cleanup = self.rollback_modules(created);
        match result {
            Err(primary) => match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(primary.with_cleanup(
                    "Win16 LoadLibrary retained its primary failure and module rollback failure",
                    cleanup,
                )),
            },
            Ok(Err(code)) => match cleanup {
                Ok(()) => self.complete_return(
                    registers, return_to.0, return_to.1, return_to.2,
                    u32::from(code), Win16ReturnKind::Word,
                ),
                Err(cleanup) => Err(cleanup.with_context(format!(
                    "Win16 LoadLibrary returned guest error {code}; module rollback was incomplete",
                ))),
            },
            Ok(Ok(_)) => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "successful Win16 module discovery entered the failure rollback path",
            )),
        }
    }

    fn preflight_module_resume_context(
        &self,
        cpu: Option<&x86_cpu::Cpu>,
    ) -> Result<(), RuntimeError> {
        let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "DLL continuation frame is missing"))?;
        let Some(context) = frame.resume_context.as_ref() else {
            return Ok(());
        };
        let Some(cpu) = cpu else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "automatic DLL teardown lost its CPU owner before continuation work",
            ));
        };
        cpu.check_context(context)?;
        Ok(())
    }

    pub(super) fn begin_load_library(&mut self, name: &[u8], registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, return_to: (u16, u16, u32))
        -> Result<Option<u8>, RuntimeError> {
        let mut created = Vec::new();
        let result = self.discover_library(name, memory, host, &mut created, 0);
        let root = match result {
            Ok(Ok(root)) => root,
            failure => return self.return_failed_load_attempt(
                &created, failure, registers, return_to,
            ),
        };
        match self.relocate_libraries(&created, memory, host) {
            Ok(Ok(())) => {}
            failure => return self.return_failed_load_attempt(
                &created, failure, registers, return_to,
            ),
        }
        let queue = self.module_initialization_order(root, &created).into();
        let callback_id = self.reserve_callback_frame_id()?;
        self.module_callbacks.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 DLL load continuation frame",
            error,
        ))?;
        self.push_callback_kind(CallbackKind::Module, callback_id)?;
        for &handle in &created {
            self.modules.records.get_mut(&handle).expect("new module").state = ModuleState::Initializing;
        }
        self.module_callbacks.push(ModuleCallFrame {
            callback_id, saved: registers.clone(), return_to,
            resume_context: None,
            action: ModuleAction::Load { root, created }, phase: ModuleCallPhase::EnterNext,
            queue, active: None,
            expected_sp: registers.sp(), initialized: Vec::new(),
        });
        self.advance_module_calls(ModuleExecution::Registers(registers), memory, host)?;
        Ok(None)
    }

    pub(super) fn begin_free_library(&mut self, input: u16, registers: &mut Registers,
        memory: &mut Memory, host: &mut impl RuntimeHost, return_to: (u16, u16, u32))
        -> Result<Option<u8>, RuntimeError> {
        let callback_id = self.reserve_callback_frame_id()?;
        if let Some(handle) = self.modules.by_handle(input) {
            if let Some(record) = self.modules.records.get_mut(&handle) {
                if !record.pinned { record.explicit_refs = record.explicit_refs.saturating_sub(1); }
            }
        }
        self.module_reap_pending = true;
        let candidates = self.modules.unreachable(&[]);
        self.release_module_classes(&candidates, host)?;
        let roots = self.module_code_roots(guest_code_reference(return_to.0, return_to.1))?;
        let modules = self.modules.unreachable(&roots);
        // Dependents initialize last; their WEP must run before dependencies.
        let mut order = Vec::new();
        for &handle in &modules {
            for next in self.module_initialization_order(handle, &modules) {
                if !order.contains(&next) { order.push(next); }
            }
        }
        order.reverse();
        self.module_callbacks.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 DLL unload continuation frame",
            error,
        ))?;
        self.push_callback_kind(CallbackKind::Module, callback_id)?;
        for &handle in &modules {
            let record = self.modules.records.get_mut(&handle).expect("unreachable module");
            if record.state != ModuleState::Retired {
                record.state = ModuleState::Unloading;
            }
        }
        self.module_callbacks.push(ModuleCallFrame {
            callback_id, saved: registers.clone(), return_to,
            resume_context: None,
            action: ModuleAction::Unload { modules, failed_load: false, resume: false },
            phase: ModuleCallPhase::EnterNext,
            queue: order.into(), active: None, expected_sp: registers.sp(), initialized: Vec::new(),
        });
        self.advance_module_calls(ModuleExecution::Registers(registers), memory, host)?;
        Ok(None)
    }

    /// Revisit zero-reference modules at execution safe points. Ordinary FAR
    /// returns and callback completion can release their last code reference.
    pub(super) fn reap_modules(&mut self, cpu: &mut x86_cpu::Cpu, memory: &mut Memory,
        host: &mut impl RuntimeHost) -> Result<(), RuntimeError> {
        if !self.module_reap_pending || !self.module_callbacks.is_empty()
            || cpu.interrupt_shadow_active() { return Ok(()); }
        let callback_id = self.reserve_callback_frame_id()?;
        let resume_context = cpu.capture_context();
        cpu.check_context(&resume_context)?;
        let registers = &mut cpu.regs;
        let candidates = self.modules.unreachable(&[]);
        self.release_module_classes(&candidates, host)?;
        let roots = self.module_code_roots(guest_code_reference(registers.cs, registers.ip()))?;
        let modules = self.modules.unreachable(&roots);
        if modules.is_empty() {
            self.module_reap_pending = self.has_reapable_unreachable_modules()?;
            return Ok(());
        }
        let mut order = Vec::new();
        for &handle in &modules {
            for next in self.module_initialization_order(handle, &modules) {
                if !order.contains(&next) { order.push(next); }
            }
        }
        order.reverse();
        self.module_callbacks.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 automatic DLL teardown continuation frame",
            error,
        ))?;
        self.push_callback_kind(CallbackKind::Module, callback_id)?;
        for handle in &modules {
            let record = self.modules.records.get_mut(handle).expect("module");
            if record.state != ModuleState::Retired {
                record.state = ModuleState::Unloading;
            }
        }
        self.module_callbacks.push(ModuleCallFrame {
            callback_id, saved: registers.clone(), return_to: (registers.cs, registers.ip(), u32::from(registers.sp())),
            resume_context: Some(resume_context),
            action: ModuleAction::Unload { modules, failed_load: false, resume: true },
            phase: ModuleCallPhase::EnterNext,
            queue: order.into(), active: None, expected_sp: registers.sp(), initialized: Vec::new(),
        });
        self.advance_module_calls(ModuleExecution::Cpu(cpu), memory, host)
    }

    fn module_code_roots(&self, return_address: u32) -> Result<Vec<u16>, RuntimeError> {
        self.collect_module_code_roots(return_address, None)
    }

    fn module_code_roots_after_callback_return(
        &self,
        return_address: u32,
    ) -> Result<Vec<u16>, RuntimeError> {
        let Some(active_frame) = self.module_callbacks.len().checked_sub(1) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "returned DLL callback lost its continuation frame",
            ));
        };
        if self.module_callbacks[active_frame].active.is_none() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "returned DLL callback lost its active module owner",
            ));
        }
        self.collect_module_code_roots(return_address, Some(active_frame))
    }

    fn pop_module_call_front(&mut self, expected: u16) -> Result<(), RuntimeError> {
        let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "DLL continuation frame is missing"))?;
        if frame.active.is_some() || frame.phase != ModuleCallPhase::EnterNext
            || frame.queue.front().copied() != Some(expected)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLL queue owner changed before its completion was committed",
            ));
        }
        frame.queue.pop_front().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 DLL queue owner disappeared during completion"))?;
        Ok(())
    }

    fn collect_module_code_roots(
        &self,
        return_address: u32,
        excluded_active_frame: Option<usize>,
    ) -> Result<Vec<u16>, RuntimeError> {
        // Preserve selector:offset references through owner lookup; only the
        // final root set is module handles consumed by `unreachable`.
        let mut references = self.window_code_references();
        references.extend(self.font_code_references());
        references.extend(self.line_dda_code_references());
        references.extend(self.window_enumeration_code_references());
        references.extend(self.user_hook_code_references());
        references.extend(self.ole1_callback_code_references());
        references.extend(self.asynchronous_callback_code_references());
        references.extend(self.class_code_references());
        references.extend(self.proc_code_references());
        references.extend(self.toolhelp_code_references());
        references.extend(self.toolhelp_notify_code_references());
        references.extend(self.toolhelp_notify_active_code_references());
        references.extend(self.acm.code_references());
        references.extend(self.kernel_file_system.code_references());
        references.extend(self.protected_dos_vectors.values().flatten()
            .map(|pointer| pointer.far_value()));
        references.extend(self.win87em_exception_handler.iter()
            .map(|pointer| pointer.far_value()));
        references.extend(self.resource_code_references());
        references.extend(self.mci_code_references()?);
        references.push(return_address);
        references.extend(self.far_returns.iter().map(|entry| u32::from(entry.selector) << 16));
        references.extend(self.interrupt_returns.iter()
            .map(|entry| u32::from(entry.code.raw().0) << 16));
        for (index, frame) in self.module_callbacks.iter().enumerate() {
            references.push(guest_code_reference(frame.saved.cs, frame.saved.ip()));
            references.push(guest_code_reference(frame.return_to.0, frame.return_to.1));
            if excluded_active_frame != Some(index)
                && let Some(active) = frame.active
            {
                if let Some(record) = self.modules.records.get(&active) {
                    references.push(u32::from(record.handle) << 16);
                }
            }
        }
        let mut roots: Vec<_> = references.into_iter().filter_map(|address|
            self.modules.retained_owner((address >> 16) as u16, &self.selectors)).collect();
        roots.extend(self.selector_backing_leases.values().flat_map(|entry|
            entry.leases.iter().filter_map(
                super::selector_ownership::SelectorBackingLease::module,
            )));
        roots.extend(self.class_owner_modules());
        roots.extend(self.proc_owner_modules());
        self.retain_resource_handler_modules(&mut roots);
        roots.extend(self.user_accelerator_module_roots());
        Ok(roots)
    }

    fn advance_module_calls(
        &mut self,
        mut execution: ModuleExecution<'_>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        // Reject a profile mismatch before changing the entry phase or doing
        // any WEP/entry work. The full restore follows every callback.
        self.preflight_module_resume_context(execution.cpu())?;
        match self.module_callbacks.last().map(|frame| frame.phase) {
            Some(ModuleCallPhase::EnterNext) => {}
            Some(ModuleCallPhase::Complete) => {
                return self.complete_module_calls(&mut execution);
            }
            Some(ModuleCallPhase::AwaitCallbackReturn) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DLL entry advanced before its guest callback returned",
                ));
            }
            None => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL continuation frame is missing",
                ));
            }
        }
        loop {
            let handle = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "DLL continuation frame is missing"))?
                .queue.front().copied();
            let Some(handle) = handle else {
                let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "DLL continuation frame is missing"))?;
                frame.phase = ModuleCallPhase::Complete;
                return self.complete_module_calls(&mut execution);
            };
            let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "DLL continuation frame is missing"))?;
            if frame.active.is_some() || frame.phase != ModuleCallPhase::EnterNext {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DLL entry queue has no matching continuation phase",
                ));
            }
            let loading = matches!(frame.action, ModuleAction::Load { .. });
            let saved = frame.saved.clone();
            let record = self.modules.records.get(&handle).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "DLL continuation module is missing"))?;
            if !loading && record.wep_called {
                self.pop_module_call_front(handle)?;
                continue;
            }
            if record.definition.is_none() {
                self.pop_module_call_front(handle)?;
                continue;
            }
            let entry = if loading { record.loaded.as_ref().and_then(|loaded| loaded.code_entry) }
                else { self.module_entry(handle, &Win16ProcReference::Name(b"WEP".to_vec()), false)
                    .map_err(crate::runtime_error)? };
            let Some(entry) = entry else {
                let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "DLL continuation frame is missing"))?;
                if frame.active.is_some() || frame.phase != ModuleCallPhase::EnterNext
                    || frame.queue.front().copied() != Some(handle)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DLL entry owner changed before its no-entry completion",
                    ));
                }
                if loading {
                    frame.initialized.try_reserve(1).map_err(|error| RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve initialized Win16 DLL continuation owner",
                            error,
                        ))?;
                }
                let record = self.modules.records.get_mut(&handle).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "DLL continuation module is missing"))?;
                let _ = frame.queue.pop_front();
                if loading {
                    record.state = ModuleState::Ready;
                    frame.initialized.push(handle);
                }
                continue;
            };
            let record = &self.modules.records[&handle];
            let definition = record.definition.as_ref().expect("NE definition");
            let name = record.name.clone();
            let data = if definition.header.flags & 1 != 0 {
                record.loaded.as_ref().and_then(|loaded|
                    loaded.segment_selector(definition.header.automatic_data_segment)).map_or(0, |selector| selector.0)
            } else { 0 };
            let heap = if data == 0 { 0 } else { definition.header.heap_size };
            let instance = record.instance;
            let start_dll_data = if loading {
                Some(super::toolhelp_notify::Win16ToolhelpNotifyData::StartDll {
                    module: handle,
                    module_generation: self.selectors
                        .reference(guest_core::Selector(handle))
                        .map_err(crate::runtime_error)?,
                    code_segment: entry.selector.0,
                    instruction_pointer: entry.offset,
                })
            } else {
                None
            };
            let size = if loading { 4 } else { 6 };
            let sp = saved.sp().checked_sub(size).ok_or_else(|| RuntimeError::new(
                Kind::GuestFault, "Win16 DLL entry has insufficient guest stack"))?;
            let target = self.selectors.pointer_from_raw(entry.selector, entry.offset).map_err(crate::runtime_error)?;
            self.selectors.translate(target, Access::Execute, 1, memory).map_err(crate::runtime_error)?;
            let stack = self.selectors.pointer_from_raw(Selector(saved.ss), sp).map_err(crate::runtime_error)?;
            let mut bytes = vec![0_u8; usize::from(size)];
            bytes[2..4].copy_from_slice(&self.callback_gate_selector.0.to_le_bytes());
            // FreeLibrary invokes WEP(0), where 0 is WEP_FREE_DLL.
            self.selectors.write(memory, stack, &bytes).map_err(crate::runtime_error)?;

            // The callback gate now has a checked far-return frame. Commit
            // queue/active/WEP ownership only after that guest frame exists.
            let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "DLL continuation frame is missing"))?;
            let record = self.modules.records.get_mut(&handle).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "DLL continuation module is missing"))?;
            if frame.queue.front().copied() != Some(handle)
                || frame.active.is_some()
                || frame.phase != ModuleCallPhase::EnterNext
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DLL entry owner changed before callback publication",
                ));
            }
            if !loading {
                record.wep_called = true;
            }
            frame.active = Some(handle);
            frame.phase = ModuleCallPhase::AwaitCallbackReturn;
            let registers = execution.registers();
            *registers = saved;
            registers.cs = entry.selector.0;
            registers.set_ip(entry.offset);
            registers.set_sp(sp);
            registers.ds = data;
            registers.es = data;
            if let Some(start_dll_data) = start_dll_data {
                registers.set_ax(0); registers.set_bx(0); registers.set_si(0);
                registers.set_cx(heap); registers.set_di(instance);
                // Queue STARTDLL only after the exact module continuation has
                // been committed, but before the execute loop can step the
                // first LibMain instruction.
                self.queue_toolhelp_notify_current(
                    super::toolhelp_notify::NFY_STARTDLL,
                    start_dll_data,
                )?;
                host.report_diagnostic(&Diagnostic::info(Kind::CompatibilityGap,
                    format!("Win16 initializes {} at {:04X}:{:04X}",
                        String::from_utf8_lossy(&name), entry.selector.0, entry.offset)));
            }
            return Ok(());
        }
    }

    pub(super) fn finish_module_callback(&mut self, cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory, host: &mut impl RuntimeHost)
        -> Result<(), RuntimeError> {
        // Keep the active module and its continuation frame available if the
        // immutable machine profile does not match the saved resume context.
        self.preflight_module_resume_context(Some(cpu))?;
        let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
            Kind::GuestFault, "Win16 DLL return has no active entry"))?;
        if cpu.regs.ip() != 0 || cpu.regs.ss != frame.saved.ss || cpu.regs.sp() != frame.expected_sp {
            return Err(RuntimeError::new(Kind::GuestFault, "Win16 DLL entry returned with an unexpected stack"));
        }
        let Some(handle) = frame.active else {
            // A prior completion attempt may have returned a typed failure
            // while this callback-gate return still owns the top frame.
            return self.advance_module_calls(ModuleExecution::Cpu(cpu), memory, host);
        };
        if frame.phase != ModuleCallPhase::AwaitCallbackReturn
            || frame.queue.front().copied() != Some(handle)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 DLL callback return lost its queued module owner",
            ));
        }
        let loading = matches!(frame.action, ModuleAction::Load { .. });
        if loading && cpu.regs.ax() == 0 {
            let (return_address, created, initialized) = {
                let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant, "failed Win16 DLL load lost its continuation frame"))?;
                let ModuleAction::Load { created, .. } = &frame.action else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "failed Win16 DLL initialization changed its action before rollback",
                    ));
                };
                let created = copy_module_handles(
                    created,
                    "reserve Win16 DLL rollback module owners",
                )?;
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
            unloading.try_reserve_exact(created.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve failed-load Win16 DLL retirement plan",
                    error,
                )
            })?;
            let mut queue = VecDeque::new();
            queue.try_reserve_exact(initialized.len()).map_err(|error| {
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
            let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "failed Win16 DLL commit lost its continuation frame"))?;
            frame.action = ModuleAction::Unload {
                modules: unloading,
                failed_load: true,
                resume: false,
            };
            frame.queue = queue;
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                "Win16 library initialization returned FALSE; rolling back LoadLibrary"));
        } else if loading {
            let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "initialized DLL lost its continuation frame"))?;
            let record = self.modules.records.get_mut(&handle).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "initialized DLL is missing"))?;
            if frame.phase != ModuleCallPhase::AwaitCallbackReturn
                || frame.active != Some(handle)
                || frame.queue.front().copied() != Some(handle)
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "initialized DLL callback changed its continuation owner before commit",
                ));
            }
            frame.initialized.try_reserve(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve initialized Win16 DLL continuation owner",
                error,
            ))?;
            let _ = frame.queue.pop_front();
            record.state = ModuleState::Ready;
            frame.initialized.push(handle);
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
        } else {
            let frame = self.module_callbacks.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "WEP return lost its continuation frame"))?;
            let _ = frame.queue.pop_front();
            frame.active = None;
            frame.phase = ModuleCallPhase::EnterNext;
        }
        self.advance_module_calls(ModuleExecution::Cpu(cpu), memory, host)
    }

    fn complete_module_calls(&mut self, execution: &mut ModuleExecution<'_>)
        -> Result<(), RuntimeError> {
        let callback_id = self.require_callback_top(CallbackKind::Module)?;
        let (plan, saved, return_to) = {
            let frame = self.module_callbacks.last().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 DLL completion has no frame"))?;
            if frame.callback_id != callback_id
                || frame.phase != ModuleCallPhase::Complete
                || frame.active.is_some()
                || !frame.queue.is_empty()
            {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 DLL completion began before its continuation queue was exhausted",
                ));
            }
            let plan = match &frame.action {
                ModuleAction::Load { root, .. } => {
                    let record = self.modules.records.get(root).ok_or_else(|| RuntimeError::new(
                        Kind::InternalInvariant, "loaded Win16 DLL is missing"))?;
                    let explicit_refs = record.explicit_refs.checked_add(1).ok_or_else(|| {
                        RuntimeError::new(
                            Kind::ResourceExhausted,
                            "Win16 module reference count overflow",
                        )
                    })?;
                    ModuleCompletionPlan::Load {
                        root: *root,
                        explicit_refs,
                        value: u32::from(record.instance),
                    }
                }
                ModuleAction::Unload { modules, failed_load, resume } => {
                    if *resume && frame.resume_context.is_none() {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "automatic DLL teardown has no saved CPU context",
                        ));
                    }
                    ModuleCompletionPlan::Unload {
                        modules: copy_module_handles(
                            modules,
                            "reserve Win16 DLL completion module owners",
                        )?,
                        failed_load: *failed_load,
                        resume: *resume,
                    }
                }
            };
            (plan, frame.saved.clone(), frame.return_to)
        };

        let (resume, value, kind) = match &plan {
            ModuleCompletionPlan::Load { value, .. } => {
                (false, *value, Win16ReturnKind::Word)
            }
            ModuleCompletionPlan::Unload { failed_load, resume, .. } => (
                *resume,
                0,
                if *failed_load { Win16ReturnKind::Word } else { Win16ReturnKind::Void },
            ),
        };
        if let ModuleCompletionPlan::Unload { modules, .. } = &plan {
            // WEP may publish new callbacks. Recheck after all WEP calls,
            // retaining retired code until those references are released.
            for handle in modules {
                if let Some(record) = self.modules.records.get_mut(handle) {
                    record.state = ModuleState::Retired;
                    record.wep_called = true;
                }
            }
            let mut roots = self.module_code_roots(guest_code_reference(return_to.0, return_to.1))?;
            let segment_lock_roots = self.module_segment_lock_roots()?;
            roots.try_reserve(segment_lock_roots.len()).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 post-WEP segment-lock roots",
                    error,
                )
            })?;
            roots.extend(segment_lock_roots);
            let unused = self.modules.unreachable(&roots);
            for &handle in modules {
                if unused.contains(&handle) {
                    match self.remove_module(handle)? {
                        ModuleRemoval::Removed | ModuleRemoval::DeferredByGuestLock => {}
                    }
                }
            }
            self.module_reap_pending = self.has_reapable_unreachable_modules()?;
        }

        if resume {
            let context = self.module_callbacks.last()
                .and_then(|frame| frame.resume_context.as_ref())
                .ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "automatic DLL teardown lost its saved CPU context before restore",
                ))?;
            execution.restore_context(context)?;
        }

        let mut completed_registers = saved;
        if !resume {
            self.complete_return(
                &mut completed_registers,
                return_to.0,
                return_to.1,
                return_to.2,
                value,
                kind,
            )?;
        }
        if let ModuleCompletionPlan::Load { root, explicit_refs, .. } = plan {
            let record = self.modules.records.get_mut(&root).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "loaded Win16 DLL disappeared before completion commit",
            ))?;
            record.explicit_refs = explicit_refs;
        }
        let frame = self.module_callbacks.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 DLL completion lost its retained frame"))?;
        if frame.callback_id != callback_id {
            self.module_callbacks.push(frame);
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 DLL completion popped a different continuation owner"));
        }
        if let Err(error) = self.retire_callback_binding(CallbackKind::Module, callback_id) {
            self.module_callbacks.push(frame);
            return Err(error);
        }
        *execution.registers() = completed_registers;
        Ok(())
    }
}
