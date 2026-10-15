//! Guest CPU continuations for DLL initialization and WEP teardown.

use std::collections::VecDeque;
use win16_abi::{Win16ProcReference, Win16ReturnKind};
use super::*;
use super::module_registry::ModuleState;
use super::module_loading::ModuleRemoval;
use dos_kernel::DosKernel;
use x86_cpu::Cpu;
#[path = "win16_module_calls/entry.rs"]
mod entry;
#[path = "win16_module_calls/finish.rs"]
mod finish;
#[path = "win16_module_calls/cpu.rs"]
mod cpu;
#[path = "win16_module_calls/startup.rs"]
mod startup;
#[path = "win16_module_calls/task_exit.rs"]
mod task_exit;
use cpu::ModuleCpuOwners;
use super::toolhelp_notify_exit::TaskExitModuleScope;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ModuleStartupState {
    Pending,
    Loading,
    Ready,
    Failed(u16),
}

enum ModuleAction {
    Discover { created: Vec<u16> },
    LoadFailure { code: u16, created: Vec<u16> },
    Load { root: u16, created: Vec<u16> },
    Unload { modules: Vec<u16>, failed_load: bool, resume: bool },
    TaskExit { modules: Vec<u16>, scope: TaskExitModuleScope },
}

enum ModuleCompletionPlan {
    LoadFailure { code: u16, modules: Vec<u16> },
    Load {
        root: u16,
        previous_refs: u16,
        explicit_refs: u16,
        value: u32,
    },
    Unload {
        modules: Vec<u16>,
        failed_load: bool,
        resume: bool,
    },
    TaskExit { modules: Vec<u16>, scope: TaskExitModuleScope },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModuleCallPhase {
    EnterNext,
    AwaitCallbackReturn,
    Complete,
    Returned,
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
    cpu: ModuleCpuOwners,
    completion: Option<ModuleCompletionPlan>,
    prepared: bool,
    terminal: bool,
    return_to: (u16, u16, u32),
    action: ModuleAction,
    phase: ModuleCallPhase,
    queue: VecDeque<u16>,
    active: Option<u16>,
    initialized: Vec<u16>,
    /// Startup restores an exact parked entry context, without a Pascal API
    /// return or an explicit LoadLibrary reference on the executable.
    startup: bool,
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
        references.extend(self.object_code_references());
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
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.preflight_module_cpu_owners(cpu)?;
        match self.module_callbacks.last().map(|frame| frame.phase) {
            Some(ModuleCallPhase::EnterNext) => {}
            Some(ModuleCallPhase::Complete | ModuleCallPhase::Returned) => {
                return self.complete_module_calls(cpu, dos, memory);
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
                return self.complete_module_calls(cpu, dos, memory);
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
            // KERNEL31 CallWEP skips pre-3.0 libraries and modules whose
            // LibMain was never entered. Ready data/resource-only images
            // must not gain a synthetic WEP invocation just by exporting it.
            let started = record.definition.as_ref().is_some_and(|definition|
                definition.header.expected_windows_version >= 0x0300
                    && definition.header.flags & 0x8000 != 0)
                && record.loaded.as_ref().is_some_and(|loaded| loaded.code_entry.is_some());
            let entry = if loading { record.loaded.as_ref().and_then(|loaded| loaded.code_entry) }
                else if started {
                    self.module_entry(handle, &Win16ProcReference::Name(b"WEP".to_vec()), false)
                        .map_err(crate::runtime_error)?
                } else { None };
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
            if cpu.regs != saved {
                return Err(RuntimeError::new(Kind::GuestFault,
                    "DLL entry cannot replace a different caller register image"));
            }
            let mut entry_registers = saved;
            entry_registers.ds = data;
            entry_registers.es = data;
            if loading {
                // The Windows 3.1 SDK LIBENTRY.ASM passes ES:SI as the
                // reserved NULL argument to the C LibMain routine.
                entry_registers.es = 0;
                // StartLibrary supplies AX=1 on entry; the DLL's actual AX
                // return is still checked before committing initialization.
                entry_registers.set_ax(1); entry_registers.set_bx(0); entry_registers.set_si(0);
                entry_registers.set_cx(heap); entry_registers.set_di(instance);
            }
            let wep_argument = [super::far_callback::Win16FarCallbackArgument::Word(0)];
            let callback = self.enter_guest_far_callback_checked_with_registers(
                cpu, dos, memory, guest_code_reference(entry.selector.0, entry.offset),
                if loading { &[] } else { &wep_argument },
                super::far_callback::Win16FarCallbackConvention::Pascal,
                super::far_callback::Win16FarCallbackReturn::Word, entry_registers,
            )?;
            // Entry is now committed; publish its exact CPU owner before a
            // notification or any other fallible operation can run.
            let frame = self.module_callbacks.last_mut().expect("checked DLL source remains");
            frame.cpu.active_call = Some(callback);
            frame.active = Some(handle);
            frame.phase = ModuleCallPhase::AwaitCallbackReturn;
            if !loading {
                self.modules.records.get_mut(&handle).expect("retained WEP module").wep_called = true;
            }
            if let Some(start_dll_data) = start_dll_data {
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


}
