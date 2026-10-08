//! Task-local Win16 USER hook chains.
//!
//! The implemented delivery path is task-local WH_MSGFILTER. The Windows 3.1
//! Programmer's Reference defines both the HHOOK-returning legacy API and its
//! extended form; the HOOKS/MAKEAPP samples establish the callback usage. Other
//! hook kinds and system-scope hooks require typed event delivery and are
//! rejected until that path is connected. No native process-wide hook is
//! installed here.

use dos_kernel::DosKernel;
use guest_core::{GuestMemory, memory::Memory};
use win16_abi::{Access, DescriptorInfo, SelectorRef};

use super::{Win16State, far_callback::Win16FarCallbackReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16GuestCallbackToken,
};

#[path = "win16_user_hooks_callback.rs"]
mod callback;

const WH_MSGFILTER: i16 = -1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct HookNodeId(u64);

#[derive(Clone, Debug)]
struct HookRegistration {
    id: HookNodeId,
    /// Opaque Win16 HHOOK token. It is only compared against this family map;
    /// it is never converted to a native handle or pointer.
    handle: u32,
    hook_type: i16,
    task: u16,
    procedure: u32,
    selector: SelectorRef,
    descriptor: DescriptorInfo,
    callback_token: Win16GuestCallbackToken,
    next: Option<HookNodeId>,
    installed: bool,
}

/// Family state is separate from the shared callback LIFO. Each callback
/// frame is also bound to that shared stack with a `CallbackFrameId`.
pub(super) struct Win16UserHooks {
    next_node_id: u64,
    next_hook_handle: u32,
    registrations: Vec<HookRegistration>,
    callbacks: callback::HookCallbackStack,
}

impl Default for Win16UserHooks {
    fn default() -> Self {
        Self {
            next_node_id: 1,
            next_hook_handle: 1,
            registrations: Vec::new(),
            callbacks: callback::HookCallbackStack::default(),
        }
    }
}

impl Win16UserHooks {
    fn entry(&self, id: HookNodeId) -> Option<&HookRegistration> {
        self.registrations.iter().find(|entry| entry.id == id)
    }

    fn by_handle(&self, handle: u32) -> Option<&HookRegistration> {
        self.registrations
            .iter()
            .find(|entry| entry.handle == handle)
    }

    fn head(&self, task: u16, hook_type: i16) -> Option<&HookRegistration> {
        self.registrations
            .iter()
            .rev()
            .find(|entry| entry.installed && entry.task == task && entry.hook_type == hook_type)
    }

    fn resolve_next(&self, id: HookNodeId) -> Option<&HookRegistration> {
        let next = self.entry(id)?.next?;
        self.entry(next).filter(|entry| entry.installed)
    }
}

impl Win16State {
    /// Install a task-local WH_MSGFILTER procedure and return its opaque HHOOK.
    /// Windows 3.1 specifies NULL on failure; an empty prior chain does not
    /// change the successful return value.
    pub(super) fn set_windows_hook(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        hook_type: i16,
        procedure: u32,
    ) -> Result<u32, RuntimeError> {
        let task = self.current_task_handle()?;
        self.install_task_hook(memory, host, hook_type, procedure, task, None)
    }

    /// SetWindowsHookEx has task and module identity arguments. The SDK defines
    /// a null task as system scope; that cannot be safely emulated by a
    /// task-local continuation, so only this current task is accepted.
    pub(super) fn set_windows_hook_ex(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        hook_type: i16,
        procedure: u32,
        instance: u16,
        task: u16,
    ) -> Result<u32, RuntimeError> {
        let current_task = self.current_task_handle()?;
        if task == 0 {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 SetWindowsHookEx system-scope hooks have no connected guest event path",
            ));
            return Ok(0);
        }
        if task != current_task {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "Win16 SetWindowsHookEx task {task:#06x} is not the current task {current_task:#06x}"
                ),
            ));
            return Ok(0);
        }
        let Some(module) = (instance != 0)
            .then(|| self.module_handle_for_instance(instance))
            .flatten()
        else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("Win16 SetWindowsHookEx module instance {instance:#06x} is not loaded"),
            ));
            return Ok(0);
        };
        self.install_task_hook(memory, host, hook_type, procedure, task, Some(module))
    }

    fn install_task_hook(
        &mut self,
        memory: &Memory,
        host: &mut impl RuntimeHost,
        hook_type: i16,
        procedure: u32,
        task: u16,
        expected_module: Option<u16>,
    ) -> Result<u32, RuntimeError> {
        if hook_type != WH_MSGFILTER {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("Win16 hook type {hook_type} has no connected guest event path"),
            ));
            return Ok(0);
        }
        if procedure == 0 {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 hook registration with a null guest procedure failed",
            ));
            return Ok(0);
        }
        let pointer = self
            .selectors
            .pointer_from_far(procedure)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        let descriptor = self
            .selectors
            .describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let code_procedure = self.proc_instance_target(procedure).unwrap_or(procedure);
        let code_pointer = self
            .selectors
            .pointer_from_far(code_procedure)
            .map_err(crate::runtime_error)?;
        let Some(module) = self.live_code_module_owner(code_pointer.selector().raw().0) else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 hook procedure is not owned by a live module",
            ));
            return Ok(0);
        };
        if expected_module.is_some_and(|expected| module != expected) {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 SetWindowsHookEx module does not contain the hook procedure",
            ));
            return Ok(0);
        }
        self.user_hooks
            .registrations
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain Win16 USER hook registration",
                    error,
                )
            })?;
        let next_id = self.user_hooks.next_node_id;
        let following_id = next_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 hook-registration identities exhausted",
            )
        })?;
        let handle = self.user_hooks.next_hook_handle;
        if handle == 0 {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 HHOOK token sequence reached its reserved null value",
            ));
        }
        let following_handle = handle.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 HHOOK token identities exhausted",
            )
        })?;
        let callback_token = self.register_guest_callback(
            memory,
            procedure,
            super::far_callback::Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Dword,
        )?;
        let next = self.user_hooks.head(task, hook_type).map(|entry| entry.id);
        self.user_hooks.registrations.push(HookRegistration {
            id: HookNodeId(next_id),
            handle,
            hook_type,
            task,
            procedure,
            selector: pointer.selector(),
            descriptor,
            callback_token,
            next,
            installed: true,
        });
        self.user_hooks.next_node_id = following_id;
        self.user_hooks.next_hook_handle = following_handle;
        Ok(handle)
    }

    /// Remove one matching task-local hook. Removal rewires all live chain
    /// links before retiring its checked callback registration.
    pub(super) fn unhook_windows_hook(
        &mut self,
        host: &mut impl RuntimeHost,
        hook_type: i16,
        procedure: u32,
    ) -> Result<u16, RuntimeError> {
        if hook_type != WH_MSGFILTER {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "Win16 UnhookWindowsHook type {hook_type} has no connected guest event path"
                ),
            ));
            return Ok(0);
        }
        let task = self.current_task_handle()?;
        let Some(index) = self.user_hooks.registrations.iter().rposition(|entry| {
            entry.installed
                && entry.task == task
                && entry.hook_type == hook_type
                && entry.procedure == procedure
        }) else {
            return Ok(0);
        };
        self.remove_hook_at(index);
        self.prune_retired_user_hook_nodes();
        Ok(1)
    }

    pub(super) fn unhook_windows_hook_ex(
        &mut self,
        host: &mut impl RuntimeHost,
        handle: u32,
    ) -> Result<u16, RuntimeError> {
        let task = self.current_task_handle()?;
        let Some(index) = self
            .user_hooks
            .registrations
            .iter()
            .position(|entry| entry.installed && entry.handle == handle && entry.task == task)
        else {
            return Ok(0);
        };
        if self.user_hooks.registrations[index].hook_type != WH_MSGFILTER {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 UnhookWindowsHookEx registration has no connected event path",
            ));
            return Ok(0);
        }
        self.remove_hook_at(index);
        self.prune_retired_user_hook_nodes();
        Ok(1)
    }

    fn remove_hook_at(&mut self, index: usize) {
        let removed = self.user_hooks.registrations[index].clone();
        self.user_hooks.registrations[index].installed = false;
        for entry in &mut self.user_hooks.registrations {
            if entry.next == Some(removed.id) {
                entry.next = removed.next;
            }
        }
    }

    pub(super) fn begin_call_msg_filter(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        message_far: u32,
        code: i16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let task = self.current_task_handle()?;
        let Some(entry) = self.user_hooks.head(task, WH_MSGFILTER).cloned() else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Word,
            );
        };
        self.validate_hook_entry(memory, &entry)?;
        // CallMsgFilter exposes a mutable MSG16 to guest hook code. Validate
        // both read and write access before entering that callback.
        self.validate_message_payload(memory, message_far)?;
        self.begin_hook_callback(
            cpu,
            dos,
            memory,
            entry,
            &[
                callback::HookArgument::Word(code as u16),
                callback::HookArgument::Word(0),
                callback::HookArgument::GuestPointer {
                    far: message_far,
                    access: Access::Write,
                    bytes: win16_abi::Msg16::SIZE as u32,
                },
            ],
            return_to,
            callback::HookCallbackReturn::CallMsgFilter,
        )
    }

    pub(super) fn begin_def_hook_proc(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        code: i16,
        w_param: u16,
        l_param: u32,
        hook_slot_far: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 callback kind and identity stacks differ during DefHookProc",
            ));
        }
        if self.callback_kinds.last() != Some(&super::CallbackKind::UserHook) {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 DefHookProc was called without an active USER hook callback",
            ));
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        }
        let callback_id = self.require_callback_top(super::CallbackKind::UserHook)?;
        if self.user_hooks.callbacks.active_callback_id() != Some(callback_id) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER hook callback differs from the shared callback LIFO top",
            ));
        }
        let current_id = self
            .user_hooks
            .callbacks
            .active_hook_node()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "DefHookProc was called outside an active Win16 hook callback",
                )
            })?;
        let current = self.user_hooks.entry(current_id).cloned().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "active Win16 hook callback lost its chain node",
            )
        })?;
        let slot = self
            .selectors
            .pointer_from_far(hook_slot_far)
            .map_err(crate::runtime_error)?;
        let slot_address = self
            .selectors
            .translate(slot, Access::Read, 4, memory)
            .map_err(crate::runtime_error)?;
        let mut bytes = [0_u8; 4];
        memory
            .read(slot_address, &mut bytes)
            .map_err(crate::runtime_error)?;
        let slot_hook = u32::from_le_bytes(bytes);
        if slot_hook != current.handle {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 DefHookProc HHOOK slot does not identify the active hook registration",
            ));
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        }
        let next = self.user_hooks.resolve_next(current_id).cloned();
        let Some(next) = next else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        };
        self.validate_hook_entry(memory, &next)?;
        self.validate_message_payload(memory, l_param)?;
        self.begin_hook_callback(
            cpu,
            dos,
            memory,
            next,
            &[
                callback::HookArgument::Word(code as u16),
                callback::HookArgument::Word(w_param),
                callback::HookArgument::GuestPointer {
                    far: l_param,
                    access: Access::Write,
                    bytes: win16_abi::Msg16::SIZE as u32,
                },
            ],
            return_to,
            callback::HookCallbackReturn::DefHookProc,
        )
    }

    /// CallNextHookEx can continue only the active task-local registration. The
    /// SDK declares WH_MSGFILTER's LPARAM as a mutable MSG pointer; retaining
    /// it as a checked guest pointer preserves its Win16 ABI bits.
    pub(super) fn begin_call_next_hook_ex(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        handle: u32,
        code: i16,
        w_param: u16,
        l_param: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 callback kind and identity stacks differ during CallNextHookEx",
            ));
        }
        if self.callback_kinds.last() != Some(&super::CallbackKind::UserHook) {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 CallNextHookEx was called without an active USER hook callback",
            ));
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        }
        let callback_id = self.require_callback_top(super::CallbackKind::UserHook)?;
        if self.user_hooks.callbacks.active_callback_id() != Some(callback_id) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER hook callback differs from the shared callback LIFO top during CallNextHookEx",
            ));
        }
        let task = self.current_task_handle()?;
        let active_id = self
            .user_hooks
            .callbacks
            .active_hook_node()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "CallNextHookEx was called outside an active hook procedure",
                )
            })?;
        let Some(current) = self.user_hooks.by_handle(handle).cloned() else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 CallNextHookEx received an unknown HHOOK token",
            ));
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        };
        if current.task != task || current.hook_type != WH_MSGFILTER || active_id != current.id {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 CallNextHookEx HHOOK does not identify the active task-local hook",
            ));
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        }
        let Some(next) = self.user_hooks.resolve_next(current.id).cloned() else {
            return self.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                win16_abi::Win16ReturnKind::Dword,
            );
        };
        self.validate_hook_entry(memory, &next)?;
        self.validate_message_payload(memory, l_param)?;
        self.begin_hook_callback(
            cpu,
            dos,
            memory,
            next,
            &[
                callback::HookArgument::Word(code as u16),
                callback::HookArgument::Word(w_param),
                callback::HookArgument::GuestPointer {
                    far: l_param,
                    access: Access::Write,
                    bytes: win16_abi::Msg16::SIZE as u32,
                },
            ],
            return_to,
            callback::HookCallbackReturn::CallNextHookEx,
        )
    }

    fn validate_message_payload(&self, memory: &Memory, far: u32) -> Result<(), RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(far)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Read, win16_abi::Msg16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Write, win16_abi::Msg16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        Ok(())
    }

    fn validate_hook_entry(
        &self,
        memory: &Memory,
        entry: &HookRegistration,
    ) -> Result<(), RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(entry.procedure)
            .map_err(crate::runtime_error)?;
        if pointer.selector() != entry.selector
            || self
                .selectors
                .describe(pointer.selector())
                .map_err(crate::runtime_error)?
                != entry.descriptor
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 hook procedure selector generation changed before guest entry",
            ));
        }
        self.selectors
            .translate(pointer, Access::Execute, 1, memory)
            .map_err(crate::runtime_error)?;
        Ok(())
    }

    pub(super) fn user_hook_code_references(&self) -> Vec<u32> {
        let mut references = Vec::new();
        for entry in &self.user_hooks.registrations {
            if entry.installed {
                references.push(entry.procedure);
            }
        }
        references.extend(self.user_hooks.callbacks.code_references(&self.user_hooks));
        references
    }

    fn prune_retired_user_hook_nodes(&mut self) {
        // New registrations only link to older nodes. Retire newest first,
        // so removing a link also makes its older target eligible in this pass.
        // Active callback frames still retain their exact node independently.
        let mut index = self.user_hooks.registrations.len();
        while index != 0 {
            index -= 1;
            let id = self.user_hooks.registrations[index].id;
            let active = self.user_hooks.callbacks.references_node(id);
            let referenced = self
                .user_hooks
                .registrations
                .iter()
                .any(|entry| entry.next == Some(id));
            if !self.user_hooks.registrations[index].installed && !active && !referenced {
                let removed = self.user_hooks.registrations.remove(index);
                let _ = self.unregister_guest_callback(removed.callback_token);
            }
        }
    }

    pub(in crate::win16_runtime) fn retire_user_hooks_for_task_end(&mut self) {
        for entry in &mut self.user_hooks.registrations {
            if entry.installed {
                entry.installed = false;
            }
        }
        self.prune_retired_user_hook_nodes();
    }
}
