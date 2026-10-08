//! Guest-owned ToolHelp notification registrations and checked BOOL callback ABI.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Access, SelectorRef, SelectorTable, SegmentedPointer};
use win16_abi::toolhelp_abi::{NF_TASKSWITCH, NF_RIP};

use super::far_callback::{
    Win16FarCallbackArgument, Win16FarCallbackConvention, Win16FarCallbackFrame,
    Win16FarCallbackReturn,
};
use super::toolhelp_notify_lifecycle::{
    Win16ToolhelpNotifyEventFrame, Win16ToolhelpNotifyProgress,
};
#[path = "win16_toolhelp_notify_module.rs"]
mod module_events;
#[path = "win16_toolhelp_notify_module_entry.rs"]
mod module_entry;
pub(super) use module_entry::{
    Win16ToolhelpModuleEntryParent, Win16ToolhelpModuleEntryScope,
};
#[path = "win16_toolhelp_notify_task.rs"]
mod task_owners;
#[path = "win16_toolhelp_notify_dispatch.rs"]
mod dispatch;
use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

pub(super) const NFY_RIP: u16 = win16_abi::toolhelp_abi::NFY_RIP;
pub(super) const NFY_EXITTASK: u16 = win16_abi::toolhelp_abi::NFY_EXITTASK;
pub(super) const NFY_LOADSEG: u16 = win16_abi::toolhelp_abi::NFY_LOADSEG;
const NFY_TASKIN: u16 = win16_abi::toolhelp_abi::NFY_TASKIN;
const NFY_TASKOUT: u16 = win16_abi::toolhelp_abi::NFY_TASKOUT;
pub(super) const NFY_FREESEG: u16 = win16_abi::toolhelp_abi::NFY_FREESEG;
pub(super) const NFY_STARTDLL: u16 = win16_abi::toolhelp_abi::NFY_STARTDLL;
pub(super) const NFY_DELMODULE: u16 = win16_abi::toolhelp_abi::NFY_DELMODULE;
pub(super) const NE_SEGMENT_DATA: u16 = 0x0001;
pub(super) const NE_LIBRARY: u16 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16ToolhelpNotifyRegistration {
    id: u64,
    /// Task passed to NotifyRegister; this controls registration lifetime,
    /// while notification callbacks run in the event's source task context.
    owner_task: u16,
    pub(super) callback: SegmentedPointer,
    pub(super) flags: u16,
}

#[derive(Clone, Debug)]
pub(super) enum Win16ToolhelpNotifyData {
    Scalar(u32),
    LoadSegment {
        module_handle: u16,
        module_generation: SelectorRef,
        selector_generation: SelectorRef,
        selector: u16,
        segment_number: u16,
        segment_type: u16,
        instance_count: u16,
        module_name: Vec<u8>,
    },
    StartDll {
        module: u16,
        module_generation: SelectorRef,
        code_segment: u16,
        instruction_pointer: u16,
    },
    FreeSegment {
        module_handle: u16,
        selector_generation: SelectorRef,
        selector: u16,
    },
    DeleteModule {
        module_handle: u16,
        selector_generation: SelectorRef,
    },
    Rip {
        instruction_pointer: u16,
        code_segment: u16,
        stack_segment: u16,
        base_pointer: u16,
        exit_code: u16,
    },
}

#[derive(Clone, Debug)]
pub(super) struct Win16ToolhelpNotifyEvent {
    /// HTASK active when KERNEL produced the event. It is not the task that
    /// owns each callback registration in the global Notify chain.
    pub(super) task: u16,
    pub(super) notification: u16,
    pub(super) data: Win16ToolhelpNotifyData,
    pub(super) registrations: Vec<Win16ToolhelpNotifyRegistration>,
    pub(super) termination_id: Option<u64>,
    pub(super) module_root: Option<u16>,
}

#[derive(Clone, Debug, Default)]
struct ModuleRetirementNotifications {
    announced_segments: BTreeSet<u16>,
    deletion_announced: bool,
    pending: usize,
}

/// Callback registrations are scoped to the real Win16 task handle and retain
/// the selector generation carried by `SegmentedPointer`.
#[derive(Clone, Debug)]
pub(super) struct Win16ToolhelpNotifyRegistry {
    by_task: BTreeMap<u16, Win16ToolhelpNotifyRegistration>,
    pending: VecDeque<Win16ToolhelpNotifyEvent>,
    /// Synchronous DLL-load events must run at their exact LibMain entry
    /// boundary, independently of unrelated global FIFO notifications.
    module_entry_pending: HashMap<Win16ToolhelpModuleEntryScope, VecDeque<Win16ToolhelpNotifyEvent>>,
    module_retirements: BTreeMap<u16, ModuleRetirementNotifications>,
    next_registration_id: u64,
}

impl Default for Win16ToolhelpNotifyRegistry {
    fn default() -> Self {
        Self {
            by_task: BTreeMap::new(),
            pending: VecDeque::new(),
            module_entry_pending: HashMap::new(),
            module_retirements: BTreeMap::new(),
            next_registration_id: 1,
        }
    }
}

impl Win16ToolhelpNotifyRegistry {
    pub(super) fn register(
        &mut self,
        task: u16,
        callback: u32,
        flags: u16,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        if task == 0 || callback == 0 || flags & !(NF_TASKSWITCH | NF_RIP) != 0
            || self.by_task.contains_key(&task)
        {
            return Ok(0);
        }
        let Ok(pointer) = selectors.pointer_from_far(callback) else { return Ok(0); };
        if selectors.translate(pointer, Access::Execute, 1, memory).is_err() {
            return Ok(0);
        }
        let id = self.next_registration_id;
        let Some(next_registration_id) = id.checked_add(1) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 ToolHelp notification registration identity exhausted",
            ));
        };
        self.by_task.insert(task, Win16ToolhelpNotifyRegistration {
            id,
            owner_task: task,
            callback: pointer,
            flags,
        });
        self.next_registration_id = next_registration_id;
        Ok(1)
    }

    pub(super) fn unregister(&mut self, task: u16) -> u16 {
        u16::from(self.by_task.remove(&task).is_some())
    }

    pub(super) fn enqueue(
        &mut self,
        event: Win16ToolhelpNotifyEvent,
    ) -> Result<bool, RuntimeError> {
        let mut events = Vec::new();
        events.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve one Win16 ToolHelp notification event",
            error,
        ))?;
        events.push(event);
        Ok(self.enqueue_batch(events)? != 0)
    }

    pub(super) fn enqueue_batch(
        &mut self,
        events: Vec<Win16ToolhelpNotifyEvent>,
    ) -> Result<usize, RuntimeError> {
        self.enqueue_batch_to(events, None)
    }

    fn enqueue_batch_to(
        &mut self,
        events: Vec<Win16ToolhelpNotifyEvent>,
        module_entry_scope: Option<Win16ToolhelpModuleEntryScope>,
    ) -> Result<usize, RuntimeError> {
        if let Some(scope) = module_entry_scope {
            for event in &events {
                let (module, generation, notification) = match &event.data {
                    Win16ToolhelpNotifyData::LoadSegment {
                        module_handle,
                        module_generation,
                        ..
                    } => (*module_handle, *module_generation, NFY_LOADSEG),
                    Win16ToolhelpNotifyData::StartDll {
                        module,
                        module_generation,
                        ..
                    } => (*module, *module_generation, NFY_STARTDLL),
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "non-loader ToolHelp event was assigned to a LibMain-entry scope")),
                };
                if event.task != scope.task
                    || event.notification != notification
                    || module != scope.module_handle
                    || generation != scope.module_generation
                    || event.termination_id.is_some()
                    || event.module_root.is_some()
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "ToolHelp module-entry event does not match its exact task/module scope"));
                }
            }
        }
        let mut accepted = Vec::new();
        accepted.try_reserve_exact(events.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 ToolHelp notification batch",
            error,
        ))?;
        for mut event in events {
            let recipients = self.by_task.values().filter(|registration|
                notification_matches(registration.flags, event.notification)).count();
            if recipients == 0 { continue; }
            event.registrations.try_reserve_exact(recipients).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "snapshot Win16 ToolHelp notification recipients",
                error,
            ))?;
            event.registrations.extend(self.by_task.values().copied().filter(|registration|
                notification_matches(registration.flags, event.notification)));
            // TOOLHELP.DLL appends registrations to one list and walks that
            // list in order; callback TRUE stops the same global chain.
            event.registrations.sort_unstable_by_key(|registration| registration.id);
            accepted.push(event);
        }
        let count = accepted.len();
        if count == 0 {
            return Ok(0);
        }
        let mut module_additions: Vec<(u16, usize)> = Vec::new();
        module_additions.try_reserve_exact(count).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve ToolHelp module-retirement event counts", error))?;
        for event in &accepted {
            if let Some(module) = event.module_root {
                if matches!(&event.data,
                    Win16ToolhelpNotifyData::FreeSegment { .. }
                        | Win16ToolhelpNotifyData::DeleteModule { .. })
                {
                    if let Some((_, amount)) = module_additions.iter_mut()
                        .find(|(existing, _)| *existing == module)
                    {
                        *amount = amount.checked_add(1).ok_or_else(|| RuntimeError::new(
                            Kind::ResourceExhausted,
                            "Win16 ToolHelp module-retirement batch count exhausted"))?;
                    } else {
                        module_additions.push((module, 1));
                    }
                }
            }
        }
        // Validate every counter before publishing any counter or queue entry.
        for (module, addition) in &module_additions {
            let pending = self.module_retirements.get(module)
                .map_or(0, |state| state.pending);
            pending.checked_add(*addition).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 ToolHelp module-retirement notification count exhausted"))?;
        }
        let mut new_module_entry_queue = None;
        if let Some(scope) = module_entry_scope {
            if let Some(queue) = self.module_entry_pending.get_mut(&scope) {
                queue.try_reserve(count).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "queue scoped Win16 ToolHelp module-entry notifications",
                    error,
                ))?;
            } else {
                self.module_entry_pending.try_reserve(1).map_err(|error|
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "reserve scoped Win16 ToolHelp module-entry queue", error))?;
                let mut queue = VecDeque::new();
                queue.try_reserve(count).map_err(|error| RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "queue scoped Win16 ToolHelp module-entry notifications",
                    error,
                ))?;
                new_module_entry_queue = Some(queue);
            }
        } else {
            self.pending.try_reserve(count).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "queue Win16 ToolHelp notification batch",
                error,
            ))?;
        }
        for (module, addition) in module_additions {
            let state = self.module_retirements.entry(module).or_default();
            state.pending += addition;
        }
        if let Some(scope) = module_entry_scope {
            if let Some(mut queue) = new_module_entry_queue {
                queue.extend(accepted);
                self.module_entry_pending.insert(scope, queue);
            } else if let Some(queue) = self.module_entry_pending.get_mut(&scope) {
                queue.extend(accepted);
            }
        } else {
            self.pending.extend(accepted);
        }
        Ok(count)
    }

    pub(super) fn pop_pending(&mut self) -> Option<Win16ToolhelpNotifyEvent> {
        self.pending.pop_front()
    }

    pub(super) fn pop_any_pending(&mut self) -> Option<Win16ToolhelpNotifyEvent> {
        self.pending.pop_front().or_else(|| self.pop_any_module_entry_event())
    }

    pub(super) fn push_pending_front(&mut self, event: Win16ToolhelpNotifyEvent) {
        self.pending.push_front(event);
    }

    pub(super) fn validate_rip_cancellation_events(&self, id: u64) -> Result<usize, RuntimeError> {
        let mut count = 0usize;
        for event in self.pending.iter().filter(|event| event.termination_id == Some(id)) {
            if event.notification != NFY_EXITTASK || count != 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "handled ToolHelp RIP found an unexpected queued terminal event"));
            }
            count = 1;
        }
        Ok(count)
    }

    pub(super) fn cancel_termination_events(
        &mut self,
        id: u64,
        expected: usize,
    ) -> Result<(), RuntimeError> {
        let count = self.validate_rip_cancellation_events(id)?;
        if count != expected {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp terminal event queue changed after its exact cancellation preflight"));
        }
        self.pending.retain(|event| event.termination_id != Some(id));
        Ok(())
    }

    pub(super) fn retire_task(
        &mut self,
        task: u16,
    ) -> Result<Vec<Win16ToolhelpNotifyEvent>, RuntimeError> {
        let mut retained = VecDeque::new();
        retained.try_reserve(self.pending.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain other-task ToolHelp notifications during task retirement",
            error,
        ))?;
        let mut retired = Vec::new();
        let scoped_count = self.module_entry_pending.values().try_fold(0usize, |total, queue|
            total.checked_add(queue.len()).ok_or_else(|| RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 ToolHelp scoped event count exhausted",
            )))?;
        let all_queued = self.pending.len().checked_add(scoped_count).ok_or_else(||
            RuntimeError::new(Kind::ResourceExhausted,
                "Win16 ToolHelp task-retirement event count overflowed"))?;
        retired.try_reserve_exact(all_queued).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "collect queued ToolHelp events during task retirement", error))?;
        // Reserve the complete drain plan before removing the registration or
        // moving any accepted event, so allocation failure has no partial
        // retirement effect.
        self.by_task.remove(&task);
        while let Some(event) = self.pending.pop_front() {
            if event.task == task {
                retired.push(event);
            } else {
                retained.push_back(event);
            }
        }
        self.pending = retained;
        self.drain_module_entry_events_for_task(task, &mut retired);
        Ok(retired)
    }

    /// A queued LOADSEG refers to module-owned selectors. Rollback and normal
    /// unload cancel those not-yet-entered notifications before releasing the
    /// module's selector allocations.
    pub(super) fn cancel_module_segments(
        &mut self,
        module_handle: u16,
        module_generation: win16_abi::SelectorRef,
    ) {
        self.pending.retain(|event| !matches!(
            &event.data,
            Win16ToolhelpNotifyData::LoadSegment {
                module_handle: owner,
                module_generation: generation,
                ..
            } if *owner == module_handle && *generation == module_generation
        ));
        self.cancel_module_entry_events(module_handle, module_generation);
    }

    pub(super) fn contains(
        &self,
        registration: Win16ToolhelpNotifyRegistration,
    ) -> bool {
        self.by_task.get(&registration.owner_task) == Some(&registration)
    }

    pub(super) fn clear(&mut self) {
        self.by_task.clear();
        self.pending.clear();
        self.module_entry_pending.clear();
        self.module_retirements.clear();
    }

    pub(super) fn module_segment_was_announced(&self, module: u16, selector: u16) -> bool {
        self.module_retirements.get(&module).is_some_and(|state|
            state.announced_segments.contains(&selector))
    }

    pub(super) fn announce_module_segment(&mut self, module: u16, selector: u16) {
        self.module_retirements.entry(module).or_default()
            .announced_segments.insert(selector);
    }

    pub(super) fn module_delete_was_announced(&self, module: u16) -> bool {
        self.module_retirements.get(&module).is_some_and(|state| state.deletion_announced)
    }

    pub(super) fn announce_module_delete(&mut self, module: u16) {
        self.module_retirements.entry(module).or_default().deletion_announced = true;
    }

    pub(super) fn complete_module_retirement_notification(
        &mut self,
        module: u16,
    ) -> Result<(), RuntimeError> {
        let state = self.module_retirements.get_mut(&module).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-retirement event lost its exact owner record"))?;
        state.pending = state.pending.checked_sub(1).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "ToolHelp module-retirement event count underflowed"))?;
        Ok(())
    }

    pub(super) fn has_pending_module_retirement_notifications(&self, module: u16) -> bool {
        self.module_retirements.get(&module).is_some_and(|state| state.pending != 0)
    }

    pub(super) fn forget_module_retirement(&mut self, module: u16) {
        self.module_retirements.remove(&module);
    }

    pub(super) fn has_matching_registration(&self, notification: u16) -> bool {
        self.by_task.values().any(|registration|
            notification_matches(registration.flags, notification))
    }

    pub(super) fn module_retirement_pending_count(&self, module: u16) -> Option<usize> {
        self.module_retirements.get(&module).map(|state| state.pending)
    }

    pub(super) fn code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.by_task.values().map(|registration| registration.callback.far_value())
    }
}

fn notification_matches(flags: u16, notification: u16) -> bool {
    match notification {
        NFY_TASKIN | NFY_TASKOUT => flags & NF_TASKSWITCH != 0,
        NFY_RIP => flags & NF_RIP != 0,
        // KERNEL's notification dispatcher uses a zero match mask for its
        // ordinary events, so all registered callbacks receive them.
        _ => true,
    }
}

impl Win16State {
    pub(super) fn queue_toolhelp_notify_current(
        &mut self,
        notification: u16,
        data: Win16ToolhelpNotifyData,
    ) -> Result<bool, RuntimeError> {
        let task = self.current_task_handle()?;
        let event = Win16ToolhelpNotifyEvent {
            task,
            notification,
            data,
            registrations: Vec::new(),
            termination_id: None,
            module_root: None,
        };
        if let Win16ToolhelpNotifyData::StartDll { module, .. } = &event.data {
            let scope = self.toolhelp_notify_module_entry_scope(*module)?
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "STARTDLL was queued without an exact library module-entry scope"))?;
            self.toolhelp_notify.enqueue_module_entry_event(scope, event)
        } else {
            self.toolhelp_notify.enqueue(event)
        }
    }

    pub(super) fn begin_toolhelp_notify_event(
        &mut self,
        callback_id: super::CallbackFrameId,
        event: &Win16ToolhelpNotifyEvent,
        registrations: Vec<Win16ToolhelpNotifyRegistration>,
        module_entry_parent: Option<Win16ToolhelpModuleEntryParent>,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<Win16ToolhelpNotifyEventFrame>, RuntimeError> {
        let Some(registration) = registrations.first().copied() else { return Ok(None); };
        match module_entry_parent {
            Some(parent) => {
                self.validate_published_toolhelp_module_entry_parent(
                    callback_id, parent, event.task,
                )?;
                if !self.toolhelp_notify_event_owner_is_live_under_module_entry_parent(
                    event, parent,
                ) {
                    return Ok(None);
                }
            }
            None => {
                if matches!(&event.data, Win16ToolhelpNotifyData::StartDll { .. }) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "STARTDLL publication lost its exact Module parent identity"));
                }
                if !self.toolhelp_notify_event_owner_is_live(event) { return Ok(None); }
            }
        }
        let payload_count = match &event.data {
            Win16ToolhelpNotifyData::Scalar(_) => 0,
            Win16ToolhelpNotifyData::FreeSegment { .. }
            | Win16ToolhelpNotifyData::DeleteModule { .. } => 0,
            Win16ToolhelpNotifyData::LoadSegment { .. } => 2,
            Win16ToolhelpNotifyData::StartDll { .. } | Win16ToolhelpNotifyData::Rip { .. } => 1,
        };
        self.reserve_retained_callback_buffer_capacity(payload_count)?;
        let mut payload_buffers = Vec::new();
        payload_buffers.try_reserve_exact(payload_count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 ToolHelp notification payload owners",
                error,
            )
        })?;
        let data = match self.toolhelp_notify_guest_data(&event.data, memory, &mut payload_buffers) {
            Ok(data) => data,
            Err(primary) => return Err(self.finish_toolhelp_notify_payload_setup_failure(
                primary, payload_buffers,
            )),
        };
        let module_root = match &event.data {
            Win16ToolhelpNotifyData::LoadSegment { module_handle, .. } => {
                if let Err(primary) = self.retain_toolhelp_notify_module_root(*module_handle) {
                    return Err(self.finish_toolhelp_notify_payload_setup_failure(
                        primary, payload_buffers,
                    ));
                }
                Some(*module_handle)
            }
            Win16ToolhelpNotifyData::StartDll { module, .. } => {
                if let Err(primary) = self.retain_toolhelp_notify_module_root(*module) {
                    return Err(self.finish_toolhelp_notify_payload_setup_failure(
                        primary, payload_buffers,
                    ));
                }
                Some(*module)
            }
            Win16ToolhelpNotifyData::FreeSegment { module_handle, .. }
            | Win16ToolhelpNotifyData::DeleteModule { module_handle, .. } => {
                if let Err(primary) = self.retain_toolhelp_notify_module_root(*module_handle) {
                    return Err(self.finish_toolhelp_notify_payload_setup_failure(
                        primary, payload_buffers,
                    ));
                }
                Some(*module_handle)
            }
            _ => None,
        };
        let module_retirement = match &event.data {
            Win16ToolhelpNotifyData::FreeSegment { module_handle, .. }
            | Win16ToolhelpNotifyData::DeleteModule { module_handle, .. } => Some(*module_handle),
            _ => None,
        };
        let active_call = match self.begin_toolhelp_notify_callback(
            registration,
            event.notification,
            data,
            cpu,
            dos,
            memory,
        ) {
            Ok(active_call) => active_call,
            Err(primary) => {
                let mut failure = self.finish_toolhelp_notify_payload_setup_failure(
                    primary, payload_buffers,
                );
                if let Some(module) = module_root
                    && let Err(cleanup) = self.release_toolhelp_notify_module_root(module)
                {
                    failure = failure.with_cleanup(
                        "ToolHelp callback entry retained its primary failure and module-root release failure",
                        cleanup,
                    );
                }
                return Err(failure);
            }
        };
        Ok(Some(Win16ToolhelpNotifyEventFrame {
            callback_id,
            task: event.task,
            notification: event.notification,
            data,
            registrations,
            next_registration: 0,
            active_call: Some(active_call),
            returned_call: None,
            completed_handled: None,
            payload_buffers,
            module_root,
            module_retirement,
            termination_id: event.termination_id,
            module_entry_parent,
        }))
    }

    /// Complete one callback and enter the next still-registered callback only
    /// when AX is FALSE. `true` means the notification chain is complete.
    pub(super) fn finish_toolhelp_notify_event_callback(
        &mut self,
        frame: &mut Win16ToolhelpNotifyEventFrame,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        still_registered: &[Win16ToolhelpNotifyRegistration],
    ) -> Result<Win16ToolhelpNotifyProgress, RuntimeError> {
        if frame.completed_handled.is_none() {
            if frame.returned_call.is_none() {
                let mut active_call = frame.active_call.take().ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp notification event lost its active checked callback",
                ))?;
                let handled = match self.finish_toolhelp_notify_callback(
                    cpu, dos, memory, &mut active_call,
                ) {
                    Ok(handled) => handled,
                    Err(error) => {
                        frame.active_call = Some(active_call);
                        return Err(error);
                    }
                };
                frame.returned_call = Some((active_call, handled));
            }
            let (mut returned_call, handled) = frame.returned_call.take().ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "ToolHelp callback ACK lost its exact checked owner during retry"))?;
            if let Err(error) = self.release_guest_far_callback_owner(
                &mut returned_call, dos, memory,
            ) {
                frame.returned_call = Some((returned_call, handled));
                return Err(error);
            }
            frame.completed_handled = Some(handled);
        }
        let handled = frame.completed_handled.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "ToolHelp callback chain lost its acknowledged result",
        ))?;
        if handled {
            return Ok(Win16ToolhelpNotifyProgress::Complete { handled: true });
        }

        let mut index = frame.next_registration.saturating_add(1);
        while let Some(registration) = frame.registrations.get(index).copied() {
            index += 1;
            if !still_registered.contains(&registration) {
                frame.next_registration = index - 1;
                continue;
            }
            let active_call = match self.begin_toolhelp_notify_callback(
                registration,
                frame.notification,
                frame.data,
                cpu,
                dos,
                memory,
            ) {
                Ok(active_call) => active_call,
                Err(error) => return Err(error),
            };
            frame.next_registration = index - 1;
            frame.active_call = Some(active_call);
            frame.completed_handled = None;
            return Ok(Win16ToolhelpNotifyProgress::CallbackEntered);
        }
        Ok(Win16ToolhelpNotifyProgress::Complete { handled: false })
    }

    /// Enter one registered ToolHelp callback with its exact Pascal stack and
    /// checked BOOL return contract. The caller owns the callback frame and
    /// shared callback-stack binding until the guest reaches the return gate.
    pub(super) fn begin_toolhelp_notify_callback(
        &mut self,
        registration: Win16ToolhelpNotifyRegistration,
        notification: u16,
        data: u32,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Win16FarCallbackFrame, RuntimeError> {
        if self.selectors.translate(registration.callback, Access::Execute, 1, memory).is_err() {
            return Err(RuntimeError::new(Kind::GuestFault,
                "ToolHelp notification callback selector was retired before guest entry"));
        }
        self.enter_guest_far_callback_checked(
            cpu,
            dos,
            memory,
            registration.callback.far_value(),
            &[
                Win16FarCallbackArgument::Word(notification),
                Win16FarCallbackArgument::Dword(data),
            ],
            Win16FarCallbackConvention::Pascal,
            Win16FarCallbackReturn::Word,
        )
    }

    /// Finish only an exact checked guest FAR return and project AX as BOOL.
    /// TRUE stops propagation to later ToolHelp notification registrations.
    pub(super) fn finish_toolhelp_notify_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        frame: &mut Win16FarCallbackFrame,
    ) -> Result<bool, RuntimeError> {
        let value = self.finish_guest_far_callback_checked(cpu, dos, memory, frame)?;
        Ok(value as u16 != 0)
    }
}
