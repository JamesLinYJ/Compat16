//! Win16 ToolHelp task interrupt callback registrations.

use guest_core::{memory::Memory, GuestMemory, PhysAddr, Registers, Selector};
use win16_abi::task_database::{
    INSTANCE_DATA_STACK_BOTTOM_OFFSET, INSTANCE_DATA_STACK_MINIMUM_OFFSET,
    INSTANCE_DATA_STACK_TOP_OFFSET, TASK_DATABASE_HINSTANCE_OFFSET,
    TASK_DATABASE_HMODULE_OFFSET,
};
use win16_abi::toolhelp_abi::{
    ClassEntry16, LocalEntry16, LocalInfo16, ModuleEntry16, TaskEntry16, TimerInfo16,
};
use win16_abi::local_heap::{
    LOCAL_ENTRY_FIXED, LOCAL_ENTRY_FREE, LOCAL_ENTRY_MOVEABLE, LOCAL_ENTRY_TYPE_FREE,
};
use win16_abi::{Access, SegmentedPointer, Win16ModuleReference};

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn toolhelp_code_references(&self) -> Vec<u32> {
        self.interrupt_callbacks.values().map(|pointer| pointer.far_value())
            .chain(self.toolhelp_interrupt_frames.iter()
                .flat_map(|frame| frame.code_references()))
            .collect()
    }

    fn toolhelp_task_handle(&self, requested: u16) -> Result<Option<u16>, RuntimeError> {
        let task = if requested == 0 { self.current_task_handle()? } else { requested };
        Ok(self.task_handles.values().any(|handle| *handle == task).then_some(task))
    }

    pub(super) fn interrupt_register(
        &mut self,
        task_handle: u16,
        callback: u32,
        memory: &Memory,
        _host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some(task) = self.toolhelp_task_handle(task_handle)? else { return Ok(0); };
        if callback == 0 { return Ok(0); }
        let Ok(pointer) = self.selectors.pointer_from_far(callback) else { return Ok(0); };
        if self.interrupt_callbacks.contains_key(&task)
            || self.toolhelp_interrupt_handles.contains_key(&task)
        {
            return Ok(0);
        }
        let descriptor = match self.selectors.describe(pointer.selector()) {
            Ok(descriptor) => descriptor,
            Err(_) => return Ok(0),
        };
        if !descriptor.present || !descriptor.rights.executable() {
            return Ok(0);
        }
        if let Err(error) = self.selectors.translate(pointer, Access::Execute, 1, memory) {
            let error = crate::runtime_error(error);
            return if matches!(error.kind(), crate::DiagnosticKind::GuestFault
                | crate::DiagnosticKind::CompatibilityGap)
            {
                Ok(0)
            } else {
                Err(error)
            };
        }
        let Some(registration_handle) = u16::try_from(self.next_toolhelp_interrupt_handle)
            .ok().filter(|handle| *handle != 0) else {
            return Ok(0);
        };
        let next_handle = self.next_toolhelp_interrupt_handle.checked_add(1)
            .ok_or_else(|| RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                "ToolHelp private interrupt-handle sequence exhausted"))?;
        let registration = super::toolhelp_interrupt::Win16ToolhelpInterruptRegistration {
            guest_handle: registration_handle,
            callback_selector: pointer.selector(),
        };
        self.interrupt_callbacks.insert(task, pointer);
        self.toolhelp_interrupt_handles.insert(task, registration);
        self.next_toolhelp_interrupt_handle = next_handle;
        Ok(1)
    }

    pub(super) fn interrupt_unregister(&mut self, task_handle: u16) -> Result<u16, RuntimeError> {
        let Some(task) = self.toolhelp_task_handle(task_handle)? else { return Ok(0); };
        let callback = self.interrupt_callbacks.remove(&task);
        let registration = self.toolhelp_interrupt_handles.remove(&task);
        match (callback, registration) {
            (None, None) => Ok(0),
            (Some(callback), Some(registration))
                if callback.selector() == registration.callback_selector => Ok(1),
            (callback, registration) => {
                if let Some(callback) = callback {
                    self.interrupt_callbacks.insert(task, callback);
                }
                if let Some(registration) = registration {
                    self.toolhelp_interrupt_handles.insert(task, registration);
                }
                Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "ToolHelp interrupt registration maps disagree during unregister"))
            }
        }
    }

    /// Enumerates the live guest modules in stable handle order. The module
    /// list contains only guest NE modules; host DLLs are never reported as
    /// guest handles.
    pub(super) fn toolhelp_module_first(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ ModuleEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let entries = self.toolhelp_module_entries()?;
        let Some(mut entry) = entries.first().cloned() else { return Ok(0); };
        entry.next = entries.get(1).map_or(0, |next| next.module_handle);
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_module_next(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, bytes)) = self.toolhelp_read_output::<{ ModuleEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let (_, previous) = ModuleEntry16::decode(&bytes);
        if previous.next == 0 { return Ok(0); }
        let entries = self.toolhelp_module_entries()?;
        let Some(index) = entries.iter().position(|entry| entry.module_handle == previous.next)
        else { return Ok(0); };
        let mut entry = entries[index].clone();
        entry.next = entries.get(index + 1).map_or(0, |next| next.module_handle);
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_module_find_name(
        &self, output: u32, name: &[u8], memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some(handle) = self.module_handle(&Win16ModuleReference::Name(name.to_vec())) else {
            return Ok(0);
        };
        self.toolhelp_module_find_handle(output, handle, memory)
    }

    pub(super) fn toolhelp_module_find_handle(
        &self, output: u32, handle: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ ModuleEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let entries = self.toolhelp_module_entries()?;
        let Some(mut entry) = entries.iter().find(|entry| entry.module_handle == handle).cloned()
        else { return Ok(0); };
        entry.next = 0;
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    fn toolhelp_module_entries(&self) -> Result<Vec<ModuleEntry16>, RuntimeError> {
        let mut rows: Vec<_> = self.modules.records.values()
            .filter(|record| record.external_application.is_none()
                && record.state != super::module_registry::ModuleState::Retired)
            .collect();
        rows.sort_by_key(|record| record.handle);
        let mut entries = Vec::new();
        entries.try_reserve_exact(rows.len()).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "allocate Win16 ToolHelp module snapshot", error,
        ))?;
        for record in rows {
            let mut entry = ModuleEntry16::default();
            let name = if record.name.is_empty() {
                basename(&record.path)
            } else {
                record.name.as_slice()
            };
            copy_terminated(&mut entry.module_name, name);
            copy_terminated(&mut entry.executable_path, &record.path);
            entry.module_handle = record.handle;
            entry.usage_count = self.modules.usage(record.handle);
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Reports the currently registered guest tasks. This runtime presently
    /// has one runnable Win16 task; entries are built from its actual TDB,
    /// task registry, loaded module, and active CPU registers.
    pub(super) fn toolhelp_task_first(
        &self, output: u32, registers: &Registers, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ TaskEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let entries = self.toolhelp_task_entries(registers, memory)?;
        let Some(mut entry) = entries.first().cloned() else { return Ok(0); };
        entry.next = entries.get(1).map_or(0, |next| next.task);
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_task_next(
        &self, output: u32, registers: &Registers, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, bytes)) = self.toolhelp_read_output::<{ TaskEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let (_, previous) = TaskEntry16::decode(&bytes);
        if previous.next == 0 { return Ok(0); }
        let entries = self.toolhelp_task_entries(registers, memory)?;
        let Some(index) = entries.iter().position(|entry| entry.task == previous.next) else {
            return Ok(0);
        };
        let mut entry = entries[index].clone();
        entry.next = entries.get(index + 1).map_or(0, |next| next.task);
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_task_find_handle(
        &self, output: u32, task_handle: u16, registers: &Registers,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ TaskEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let entries = self.toolhelp_task_entries(registers, memory)?;
        let Some(mut entry) = entries.into_iter().find(|entry| entry.task == task_handle) else {
            return Ok(0);
        };
        entry.next = 0;
        self.selectors.write(memory, pointer, &entry.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    /// ToolHelp defines this as the next CS:IP of a sleeping task. The XP
    /// implementation returns DWORD zero for the current task; this runtime
    /// has no scheduler-owned inactive CPU context to report for other tasks.
    pub(super) fn toolhelp_task_get_csip(
        &self, task_handle: u16, _registers: &Registers,
    ) -> Result<u32, RuntimeError> {
        let Some(task) = self.toolhelp_task_handle(task_handle)? else { return Ok(0); };
        if task == self.current_task_handle()? { return Ok(0); }
        Ok(0)
    }

    /// This runtime models one runnable task and exits the Win16 app as a
    /// whole. A request for that task can therefore use the normal app cleanup
    /// path; another or unknown task cannot be terminated through this API.
    pub(super) fn toolhelp_terminate_app_target(
        &self, task_handle: u16,
    ) -> Result<bool, RuntimeError> {
        let Some(task) = self.toolhelp_task_handle(task_handle)? else { return Ok(false); };
        Ok(task == self.current_task_handle()?)
    }

    /// Enumerates registered guest classes only. Host system classes and
    /// native class handles are outside this guest-visible registry.
    pub(super) fn toolhelp_class_first(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ ClassEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let mut entries = self.window_classes.entries();
        let Some(entry) = entries.next() else { return Ok(0); };
        let next = entries.next().map_or(0, |entry| entry.atom);
        let encoded = self.toolhelp_class_entry(entry, dw_size, next);
        self.selectors.write(memory, pointer, &encoded).map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_class_next(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, bytes)) = self.toolhelp_read_output::<{ ClassEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let (_, previous) = ClassEntry16::decode(&bytes);
        if previous.next == 0 { return Ok(0); }
        let mut entries = self.window_classes.entries();
        while let Some(entry) = entries.next() {
            if entry.atom != previous.next { continue; }
            let next = entries.next().map_or(0, |entry| entry.atom);
            let encoded = self.toolhelp_class_entry(entry, dw_size, next);
            self.selectors.write(memory, pointer, &encoded).map_err(crate::runtime_error)?;
            return Ok(1);
        }
        Ok(0)
    }

    fn toolhelp_class_entry(
        &self, entry: super::classes::GuestWindowClassEntry<'_>, dw_size: u32, next: u16,
    ) -> [u8; ClassEntry16::SIZE] {
        let mut value = ClassEntry16 {
            instance: self.modules.by_handle(entry.instance).unwrap_or(0),
            next,
            ..ClassEntry16::default()
        };
        copy_terminated(&mut value.class_name, entry.name);
        value.encode_with_size(dw_size)
    }

    /// Reports the host system tick and its wrap-safe delta from the moment
    /// this Win16 VM was created. `vm_start_tick` must be captured by the
    /// runtime owner when it constructs the task, not on first API use.
    pub(super) fn toolhelp_timer_count(
        &self,
        output: u32,
        vm_start_tick: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ TimerInfo16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let now = host.win16_get_tick_count()?;
        let info = TimerInfo16 {
            milliseconds_since_start: now,
            milliseconds_this_vm: now.wrapping_sub(vm_start_tick),
        };
        self.selectors.write(memory, pointer, &info.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    fn toolhelp_task_entries(
        &self, registers: &Registers, memory: &Memory,
    ) -> Result<Vec<TaskEntry16>, RuntimeError> {
        let current = self.current_task_handle()?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(self.task_handles.len()).map_err(|error|
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "allocate Win16 ToolHelp task snapshot", error))?;
        for (&owner, &handle) in &self.task_handles {
            let Ok(info) = self.tasks.info(owner) else { continue; };
            if matches!(info.state, win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited) {
                continue;
            }
            let task_pointer = self.selectors.pointer_from_raw(Selector(handle), 0)
                .map_err(crate::runtime_error)?;
            let read_task_word = |offset: usize| -> Result<u16, RuntimeError> {
                let pointer = self.selectors.add_bytes(task_pointer, offset as u32)
                    .map_err(crate::runtime_error)?;
                let mut bytes = [0; 2];
                self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
                Ok(u16::from_le_bytes(bytes))
            };
            let module = read_task_word(TASK_DATABASE_HMODULE_OFFSET)?;
            let instance = read_task_word(TASK_DATABASE_HINSTANCE_OFFSET)?;
            let event_count = self.tasks.pending_events(owner).map_err(crate::runtime_error)?;
            let mut entry = TaskEntry16 {
                task: handle,
                parent_task: info.parent.and_then(|parent| self.task_handles.get(&parent).copied()).unwrap_or(0),
                instance,
                module,
                event_count,
                psp_offset: 0,
                ..TaskEntry16::default()
            };
            if handle == current {
                entry.stack_segment = registers.ss;
                entry.stack_pointer = registers.sp();
                let read_instance_word = |offset: usize| -> u16 {
                    let Ok(pointer) = self.selectors.pointer_from_raw(Selector(registers.ds), offset as u16)
                    else { return 0; };
                    let mut bytes = [0; 2];
                    self.selectors.read(memory, pointer, &mut bytes).ok().map(|()|
                        u16::from_le_bytes(bytes)).unwrap_or(0)
                };
                entry.stack_top = read_instance_word(INSTANCE_DATA_STACK_TOP_OFFSET);
                entry.stack_minimum = read_instance_word(INSTANCE_DATA_STACK_MINIMUM_OFFSET);
                entry.stack_bottom = read_instance_word(INSTANCE_DATA_STACK_BOTTOM_OFFSET);
            }
            if let Some(record) = self.modules.records.get(&module) {
                copy_terminated(&mut entry.module_name, &record.name);
            }
            entries.push(entry);
        }
        entries.sort_by_key(|entry| entry.task);
        Ok(entries)
    }

    pub(super) fn toolhelp_local_info(
        &self, output: u32, heap_handle: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ LocalInfo16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let Some((_selector, entries)) = self.toolhelp_local_heap_entries(heap_handle, memory)?
        else { return Ok(0); };
        let Ok(items) = u16::try_from(entries.len()) else { return Ok(0); };
        self.selectors.write(memory, pointer, &LocalInfo16 { items }.encode_with_size(dw_size))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_local_first(
        &self, output: u32, heap_handle: u16, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<{ LocalEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let Some((selector, entries)) = self.toolhelp_local_heap_entries(heap_handle, memory)?
        else { return Ok(0); };
        let Some(entry) = entries.first() else { return Ok(0); };
        let encoded = self.toolhelp_local_entry(*entry, selector, dw_size,
            entries.get(1).map(|next| next.arena_offset).unwrap_or(0));
        self.selectors.write(memory, pointer, &encoded).map_err(crate::runtime_error)?;
        Ok(1)
    }

    pub(super) fn toolhelp_local_next(
        &self, output: u32, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((pointer, dw_size, bytes)) = self.toolhelp_read_output::<{ LocalEntry16::SIZE }>(
            output, memory,
        )? else { return Ok(0); };
        let (_, previous) = LocalEntry16::decode(&bytes);
        if previous.next == 0 { return Ok(0); }
        let Some((selector, entries)) = self.toolhelp_local_heap_entries(previous.heap, memory)?
        else { return Ok(0); };
        let Some(index) = entries.iter().position(|entry| entry.arena_offset == previous.next)
        else { return Ok(0); };
        let entry = entries[index];
        let encoded = self.toolhelp_local_entry(entry, selector, dw_size,
            entries.get(index + 1).map(|next| next.arena_offset).unwrap_or(0));
        self.selectors.write(memory, pointer, &encoded).map_err(crate::runtime_error)?;
        Ok(1)
    }

    fn toolhelp_local_entry(
        &self, entry: win16_abi::local_heap::LocalHeapEntry, selector: u16,
        dw_size: u32, next: u16,
    ) -> [u8; LocalEntry16::SIZE] {
        let flags = match entry.flags {
            LOCAL_ENTRY_FIXED => LOCAL_ENTRY_FIXED,
            LOCAL_ENTRY_MOVEABLE => LOCAL_ENTRY_MOVEABLE,
            _ => LOCAL_ENTRY_FREE,
        };
        let kind = if flags == LOCAL_ENTRY_FREE { LOCAL_ENTRY_TYPE_FREE } else { entry.kind };
        LocalEntry16 {
            handle: entry.handle, address: entry.address, block_size: entry.size,
            flags, lock_count: entry.lock_count, block_type: kind, heap: selector,
            heap_type: 0, next,
        }.encode_with_size(dw_size)
    }

    /// Copy bytes between checked guest selectors for ToolHelp's process-memory
    /// inspection API. Invalid guest ranges produce the documented zero-byte
    /// result; no host process address is accepted or exposed.
    pub(super) fn toolhelp_memory_read(
        &self, source_selector: u16, source_offset: u32, destination: u32,
        count: u32, memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if count == 0 { return Ok(0); }
        let Ok(length) = usize::try_from(count) else { return Ok(0); };
        let Ok(base) = self.selectors.pointer_from_raw(Selector(source_selector), 0) else {
            return Ok(0);
        };
        let Ok(source) = self.selectors.add_bytes(base, source_offset) else {
            return Ok(0);
        };
        let Ok(target) = self.selectors.pointer_from_far(destination) else { return Ok(0); };
        let Some(source_ranges) = self.toolhelp_memory_ranges(source, Access::Read, length, memory)?
        else { return Ok(0); };
        let Some(target_ranges) = self.toolhelp_memory_ranges(target, Access::Write, length, memory)?
        else { return Ok(0); };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "allocate Win16 ToolHelp memory-read buffer", error,
        ))?;
        bytes.resize(length, 0);
        let mut cursor = 0;
        for (address, chunk) in source_ranges {
            memory.read(address, &mut bytes[cursor..cursor + chunk]).map_err(crate::runtime_error)?;
            cursor += chunk;
        }
        cursor = 0;
        for (address, chunk) in target_ranges {
            memory.write(address, &bytes[cursor..cursor + chunk]).map_err(crate::runtime_error)?;
            cursor += chunk;
        }
        Ok(count)
    }

    pub(super) fn toolhelp_memory_write(
        &self, destination_selector: u16, destination_offset: u32, source: u32,
        count: u32, memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if count == 0 { return Ok(0); }
        let Ok(length) = usize::try_from(count) else { return Ok(0); };
        let Ok(base) = self.selectors.pointer_from_raw(Selector(destination_selector), 0) else {
            return Ok(0);
        };
        let Ok(target) = self.selectors.add_bytes(base, destination_offset) else {
            return Ok(0);
        };
        let Ok(source) = self.selectors.pointer_from_far(source) else { return Ok(0); };
        let Some(target_ranges) = self.toolhelp_memory_ranges(target, Access::Write, length, memory)?
        else { return Ok(0); };
        let Some(source_ranges) = self.toolhelp_memory_ranges(source, Access::Read, length, memory)?
        else { return Ok(0); };
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "allocate Win16 ToolHelp memory-write buffer", error,
        ))?;
        bytes.resize(length, 0);
        let mut cursor = 0;
        for (address, chunk) in source_ranges {
            memory.read(address, &mut bytes[cursor..cursor + chunk]).map_err(crate::runtime_error)?;
            cursor += chunk;
        }
        cursor = 0;
        for (address, chunk) in target_ranges {
            memory.write(address, &bytes[cursor..cursor + chunk]).map_err(crate::runtime_error)?;
            cursor += chunk;
        }
        Ok(count)
    }

    /// Validate a large ToolHelp memory range across the descriptor chain of
    /// one guest selector allocation. Every chunk is checked before a caller
    /// copies bytes, so a bad tail never causes a partial guest write.
    pub(super) fn toolhelp_memory_ranges(
        &self,
        pointer: SegmentedPointer,
        access: Access,
        length: usize,
        memory: &Memory,
    ) -> Result<Option<Vec<(PhysAddr, usize)>>, RuntimeError> {
        let mut ranges = Vec::new();
        let mut current = pointer;
        let mut remaining = length;
        while remaining != 0 {
            let Ok(descriptor) = self.selectors.describe(current.selector()) else {
                return Ok(None);
            };
            let Some(descriptor_remaining) = descriptor.limit.checked_add(1)
                .and_then(|size| size.checked_sub(u32::from(current.offset())))
            else { return Ok(None); };
            let Ok(descriptor_remaining) = usize::try_from(descriptor_remaining) else {
                return Ok(None);
            };
            let chunk = remaining.min(descriptor_remaining);
            if chunk == 0 { return Ok(None); }
            let Ok(address) = self.selectors.translate(current, access, chunk, memory) else {
                return Ok(None);
            };
            ranges.try_reserve(1).map_err(|error| RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "allocate Win16 ToolHelp memory-range snapshot", error,
            ))?;
            ranges.push((address, chunk));
            remaining -= chunk;
            if remaining != 0 {
                let Ok(chunk) = u32::try_from(chunk) else { return Ok(None); };
                let Ok(next) = self.selectors.add_bytes(current, chunk) else { return Ok(None); };
                current = next;
            }
        }
        Ok(Some(ranges))
    }

    fn toolhelp_output_pointer<const N: usize>(
        &self, raw: u32, memory: &Memory,
    ) -> Result<Option<(SegmentedPointer, u32)>, RuntimeError> {
        let Ok(pointer) = self.selectors.pointer_from_far(raw) else { return Ok(None); };
        if self.selectors.translate(pointer, Access::Read, 4, memory).is_err() {
            return Ok(None);
        }
        let mut size = [0; 4];
        self.selectors.read(memory, pointer, &mut size).map_err(crate::runtime_error)?;
        let dw_size = u32::from_le_bytes(size);
        if dw_size < N as u32 || self.selectors.translate(pointer, Access::Write, N, memory).is_err() {
            return Ok(None);
        }
        Ok(Some((pointer, dw_size)))
    }

    fn toolhelp_read_output<const N: usize>(
        &self, raw: u32, memory: &Memory,
    ) -> Result<Option<(SegmentedPointer, u32, [u8; N])>, RuntimeError> {
        let Some((pointer, dw_size)) = self.toolhelp_output_pointer::<N>(raw, memory)? else {
            return Ok(None);
        };
        let mut bytes = [0; N];
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(Some((pointer, dw_size, bytes)))
    }
}

fn copy_terminated<const N: usize>(destination: &mut [u8; N], source: &[u8]) {
    let count = source.len().min(N.saturating_sub(1));
    destination[..count].copy_from_slice(&source[..count]);
    destination[count] = 0;
}

fn basename(path: &[u8]) -> &[u8] {
    let start = path.iter().rposition(|byte| *byte == b'/' || *byte == b'\\')
        .map_or(0, |separator| separator + 1);
    &path[start..]
}
