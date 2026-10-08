//! ToolHelp interrupt selector ownership and event eligibility.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn retire_toolhelp_interrupt_task_owners(
        &mut self,
        task: u16,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < self.toolhelp_interrupt_retained_selector_owners.len() {
            if self.toolhelp_interrupt_retained_selector_owners[index].task != task {
                index += 1;
                continue;
            }
            let mut retained = self
                .toolhelp_interrupt_retained_selector_owners
                .remove(index);
            if let Err(error) =
                self.release_legacy_cpu_binding_owner(&mut retained.owner, dos, memory)
            {
                self.toolhelp_interrupt_retained_selector_owners
                    .insert(index, retained);
                return Err(error);
            }
        }
        index = 0;
        while index < self.toolhelp_interrupt_retained_stacks.len() {
            if self.toolhelp_interrupt_retained_stacks[index].task != task {
                index += 1;
                continue;
            }
            let mut retained = self.toolhelp_interrupt_retained_stacks.remove(index);
            if let Err(error) =
                self.release_toolhelp_private_stack(&mut retained.allocation, cpu, memory)
            {
                self.toolhelp_interrupt_retained_stacks
                    .insert(index, retained);
                return Err(error);
            }
        }
        if self
            .toolhelp_interrupt_stopped_event
            .as_ref()
            .is_some_and(|event| event.task == Some(task))
        {
            self.toolhelp_interrupt_stopped_event = None;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn clear_toolhelp_interrupt_retained_owners(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let tasks: std::collections::BTreeSet<u16> = self
            .toolhelp_interrupt_retained_selector_owners
            .iter()
            .map(|owner| owner.task)
            .chain(
                self.toolhelp_interrupt_retained_stacks
                    .iter()
                    .map(|stack| stack.task),
            )
            .collect();
        for task in tasks {
            self.retire_toolhelp_interrupt_task_owners(task, cpu, dos, memory)?;
        }
        self.toolhelp_interrupt_stopped_event = None;
        Ok(())
    }

    pub(super) fn retain_stopped_toolhelp_event(
        &mut self,
        origin: Registers,
        resume: Win16ToolhelpInterruptResume,
    ) -> Result<(), RuntimeError> {
        self.stop_toolhelp_interrupt_execution(origin, Some(resume))
    }

    pub(super) fn stop_toolhelp_interrupt_execution(
        &mut self,
        origin: Registers,
        resume: Option<Win16ToolhelpInterruptResume>,
    ) -> Result<(), RuntimeError> {
        if self.toolhelp_interrupt_stopped_event.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 execution stopped while an earlier ToolHelp event was already retained",
            ));
        }
        self.toolhelp_interrupt_stopped_event = Some(Win16ToolhelpStoppedEvent {
            task: self.current_task_handle().ok(),
            _origin: origin,
            _resume: resume,
        });
        Ok(())
    }

    pub(in crate::win16_runtime) fn toolhelp_interrupt_owns_selector(
        &self,
        reference: win16_abi::SelectorRef,
    ) -> bool {
        self.toolhelp_interrupt_frames.iter().any(|frame| {
            if same_selector_generation(frame.callback.selector(), reference) {
                return true;
            }
            if frame
                .private_stack
                .as_ref()
                .is_some_and(|stack| same_selector_generation(stack.selector, reference))
            {
                return true;
            }
            match frame.cpu_owner.as_ref() {
                Some(Win16ToolhelpInterruptCallOwner::Legacy(id)) => {
                    self.legacy_cpu_owner_owns_selector(*id, reference)
                }
                Some(Win16ToolhelpInterruptCallOwner::Architectural(owner)) => owner
                    .selector_roots
                    .as_ref()
                    .is_some_and(|roots| roots.owns_selector(reference)),
                None => false,
            }
        }) || self
            .toolhelp_interrupt_retained_selector_owners
            .iter()
            .any(|retained| retained.owner.owns_selector(reference))
            || self
                .toolhelp_interrupt_retained_stacks
                .iter()
                .any(|retained| same_selector_generation(retained.allocation.selector, reference))
            || self
                .toolhelp_interrupt_handles
                .values()
                .any(|registration| {
                    same_selector_generation(registration.callback_selector, reference)
                })
    }

    pub(super) fn capture_toolhelp_architectural_owner(
        &mut self,
        cpu: &x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        registers: &Registers,
        deferred_event: Option<&CpuDeferredEvent>,
    ) -> Result<Win16ToolhelpArchitecturalOwner, RuntimeError> {
        let continuation = match deferred_event {
            Some(event) => cpu.capture_deferred_event_observer_continuation(event),
            None => cpu.capture_event_observer_continuation(),
        }
        .map_err(super::toolhelp_cpu_capture_error)?;
        self.toolhelp_interrupt_retained_selector_owners
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve retained ToolHelp selector-owner cleanup slot",
                    error,
                )
            })?;
        let selector_roots = match self
            .capture_legacy_cpu_binding_owner_for_event_observer(registers, dos, memory)
        {
            Ok(owner) => owner,
            Err(mut error) => {
                let primary = super::toolhelp_binding_error(error.cause)
                    .with_context("retain interrupted Win16 selector roots for ToolHelp observer");
                return match self.release_legacy_cpu_binding_owner(&mut error.owner, dos, memory) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => {
                        self.toolhelp_interrupt_retained_selector_owners.push(
                            Win16ToolhelpRetainedSelectorOwner {
                                task: self.current_task_handle()?,
                                owner: error.owner,
                            },
                        );
                        Err(primary.with_cleanup(
                            "release partial ToolHelp observer selector roots; owner retained for task teardown",
                            cleanup,
                        ))
                    }
                };
            }
        };
        Ok(Win16ToolhelpArchitecturalOwner {
            continuation: Some(continuation),
            selector_roots: Some(selector_roots),
        })
    }

    /// VM86 remains outside the currently modeled ToolHelp callback frame
    /// contract. Real-address, legacy-selector, and protected 16-bit contexts
    /// use their corresponding checked CPU continuation path.
    pub(in crate::win16_runtime) fn has_toolhelp_interrupt_registration(&self, vector: u8) -> bool {
        if !toolhelp_vector_supported(vector) {
            return false;
        }
        self.current_task_handle()
            .ok()
            .is_some_and(|task| self.interrupt_callbacks.contains_key(&task))
    }

    pub(in crate::win16_runtime) fn can_observe_toolhelp_interrupt(
        &self,
        cpu: &x86_cpu::Cpu,
        vector: u8,
        saved_ip: u32,
        memory: &Memory,
    ) -> bool {
        self.can_observe_toolhelp_interrupt_with_event(cpu, vector, saved_ip, memory, None)
    }

    pub(in crate::win16_runtime) fn can_observe_toolhelp_deferred_event(
        &self,
        cpu: &x86_cpu::Cpu,
        event: &CpuDeferredEvent,
        memory: &Memory,
    ) -> bool {
        let observation = event.observation();
        self.can_observe_toolhelp_interrupt_with_event(
            cpu,
            observation.vector,
            observation.saved_ip,
            memory,
            Some(event),
        )
    }

    fn can_observe_toolhelp_interrupt_with_event(
        &self,
        cpu: &x86_cpu::Cpu,
        vector: u8,
        saved_ip: u32,
        _memory: &Memory,
        _deferred_event: Option<&CpuDeferredEvent>,
    ) -> bool {
        if matches!(
            cpu.architectural_execution_mode(),
            Some(CpuExecutionMode::Virtual8086)
        ) {
            return false;
        }
        if !self.has_toolhelp_interrupt_registration(vector) {
            return false;
        }
        // TOOLHELP.H stores the observed return IP as one WORD. Refuse
        // interception when the architectural event cannot be represented.
        if saved_ip > u32::from(u16::MAX) {
            return false;
        }
        let Some(task) = self.current_task_handle().ok() else {
            return false;
        };
        let Some(registration) = self.toolhelp_interrupt_handles.get(&task) else {
            return false;
        };
        let Some(callback) = self.interrupt_callbacks.get(&task).copied() else {
            return false;
        };
        if self.selectors.reference(callback.selector().raw()).ok()
            != Some(registration.callback_selector)
        {
            return false;
        }

        if !cpu.supports_guest_16bit_callback_context()
            && cpu.architectural_execution_mode().is_some()
        {
            return false;
        }
        if cpu.architectural_execution_mode().is_none() {
            return true;
        }
        // Keep this eligibility check free of descriptor/page-table reads and
        // continuation capture. The caller still owns the event here; all
        // fallible checked entry work runs after the exact event is placed in
        // its ToolHelp frame so a storage failure cannot silently drop it.
        true
    }
}
