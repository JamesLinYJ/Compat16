//! Checked guest stack allocation and CPU descriptor projection for ToolHelp observers.

use super::*;
use crate::RuntimeHost;

impl Win16State {
    pub(super) fn prepare_toolhelp_callback_stack(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        origin: &Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16ToolhelpCallbackStack>, RuntimeError> {
        let task = self.current_task_handle()?;
        let Some(callback) = self.interrupt_callbacks.get(&task).copied() else {
            return Ok(None);
        };
        let callback_descriptor = match self.selectors.describe(callback.selector()) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let error = crate::runtime_error(error);
                return if super::toolhelp_preflight_declines(&error) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
        };
        if !callback_descriptor.present || !callback_descriptor.rights.executable() {
            return Ok(None);
        }
        let callback_code_selector = if cpu.architectural_execution_mode().is_some() {
            let segments = Win16Segments {
                selectors: &self.selectors,
                memory_len: memory.len(),
            };
            match cpu.guest_code_selector_for_projection(
                callback.selector().raw().0,
                callback_descriptor.base.0,
                callback_descriptor.limit,
                callback.offset(),
                memory,
                &segments,
            ) {
                Ok(Some(selector)) => selector,
                Ok(None) => return Ok(None),
                Err(error) => {
                    let error = crate::runtime_error(error);
                    return if super::toolhelp_preflight_declines(&error) {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                }
            }
        } else {
            callback.selector().raw().0
        };
        let direct_callback_sp = origin.sp().checked_sub(CALLBACK_FRAME_BYTES);
        let direct_working_start =
            direct_callback_sp.and_then(|sp| sp.checked_sub(TOOLHELP_CALLBACK_WORKING_STACK_BYTES));
        if let Some(working_start) = direct_working_start {
            let runtime_mapping = match self
                .selectors
                .pointer_from_raw(Selector(origin.ss), working_start)
            {
                Ok(pointer) => match self.selectors.translate(
                    pointer,
                    Access::Write,
                    usize::from(TOOLHELP_DIRECT_STACK_BYTES),
                    memory,
                ) {
                    Ok(_) => true,
                    Err(error) => declines_or_errors(crate::runtime_error(error))?,
                },
                Err(error) => declines_or_errors(crate::runtime_error(error))?,
            };
            let cpu_mapping = if cpu.architectural_execution_mode().is_some() {
                self.architectural_stack_matches_runtime(cpu, origin, working_start, memory)?
            } else {
                true
            };
            if runtime_mapping && cpu_mapping {
                let callback_sp = direct_callback_sp.expect("checked direct callback SP");
                let callback_return_sp = callback_sp.checked_add(4).ok_or_else(|| {
                    RuntimeError::new(
                        Kind::GuestFault,
                        "ToolHelp direct callback return SP overflowed",
                    )
                })?;
                return Ok(Some(Win16ToolhelpCallbackStack {
                    callback_code_selector,
                    selector: origin.ss,
                    callback_sp,
                    callback_return_sp,
                    fault_stack_frame: false,
                    private: None,
                }));
            }
        }

        let protected_selector = match cpu.architectural_execution_mode() {
            Some(x86_cpu::CpuExecutionMode::Protected) => {
                self.find_empty_guest_ldt_selector(cpu, memory)?
            }
            Some(
                x86_cpu::CpuExecutionMode::RealAddress | x86_cpu::CpuExecutionMode::Virtual8086,
            ) => {
                // A real-address SS must have base SS<<4. Arbitrary GlobalHeap
                // allocations cannot satisfy that segment-base contract.
                return Ok(None);
            }
            None => None,
        };
        if cpu.architectural_execution_mode() == Some(x86_cpu::CpuExecutionMode::Protected)
            && protected_selector.is_none()
        {
            return Ok(None);
        }

        // XP's DIH_Exception reserves a 20-byte internal frame and requires
        // 128 bytes below the user callback SP before using the interrupted
        // 16-bit stack. Keep that source-derived callback budget separate
        // from the SDK's documented 16-byte user frame.
        let required_retained_slots = self
            .toolhelp_interrupt_frames
            .len()
            .checked_add(self.toolhelp_interrupt_retained_stacks.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "ToolHelp private-stack cleanup capacity overflowed",
                )
            })?;
        self.toolhelp_interrupt_retained_stacks
            .try_reserve(
                required_retained_slots
                    .saturating_sub(self.toolhelp_interrupt_retained_stacks.len()),
            )
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve ToolHelp private-stack cleanup slot",
                    error,
                )
            })?;
        let handle = match protected_selector {
            Some(selector) => self.global_alloc_at_selector(
                0,
                u32::from(TOOLHELP_PRIVATE_STACK_BYTES),
                selector,
                memory,
                host,
            )?,
            None => self.global_alloc(0, u32::from(TOOLHELP_PRIVATE_STACK_BYTES), memory, host)?,
        };
        if handle == 0 {
            return Ok(None);
        }
        let Some(selector) = self.global_selectors.get(&handle).copied() else {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp private GlobalAlloc has no exact selector generation",
            );
            return match self.global_free(handle) {
                Ok(0) => Err(primary),
                Ok(_) => Err(primary.with_cleanup(
                    "global allocation remains tracked for task teardown",
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "orphaned ToolHelp stack GlobalFree returned a busy handle",
                    ),
                )),
                Err(cleanup) => Err(primary.with_cleanup(
                    "release ToolHelp stack without a selector generation",
                    cleanup,
                )),
            };
        };
        let mut allocation = Win16ToolhelpPrivateStack {
            global_handle: handle,
            selector,
            descriptor_lease: None,
        };
        if protected_selector.is_some_and(|raw| selector.raw().0 & !7 != raw & !7) {
            let primary = RuntimeError::new(
                Kind::InternalInvariant,
                "exact ToolHelp GlobalAlloc returned a different selector-table index",
            );
            return match self.release_toolhelp_private_stack(&mut allocation, cpu, memory) {
                Ok(()) => Err(primary),
                Err(cleanup) => {
                    self.toolhelp_interrupt_retained_stacks
                        .push(Win16ToolhelpRetainedStack { task, allocation });
                    Err(primary.with_cleanup(
                        "retain exact ToolHelp stack after selector-slot mismatch",
                        cleanup,
                    ))
                }
            };
        }
        let stack_is_valid = match self.selectors.pointer_from_raw(selector.raw(), 0) {
            Ok(pointer) => match self.selectors.translate(
                pointer,
                Access::Write,
                usize::from(TOOLHELP_DIRECT_STACK_BYTES),
                memory,
            ) {
                Ok(_) => true,
                Err(error) => match self.release_stack_after_preflight_error(
                    allocation,
                    task,
                    cpu,
                    memory,
                    crate::runtime_error(error),
                ) {
                    Ok(()) => return Ok(None),
                    Err(error) => return Err(error),
                },
            },
            Err(error) => match self.release_stack_after_preflight_error(
                allocation,
                task,
                cpu,
                memory,
                crate::runtime_error(error),
            ) {
                Ok(()) => return Ok(None),
                Err(error) => return Err(error),
            },
        };
        if !stack_is_valid {
            let primary = RuntimeError::new(
                Kind::GuestFault,
                "ToolHelp private GlobalAlloc does not expose the complete callback stack",
            );
            return match self
                .release_stack_after_preflight_error(allocation, task, cpu, memory, primary)
            {
                Ok(()) => Ok(None),
                Err(error) => Err(error),
            };
        }
        if let Some(raw_selector) = protected_selector {
            let Some(&heap_handle) = self.global_handles.get(&handle) else {
                let primary = RuntimeError::new(
                    Kind::InternalInvariant,
                    "protected ToolHelp stack lost its GlobalHeap identity",
                );
                return match self.release_toolhelp_private_stack(&mut allocation, cpu, memory) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => {
                        self.toolhelp_interrupt_retained_stacks
                            .push(Win16ToolhelpRetainedStack { task, allocation });
                        Err(primary.with_cleanup(
                            "retain protected ToolHelp stack after missing heap identity",
                            cleanup,
                        ))
                    }
                };
            };
            let info = match self.heap.info(heap_handle) {
                Ok(info) => info,
                Err(error) => {
                    let primary = crate::runtime_error(error);
                    return match self.release_toolhelp_private_stack(&mut allocation, cpu, memory) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => {
                            self.toolhelp_interrupt_retained_stacks
                                .push(Win16ToolhelpRetainedStack { task, allocation });
                            Err(primary.with_cleanup(
                                "retain protected ToolHelp stack after heap-info failure",
                                cleanup,
                            ))
                        }
                    };
                }
            };
            let segments = Win16Segments {
                selectors: &self.selectors,
                memory_len: memory.len(),
            };
            match cpu.install_guest_ldt_data_segment(
                raw_selector,
                info.base.0,
                info.size.saturating_sub(1),
                memory,
                &segments,
            ) {
                Ok(lease) => allocation.descriptor_lease = Some(lease),
                Err(error) => {
                    let (error, lease) = error.into_parts();
                    if let Some(lease) = lease {
                        allocation.descriptor_lease = Some(lease);
                    }
                    let primary = crate::runtime_error(error).with_context(
                        "publish protected ToolHelp stack descriptor in the active LDT",
                    );
                    return match self
                        .release_stack_after_preflight_error(allocation, task, cpu, memory, primary)
                    {
                        Ok(()) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
            }
            let segments = Win16Segments {
                selectors: &self.selectors,
                memory_len: memory.len(),
            };
            let stack_size = match usize::try_from(info.size) {
                Ok(size) => size,
                Err(_) => {
                    let primary = RuntimeError::new(
                        Kind::ResourceExhausted,
                        "ToolHelp private stack size does not fit the host address space",
                    );
                    return match self
                        .release_stack_after_preflight_error(allocation, task, cpu, memory, primary)
                    {
                        Ok(()) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
            };
            let identity_mapped = cpu.guest_stack_range_is_identity_mapped(
                raw_selector,
                0,
                stack_size,
                true,
                memory,
                &segments,
            );
            match identity_mapped {
                Ok(true) => {}
                Ok(false) => {
                    let primary = RuntimeError::new(
                        Kind::CompatibilityGap,
                        "the protected ToolHelp stack allocation is not identity-mapped by guest paging",
                    );
                    return match self
                        .release_stack_after_preflight_error(allocation, task, cpu, memory, primary)
                    {
                        Ok(()) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
                Err(error) => {
                    let primary = crate::runtime_error(error)
                        .with_context("validate guest paging for protected ToolHelp stack");
                    return match self
                        .release_stack_after_preflight_error(allocation, task, cpu, memory, primary)
                    {
                        Ok(()) => Ok(None),
                        Err(error) => Err(error),
                    };
                }
            }
        }
        Ok(Some(Win16ToolhelpCallbackStack {
            callback_code_selector,
            selector: protected_selector.unwrap_or(selector.raw().0),
            callback_sp: TOOLHELP_CALLBACK_WORKING_STACK_BYTES,
            callback_return_sp: TOOLHELP_CALLBACK_WORKING_STACK_BYTES + 4,
            fault_stack_frame: true,
            private: Some(allocation),
        }))
    }

    pub(super) fn release_toolhelp_private_stack(
        &mut self,
        allocation: &mut Win16ToolhelpPrivateStack,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if self
            .global_selectors
            .get(&allocation.global_handle)
            .copied()
            != Some(allocation.selector)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp private stack selector generation changed before release",
            ));
        }
        if let Some(lease) = allocation.descriptor_lease.take() {
            let segments = Win16Segments {
                selectors: &self.selectors,
                memory_len: memory.len(),
            };
            if let Err(error) = cpu.restore_guest_ldt_data_segment(lease, memory, &segments) {
                let (error, lease) = error.into_parts();
                allocation.descriptor_lease = Some(lease);
                return Err(crate::runtime_error(error)
                    .with_context("restore exact guest LDT slot before releasing ToolHelp stack"));
            }
        }
        let identity = self
            .global_handles
            .get(&allocation.global_handle)
            .copied()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "ToolHelp private stack lost its GlobalHeap handle before release",
                )
            })?;
        if self
            .global_selectors
            .get(&allocation.global_handle)
            .copied()
            != Some(allocation.selector)
            || self
                .heap
                .runtime_primary_selector(identity)
                .map_err(crate::runtime_error)?
                != Some(allocation.selector)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "ToolHelp private stack GlobalHeap identity changed before release",
            ));
        }
        match self.free_runtime_global_on_teardown(identity)? {
            super::super::global_memory::GlobalTeardownResult::Freed => Ok(()),
            retained @ super::super::global_memory::GlobalTeardownResult::Retained { .. } => {
                Err(retained
                    .retained_error("ToolHelp private stack")
                    .unwrap_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "retained ToolHelp stack teardown result lost its cause",
                        )
                    }))
            }
        }
    }

    fn release_stack_after_preflight_error(
        &mut self,
        mut allocation: Win16ToolhelpPrivateStack,
        task: u16,
        cpu: &mut x86_cpu::Cpu,
        memory: &mut Memory,
        primary: RuntimeError,
    ) -> Result<(), RuntimeError> {
        let decline = super::toolhelp_preflight_declines(&primary);
        match self.release_toolhelp_private_stack(&mut allocation, cpu, memory) {
            Ok(()) if decline => Ok(()),
            Ok(()) => Err(primary),
            Err(cleanup) => {
                self.toolhelp_interrupt_retained_stacks
                    .push(Win16ToolhelpRetainedStack { task, allocation });
                Err(primary.with_cleanup(
                    "retain ToolHelp private stack after failed preflight cleanup",
                    cleanup,
                ))
            }
        }
    }

    fn find_empty_guest_ldt_selector(
        &self,
        cpu: &x86_cpu::Cpu,
        memory: &mut Memory,
    ) -> Result<Option<u16>, RuntimeError> {
        let Some(cpl) = cpu.current_privilege_level() else {
            return Ok(None);
        };
        let segments = Win16Segments {
            selectors: &self.selectors,
            memory_len: memory.len(),
        };
        for index in 1..self.selectors.slot_capacity() {
            if !self.selectors.selector_slot_is_free(index) {
                continue;
            }
            let Ok(index) = u16::try_from(index) else {
                continue;
            };
            let Some(selector) = index
                .checked_shl(3)
                .map(|index| index | 0x04 | u16::from(cpl))
            else {
                continue;
            };
            match cpu.guest_ldt_slot_is_empty(selector, memory, &segments) {
                Ok(true) => return Ok(Some(selector)),
                Ok(false) => {}
                Err(error) => {
                    let error = crate::runtime_error(error);
                    if !super::toolhelp_preflight_declines(&error) {
                        return Err(error);
                    }
                }
            }
        }
        Ok(None)
    }

    fn architectural_stack_matches_runtime(
        &self,
        cpu: &x86_cpu::Cpu,
        origin: &Registers,
        working_start: u16,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let projection = cpu.current_stack_segment_projection();
        if !projection.usable
            || projection.selector != origin.ss
            || projection.flags & 0x40 != 0
            || projection.access & 0x92 != 0x92
            || u32::from(working_start) + u32::from(TOOLHELP_DIRECT_STACK_BYTES) - 1
                > projection.limit
        {
            return Ok(false);
        }
        let reference = match self.selectors.reference(Selector(origin.ss)) {
            Ok(reference) => reference,
            Err(error) => return declines_or_errors(crate::runtime_error(error)),
        };
        let runtime = match self.selectors.describe(reference) {
            Ok(runtime) => runtime,
            Err(error) => return declines_or_errors(crate::runtime_error(error)),
        };
        if runtime.base.0 != projection.base
            || runtime.limit != projection.limit
            || !runtime.rights.writable()
        {
            return Ok(false);
        }
        let segments = Win16Segments {
            selectors: &self.selectors,
            memory_len: memory.len(),
        };
        match cpu.guest_stack_range_is_identity_mapped(
            origin.ss,
            working_start,
            usize::from(TOOLHELP_DIRECT_STACK_BYTES),
            true,
            memory,
            &segments,
        ) {
            Ok(identity_mapped) => Ok(identity_mapped),
            Err(error) => declines_or_errors(crate::runtime_error(error)),
        }
    }
}

fn declines_or_errors(error: RuntimeError) -> Result<bool, RuntimeError> {
    if super::toolhelp_preflight_declines(&error) {
        Ok(false)
    } else {
        Err(error)
    }
}
