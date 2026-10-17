//! Construction of the first protected-mode Win16 process state.

use super::*;
use guest_core::arena::ReservedRegion;

impl Win16State {
    pub(crate) fn load(
        image: &[u8],
        module: &NeModule,
        process: Win16ProcessBootstrap,
        program_path: &[u8],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        pe32_region: ReservedRegion,
        win16_region: ReservedRegion,
    ) -> Result<(Self, Registers), RuntimeError> {
        let (pe32_dispatch, win32_imports) = super::pe32_dispatch::Pe32ThunkDispatcher::new(
            pe32_region, memory, program_path)?;
        let mut selectors = SelectorTable::new().map_err(crate::runtime_error)?;
        let mut runtime_arena_backing = runtime_arena_backing::RuntimeArenaBackingRegistry::new(
            win16_region, memory,
        )?;
        let gate = selectors.alloc_block(
            PhysAddr(WIN16_ARENA_BASE), SERVICE_GATE_BYTES,
            AccessRights::code(), memory,
        ).map_err(crate::runtime_error)?;
        let gate_selector = gate.raw();
        runtime_arena_backing.register_chunk(
            runtime_arena_backing::RuntimeArenaChunkKind::ServiceGate,
            gate, &selectors, memory,
        )?;
        // A dedicated executable selector is a return target for guest FAR
        // callbacks. It cannot alias an imported API slot in the service gate.
        let callback_gate = selectors.alloc_block(
            PhysAddr(WIN16_ARENA_BASE + SERVICE_GATE_BYTES), 16,
            AccessRights::code(), memory,
        ).map_err(crate::runtime_error)?;
        let callback_gate_selector = callback_gate.raw();
        runtime_arena_backing.register_chunk(
            runtime_arena_backing::RuntimeArenaChunkKind::CallbackReturnGate,
            callback_gate, &selectors, memory,
        )?;
        let data_base = WIN16_ARENA_BASE + SERVICE_GATE_BYTES + 16;
        let (builtin_data_exports, next_module_base, runtime_selector_aliases) =
            crate::win16_builtin_data_exports::bootstrap_builtin_data_exports(
            &mut selectors, memory, data_base, WIN16_MEMORY_END,
        )?;
        for (&module_name, data) in &builtin_data_exports {
            if let Some(selector) = data.selector {
                runtime_arena_backing.register_chunk(
                    runtime_arena_backing::RuntimeArenaChunkKind::BuiltinData(module_name),
                    selector, &selectors, memory,
                )?;
            }
        }
        let bindings = Vec::new();
        // The task filesystem and complete DLL graph are not available yet.
        // Bootstrap owns pristine segments; startup resolves typed function,
        // selector and constant imports before any guest code may execute.
        let imports = |_: &[u8], _: &NeImportTarget| Err(FormatError::InvalidNeLoad(
            "unlinked Win16 bootstrap cannot resolve imports"));
        let mut resolver = Win16LoadResolver::new(
            selectors,
            PhysAddr(next_module_base),
            PhysAddr(WIN16_MEMORY_END),
            memory.len(),
            imports,
        ).map_err(crate::runtime_error)?;
        let loaded = formats::load_ne_segments_unlinked(image, module, &mut resolver, memory).map_err(crate::runtime_error)?;
        let loaded_segment_handles = loaded.segments.iter().zip(&module.segments)
            .map(|(loaded, segment)| {
                let selector = loaded.selector.0;
                let handle = if segment.flags & NE_SEGMENT_MOVEABLE != 0 {
                    selector.checked_sub(1).unwrap_or(0)
                } else { selector };
                (selector, handle)
            }).collect();
        let (mut selectors, next_free, automatic_data) = resolver.finish();
        let task_base = next_free.0.checked_add(15).map(|value| value & !15)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "Win16 task base overflow"))?;
        let task_end = task_base.checked_add(TASK_DATABASE_PREFIX_SIZE as u32)
            .filter(|end| *end <= WIN16_MEMORY_END)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "Win16 task database has no space"))?;
        let task_selector = selectors.alloc_block(
            PhysAddr(task_base), TASK_DATABASE_PREFIX_SIZE as u32,
            AccessRights::read_write(), memory,
        ).map_err(crate::runtime_error)?;
        runtime_arena_backing.register_chunk(
            runtime_arena_backing::RuntimeArenaChunkKind::TaskDatabase,
            task_selector, &selectors, memory,
        )?;
        let heap_base = task_end.checked_add(15).map(|value| value & !15)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "Win16 heap base overflow"))?;
        let heap_size = WIN16_MEMORY_END.checked_sub(heap_base)
            .filter(|size| *size != 0)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted, "Win16 heap has no space"))?;
        let heap = GlobalHeap::new(PhysAddr(heap_base), heap_size).map_err(crate::runtime_error)?;
        let mut tasks = TaskRegistry::new();
        tasks.create(OwnerId(1), None).map_err(crate::runtime_error)?;
        tasks.dispatch(OwnerId(1)).map_err(crate::runtime_error)?;
        // Windows starts a new Win16 task with one posted event. Its startup
        // WaitEvent(0) consumes that token before entering application code.
        tasks.post_current_event().map_err(crate::runtime_error)?;
        let entry = loaded.code_entry.ok_or_else(|| RuntimeError::new(
            Kind::InvalidInput, "Win16 executable has no initial code entry",
        ))?;
        let stack = loaded.stack.ok_or_else(|| RuntimeError::new(
            Kind::CompatibilityGap, "Win16 executable has no initial stack",
        ))?;
        let data_selector = loaded.segment_selector(module.header.automatic_data_segment)
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                "Win16 executable has no automatic data segment"))?;
        let instance_selector = selectors.reference(data_selector).map_err(crate::runtime_error)?;
        let data_index = module.header.automatic_data_segment.checked_sub(1)
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                "Win16 automatic data segment number is zero"))?;
        let data_segment = module.segments.get(usize::from(data_index))
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                "Win16 automatic data segment has no NE segment record"))?;
        let instance_handle = if data_segment.flags & NE_SEGMENT_MOVEABLE != 0 {
            data_selector.0.checked_sub(1).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 movable instance selector has no handle value"))?
        } else {
            data_selector.0
        };
        let task_handle = task_selector.raw().0;
        let (mut process_views, compat) = process_views::Win16ProcessViews::create(
            dos, &mut selectors, process, memory,
        )?;
        let psp_selector = process_views.selector();
        let mut task_database = TaskDatabase::new();
        task_database.set_hself(task_handle);
        task_database.set_hpdb(psp_selector.raw().0);
        task_database.set_hinstance(instance_handle);
        task_database.set_event_count(tasks.current_pending_events().map_err(crate::runtime_error)?);
        task_database.set_show_command(1);
        task_database.set_dta((u32::from(psp_selector.raw().0) << 16) | 0x0080);
        task_database.set_magic(TASK_DATABASE_MAGIC);
        if let Err(error) = memory.write(PhysAddr(task_base), task_database.as_bytes()) {
            return Err(process_views::rollback_error(crate::runtime_error(error),
                process_views.release(dos, &mut selectors, memory)));
        }
        let mut task_handles = BTreeMap::new();
        task_handles.insert(OwnerId(1), task_handle);
        let mut registers = Registers {
            cs: entry.selector.0,
            eip: u32::from(entry.offset),
            ss: stack.selector.0,
            ds: data_selector.0,
            es: psp_selector.raw().0,
            eflags: 0x0202,
            ..Registers::default()
        };
        registers.set_sp(stack.offset);
        // Win16 startup passes the NE stack/heap reserves and instance handles
        // to the program entry in registers. KERNEL.InitTask consumes this
        // register context rather than Pascal stack arguments.
        registers.set_ax(0);
        registers.set_bx(module.header.stack_size);
        registers.set_cx(module.header.heap_size);
        registers.set_si(0);
        registers.set_di(instance_handle);
        registers.set_bp(0);
        let mut state = Self {
            ole1_client_documents: super::ole1::Win16Ole1ClientDocuments::new(),
            ole1_callbacks: Vec::new(),
            ole1_server_release_cascades: Vec::new(),
            ole1_server_state: super::win16_ole1_server_state::Ole1ServerState::new(),
            ole1_com_callback_resumes: Vec::new(),
            ole1_com_callback_resume_failures: Vec::new(),
            com_operations: super::com_operations::Win16ComOperationTable::default(),
            print_queues: super::print_queue::Win16PrintQueueState::default(),
            winmem32: super::winmem32::Win16Winmem32State::default(),
            selectors, gate_selector, callback_gate_selector, bindings, builtin_data_exports,
            runtime_selector_aliases,
            runtime_arena_backing,
            native_thunks_available: false,
            pe32_dispatch,
            win32_imports,
            network: crate::win16_network::Win16NetworkState::new(),
            netbios: super::netbios_async::Win16NetbiosState::default(),
            acm: super::acm::Win16AcmState::new(),
            mci: super::mci::Win16MciState::default(),
            midi: super::midi::Win16MidiState::default(),
            media_services: crate::win16_media_services::Win16MediaServicesState::default(),
            mixer: super::mixer::Win16MixerState::default(),
            wave_audio: super::multimedia_buffers::Win16WaveState::default(),
            sound: sound_state::Win16SoundState::default(),
            automation: crate::win16_automation::Win16AutomationState::default(),
            dos_caller_addresses: dos_address_space::Win16DosCallerAddresses::default(),
            dde: crate::win16_dde::Win16DdeState::new(),
            classic_dde: classic_dde_dispatch::ClassicDdeRuntimeState::default(),
            dde_runtime_quiesced: false,
            dde_abort_receipt: None,
            dde_retired_callback_tokens: Vec::new(),
            dde_retired_guest_blocks: Vec::new(),
            dde_callbacks: Vec::new(), dde_guest_contexts: Vec::new(),
            dde_context_restores: Vec::new(),
            callback_kinds: Vec::new(), callback_frame_ids: Vec::new(),
            callback_owners_quiesced: false, font_callbacks: Vec::new(),
            object_callbacks: Vec::new(),
            next_callback_frame_id: 1,
            callback_scheduler: callback_scheduler::Win16CallbackScheduler::default(),
            legacy_cpu_frames: Vec::new(),
            next_legacy_cpu_frame: 1,
            task_event_waits: Vec::new(),
            active_dispatch_call_owner: None,
            active_dispatch_return: None,
            vm_start_tick: None,
            line_dda_callbacks: Vec::new(),
            window_enumerations: Vec::new(),
            deferred_window_batches: super::window_operations::DeferredWindowBatches::default(),
            user_hooks: super::user_hooks::Win16UserHooks::default(),
            user_declared: super::user_declared::UserDeclaredSession::default(),
            ole_remainder_reported: BTreeSet::new(),
            driver_gaps: super::driver::DriverGaps::default(),
            window_callbacks: Vec::new(), retired_window_payloads: Vec::new(),
            native_function_callbacks: Vec::new(), loaded, heap, tasks,
            window_operations: Vec::new(), window_abort_receipt: None,
            window_dispatch_context: None,
            window_procedures: BTreeMap::new(),
            next_window_operation: 1,
            dialog_procedures: BTreeMap::new(),
            window_data: BTreeMap::new(),
            native_procedures: native_procedures::NativeProcedureGates::default(),
            untranslated_window_messages: BTreeSet::new(),
            psp_selector, process_views, instance_selector, instance_handle, automatic_data,
            task_handles, first_task_handle: task_handle,
            task_controls: super::kernel_task::TaskControls::default(),
            module_path: program_path.to_vec(), user_queue: None, user_task_queue: None,
            module_startup: module_calls::ModuleStartupState::Pending,
            program_load_reported: false,
            next_app_notification_sequence: 1,
            modules: module_registry::ModuleRegistry::default(),
            external_selector_cleanup: Vec::new(), module_callbacks: Vec::new(),
            resources: resources::ResourceState::new(),
            resource_handlers: BTreeMap::new(), resource_callbacks: Vec::new(),
            far_returns: Vec::new(),
            next_far_call_id: 1,
            next_interrupt_id: 1,
            catch_records: super::catch_throw::CatchRecords::default(),
            interrupt_returns: Vec::new(),
            module_reap_pending: false,
            proc_instances: proc::ProcInstances::new(),
            interrupt_callbacks: BTreeMap::new(),
            toolhelp_interrupt_handles: BTreeMap::new(),
            next_toolhelp_interrupt_handle: 1,
            toolhelp_notify: toolhelp_notify::Win16ToolhelpNotifyRegistry::default(),
            toolhelp_notify_frames: Vec::new(),
            toolhelp_task_exit: toolhelp_notify_exit::Win16ToolhelpTaskExitState::default(),
            toolhelp_interrupt_frames: Vec::new(),
            toolhelp_interrupt_retained_selector_owners: Vec::new(),
            toolhelp_interrupt_retained_stacks: Vec::new(),
            toolhelp_interrupt_stopped_event: None,
            protected_dos_vectors: BTreeMap::new(),
            real_mode_vector_aliases: BTreeMap::new(),
            guest_gdi: gdi::GuestGdiHandles::new(),
            wing_bitmaps: wing_bitmap::Win16WingBitmapState::default(),
            guest_images: images::GuestImageHandles::new(),
            guest_accelerators: user_cursor_accelerator::GuestAcceleratorHandles::new(),
            win87em_install_count: 0,
            win87em_exception_handler: None,
            files: BTreeMap::new(), next_file: FIRST_GUEST_HFILE,
            network_print_jobs: BTreeMap::new(),
            printer_environments: BTreeMap::new(),
            global_handles: BTreeMap::new(), global_selectors: BTreeMap::new(),
            queued_drop_files: Vec::new(),
            finished_queued_drop_leases: Vec::new(),
            dos_global_blocks: BTreeMap::new(),
            orphaned_dos_leases: Vec::new(),
            allocated_selector_aliases: BTreeMap::new(),
            api_allocated_selectors: BTreeMap::new(),
            selector_backing_leases: BTreeMap::new(),
            mapls_selectors: BTreeMap::new(),
            mapls_bases: BTreeMap::new(),
            window_classes: classes::GuestWindowClasses::new(),
            window_system_classes: BTreeMap::new(),
            mdi_children: BTreeSet::new(),
            sysmodal_window: None,
            window_creations: BTreeMap::new(),
            guest_menus: menu::GuestMenus::new(),
            timers: message_calls::Win16TimerRegistrations::default(),
            window_handles: BTreeMap::new(), next_window_handle: 1, next_window_creation: 1,
            window_parents: BTreeMap::new(),
            window_parent_observations: BTreeMap::new(),
            owned_window_handles: BTreeSet::new(),
            clipboard_state: user_services_controls::GuestClipboardState::default(),
            common_dialog_state: commdlg::Win16CommonDialogState::default(),
            kernel_file_system: kernel_file_system::Win16KernelFileSystemState::new(),
            pending_kernel_diagnostic_effects: Vec::new(),
            window_teardown_state: super::WindowTeardownState::Live,
            loaded_segment_handles,
            discarded_handles: BTreeSet::new(),
            reported_global_flags: BTreeSet::new(),
            reported_global_realloc_flags: BTreeSet::new(),
            compat,
            comm_ports: super::comm::Win16CommPorts::default(),
        };
        // This task has the portable PE32 CPU dispatcher. Reclassify only
        // KERNEL.513–518 gate bindings; this does not assert a native x86
        // mapping or a host-side DLL execution worker.
        state.set_native_thunks_available(true);
        if let Err(error) = state.initialize_modules(image, module, memory) {
            return Err(process_views::rollback_error(error,
                state.release_process_views(dos, memory)));
        }
        Ok((state, registers))
    }
}
