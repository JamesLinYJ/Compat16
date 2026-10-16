//! Runtime request arms owned by the Kernel service group.

use guest_core::Registers;
use guest_core::memory::Memory;
use dos_kernel::DosKernel;
use win16_abi::{Win16ApiRequest, Win16ExportDescriptor};

use super::COMPAT_DOS_VERSION_WORD;
use super::Win16State;
use super::local_heap::LocalOperation;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use win16_abi::{WIN16_MACHINE_FEATURES, WINDOWS_COMPATIBILITY_PROFILE};

impl Win16State {
    pub(super) fn dispatch_kernel(
        &mut self,
        request: Win16ApiRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) = return_to;
        let preserve_registers = descriptor.id
            == win16_abi::Win16ExportId::KernelGlobalChangeLockCount;
        let value = match request {
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Atoms(request)) => {
                u32::from(self.local_atom_request(registers.ds, request, memory, host)?)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Instance(request)) => {
                use win16_abi::Win16KernelInstanceRequest;
                match request {
                    Win16KernelInstanceRequest::GetInstanceData {
                        previous_instance, buffer_offset, byte_count,
                    } => u32::from(self.kernel_get_instance_data(
                        previous_instance, buffer_offset, byte_count, registers.ds, memory,
                    )?),
                    Win16KernelInstanceRequest::GetCodeHandle { procedure } => {
                        self.kernel_get_code_handle(procedure, memory)
                    }
                    Win16KernelInstanceRequest::GetCodeInfo {
                        procedure_or_module_segment, output,
                    } => {
                        self.kernel_get_code_info(procedure_or_module_segment, output, memory)?;
                        0
                    }
                }
            }
            Win16ApiRequest::KernelProfileSection(request) => {
                super::profile_sections::dispatch(self, &request, memory, host)?
            }
            request @ (Win16ApiRequest::KernelMemory(_)
            | Win16ApiRequest::KernelTask(_)
            | Win16ApiRequest::KernelModule(_)
            | Win16ApiRequest::KernelString(_)
            | Win16ApiRequest::Toolhelp(_)
            | Win16ApiRequest::System(_)) => {
                match self.dispatch_kernel_services(
                    request,
                    registers,
                    memory,
                    host,
                    self.vm_start_tick,
                )? {
                    super::kernel_services::Win16KernelServicesResult::Return(value) => value,
                    super::kernel_services::Win16KernelServicesResult::TerminateApp {
                        exit_code,
                    } => {
                        if let Some(status) = self.finish_task(memory, host, exit_code)? {
                            return Ok(Some(status));
                        }
                        return self.complete_return(
                            registers,
                            return_selector,
                            return_offset,
                            return_sp,
                            u32::from(exit_code),
                            descriptor.return_kind,
                        );
                    }
                }
            }
            Win16ApiRequest::KernelPathInfo(request) => {
                self.execute_kernel_path_info(request, memory, host)?
            }
            Win16ApiRequest::KernelFileSystem(request) => {
                self.execute_kernel_file_system(request, memory, host)?
            }
            Win16ApiRequest::InitTask { .. } => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 InitTask reached the stack-call dispatcher",
                ));
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::WaitEvent { .. },
            )) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "WaitEvent bypassed its owned CPU suspension boundary")),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::PostEvent { task_handle },
            )) => {
                self.post_task_event(task_handle, memory)?;
                0
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::FindResource {
                    module,
                    name,
                    resource_type,
                },
            )) => u32::from(self.find_resource(module, &name, &resource_type, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::LoadResource { .. }
                | win16_abi::Win16KernelResourcesRequest::LockResource { .. },
            )) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "resource loading requires the CPU-owned KERNEL dispatch route")),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::FreeResource { data },
            )) => {
                match self.release_resource(data)? {
                    super::resources::ResourceRelease::Return(value) => u32::from(value),
                    super::resources::ResourceRelease::GlobalHeapReturn(value) => {
                        // The final non-discardable resource release calls the
                        // global heap entry point (KERNEL resaux IFreeResource),
                        // inheriting its volatile segment-register effects.
                        finish_global_heap_call(registers);
                        u32::from(value)
                    }
                }
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::AccessResource { module, info },
            )) => u32::from(self.access_resource(module, info, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::SizeofResource { module, info },
            )) => self.size_of_resource(module, info),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::AllocResource { module, info, size },
            )) => u32::from(self.alloc_resource(module, info, size, memory, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::SetResourceHandler {
                    module,
                    type_name,
                    handler,
                },
            )) => self.set_resource_handler(module, &type_name, handler, host)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::DefResourceHandler { data, module, info },
            )) => {
                if let Some(metadata) = (module != 0)
                    .then(|| self.resource_metadata(module, info))
                    .flatten()
                {
                    u32::from(self.default_resource_load(data, metadata.key, memory, host)?)
                } else {
                    0
                }
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::SetHandleCount { requested_count },
            )) => u32::from(host.win16_set_handle_count(requested_count)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::MakeProcInstance {
                    procedure,
                    instance,
                },
            )) => self.make_proc_instance(procedure, instance, registers.ds, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::FreeProcInstance { procedure },
            )) => {
                self.free_proc_instance(procedure)?;
                0
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::GetCurrentTask,
            )) => {
                let current = self.current_task_handle()?;
                u32::from(current) | (u32::from(self.first_task_handle) << 16)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::SetErrorMode { mode },
            )) => u32::from(self.set_error_mode(mode, memory, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::GetVersion,
            )) => {
                u32::from(WINDOWS_COMPATIBILITY_PROFILE.version_word())
                    | (u32::from(COMPAT_DOS_VERSION_WORD) << 16)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::GetWinFlags,
            )) => WINDOWS_COMPATIBILITY_PROFILE.win_flags(WIN16_MACHINE_FEATURES),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalInit {
                    selector,
                    start,
                    end,
                },
            )) => {
                let value = self.local_init(selector, registers.ds, start, end, memory)?;
                registers.set_cx(value);
                u32::from(value)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalAlloc { flags, size },
            )) => {
                let value = self.local_operation(
                    registers.ds,
                    LocalOperation::Alloc { flags, size },
                    memory,
                )?;
                // The Win16 allocation entry returns the handle in CX as
                // well as AX; callers compiled for that ABI use either.
                registers.set_cx(value as u16);
                value
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalReAlloc {
                    handle,
                    size,
                    flags,
                },
            )) => self.local_operation(
                registers.ds,
                LocalOperation::ReAlloc {
                    handle,
                    size,
                    flags,
                },
                memory,
            )?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalFree { handle },
            )) => self.local_operation(registers.ds, LocalOperation::Free { handle }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalLock { handle },
            )) => self.local_operation(registers.ds, LocalOperation::Lock { handle }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalUnlock { handle },
            )) => self.local_operation(registers.ds, LocalOperation::Unlock { handle }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalSize { handle },
            )) => self.local_operation(registers.ds, LocalOperation::Size { handle }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalHandle { offset },
            )) => self.local_operation(registers.ds, LocalOperation::Handle { offset }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalFlags { handle },
            )) => self.local_operation(registers.ds, LocalOperation::Flags { handle }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalShrink { heap, minimum },
            )) => self.kernel_local_shrink(registers, heap, minimum, return_sp, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalCompact { minimum },
            )) => {
                self.local_operation(registers.ds, LocalOperation::Compact { minimum }, memory)?
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalHandleDelta { delta },
            )) => self.local_operation(registers.ds, LocalOperation::HandleDelta { delta }, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalCountFree,
            )) => self.local_operation(registers.ds, LocalOperation::CountFree, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::LocalHeap(
                win16_abi::Win16KernelLocalHeapRequest::LocalHeapSize,
            )) => self.local_operation(registers.ds, LocalOperation::HeapSize, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalAlloc { flags, size },
            )) => {
                let handle = self.global_alloc_with_caller(
                    flags, size, return_selector, memory, host,
                )?;
                registers.eax = u32::from(handle);
                registers.ebx = u32::from(handle);
                registers.ecx = u32::from(handle);
                registers.es = 0;
                u32::from(handle)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalFree { handle },
            )) => {
                let result = if self.dos_global_blocks.contains_key(&handle) {
                    u32::from(self.kernel_global_dos_free(handle, dos, memory)?)
                } else {
                    u32::from(self.global_free(handle)?)
                };
                finish_global_heap_call(registers);
                result
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalLock { handle },
            )) => self.global_lock(handle, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalUnlock { handle },
            )) => self.global_unlock(handle)? as u32,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalSize { handle },
            )) => self.global_size(handle)?,
            Win16ApiRequest::KernelGlobalHeap(request) => match request {
                win16_abi::Win16KernelGlobalHeapRequest::GlobalFreeAll { owner } => {
                    self.kernel_global_free_all(owner, dos, memory)?;
                    finish_global_heap_call(registers);
                    0
                }
                win16_abi::Win16KernelGlobalHeapRequest::FarSetOwner { handle, owner } => {
                    self.kernel_far_set_owner(handle, owner)?;
                    0
                }
                win16_abi::Win16KernelGlobalHeapRequest::FarGetOwner { handle } => {
                    u32::from(self.kernel_far_get_owner(handle))
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalPageLock { handle } => {
                    u32::from(self.kernel_global_page_lock(handle)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalPageUnlock { handle } => {
                    u32::from(self.kernel_global_page_unlock(handle)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalLruOldest { handle } => {
                    u32::from(self.kernel_global_lru(handle, true)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalLruNewest { handle } => {
                    u32::from(self.kernel_global_lru(handle, false)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalDosAlloc { size } => {
                    self.kernel_global_dos_alloc(size, dos, memory)?
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalDosFree { selector } => {
                    let result = u32::from(self.kernel_global_dos_free(selector, dos, memory)?);
                    finish_global_heap_call(registers);
                    result
                }
                // The pinned Win16 implementation documents zero as “no
                // global heap”; its older task-specific dummy form is not
                // implemented by this runtime.
                win16_abi::Win16KernelGlobalHeapRequest::GlobalMasterHandle => 0,
                win16_abi::Win16KernelGlobalHeapRequest::GlobalChangeLockCount {
                    handle, delta,
                } => {
                    self.kernel_global_change_lock_count(handle, delta, memory)?;
                    0
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalReAlloc {
                    handle,
                    size,
                    flags,
                } => {
                    let result = u32::from(self.kernel_global_realloc_with_caller(
                        handle, size, flags,
                        Some(super::global_memory::GlobalMemoryCaller::GuestCode(return_selector)),
                        memory, host,
                    )?);
                    finish_global_heap_call(registers);
                    result
                },
                win16_abi::Win16KernelGlobalHeapRequest::GlobalFlags { handle } => {
                    self.kernel_global_flags(handle)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalCompact { minimum_free } => {
                    self.kernel_global_compact(minimum_free, memory)?
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalFix { handle } => {
                    u32::from(self.kernel_global_fix(handle, memory)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalUnfix { handle } => {
                    let remaining = self.kernel_global_unfix(handle)?;
                    registers.set_cx(remaining);
                    0
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalWire { handle } => {
                    self.kernel_global_wire(handle, memory)?
                }
                win16_abi::Win16KernelGlobalHeapRequest::GlobalUnWire { handle } => {
                    u32::from(self.kernel_global_unwire(handle)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::LockSegment { segment } => {
                    // SDK 3.1, Vol. 2, p. 600: WORD(-1) selects caller DS.
                    let segment = if segment == u16::MAX { registers.ds } else { segment };
                    u32::from(self.kernel_lock_segment(segment, memory)?)
                }
                win16_abi::Win16KernelGlobalHeapRequest::UnlockSegment { segment } => {
                    // SDK 3.1, Vol. 2, pp. 959-960: the same caller-DS sentinel.
                    let segment = if segment == u16::MAX { registers.ds } else { segment };
                    let remaining = self.kernel_unlock_segment(segment)?;
                    // The SDK declares this export void; its architectural
                    // result is the remaining segment lock count in CX.
                    registers.set_cx(remaining);
                    0
                }
                win16_abi::Win16KernelGlobalHeapRequest::GetFreeSpace { flags } => {
                    self.kernel_get_free_space(flags)?
                }
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalHandle { selector },
            )) => self.global_handle_of(selector),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::GetModuleFileName { module, output },
            )) => u32::from(self.get_module_file_name(module, output, memory, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::GetModuleHandle { module },
            )) => {
                u32::from(self.module_handle(&module).unwrap_or(0))
                    | (u32::from(self.modules.first) << 16)
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::GetModuleUsage { module },
            )) => match self.modules.by_handle(module) {
                Some(handle) if self.external_application(handle).is_some() => {
                    super::external_application::report_external_identity_query(
                        host,
                        "GetModuleUsage",
                        handle,
                    );
                    0
                }
                Some(handle) => u32::from(self.modules.usage(handle)),
                None => 0,
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::GetDriveType { drive },
            )) => u32::from(self.drive_type(drive, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::GetProcAddress { module, procedure },
            )) => {
                let result = self.get_proc_address(&module, &procedure, host);
                host.observe_win16_io(&crate::Win16IoEvent::ProcedureLookup {
                    module: &module,
                    procedure: &procedure,
                    result: result.as_ref().ok().and_then(|lookup| match lookup {
                        super::module::ProcedureLookup::Address(value) => Some(*value),
                        super::module::ProcedureLookup::Missing
                        | super::module::ProcedureLookup::UnsupportedDataExport => Some(0),
                    }),
                });
                match result? {
                    super::module::ProcedureLookup::Address(value) => value,
                    super::module::ProcedureLookup::Missing => 0,
                    super::module::ProcedureLookup::UnsupportedDataExport => {
                        host.report_diagnostic(&crate::Diagnostic::warning(Kind::CompatibilityGap,
                            "Win16 GetProcAddress does not provide a documented callable address for this data export"));
                        0
                    }
                }
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::LoadLibrary { .. }
                | win16_abi::Win16KernelModulesRequest::FreeLibrary { .. },
            )) => return Err(RuntimeError::new(Kind::InternalInvariant,
                "DLL loading requires the CPU-owned KERNEL dispatch route")),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Strings(
                win16_abi::Win16KernelStringsRequest::StringLength { byte_count },
            )) => u32::from(byte_count),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Strings(
                win16_abi::Win16KernelStringsRequest::StringCopy {
                    destination,
                    source,
                },
            )) => self.string_copy(destination, source, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Strings(
                win16_abi::Win16KernelStringsRequest::StringConcat {
                    destination,
                    source,
                },
            )) => self.string_concat(destination, &source, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::AllocSelector { source_selector },
            )) => {
                let result = self.alloc_selector(source_selector, dos, memory);
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "AllocSelector", source: source_selector,
                    destination: None, result: &result,
                });
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::PrestoChangoSelector {
                    source_selector,
                    destination_selector,
                },
            )) => {
                let result = self.presto_chango_selector(
                    source_selector, destination_selector, dos, memory,
                );
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "PrestoChangoSelector", source: source_selector,
                    destination: Some(destination_selector), result: &result,
                });
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::AllocCStoDSAlias { source_selector },
            )) => {
                let result = self.alloc_cs_to_ds_alias(source_selector, dos, memory);
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "AllocCStoDSAlias", source: source_selector,
                    destination: None, result: &result,
                });
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::AllocDStoCSAlias { source_selector },
            )) => {
                let result = self.alloc_ds_to_cs_alias(source_selector, dos, memory);
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "AllocDStoCSAlias", source: source_selector,
                    destination: None, result: &result,
                });
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::AllocAlias { source_selector },
            )) => {
                let result = self.alloc_cs_to_ds_alias(source_selector, dos, memory);
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "AllocAlias", source: source_selector,
                    destination: None, result: &result,
                });
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::FreeSelector { selector },
            )) => {
                let result = self.free_selector(selector, dos, memory);
                host.observe_win16_io(&crate::Win16IoEvent::SelectorChange {
                    operation: "FreeSelector", source: selector,
                    destination: None, result: &result,
                });
                registers.es = 0;
                u32::from(result?)
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::GetSelectorBase { selector },
            )) => self.get_selector_base(selector),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::SetSelectorBase { selector, base },
            )) => u32::from(self.set_selector_base(selector, base, dos, memory)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::GetSelectorLimit { selector },
            )) => self.get_selector_limit(selector),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::SetSelectorLimit { selector, limit },
            )) => u32::from(self.set_selector_limit(selector, limit, dos, memory)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::SelectorAccessRights {
                    selector, operation, access,
                },
            )) => u32::from(self.selector_access_rights(
                selector, operation, access, dos, memory,
            )?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::AllocSelectorArray { count },
            )) => u32::from(self.alloc_selector_array(count, dos, memory)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::LongPtrAdd { far_pointer, amount },
            )) => {
                let result = self.long_ptr_add(far_pointer, amount, dos, memory)?;
                registers.es = 0;
                result
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::IsSharedSelector { selector },
            )) => u32::from(self.is_shared_selector(selector)),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::MapSL { far_pointer },
            )) => self.map_sl(far_pointer, dos, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::MapLS { guest_linear },
            )) => self.map_ls(guest_linear, dos, memory)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Selectors(
                win16_abi::Win16KernelSelectorsRequest::UnMapLS { far_pointer },
            )) => {
                self.unmap_ls(far_pointer, dos, memory)?;
                0
            },
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::CreateFile { path, attributes },
            )) => u32::from(self.open_legacy_file(&path, attributes, true, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::OpenFile { path, mode },
            )) => u32::from(self.open_legacy_file(&path, mode as u16, false, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::OpenStructuredFile { path, ofstruct, style },
            )) => u32::from(self.open_structured_file(&path, ofstruct, style, memory, host)?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::ReadFile {
                    file_handle,
                    buffer,
                    count,
                },
            )) => self.read_file(file_handle, buffer, count, memory, host)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::SeekFile {
                    file_handle,
                    offset,
                    origin,
                },
            )) => self.seek_file(file_handle, offset, origin as u16, host)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::WriteFile {
                    file_handle,
                    buffer,
                    count,
                },
            )) => self.write_file(file_handle, buffer, count, memory, host)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::HugeMemoryCopy {
                    destination,
                    source,
                    count,
                },
            )) => {
                self.copy_huge_memory(destination, source, count, memory)?;
                0
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Files(
                win16_abi::Win16KernelFilesRequest::CloseFile { file_handle },
            )) => self.close_legacy_file(file_handle, host)?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Profiles(
                win16_abi::Win16KernelProfilesRequest::GetPrivateProfileInt {
                    section,
                    key,
                    default_value,
                    filename,
                },
            )) => host.win16_profile_int(
                section.as_deref(),
                key.as_deref(),
                i32::from(default_value),
                &self.private_profile_path(filename.as_deref(), host)?,
            )?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Profiles(
                win16_abi::Win16KernelProfilesRequest::GetProfileInt {
                    section,
                    key,
                    default_value,
                },
            )) => host.win16_system_profile_int(
                section.as_deref(),
                key.as_deref(),
                i32::from(default_value),
            )?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Profiles(
                win16_abi::Win16KernelProfilesRequest::GetPrivateProfileString {
                    section,
                    key,
                    default_value,
                    output_buffer,
                    filename,
                },
            )) => self.profile_string(
                section.as_deref(),
                key.as_deref(),
                default_value.as_deref(),
                filename.as_deref(),
                output_buffer,
                memory,
                host,
            )?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Profiles(
                win16_abi::Win16KernelProfilesRequest::GetProfileString {
                    section,
                    key,
                    default_value,
                    output_buffer,
                },
            )) => self.system_profile_string(
                section.as_deref(),
                key.as_deref(),
                default_value.as_deref(),
                output_buffer,
                memory,
                host,
            )?,
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Profiles(
                win16_abi::Win16KernelProfilesRequest::WritePrivateProfileString {
                    section,
                    key,
                    value,
                    filename,
                },
            )) => u32::from(host.win16_profile_write(
                section.as_deref(),
                key.as_deref(),
                value.as_deref(),
                &self.private_profile_path(filename.as_deref(), host)?,
            )?),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
                win16_abi::Win16KernelRuntimeRequest::ExitProcess { status },
            )) => {
                if let Some(exit_status) = self.finish_task(memory, host, status)? {
                    return Ok(Some(exit_status));
                }
                return self.complete_return(
                    registers,
                    return_selector,
                    return_offset,
                    return_sp,
                    u32::from(status),
                    descriptor.return_kind,
                );
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 request reached a dispatch group that does not own it",
                ));
            }
        };
        if preserve_registers {
            self.retire_far_return(return_selector, u32::from(return_offset), registers.ss);
            registers.cs = return_selector;
            registers.set_ip(return_offset);
            registers.set_sp(return_sp as u16);
            return Ok(None);
        }
        self.complete_return(
            registers,
            return_selector,
            return_offset,
            return_sp,
            value,
            descriptor.return_kind,
        )
    }
}

// These guest heap entry points clobber ES/FS/GS on every normal return,
// including a rejected operation. SDK 3.0 Guide section 14.6 makes ES
// volatile; the enhanced-mode KERNEL GENTER32/GLEAVE32 implementation
// clears these registers. Keeping ES across a free or move would expose
// a retired selector to the next API. Internal heap helpers do not have
// this caller-register side effect.
pub(super) fn finish_global_heap_call(registers: &mut Registers) {
    registers.es = 0;
    registers.fs = 0;
    registers.gs = 0;
}

#[cfg(test)]
#[path = "win16_lstrlen_tests.rs"]
mod lstrlen_tests;
