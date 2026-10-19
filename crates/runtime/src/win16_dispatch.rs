//! Win16 service-gate dispatch over decoded project ABI requests.

use super::*;
use win16_abi::{
    ReturnAddressWidth, Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind, Win16RegisterContext,
    decode_export_call_with_register_context,
};
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, Cpu, LegacyRegisterTransfer};

#[cfg(test)]
#[path = "win16_dispatch_input_event_tests.rs"]
mod input_event_tests;

impl Win16State {
    pub(crate) fn dispatch(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut dos_kernel::DosKernel,
        host: &mut impl RuntimeHost,
        pe32_step_limit: u64,
    ) -> Result<Option<u8>, RuntimeError> {
        self.prune_catch_scopes();
        let registers = &cpu.regs;
        let slot = usize::from(registers.ip()) / 2;
        if registers.ip() & 1 != 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                format!(
                    "Win16 service gate offset 0x{:04X} is not aligned",
                    registers.ip()
                ),
            ));
        }
        let binding = self.bindings.get(slot).ok_or_else(|| {
            RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "Win16 service gate has no export at offset 0x{:04X}",
                    registers.ip()
                ),
            )
        })?;
        let descriptor = match binding {
            ImportBinding::Supported(descriptor) => *descriptor,
            ImportBinding::Unavailable { .. } => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    format!("Win16 import {} has no ABI bridge yet", binding.name()),
                ));
            }
        };
        let stack_pointer = self
            .selectors
            .pointer_from_raw(Selector(registers.ss), registers.sp())
            .map_err(crate::runtime_error)?;
        let frame = Win16CallFrame::new(stack_pointer, ReturnAddressWidth::Far);
        if descriptor.module().eq_ignore_ascii_case("KERNEL")
            && (513..=518).contains(&descriptor.ordinal())
        {
            return self.begin_pe32_generic_thunk(
                cpu,
                memory,
                host,
                descriptor.ordinal(),
                frame,
                pe32_step_limit,
            );
        }
        let decoded = decode_export_call_with_register_context(
            descriptor,
            frame,
            Win16RegisterContext::from(&*registers),
            &self.selectors,
            memory,
        )
        .map_err(crate::runtime_error)?;
        match decoded.request {
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::SwitchStackTo {
                stack_selector, stack_pointer, stack_top,
            }) => {
                self.switch_stack_to(cpu, memory, dos, stack_selector, stack_pointer, stack_top)?;
                return Ok(None);
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::SwitchStackBack { context }) => {
                self.switch_stack_back(cpu, memory, dos, context)?;
                return Ok(None);
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Catch { buffer }) => {
                self.catch_guest(cpu, memory, dos, buffer)?;
                return Ok(None);
            }
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Throw { buffer, value }) => {
                self.throw_guest(cpu, memory, dos, buffer, value)?;
                return Ok(None);
            }
            _ => {}
        }
        if descriptor.abi_kind == Win16ExportAbiKind::RegisterContext {
            return match decoded.request {
                Win16ApiRequest::InitTask { context } => {
                    self.init_task(context, &mut cpu.regs, memory)?;
                    Ok(None)
                }
                Win16ApiRequest::FpMath { context } => self.fp_math(context, cpu, memory),
                Win16ApiRequest::User(win16_abi::Win16UserRequest::Input(request)) => {
                    self.inject_user_input(request, cpu, memory, host)
                }
                Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Remainder(
                    win16_abi::Win16KernelRemainderRequest::Register { .. },
                )) => self.fail_kernel_register_remainder(cpu, memory),
                _ => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 register-context export decoded to a stack request",
                )),
            };
        }
        let (return_selector, return_offset, return_sp) =
            self.far_return(registers, memory, decoded.stack_cleanup.callee_pop_bytes)?;
        let return_to = (return_selector, return_offset, return_sp);
        let heap_operation = match &decoded.request {
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::GlobalMemory(
                win16_abi::Win16KernelGlobalMemoryRequest::GlobalAlloc { flags, size },
            )) => Some(super::global_notify::GlobalHeapOperation::Allocate {
                flags: *flags, size: *size, caller: return_selector,
            }),
            Win16ApiRequest::KernelGlobalHeap(
                win16_abi::Win16KernelGlobalHeapRequest::GlobalCompact { minimum_free },
            ) => Some(super::global_notify::GlobalHeapOperation::Compact { minimum_free: *minimum_free }),
            Win16ApiRequest::KernelGlobalHeap(
                win16_abi::Win16KernelGlobalHeapRequest::GlobalReAlloc { handle, size, flags },
            ) => Some(super::global_notify::GlobalHeapOperation::Reallocate {
                handle: *handle, identity: self.global_handles.get(handle).copied(),
                size: *size, flags: *flags, caller: return_selector,
            }),
            _ => None,
        };
        if let Some(operation) = heap_operation {
            return self.begin_global_heap_operation(operation, cpu, dos, memory, host, return_to);
        }
        if let Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Runtime(
            win16_abi::Win16KernelRuntimeRequest::WaitEvent { task_handle },
        )) = &decoded.request {
            self.begin_task_event_wait(cpu, dos, memory, *task_handle, return_to)?;
            return Ok(None);
        }
        match &decoded.request {
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::LoadModule { module, parameters },
            )) => return self.begin_load_module(module, *parameters, cpu, dos, memory, host, return_to),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::FreeModule { module },
            )) => return self.begin_free_module(*module, cpu, dos, memory, host, return_to),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::LoadLibrary { library_name },
            )) => return self.begin_load_library(library_name, cpu, dos, memory, host, return_to),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Modules(
                win16_abi::Win16KernelModulesRequest::FreeLibrary { module },
            )) => return self.begin_free_library(*module, cpu, dos, memory, host, return_to),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::LoadResource { module, info },
            )) => return self.begin_load_resource(cpu, dos, memory, host, *module, *info, return_to),
            Win16ApiRequest::Kernel(win16_abi::Win16KernelRequest::Resources(
                win16_abi::Win16KernelResourcesRequest::LockResource { data },
            )) => return self.begin_lock_resource(cpu, dos, memory, host, *data, return_to),
            _ => {}
        }
        let request = match decoded.request {
            Win16ApiRequest::Ole1(request) => {
                return self.begin_ole1_request(request, cpu, dos, memory, host,
                    return_to, descriptor.return_kind);
            }
            Win16ApiRequest::KernelDiagnostics(request) => {
                let callback_context = cpu.capture_context();
                let call_owner = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
                let previous_window_context = self
                    .window_dispatch_context
                    .replace(callback_context);
                let previous_call_owner = self.active_dispatch_call_owner.replace(call_owner);
                let previous_direct_return = self.active_dispatch_return.take();
                let result = self.begin_kernel_diagnostic(request, cpu, memory, host, return_to);
                self.window_dispatch_context = previous_window_context;
                let unconsumed_owner = self.active_dispatch_call_owner.take();
                let direct_return = self.active_dispatch_return.take();
                self.active_dispatch_call_owner = previous_call_owner;
                self.active_dispatch_return = previous_direct_return;
                return match result {
                    Ok(value) => {
                        if let Some(owner) = unconsumed_owner {
                            self.finish_unconsumed_dispatch_call(
                                owner, direct_return, cpu, dos, memory,
                            )?;
                        }
                        self.drive_pending_window_completion(cpu, memory, dos, host)?;
                        Ok(value)
                    }
                    Err(error) => Err(error),
                };
            }
            Win16ApiRequest::WindowEnumeration(request) => {
                return self.begin_window_enumeration(cpu, dos, memory, host, request, return_to);
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Hooks(request)) => {
                return self.dispatch_user_hooks(request, cpu, dos, memory, host, descriptor, return_to);
            }
            request => request,
        };
        let callback_context = cpu.capture_context();
        if crate::win16_io_trace::observes_io(&request) {
            host.observe_win16_io(&crate::Win16IoEvent::Api {
                module: descriptor.module(),
                ordinal: descriptor.ordinal(),
                caller_selector: return_selector,
                caller_offset: return_offset,
            });
        }
        let dispatch_route = super::dispatch_routes::route_for_request(&request);
        let call_owner = if matches!(dispatch_route,
            super::dispatch_routes::DispatchRoute::User)
            // Queue-backed KERNEL.Yield and these library families also use USER's
            // operation stack. Capture their real caller before that stack
            // consumes it; module routing alone does not describe callbacks.
            || (matches!(&request, Win16ApiRequest::Kernel(
                win16_abi::Win16KernelRequest::Runtime(win16_abi::Win16KernelRuntimeRequest::Yield)))
                && self.kernel_yield_queue()?.is_some())
            || matches!(&request, Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::EnumMetaFile { .. }))
            || matches!(&request, Win16ApiRequest::Dde(_)
                | Win16ApiRequest::Commdlg(_)
                | Win16ApiRequest::Printer(win16_abi::Win16PrinterRequest::ExtDeviceMode { .. })
                | Win16ApiRequest::Commctrl(_)
                | Win16ApiRequest::ShellExecution(_)
                | Win16ApiRequest::ShellDrop(_)
                | Win16ApiRequest::ShellDrive(_)
                | Win16ApiRequest::Winnls(
                    win16_abi::Win16WinnlsRequest::EnableIme { .. }
                        | win16_abi::Win16WinnlsRequest::GetEnableStatus { .. }))
        {
            Some(self.capture_legacy_cpu_call_frame(cpu, dos, memory)?)
        } else {
            None
        };
        let previous_window_context = self.window_dispatch_context.replace(callback_context);
        let previous_call_owner = std::mem::replace(
            &mut self.active_dispatch_call_owner,
            call_owner,
        );
        let previous_direct_return = self.active_dispatch_return.take();
        let result = match dispatch_route {
            super::dispatch_routes::DispatchRoute::Kernel => {
                self.dispatch_kernel(request, &mut cpu.regs, memory, dos, host, descriptor, return_to)
            }
            super::dispatch_routes::DispatchRoute::User => {
                self.dispatch_user(request, &mut cpu.regs, memory, host, descriptor, return_to)
            }
            super::dispatch_routes::DispatchRoute::Gdi => {
                self.dispatch_gdi(request, cpu, dos, memory, host, descriptor, return_to)
            }
            super::dispatch_routes::DispatchRoute::Libraries => match request {
                Win16ApiRequest::Multimedia(call) => self.acm_compat_api(
                    call, cpu, dos, memory, host, return_to, descriptor.return_kind,
                ),
                request => self.dispatch_libraries(
                    request, &mut cpu.regs, memory, host, descriptor, return_to,
                ),
            },
        };
        self.window_dispatch_context = previous_window_context;
        let unconsumed_owner = self.active_dispatch_call_owner.take();
        let direct_return = self.active_dispatch_return.take();
        self.active_dispatch_call_owner = previous_call_owner;
        self.active_dispatch_return = previous_direct_return;
        match result {
            Ok(value) => {
                if let Some(owner) = unconsumed_owner {
                    self.finish_unconsumed_dispatch_call(owner, direct_return, cpu, dos, memory)?;
                }
                self.drive_pending_window_completion(cpu, memory, dos, host)?;
                Ok(value)
            }
            other => other,
        }
    }

    /// CPU-routed KERNEL calls can enter USER after classifying a module as a
    /// process. Preserve the real entry context only for that operation; DLL
    /// initialization and WEP keep their own module continuation owners.
    pub(super) fn dispatch_owned_window_call<H: RuntimeHost>(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut H,
        begin: impl FnOnce(&mut Self, &mut Cpu, &mut Memory, &mut H) -> Result<Option<u8>, RuntimeError>,
    ) -> Result<Option<u8>, RuntimeError> {
        let context = cpu.capture_context();
        let owner = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
        let previous_context = self.window_dispatch_context.replace(context);
        let previous_owner = self.active_dispatch_call_owner.replace(owner);
        let previous_return = self.active_dispatch_return.take();
        let result = begin(self, cpu, memory, host);
        self.window_dispatch_context = previous_context;
        let unconsumed_owner = self.active_dispatch_call_owner.take();
        let direct_return = self.active_dispatch_return.take();
        self.active_dispatch_call_owner = previous_owner;
        self.active_dispatch_return = previous_return;
        match result {
            Ok(value) => {
                if let Some(owner) = unconsumed_owner {
                    self.finish_unconsumed_dispatch_call(owner, direct_return, cpu, dos, memory)?;
                }
                self.drive_pending_window_completion(cpu, memory, dos, host)?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    fn finish_unconsumed_dispatch_call(
        &mut self,
        owner: u64,
        target: Option<LegacyRegisterTransfer>,
        cpu: &mut Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let target = target.ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 service dispatch returned without a retained operation or staged caller return",
        ))?;
        self.retain_legacy_cpu_frame_roots(owner, &target.registers, dos, memory)?;
        let return_address = (
            target.registers.cs,
            u32::from(target.registers.ip()),
            target.registers.ss,
        );
        self.return_legacy_cpu_call_frame(
            owner,
            cpu,
            memory,
            CallEffectPolicy::PreserveX87,
            CallResumeBoundary::NoGuestExecution,
            target,
        )?;
        self.retire_far_return(return_address.0, return_address.1, return_address.2);
        self.release_legacy_cpu_frame(owner, dos, memory)
    }
}
