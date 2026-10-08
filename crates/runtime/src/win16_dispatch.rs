//! Win16 service-gate dispatch over decoded project ABI requests.

use super::*;
use win16_abi::{
    ReturnAddressWidth, Win16ApiRequest, Win16CallFrame, Win16ExportAbiKind, Win16RegisterContext,
    decode_export_call_with_register_context,
};
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, Cpu, LegacyRegisterTransfer};

impl Win16State {
    pub(crate) fn dispatch(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut dos_kernel::DosKernel,
        host: &mut impl RuntimeHost,
        pe32_step_limit: u64,
    ) -> Result<Option<u8>, RuntimeError> {
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
        if descriptor.abi_kind == Win16ExportAbiKind::RegisterContext {
            return match decoded.request {
                Win16ApiRequest::InitTask { context } => {
                    self.init_task(context, &mut cpu.regs, memory)?;
                    Ok(None)
                }
                Win16ApiRequest::FpMath { context } => self.fp_math(context, cpu, memory),
                _ => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 register-context export decoded to a stack request",
                )),
            };
        }
        let (return_selector, return_offset, return_sp) =
            self.far_return(registers, memory, decoded.stack_cleanup.callee_pop_bytes)?;
        let return_to = (return_selector, return_offset, return_sp);
        let callback_context = cpu.capture_context();
        let request = match decoded.request {
            Win16ApiRequest::Ole1(request) => {
                return self.begin_ole1_request(request, cpu, dos, memory, host,
                    return_to, descriptor.return_kind);
            }
            Win16ApiRequest::KernelDiagnostics(request) => {
                let call_owner = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
                let previous_window_context = self
                    .window_dispatch_context
                    .replace(callback_context.clone());
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
            // These library families also suspend through the shared USER
            // operation stack. Capture their real caller before that stack
            // consumes it; module routing alone does not describe callbacks.
            || matches!(&request, Win16ApiRequest::Dde(_)
                | Win16ApiRequest::Commdlg(_)
                | Win16ApiRequest::Commctrl(_)
                | Win16ApiRequest::ShellExecution(_)
                | Win16ApiRequest::ShellDrop(_)
                | Win16ApiRequest::ShellDrive(_))
        {
            Some(self.capture_legacy_cpu_call_frame(cpu, dos, memory)?)
        } else {
            None
        };
        let previous_window_context = self.window_dispatch_context.replace(callback_context.clone());
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
                    request, &mut cpu.regs, memory, host, descriptor, return_to, callback_context,
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
        self.return_legacy_cpu_call_frame(
            owner,
            cpu,
            memory,
            CallEffectPolicy::PreserveX87,
            CallResumeBoundary::NoGuestExecution,
            target.clone(),
        )?;
        self.retire_far_return(target.registers.cs, u32::from(target.registers.ip()), target.registers.ss);
        self.release_legacy_cpu_frame(owner, dos, memory)
    }
}
