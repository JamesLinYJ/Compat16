//! Runtime request arms owned by the Libraries service group.

use guest_core::Registers;
use guest_core::memory::Memory;
use win16_abi::{Win16ApiRequest, Win16ExportDescriptor};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn dispatch_libraries(
        &mut self,
        request: Win16ApiRequest,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) = return_to;
        let value = match request {
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::IsEqualGuid {
                left, right,
            }) => u32::from(left == right),
            Win16ApiRequest::PrintQueue(request) => self.print_queue_api(request),
            Win16ApiRequest::Ole1(request) => self.ole1_client_document_api(request, memory),
            Win16ApiRequest::Mci(request) => {
                // MCI retains its own context across asynchronous callbacks.
                // Other library calls use the dispatch-owned snapshot directly.
                let callback_context = self.window_dispatch_context.clone().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 MCI operation has no CPU context from guest dispatch",
                    )
                })?;
                return self.begin_mci_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                    callback_context,
                );
            }
            Win16ApiRequest::Dde(request) => {
                return self.begin_dde_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::ToolhelpStack(request) => {
                use win16_abi::Win16ToolhelpStackRequest as Request;
                u32::from(match request {
                    Request::StackTraceFirst { output, task } => {
                        // The service gate has no guest BP prologue. Seed the
                        // first frame with the checked FAR caller return site,
                        // retaining its actual SS:BP rather than the gate IP.
                        let mut caller_registers = registers.clone();
                        caller_registers.cs = return_selector;
                        caller_registers.set_ip(return_offset);
                        self.toolhelp_stack_trace_first(
                            output, task, &caller_registers, memory, host,
                        )?
                    }
                    Request::StackTraceCsipFirst {
                        output,
                        stack_segment,
                        code_segment,
                        instruction_pointer,
                        base_pointer,
                    } => self.toolhelp_stack_trace_csip_first(
                        output,
                        stack_segment,
                        code_segment,
                        instruction_pointer,
                        base_pointer,
                        memory,
                    )?,
                    Request::StackTraceNext { output } => {
                        self.toolhelp_stack_trace_next(output, memory, host)?
                    }
                })
            }
            Win16ApiRequest::Commdlg(request) => {
                return self.begin_common_dialog_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::Ctl3d(request) => self.ctl3d_request(request, host)?,
            Win16ApiRequest::Commctrl(request) => {
                return self.begin_common_controls_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::Printer(request) => self.printer(request, memory, host)?,
            Win16ApiRequest::ShellIcon(request) => self.shell_icon_api(request, memory, host)?,
            Win16ApiRequest::ShellExecution(request) => {
                return self.begin_shell_execution_request(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::ShellDrop(request) => {
                return self.begin_shell_drop_request(
                    request, registers, memory, host,
                    (return_selector, return_offset, return_sp), descriptor.return_kind,
                );
            }
            Win16ApiRequest::ShellDrive(request) => self.shell_drive_type(request.drive, host)?,
            Win16ApiRequest::ShellRegistry(request) => {
                self.shell_registry_api(request, memory, host)?
            }
            Win16ApiRequest::Ole2Nls(request) => self.ole2nls_api(request, memory, host)?,
            Win16ApiRequest::Winnls(request @ (
                win16_abi::Win16WinnlsRequest::EnableIme { .. }
                    | win16_abi::Win16WinnlsRequest::GetEnableStatus { .. }
            )) => {
                return self.begin_winnls_ime_control(
                    request, registers, memory, host, return_to, descriptor.return_kind,
                );
            }
            Win16ApiRequest::Winnls(request) => self.winnls_api(request, memory, host)?,
            Win16ApiRequest::Winmem32(request) => self.winmem32_api(request, memory)?,
            Win16ApiRequest::Ole2Disp(request) => self.ole2disp_api(request, memory, host)?,
            Win16ApiRequest::Ole2DispConvert(request) => {
                self.ole2disp_convert_api(request, memory, host)?
            }
            Win16ApiRequest::Winsock(request) => self.winsock_api(request, memory, host)?,
            Win16ApiRequest::Aux(request) => self.aux_api(request, memory, host)?,
            Win16ApiRequest::MediaTime(request) => self.media_time_api(request, memory, host)?,
            Win16ApiRequest::Joystick(request) => self.joystick_api(request, memory, host)?,
            Win16ApiRequest::MediaIo(request) => self.media_io_api(request, memory, host)?,
            Win16ApiRequest::Midi(request) => self.midi_api(request, memory, host)?,
            Win16ApiRequest::Multimedia(_) => return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MSACM request bypassed the CPU-owned callback dispatch boundary",
            )),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Wave(request)) => {
                self.wave_api(request, memory, host)?
            }
            Win16ApiRequest::Sound(request) => self.sound_api(request, memory, host)?,
            Win16ApiRequest::Keyboard(request) => {
                self.keyboard_compat_api(request, memory, host)?
            }
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::CodePage(
                win16_abi::Win16LibraryCodePageRequest::IsDbcsLeadByte { value },
            )) => self.wifeman_dbcs_lead_byte(value, host)?,
            Win16ApiRequest::Ver(request) => {
                return self.ver_compat_api(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::LzExpand(request) => {
                return self.lzexpand_compat_api(
                    request,
                    registers,
                    memory,
                    host,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::Shell(request) => {
                return self.shell_compat_api(
                    request,
                    registers,
                    memory,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            Win16ApiRequest::FpMath { .. } => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 __fpMath reached the stack-call dispatcher",
                ));
            }
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalHandleToSel { handle },
            )) => u32::from(self.toolhelp_global_handle_to_sel(handle)),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalFirst { output, flags },
            )) => u32::from(self.toolhelp_global_first(output, flags, memory)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalNext { output, flags },
            )) => u32::from(self.toolhelp_global_next(output, flags, memory)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalInfo { output },
            )) => u32::from(self.toolhelp_global_info(output, memory)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalEntryHandle {
                    output,
                    handle,
                },
            )) => u32::from(self.toolhelp_global_entry_handle(output, handle, memory)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Toolhelp(
                win16_abi::Win16LibraryToolhelpRequest::ToolhelpGlobalEntryModule {
                    output,
                    module,
                    segment,
                },
            )) => u32::from(self.toolhelp_global_entry_module(output, module, segment, memory)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Interrupts(
                win16_abi::Win16LibraryInterruptsRequest::InterruptRegister {
                    task_handle,
                    callback,
                },
            )) => u32::from(self.interrupt_register(task_handle, callback, memory, host)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Interrupts(
                win16_abi::Win16LibraryInterruptsRequest::InterruptUnregister { task_handle },
            )) => u32::from(self.interrupt_unregister(task_handle)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Strings(
                win16_abi::Win16LibraryStringsRequest::OemToAnsi {
                    source,
                    destination,
                },
            )) => u32::from(self.oem_to_ansi(&source, destination, memory, host)?),
            Win16ApiRequest::Libraries(win16_abi::Win16LibraryRequest::Strings(
                win16_abi::Win16LibraryStringsRequest::StringCompare {
                    left,
                    right,
                    comparison,
                },
            )) => self.string_compare(&left, &right, comparison, host)? as u16 as u32,
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 request reached a dispatch group that does not own it",
                ));
            }
        };
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

#[cfg(test)]
#[path = "win16_guid_compare_tests.rs"]
mod guid_compare_tests;
