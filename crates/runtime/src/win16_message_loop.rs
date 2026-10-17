//! Win16 USER message-loop APIs over the host thread's native USER queue.
//!
//! MSG16 is decoded with the shared Win16 codec. Native handles stay opaque,
//! and guest LPARAM bits are never passed to a host API that may treat them
//! as addresses or callbacks.

use guest_core::{Registers, memory::Memory};
use win16_abi::{Msg16, Win16ReturnKind};

use super::{Win16State, windows::WindowReturn};
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16GuestNotification,
    Win16HostQueuedMessage, Win16MessageFilter, Win16MessageParam, Win16MessageSource,
    Win16MessageWindow, Win16ScalarMessage, Win16WindowInputMessage, Win16WindowOperation,
};

enum ResolvedMessageWindow {
    Thread,
    Window(crate::Win16HostWindow),
}

const WM_QUIT: u16 = 0x0012;
const WM_DROPFILES: u16 = 0x0233;

impl Win16State {
    pub(super) fn begin_post_guest_notification(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        notification: Win16GuestNotification,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let _ = self.ensure_user_queue(host)?;
        if !self.validate_guest_notification_target(notification.target) {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 guest notification target no longer matches its exact task/window identity",
            ));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        }
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::PostGuestNotification(notification),
            WindowReturn::GuestNotificationPost,
            return_to,
        )
    }

    pub(super) fn begin_get_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        output_far: u32,
        window: u16,
        min_message: u16,
        max_message: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let output = self.validate_msg16_output(output_far, memory)?;
        let Some(queue) = self.ensure_user_queue(host)? else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 GetMessage has no live task-bound native USER queue",
            ));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(u16::MAX),
                Win16ReturnKind::Word,
            );
        };
        let Some(filter) = self.message_filter(window, min_message, max_message, queue, host)?
        else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(u16::MAX),
                Win16ReturnKind::Word,
            );
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::GetMessage { filter },
            WindowReturn::GetMessage { output },
            return_to,
        )
    }

    pub(super) fn begin_peek_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        output_far: u32,
        window: u16,
        min_message: u16,
        max_message: u16,
        flags: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let output = self.validate_msg16_output(output_far, memory)?;
        let Some(queue) = self.ensure_user_queue(host)? else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                "Win16 PeekMessage has no live task-bound native USER queue",
            ));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        let Some(filter) = self.message_filter(window, min_message, max_message, queue, host)?
        else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::PeekMessage { filter, flags },
            WindowReturn::PeekMessage { output },
            return_to,
        )
    }

    pub(super) fn begin_translate_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        message: Msg16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(resolved) = self.resolve_message_window(message.hwnd, host)? else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Word,
            );
        };
        let queued = Win16HostQueuedMessage {
            source: Win16MessageSource::GuestMessage,
            window: resolved.native(),
            message: message.message,
            w_param: message.w_param,
            // TranslateMessage reads only message fields; it does not
            // dereference LPARAM. Preserve guest bits as an integer.
            l_param: Win16MessageParam::GuestBits(message.l_param),
            time: message.time,
            point: crate::Win16HostPoint {
                x: i32::from(message.pt.x),
                y: i32::from(message.pt.y),
            },
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::TranslateMessage { message: queued },
            WindowReturn::TranslateMessage,
            return_to,
        )
    }

    pub(super) fn begin_dispatch_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        message: Msg16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if message.message == WM_QUIT {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Dword,
            );
        }
        if message.message == WM_DROPFILES {
            if self.queued_drop_global_for_dispatch(message)?.is_none() {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "DispatchMessage refused WM_DROPFILES without its exact live guest HGLOBAL queue owner",
                ));
                return self.complete_return(
                    registers, return_to.0, return_to.1, return_to.2,
                    0, Win16ReturnKind::Dword,
                );
            }
            // The queue registry owns the HGLOBAL generation through the
            // guest's DragFinish call. A callback frame must not free it on
            // return because Win16 code may retain the HDROP token.
            return self.begin_guest_dispatch_callback(
                registers, memory, message, false, return_to,
            );
        }
        if super::messages_mdi::is_mdi_message(message.message) {
            // WM_MDICREATE contains a guest FAR pointer whose lifetime and
            // synchronous callback identity cannot be reconstructed from an
            // arbitrary MSG16. Every other MDI dispatch is rebuilt from the
            // current, guest-editable fields and exact live HWND/HMENU maps.
            if message.message == super::messages_mdi::WM_MDICREATE16 {
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            }
            let Some(mdi) = self.prepare_guest_dispatch_mdi_message(
                message.hwnd,
                message.message,
                message.w_param,
                message.l_param,
            )?
            else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 DispatchMessage MDI message 0x{:04X} has invalid endpoint or guest parameters",
                        message.message)));
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            };
            let mdi_output = match mdi.message {
                super::messages_mdi::Win16HostMdiMessageQueuedKind::Destroy {
                    child: Some(native_child),
                } => {
                    if self.existing_mdi_child_guest_handle(native_child) != Some(message.w_param) {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "typed WM_MDIDESTROY dispatch lost its exact guest child identity",
                        ));
                    }
                    let Some(creation) = self.window_creations.get(&message.w_param).copied()
                    else {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "live Win16 MDI child has no exact creation generation",
                        ));
                    };
                    Some(super::messages_mdi::MdiOutputPlan::Destroy(
                        super::messages_mdi::MdiChildRetirementPlan {
                            guest: message.w_param,
                            native: native_child,
                            creation,
                        },
                    ))
                }
                _ => None,
            };
            let Some(&native) = self.window_handles.get(&message.hwnd) else {
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            };
            let queued = Win16HostQueuedMessage {
                source: Win16MessageSource::GuestMessage,
                window: Some(native),
                message: message.message,
                w_param: message.w_param,
                l_param: Win16MessageParam::Mdi(mdi),
                time: message.time,
                point: crate::Win16HostPoint {
                    x: i32::from(message.pt.x),
                    y: i32::from(message.pt.y),
                },
            };
            return self.begin_window_operation(
                registers,
                memory,
                host,
                Win16WindowOperation::DispatchMessage { message: queued },
                WindowReturn::DispatchMessage { mdi_output },
                return_to,
            );
        }
        if Win16ScalarMessage::is_timer_message(message.message) && message.l_param != 0 {
            return self.begin_guest_dispatch_callback(registers, memory, message, true, return_to);
        }

        let window_input = if Win16WindowInputMessage::accepts(message.message) {
            self.window_input_from_guest(message.message, message.w_param, message.l_param)
        } else {
            None
        };
        let typed_message = match message.message {
            0x001c => match self.activation_queue_for_task(message.l_param as u16) {
                Ok(other_task_queue) => Some(Win16MessageParam::ActivationApp(
                    crate::Win16HostActivationApp {
                        active: u16::from(message.w_param != 0),
                        other_task_queue,
                    },
                )),
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_ACTIVATEAPP task identity was not mapped: {error}")));
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Dword);
                }
            },
            0x0210 => match self.parent_notification_from_guest(
                message.w_param, message.l_param,
            ) {
                Ok(input) => Some(Win16MessageParam::ParentNotification(input)),
                Err(error) => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        format!("Win16 WM_PARENTNOTIFY layout was not mapped: {error}")));
                    return self.complete_return(registers, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Dword);
                }
            },
            _ => None,
        };

        // Unknown/pointer-bearing guest LPARAMs belong to the guest address
        // space. Call the mapped Win16 procedure directly so they are never
        // interpreted as native pointers. WM_COMMAND and the checked
        // window-input family carry typed HWND identities, so they can safely
        // go through native DispatchMessage even for a borrowed native HWND.
        let scalar = Win16ScalarMessage::from_raw(message.message).is_some()
            || (Win16ScalarMessage::is_timer_message(message.message) && message.l_param == 0)
            || message.message == super::messages::WM_CHANGECBCHAIN
            || typed_message.is_some()
            || window_input.is_some();
        let has_guest_proc = self.window_procedures.contains_key(&message.hwnd)
            || self.dialog_procedures.contains_key(&message.hwnd);
        // Scalar MM_* notification LPARAMs can use a stock native default
        // procedure. Header-bearing notifications stay in the guest route;
        // their FAR value is never sent to a native window procedure.
        let multimedia_scalar = crate::is_multimedia_notification_message(message.message)
            && !crate::multimedia_notification_has_guest_far_lparam(message.message)
            && !has_guest_proc;
        let dialog_private =
            message.message >= 0x0400 && self.dialog_procedures.contains_key(&message.hwnd);
        let dialog_command =
            message.message == 0x0111 && self.dialog_procedures.contains_key(&message.hwnd);
        let borrowed_command =
            message.message == 0x0111 && !self.owned_window_handles.contains(&message.hwnd);
        if crate::multimedia_notification_has_guest_far_lparam(message.message)
            && !has_guest_proc
            && message.hwnd != 0
        {
            // Windows 3.1 MMSYSTEM.H defines WOM_DONE, WIM_DATA,
            // MIM_LONGDATA, MIM_LONGERROR and MOM_DONE as notifications whose
            // LPARAM is a guest FAR to a WAVEHDR16/MIDIHDR16. With no guest
            // FARPROC, there is no ABI-safe receiver: passing those bits to a
            // native WndProc could make it treat a guest address as a host
            // pointer. Preserve the stock unhandled-dispatch result (zero) and
            // report the missing guest procedure below.
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("Win16 multimedia message 0x{:04X} carries a guest FAR LPARAM but HWND 0x{:04X} has no guest procedure; the value was not sent to native USER", message.message, message.hwnd)));
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Dword,
            );
        }
        if !scalar && !multimedia_scalar && !borrowed_command && !dialog_private && !dialog_command
        {
            if message.hwnd != 0 && !has_guest_proc {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    format!("Win16 message 0x{:04X} has guest LPARAM bits but HWND 0x{:04X} has no guest procedure; it was not forwarded as a native pointer", message.message, message.hwnd)));
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            }
            return self
                .begin_guest_dispatch_callback(registers, memory, message, false, return_to);
        }
        let Some(resolved) = self.resolve_message_window(message.hwnd, host)? else {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Dword,
            );
        };
        if matches!(resolved, ResolvedMessageWindow::Thread) {
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Dword,
            );
        }
        let l_param = if message.message == 0x0111 {
            let command = super::messages::unpack_win16_command(message.w_param, message.l_param);
            let control = if command.control == 0 {
                None
            } else if let Some(native) = self.window_handles.get(&command.control).copied() {
                Some(native)
            } else {
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            };
            Win16MessageParam::Command {
                control,
                notify: command.notify,
                control_parent: None,
            }
        } else if message.message == super::messages::WM_CHANGECBCHAIN {
            let Some(parameter) =
                self.clipboard_chain_param(message.w_param, message.l_param as u16)
            else {
                return self.complete_return(
                    registers,
                    return_to.0,
                    return_to.1,
                    return_to.2,
                    0,
                    Win16ReturnKind::Dword,
                );
            };
            parameter
        } else if let Some(input) = window_input {
            Win16MessageParam::WindowInput(input)
        } else if let Some(input) = typed_message {
            input
        } else if dialog_private {
            Win16MessageParam::GuestBits(message.l_param)
        } else if multimedia_scalar {
            Win16MessageParam::Scalar(message.l_param)
        } else {
            Win16MessageParam::Scalar(message.l_param)
        };
        let queued = Win16HostQueuedMessage {
            source: Win16MessageSource::GuestMessage,
            window: resolved.native(),
            message: message.message,
            w_param: message.w_param,
            l_param,
            time: message.time,
            point: crate::Win16HostPoint {
                x: i32::from(message.pt.x),
                y: i32::from(message.pt.y),
            },
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::DispatchMessage { message: queued },
            WindowReturn::DispatchMessage { mdi_output: None },
            return_to,
        )
    }

    pub(super) fn begin_post_quit_message(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        exit_code: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::PostQuitMessage { exit_code },
            WindowReturn::PostQuitMessage,
            return_to,
        )
    }

    fn validate_msg16_output(
        &self,
        output_far: u32,
        memory: &Memory,
    ) -> Result<super::guest_ranges::GuestOutputRange, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(output_far)
            .map_err(crate::runtime_error)?;
        super::guest_ranges::GuestOutputRange::capture(self, memory, pointer, Msg16::SIZE)
    }

    fn message_filter(
        &self,
        window: u16,
        min_message: u16,
        max_message: u16,
        task_queue: crate::Win16HostTaskQueue,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16MessageFilter>, RuntimeError> {
        let filter_window = if window == 0 {
            Win16MessageWindow::Any
        } else if window == u16::MAX {
            Win16MessageWindow::ThreadOnly
        } else if let Some(native) = self.window_handles.get(&window).copied() {
            Win16MessageWindow::Window(native)
        } else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!(
                    "Win16 message filter HWND 0x{window:04X} is not mapped; no message was removed"
                ),
            ));
            return Ok(None);
        };
        Ok(Some(Win16MessageFilter {
            window: filter_window,
            min_message,
            max_message,
            task_queue: Some(task_queue),
        }))
    }

    pub(super) fn validate_guest_notification_target(
        &self,
        target: crate::Win16GuestNotificationTarget,
    ) -> bool {
        let Some((owner, task, generation, queue)) = self.user_task_queue else {
            return false;
        };
        // This worker has one live native queue binding. A previously cached
        // task identity must not make a notification eligible after the guest
        // scheduler has switched the exact current owner/task.
        if self.tasks.current() != Some(owner) {
            return false;
        }
        match target {
            crate::Win16GuestNotificationTarget::Window { window, guest_hwnd } => {
                self.window_handles.get(&guest_hwnd) == Some(&window)
                    && self
                        .selectors
                        .reference(guest_core::Selector(task))
                        .is_ok_and(|reference| reference.generation() == generation)
                    && self.task_handles.get(&owner) == Some(&task)
            }
            crate::Win16GuestNotificationTarget::Task {
                owner: target_owner,
                guest_htask,
                task_selector_generation,
                queue: target_queue,
            } => {
                (
                    target_owner,
                    guest_htask,
                    task_selector_generation,
                    target_queue,
                ) == (owner, task, generation, queue)
                    && self
                        .selectors
                        .reference(guest_core::Selector(task))
                        .is_ok_and(|reference| reference.generation() == generation)
                    && self.task_handles.get(&owner) == Some(&task)
            }
        }
    }

    fn resolve_message_window(
        &self,
        window: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<ResolvedMessageWindow>, RuntimeError> {
        if window == 0 {
            return Ok(Some(ResolvedMessageWindow::Thread));
        }
        if let Some(native) = self.window_handles.get(&window).copied() {
            Ok(Some(ResolvedMessageWindow::Window(native)))
        } else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("Win16 MSG HWND 0x{window:04X} is not mapped; message was not dispatched"),
            ));
            Ok(None)
        }
    }
}

impl ResolvedMessageWindow {
    fn native(self) -> Option<crate::Win16HostWindow> {
        match self {
            Self::Thread => None,
            Self::Window(window) => Some(window),
        }
    }
}
